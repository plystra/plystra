package api

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	accessTokenTTL  = 15 * time.Minute
	refreshTokenTTL = 30 * 24 * time.Hour
)

type authLoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type authRefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type authLogoutRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type sessionRecord struct {
	ID                 string
	UserID             string
	ActiveSpaceID      string
	ActiveMemberID     string
	ActiveUserMemberID string
	ExpiresAt          time.Time
	RefreshExpiresAt   time.Time
}

func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, r)
		return
	}
	var req authLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Request body is invalid JSON.", err.Error())
		return
	}
	var userID, email, status, passwordHash string
	err := s.pool.QueryRow(r.Context(), `
		SELECT id, email, status, COALESCE(password_hash, '')
		FROM users
		WHERE lower(email) = lower($1)
	`, strings.TrimSpace(req.Email)).Scan(&userID, &email, &status, &passwordHash)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, r, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED", "Email or password is incorrect.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load user.", err.Error())
		return
	}
	if status != "active" {
		writeError(w, r, http.StatusForbidden, "ACTOR_USER_INACTIVE", "User is not active.", nil)
		return
	}
	if !verifyPassword(req.Password, passwordHash) {
		writeError(w, r, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED", "Email or password is incorrect.", nil)
		return
	}

	actor, available, err := s.defaultActorForUser(r.Context(), userID)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, r, http.StatusForbidden, "ACTIVE_MEMBER_REQUIRED", "User has no active Member binding.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load actor context.", err.Error())
		return
	}

	accessToken := newToken("ply_at")
	refreshToken := newToken("ply_rt")
	session := sessionRecord{
		ID:                 "sess_" + safeIdentifier(newToken("")),
		UserID:             userID,
		ActiveSpaceID:      stringMapValue(actor, "space_id"),
		ActiveMemberID:     stringMapValue(actor, "member_id"),
		ActiveUserMemberID: stringMapValue(actor, "user_member_id"),
		ExpiresAt:          time.Now().UTC().Add(accessTokenTTL),
		RefreshExpiresAt:   time.Now().UTC().Add(refreshTokenTTL),
	}
	_, err = s.pool.Exec(r.Context(), `
		INSERT INTO sessions (
			id, user_id, active_space_id, active_member_id, active_user_member_id,
			access_token_hash, refresh_token_hash, expires_at, refresh_expires_at, ip, user_agent
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`, session.ID, session.UserID, session.ActiveSpaceID, session.ActiveMemberID, session.ActiveUserMemberID, tokenHash(accessToken), tokenHash(refreshToken), session.ExpiresAt, session.RefreshExpiresAt, remoteIPFrom(r), r.UserAgent())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create session.", err.Error())
		return
	}

	writeData(w, r, http.StatusOK, map[string]any{
		"access_token":       accessToken,
		"refresh_token":      refreshToken,
		"token_type":         "Bearer",
		"expires_at":         session.ExpiresAt.UTC().Format(time.RFC3339),
		"refresh_expires_at": session.RefreshExpiresAt.UTC().Format(time.RFC3339),
		"user":               map[string]any{"id": userID, "email": email, "status": status},
		"actor":              actor,
		"available_members":  available,
	})
}

func (s *Server) handleAuthRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, r)
		return
	}
	var req authRefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Request body is invalid JSON.", err.Error())
		return
	}
	session, err := s.sessionByRefreshToken(r.Context(), req.RefreshToken)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, r, http.StatusUnauthorized, "SESSION_EXPIRED", "Refresh token is invalid or expired.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to refresh session.", err.Error())
		return
	}

	accessToken := newToken("ply_at")
	expiresAt := time.Now().UTC().Add(accessTokenTTL)
	_, err = s.pool.Exec(r.Context(), `
		UPDATE sessions
		SET access_token_hash = $2, expires_at = $3, updated_at = now()
		WHERE id = $1
	`, session.ID, tokenHash(accessToken), expiresAt)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to rotate access token.", err.Error())
		return
	}
	writeData(w, r, http.StatusOK, map[string]any{
		"access_token":       accessToken,
		"token_type":         "Bearer",
		"expires_at":         expiresAt.UTC().Format(time.RFC3339),
		"refresh_expires_at": session.RefreshExpiresAt.UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, r)
		return
	}
	var req authLogoutRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	token := bearerToken(r)
	if token == "" {
		token = req.RefreshToken
	}
	if token != "" {
		_, _ = s.pool.Exec(r.Context(), `
			UPDATE sessions
			SET revoked_at = now(), updated_at = now()
			WHERE access_token_hash = $1 OR refresh_token_hash = $1
		`, tokenHash(token))
	}
	writeData(w, r, http.StatusOK, map[string]any{"logged_out": true})
}

func (s *Server) handleActorContext(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, r)
		return
	}
	session, err := s.sessionFromRequest(r.Context(), r)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, r, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED", "A valid access token is required.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load session.", err.Error())
		return
	}
	actor, available, err := s.actorForSession(r.Context(), session)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, r, http.StatusForbidden, "ACTIVE_MEMBER_REQUIRED", "Session has no active Member binding.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load actor context.", err.Error())
		return
	}
	writeData(w, r, http.StatusOK, map[string]any{
		"session_id":        session.ID,
		"actor":             actor,
		"available_members": available,
		"expires_at":        session.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

type switchMemberRequest struct {
	MemberID     string `json:"member_id"`
	UserMemberID string `json:"user_member_id"`
}

func (s *Server) handleActorSwitchMember(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, r)
		return
	}
	session, err := s.sessionFromRequest(r.Context(), r)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, r, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED", "A valid access token is required.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load session.", err.Error())
		return
	}
	var req switchMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Request body is invalid JSON.", err.Error())
		return
	}
	actor, err := s.actorBindingForUser(r.Context(), session.UserID, req.MemberID, req.UserMemberID)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, r, http.StatusForbidden, "ACTIVE_MEMBER_REQUIRED", "Requested Member binding is not active for this User.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to switch Member.", err.Error())
		return
	}
	_, err = s.pool.Exec(r.Context(), `
		UPDATE sessions
		SET active_space_id = $2, active_member_id = $3, active_user_member_id = $4, updated_at = now()
		WHERE id = $1
	`, session.ID, stringMapValue(actor, "space_id"), stringMapValue(actor, "member_id"), stringMapValue(actor, "user_member_id"))
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to update session actor.", err.Error())
		return
	}
	_, available, _ := s.defaultActorForUser(r.Context(), session.UserID)
	writeData(w, r, http.StatusOK, map[string]any{"actor": actor, "available_members": available})
}

func (s *Server) sessionFromRequest(ctx context.Context, r *http.Request) (sessionRecord, error) {
	token := bearerToken(r)
	if token == "" {
		return sessionRecord{}, pgx.ErrNoRows
	}
	var session sessionRecord
	err := s.pool.QueryRow(ctx, `
		SELECT id, user_id, COALESCE(active_space_id, ''), COALESCE(active_member_id, ''), COALESCE(active_user_member_id, ''), expires_at, refresh_expires_at
		FROM sessions
		WHERE access_token_hash = $1
			AND revoked_at IS NULL
			AND expires_at > now()
	`, tokenHash(token)).Scan(&session.ID, &session.UserID, &session.ActiveSpaceID, &session.ActiveMemberID, &session.ActiveUserMemberID, &session.ExpiresAt, &session.RefreshExpiresAt)
	return session, err
}

func (s *Server) sessionByRefreshToken(ctx context.Context, token string) (sessionRecord, error) {
	var session sessionRecord
	err := s.pool.QueryRow(ctx, `
		SELECT id, user_id, COALESCE(active_space_id, ''), COALESCE(active_member_id, ''), COALESCE(active_user_member_id, ''), expires_at, refresh_expires_at
		FROM sessions
		WHERE refresh_token_hash = $1
			AND revoked_at IS NULL
			AND refresh_expires_at > now()
	`, tokenHash(token)).Scan(&session.ID, &session.UserID, &session.ActiveSpaceID, &session.ActiveMemberID, &session.ActiveUserMemberID, &session.ExpiresAt, &session.RefreshExpiresAt)
	return session, err
}

func (s *Server) defaultActorForUser(ctx context.Context, userID string) (map[string]any, []map[string]any, error) {
	available, err := s.availableActorBindings(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	if len(available) == 0 {
		return nil, nil, pgx.ErrNoRows
	}
	return actorMapFromBinding(available[0]), available, nil
}

func (s *Server) actorForSession(ctx context.Context, session sessionRecord) (map[string]any, []map[string]any, error) {
	available, err := s.availableActorBindings(ctx, session.UserID)
	if err != nil {
		return nil, nil, err
	}
	for _, binding := range available {
		if binding["user_member_id"] == session.ActiveUserMemberID {
			return actorMapFromBinding(binding), available, nil
		}
	}
	if len(available) == 0 {
		return nil, nil, pgx.ErrNoRows
	}
	return actorMapFromBinding(available[0]), available, nil
}

func (s *Server) actorBindingForUser(ctx context.Context, userID, memberID, userMemberID string) (map[string]any, error) {
	where := "um.user_id = $1 AND um.status = 'active' AND (um.expires_at IS NULL OR um.expires_at > now())"
	args := []any{userID}
	if userMemberID != "" {
		args = append(args, userMemberID)
		where += fmt.Sprintf(" AND um.id = $%d", len(args))
	}
	if memberID != "" {
		args = append(args, memberID)
		where += fmt.Sprintf(" AND um.member_id = $%d", len(args))
	}
	return queryOneMap(ctx, s.pool, actorBindingSQL(where), args...)
}

func (s *Server) availableActorBindings(ctx context.Context, userID string) ([]map[string]any, error) {
	return queryMaps(ctx, s.pool, actorBindingSQL("um.user_id = $1 AND um.status = 'active' AND (um.expires_at IS NULL OR um.expires_at > now())"), userID)
}

func actorBindingSQL(where string) string {
	return `
		SELECT um.id AS user_member_id, um.user_id, u.email AS user_email,
			um.member_id, m.display_name AS member_display_name,
			um.space_id, s.name AS space_name, um.relation_type, um.is_primary
		FROM user_members um
		JOIN users u ON u.id = um.user_id
		JOIN members m ON m.id = um.member_id AND m.status = 'active'
		JOIN spaces s ON s.id = um.space_id AND s.status = 'active'
		WHERE ` + where + `
		ORDER BY um.is_primary DESC, s.name, m.display_name
	`
}

func actorMapFromBinding(binding map[string]any) map[string]any {
	return map[string]any{
		"user_id":        binding["user_id"],
		"member_id":      binding["member_id"],
		"user_member_id": binding["user_member_id"],
		"space_id":       binding["space_id"],
	}
}

func stringMapValue(values map[string]any, key string) string {
	value, _ := values[key].(string)
	return value
}

func bearerToken(r *http.Request) string {
	value := r.Header.Get("Authorization")
	if value == "" {
		return ""
	}
	parts := strings.SplitN(value, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func newToken(prefix string) string {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return prefix + hex.EncodeToString([]byte(strconv.FormatInt(time.Now().UTC().UnixNano(), 10)))
	}
	if prefix == "" {
		return hex.EncodeToString(buf[:])
	}
	return prefix + "_" + hex.EncodeToString(buf[:])
}

func tokenHash(token string) string {
	if secret := sessionTokenSecret(); secret != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		_, _ = mac.Write([]byte(token))
		return hex.EncodeToString(mac.Sum(nil))
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func sessionTokenSecret() string {
	return firstEnv("PLYSTRA_SESSION_SECRET", "SESSION_SECRET", "JWT_SECRET", "PLYSTRA_JWT_SECRET")
}

func verifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2_sha256" {
		return false
	}
	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations < 10000 {
		return false
	}
	want, err := hex.DecodeString(parts[3])
	if err != nil {
		return false
	}
	got := pbkdf2Key([]byte(password), []byte(parts[2]), iterations, len(want), sha256.New)
	return subtle.ConstantTimeCompare(got, want) == 1
}

func pbkdf2Key(password, salt []byte, iter, keyLen int, h func() hash.Hash) []byte {
	prf := hmac.New(h, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen
	var out []byte
	for block := 1; block <= numBlocks; block++ {
		prf.Reset()
		prf.Write(salt)
		prf.Write([]byte{byte(block >> 24), byte(block >> 16), byte(block >> 8), byte(block)})
		u := prf.Sum(nil)
		t := make([]byte, hashLen)
		copy(t, u)
		for i := 1; i < iter; i++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(nil)
			for x := range t {
				t[x] ^= u[x]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}
