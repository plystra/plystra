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
	"hash"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	coreent "github.com/plystra/plystra/ent"
	entmember "github.com/plystra/plystra/ent/member"
	entsession "github.com/plystra/plystra/ent/session"
	entspace "github.com/plystra/plystra/ent/space"
	entuser "github.com/plystra/plystra/ent/user"
	entusermember "github.com/plystra/plystra/ent/usermember"
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
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	u, err := client.User.Query().
		Where(entuser.EmailEqualFold(strings.TrimSpace(req.Email)), entuser.DeletedAtIsNil()).
		Only(r.Context())
	if coreent.IsNotFound(err) {
		writeError(w, r, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED", "Email or password is incorrect.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load user.", err.Error())
		return
	}
	if u.Status != "active" {
		writeError(w, r, http.StatusForbidden, "ACTOR_USER_INACTIVE", "User is not active.", nil)
		return
	}
	if !verifyPassword(req.Password, derefString(u.PasswordHash)) {
		writeError(w, r, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED", "Email or password is incorrect.", nil)
		return
	}

	actor, available, err := s.defaultActorForUser(r.Context(), u.ID)
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
		UserID:             u.ID,
		ActiveSpaceID:      stringMapValue(actor, "space_id"),
		ActiveMemberID:     stringMapValue(actor, "member_id"),
		ActiveUserMemberID: stringMapValue(actor, "user_member_id"),
		ExpiresAt:          time.Now().UTC().Add(accessTokenTTL),
		RefreshExpiresAt:   time.Now().UTC().Add(refreshTokenTTL),
	}
	_, err = client.Session.Create().
		SetID(session.ID).
		SetUserID(session.UserID).
		SetNillableActiveSpaceID(optionalString(session.ActiveSpaceID)).
		SetNillableActiveMemberID(optionalString(session.ActiveMemberID)).
		SetNillableActiveUserMemberID(optionalString(session.ActiveUserMemberID)).
		SetAccessTokenHash(tokenHash(accessToken)).
		SetRefreshTokenHash(tokenHash(refreshToken)).
		SetExpiresAt(session.ExpiresAt).
		SetRefreshExpiresAt(session.RefreshExpiresAt).
		SetNillableIP(optionalString(remoteIPFrom(r))).
		SetNillableUserAgent(optionalString(r.UserAgent())).
		Save(r.Context())
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
		"user":               map[string]any{"id": u.ID, "email": u.Email, "status": u.Status},
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
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	_, err = client.Session.Update().
		Where(entsession.ID(session.ID)).
		SetAccessTokenHash(tokenHash(accessToken)).
		SetExpiresAt(expiresAt).
		Save(r.Context())
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
		client, ok := s.requireEnt(w, r)
		if !ok {
			return
		}
		now := time.Now().UTC()
		_, _ = client.Session.Update().
			Where(entsession.Or(
				entsession.AccessTokenHash(tokenHash(token)),
				entsession.RefreshTokenHash(tokenHash(token)),
			)).
			SetRevokedAt(now).
			Save(r.Context())
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
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	_, err = client.Session.Update().
		Where(entsession.ID(session.ID)).
		SetActiveSpaceID(stringMapValue(actor, "space_id")).
		SetActiveMemberID(stringMapValue(actor, "member_id")).
		SetActiveUserMemberID(stringMapValue(actor, "user_member_id")).
		Save(r.Context())
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
	if s.ent == nil {
		return sessionRecord{}, errors.New("ent client is not configured")
	}
	record, err := s.ent.Session.Query().
		Where(
			entsession.AccessTokenHash(tokenHash(token)),
			entsession.RevokedAtIsNil(),
			entsession.ExpiresAtGT(time.Now().UTC()),
		).
		Only(ctx)
	if coreent.IsNotFound(err) {
		return sessionRecord{}, pgx.ErrNoRows
	}
	if err != nil {
		return sessionRecord{}, err
	}
	return sessionRecordFromEnt(record), nil
}

func (s *Server) sessionByRefreshToken(ctx context.Context, token string) (sessionRecord, error) {
	if s.ent == nil {
		return sessionRecord{}, errors.New("ent client is not configured")
	}
	record, err := s.ent.Session.Query().
		Where(
			entsession.RefreshTokenHash(tokenHash(token)),
			entsession.RevokedAtIsNil(),
			entsession.RefreshExpiresAtGT(time.Now().UTC()),
		).
		Only(ctx)
	if coreent.IsNotFound(err) {
		return sessionRecord{}, pgx.ErrNoRows
	}
	if err != nil {
		return sessionRecord{}, err
	}
	return sessionRecordFromEnt(record), nil
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
	bindings, err := s.availableActorBindingsFiltered(ctx, userID, memberID, userMemberID)
	if err != nil {
		return nil, err
	}
	if len(bindings) == 0 {
		return nil, pgx.ErrNoRows
	}
	return bindings[0], nil
}

func (s *Server) availableActorBindings(ctx context.Context, userID string) ([]map[string]any, error) {
	return s.availableActorBindingsFiltered(ctx, userID, "", "")
}

func (s *Server) availableActorBindingsFiltered(ctx context.Context, userID, memberID, userMemberID string) ([]map[string]any, error) {
	if s.ent == nil {
		return nil, errors.New("ent client is not configured")
	}
	now := time.Now().UTC()
	q := s.ent.UserMember.Query().
		Where(
			entusermember.UserID(userID),
			entusermember.Status("active"),
			entusermember.DeletedAtIsNil(),
			entusermember.RevokedAtIsNil(),
			entusermember.Or(entusermember.ExpiresAtIsNil(), entusermember.ExpiresAtGT(now)),
		)
	if memberID != "" {
		q = q.Where(entusermember.MemberID(memberID))
	}
	if userMemberID != "" {
		q = q.Where(entusermember.ID(userMemberID))
	}
	userRecord, err := s.ent.User.Query().
		Where(entuser.ID(userID), entuser.DeletedAtIsNil()).
		Only(ctx)
	if coreent.IsNotFound(err) {
		return []map[string]any{}, nil
	}
	if err != nil {
		return nil, err
	}
	userMembers, err := q.All(ctx)
	if err != nil {
		return nil, err
	}
	bindings := make([]map[string]any, 0, len(userMembers))
	for _, userMember := range userMembers {
		memberRecord, err := s.ent.Member.Query().
			Where(
				entmember.ID(userMember.MemberID),
				entmember.Status("active"),
				entmember.DeletedAtIsNil(),
			).
			Only(ctx)
		if coreent.IsNotFound(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		spaceRecord, err := s.ent.Space.Query().
			Where(
				entspace.ID(userMember.SpaceID),
				entspace.Status("active"),
				entspace.DeletedAtIsNil(),
			).
			Only(ctx)
		if coreent.IsNotFound(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		bindings = append(bindings, map[string]any{
			"user_member_id":      userMember.ID,
			"user_id":             userMember.UserID,
			"user_email":          userRecord.Email,
			"member_id":           userMember.MemberID,
			"member_display_name": memberRecord.DisplayName,
			"space_id":            userMember.SpaceID,
			"space_name":          spaceRecord.Name,
			"relation_type":       userMember.RelationType,
			"is_primary":          userMember.IsPrimary,
		})
	}
	sort.SliceStable(bindings, func(i, j int) bool {
		leftPrimary, _ := bindings[i]["is_primary"].(bool)
		rightPrimary, _ := bindings[j]["is_primary"].(bool)
		if leftPrimary != rightPrimary {
			return leftPrimary
		}
		leftSpace, _ := bindings[i]["space_name"].(string)
		rightSpace, _ := bindings[j]["space_name"].(string)
		if leftSpace != rightSpace {
			return leftSpace < rightSpace
		}
		leftMember, _ := bindings[i]["member_display_name"].(string)
		rightMember, _ := bindings[j]["member_display_name"].(string)
		return leftMember < rightMember
	})
	return bindings, nil
}

func (s *Server) requireEnt(w http.ResponseWriter, r *http.Request) (*coreent.Client, bool) {
	if s.ent == nil {
		writeError(w, r, http.StatusServiceUnavailable, "NOT_READY", "Ent client is not configured.", nil)
		return nil, false
	}
	return s.ent, true
}

func sessionRecordFromEnt(record *coreent.Session) sessionRecord {
	return sessionRecord{
		ID:                 record.ID,
		UserID:             record.UserID,
		ActiveSpaceID:      derefString(record.ActiveSpaceID),
		ActiveMemberID:     derefString(record.ActiveMemberID),
		ActiveUserMemberID: derefString(record.ActiveUserMemberID),
		ExpiresAt:          record.ExpiresAt,
		RefreshExpiresAt:   record.RefreshExpiresAt,
	}
}

func optionalString(value string) *string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return &value
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
