package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	coreent "github.com/plystra/plystra/ent"
	entsession "github.com/plystra/plystra/ent/session"
	entuser "github.com/plystra/plystra/ent/user"
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
