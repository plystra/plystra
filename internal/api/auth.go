package api

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	coreent "github.com/plystra/plystra/ent"
	entadmingrant "github.com/plystra/plystra/ent/admingrant"
	entsession "github.com/plystra/plystra/ent/session"
	entspace "github.com/plystra/plystra/ent/space"
	entuser "github.com/plystra/plystra/ent/user"
)

const (
	accessTokenTTL  = 15 * time.Minute
	refreshTokenTTL = 30 * 24 * time.Hour
	registerLockKey = int64(750100601006)
	defaultSpaceID  = "space_default"
)

const publicUserRegistrationEnv = "PLYSTRA_AUTH_PUBLIC_USER_REGISTRATION_ENABLED"

type registrationMode string

const (
	registrationModeOrdinary       registrationMode = "ordinary"
	registrationModeBootstrap      registrationMode = "bootstrap"
	registrationModePublicUserOnly registrationMode = "public_user_only"
)

type authLoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type authRegisterRequest struct {
	Email             string         `json:"email"`
	Password          string         `json:"password"`
	Username          *string        `json:"username"`
	Phone             *string        `json:"phone"`
	SpaceName         string         `json:"space_name"`
	SpaceSlug         string         `json:"space_slug"`
	MemberDisplayName string         `json:"member_display_name"`
	RegistrationToken string         `json:"registration_token"`
	Metadata          map[string]any `json:"metadata"`
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

func (s *Server) handleAuthRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, r)
		return
	}
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	var req authRegisterRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.normalize()
	if err := validateRegisterRequest(req); err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", err.Error(), nil)
		return
	}
	releaseLock, err := s.acquireRegistrationLock(r.Context())
	if err != nil {
		writeError(w, r, http.StatusServiceUnavailable, "REGISTRATION_LOCK_UNAVAILABLE", "Failed to acquire registration lock.", err.Error())
		return
	}
	defer releaseLock()
	mode, err := s.registrationAllowed(r.Context(), req)
	if err != nil {
		writeError(w, r, http.StatusForbidden, "REGISTRATION_DISABLED", err.Error(), nil)
		return
	}
	if mode == registrationModePublicUserOnly {
		s.handlePublicUserOnlyRegister(w, r, client, req)
		return
	}
	passwordHash, err := hashPassword(req.Password)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to hash password.", err.Error())
		return
	}
	userID := newEntityID("user")
	spaceID := defaultSpaceID
	memberID := newEntityID("member")
	userMemberID := newEntityID("um")
	now := time.Now().UTC()
	tx, err := client.Tx(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to start registration transaction.", err.Error())
		return
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	u, err := tx.User.Create().
		SetID(userID).
		SetEmail(req.Email).
		SetNillableUsername(optionalString(derefString(req.Username))).
		SetNillablePhone(optionalString(derefString(req.Phone))).
		SetPasswordHash(passwordHash).
		SetPasswordChangedAt(now).
		SetStatus("active").
		SetMetadata(nonNilMap(req.Metadata)).
		Save(r.Context())
	if err != nil {
		writeError(w, r, http.StatusConflict, "USER_CREATE_FAILED", "Failed to register user.", err.Error())
		return
	}
	spaceName := firstNonEmpty(req.SpaceName, "Default Space")
	if _, err := ensureDefaultRegistrationSpace(r.Context(), tx.Client(), spaceID, spaceName, req.SpaceSlug); err != nil {
		writeError(w, r, http.StatusConflict, "SPACE_CREATE_FAILED", "Failed to create registration space.", err.Error())
		return
	}
	memberDisplayName := firstNonEmpty(req.MemberDisplayName, displayNameFromRegistration(req), req.Email)
	if _, err := tx.Member.Create().
		SetID(memberID).
		SetSpaceID(spaceID).
		SetDisplayName(memberDisplayName).
		SetMemberType("human").
		SetStatus("active").
		SetMetadata(map[string]any{"source": "auth.register"}).
		Save(r.Context()); err != nil {
		writeError(w, r, http.StatusConflict, "MEMBER_CREATE_FAILED", "Failed to create registration member.", err.Error())
		return
	}
	if _, err := tx.UserMember.Create().
		SetID(userMemberID).
		SetUserID(userID).
		SetMemberID(memberID).
		SetSpaceID(spaceID).
		SetRelationType("self").
		SetStatus("active").
		SetIsPrimary(true).
		SetLinkedAt(now).
		SetMetadata(map[string]any{"source": "auth.register"}).
		Save(r.Context()); err != nil {
		writeError(w, r, http.StatusConflict, "USER_MEMBER_CREATE_FAILED", "Failed to create registration membership.", err.Error())
		return
	}
	spaceAdminGrantID := newEntityID("ag")
	if _, err := tx.AdminGrant.Create().
		SetID(spaceAdminGrantID).
		SetUserID(userID).
		SetMemberID(memberID).
		SetSpaceID(spaceID).
		SetLevel(adminLevelSpace).
		SetPermissionKey("*").
		SetStatus("active").
		SetGrantedByUserID(userID).
		SetGrantedByMemberID(memberID).
		SetMetadata(map[string]any{"source": "auth.register", "scope": "registered_space"}).
		Save(r.Context()); err != nil {
		writeError(w, r, http.StatusConflict, "ADMIN_GRANT_CREATE_FAILED", "Failed to create registration space admin grant.", err.Error())
		return
	}
	bootstrapGrantID := ""
	if mode == registrationModeBootstrap {
		bootstrapGrantID = newEntityID("ag")
		if _, err := tx.AdminGrant.Create().
			SetID(bootstrapGrantID).
			SetUserID(userID).
			SetMemberID(memberID).
			SetLevel(adminLevelInstanceSuper).
			SetPermissionKey("*").
			SetStatus("active").
			SetGrantedByUserID(userID).
			SetGrantedByMemberID(memberID).
			SetMetadata(map[string]any{"source": "auth.register.bootstrap"}).
			Save(r.Context()); err != nil {
			writeError(w, r, http.StatusConflict, "ADMIN_GRANT_CREATE_FAILED", "Failed to bootstrap first super admin.", err.Error())
			return
		}
	}
	accessToken, refreshToken, session, err := createSessionForUser(r.Context(), tx.Client(), r, u.ID, spaceID, memberID, userMemberID)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create registration session.", err.Error())
		return
	}
	if err := tx.Commit(); err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to commit registration.", err.Error())
		return
	}
	committed = true

	writeData(w, r, http.StatusCreated, map[string]any{
		"access_token":       accessToken,
		"refresh_token":      refreshToken,
		"token_type":         "Bearer",
		"expires_at":         session.ExpiresAt.UTC().Format(time.RFC3339),
		"refresh_expires_at": session.RefreshExpiresAt.UTC().Format(time.RFC3339),
		"user":               map[string]any{"id": u.ID, "email": u.Email, "status": u.Status},
		"actor": map[string]any{
			"user_id":        userID,
			"member_id":      memberID,
			"user_member_id": userMemberID,
			"space_id":       spaceID,
		},
		"available_members": []map[string]any{{
			"user_member_id":      userMemberID,
			"user_id":             userID,
			"user_email":          u.Email,
			"member_id":           memberID,
			"member_display_name": memberDisplayName,
			"space_id":            spaceID,
			"space_name":          spaceName,
			"relation_type":       "self",
			"is_primary":          true,
		}},
		"bootstrap_super_admin":          mode == registrationModeBootstrap,
		"bootstrap_admin_grant_id":       bootstrapGrantID,
		"space_admin_grant_id":           spaceAdminGrantID,
		"registration_mode":              string(mode),
		"user_only":                      false,
		"registration_requires_approval": false,
	})
}

func ensureDefaultRegistrationSpace(ctx context.Context, client *coreent.Client, spaceID, name, slug string) (*coreent.Space, error) {
	space, err := client.Space.Query().
		Where(entspace.ID(spaceID)).
		Only(ctx)
	if coreent.IsNotFound(err) {
		create := client.Space.Create().
			SetID(spaceID).
			SetName(firstNonEmpty(name, "Default Space")).
			SetType("default").
			SetStatus("active").
			SetMetadata(map[string]any{"source": "auth.register", "mode": "simple"})
		if slug != "" {
			create.SetSlug(slug)
		}
		return create.Save(ctx)
	}
	if err != nil {
		return nil, err
	}
	update := client.Space.UpdateOneID(space.ID).
		SetStatus("active").
		ClearDeletedAt()
	if strings.TrimSpace(space.Name) == "" && strings.TrimSpace(name) != "" {
		update.SetName(strings.TrimSpace(name))
	}
	if strings.TrimSpace(space.Type) == "" {
		update.SetType("default")
	}
	if strings.TrimSpace(space.Type) == "custom" {
		update.SetType("default")
	}
	if strings.TrimSpace(derefString(space.Slug)) == "" && strings.TrimSpace(slug) != "" {
		update.SetSlug(strings.TrimSpace(slug))
	}
	if err := update.Exec(ctx); err != nil {
		return nil, err
	}
	return client.Space.Query().Where(entspace.ID(spaceID)).Only(ctx)
}

func (s *Server) handlePublicUserOnlyRegister(w http.ResponseWriter, r *http.Request, client *coreent.Client, req authRegisterRequest) {
	passwordHash, err := hashPassword(req.Password)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to hash password.", err.Error())
		return
	}
	userID := newEntityID("user")
	now := time.Now().UTC()
	u, err := client.User.Create().
		SetID(userID).
		SetEmail(req.Email).
		SetNillableUsername(optionalString(derefString(req.Username))).
		SetNillablePhone(optionalString(derefString(req.Phone))).
		SetPasswordHash(passwordHash).
		SetPasswordChangedAt(now).
		SetStatus("active").
		SetMetadata(nonNilMap(req.Metadata)).
		Save(r.Context())
	if err != nil {
		writeError(w, r, http.StatusConflict, "USER_CREATE_FAILED", "Failed to register user.", err.Error())
		return
	}
	writeData(w, r, http.StatusCreated, map[string]any{
		"user":                           map[string]any{"id": u.ID, "email": u.Email, "status": u.Status},
		"actor":                          nil,
		"available_members":              []map[string]any{},
		"bootstrap_super_admin":          false,
		"bootstrap_admin_grant_id":       "",
		"space_admin_grant_id":           "",
		"registration_mode":              string(registrationModePublicUserOnly),
		"user_only":                      true,
		"registration_requires_approval": false,
	})
}

func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, r)
		return
	}
	var req authLoginRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Email = normalizeEmail(req.Email)
	throttleKeys := loginThrottleKeys(req.Email, r)
	if retryAfter := s.authLimiter.retryAfter(throttleKeys); retryAfter > 0 {
		writeAuthRateLimited(w, r, retryAfter)
		return
	}
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	u, err := client.User.Query().
		Where(entuser.EmailEqualFold(req.Email), entuser.DeletedAtIsNil()).
		Only(r.Context())
	if coreent.IsNotFound(err) {
		consumePasswordCheck(req.Password)
		s.recordLoginFailure(w, r, throttleKeys)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load user.", err.Error())
		return
	}
	if u.Status != "active" {
		consumePasswordCheck(req.Password)
		s.recordLoginFailure(w, r, throttleKeys)
		return
	}
	if !verifyPassword(req.Password, derefString(u.PasswordHash)) {
		s.recordLoginFailure(w, r, throttleKeys)
		return
	}
	s.authLimiter.reset(throttleKeys)

	if passwordNeedsRehash(derefString(u.PasswordHash)) {
		upgradedHash, err := hashPassword(req.Password)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to upgrade password hash.", err.Error())
			return
		}
		if err := client.User.UpdateOneID(u.ID).SetPasswordHash(upgradedHash).Exec(r.Context()); err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to upgrade password hash.", err.Error())
			return
		}
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

	accessToken, refreshToken, session, err := createSessionForUser(r.Context(), client, r, u.ID, stringMapValue(actor, "space_id"), stringMapValue(actor, "member_id"), stringMapValue(actor, "user_member_id"))
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create session.", err.Error())
		return
	}
	now := time.Now().UTC()
	_ = client.User.UpdateOneID(u.ID).SetLastLoginAt(now).Exec(r.Context())

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

func (req *authRegisterRequest) normalize() {
	req.Email = normalizeEmail(req.Email)
	req.SpaceName = strings.TrimSpace(req.SpaceName)
	req.SpaceSlug = safeSlug(req.SpaceSlug)
	req.MemberDisplayName = strings.TrimSpace(req.MemberDisplayName)
	req.RegistrationToken = strings.TrimSpace(req.RegistrationToken)
}

func validateRegisterRequest(req authRegisterRequest) error {
	if req.Email == "" {
		return validationError("email is required.")
	}
	if !strings.Contains(req.Email, "@") {
		return validationError("email must be valid.")
	}
	if message, ok := validatePlaintextPassword(req.Password); !ok {
		return validationError(message)
	}
	return nil
}

func (s *Server) registrationAllowed(ctx context.Context, req authRegisterRequest) (registrationMode, error) {
	bootstrapAvailable, err := s.bootstrapRegistrationAvailable(ctx)
	if err != nil {
		return "", err
	}
	if bootstrapAvailable && featureEnabled("PLYSTRA_BOOTSTRAP_REGISTRATION_ENABLED") {
		if strings.TrimSpace(req.RegistrationToken) != "" {
			if !registrationTokenMatches(req.RegistrationToken, "PLYSTRA_BOOTSTRAP_REGISTRATION_TOKEN") {
				return "", validationError("bootstrap registration token is required.")
			}
			return registrationModeBootstrap, nil
		}
	}
	if featureEnabled(publicUserRegistrationEnv) {
		return registrationModePublicUserOnly, nil
	}
	if bootstrapAvailable {
		return "", validationError("first instance super admin must be bootstrapped before user registration.")
	}
	if featureEnabled("PLYSTRA_AUTH_REGISTRATION_ENABLED") && strings.TrimSpace(req.RegistrationToken) != "" {
		if registrationTokenMatches(req.RegistrationToken, "PLYSTRA_AUTH_REGISTRATION_TOKEN") {
			return registrationModeOrdinary, nil
		}
		return "", validationError("registration token is invalid.")
	}
	if !featureEnabled("PLYSTRA_AUTH_REGISTRATION_ENABLED") {
		return "", validationError("registration is disabled.")
	}
	if strings.EqualFold(firstEnv("SERVER_MODE", "PLYSTRA_ENV"), "production") && strings.TrimSpace(firstEnv("PLYSTRA_AUTH_REGISTRATION_TOKEN")) == "" {
		return "", validationError("PLYSTRA_AUTH_REGISTRATION_TOKEN is required when registration is enabled in production.")
	}
	return "", validationError("registration token is invalid.")
}

func (s *Server) bootstrapRegistrationAvailable(ctx context.Context) (bool, error) {
	if s.ent == nil {
		return false, errAdminEntNotConfigured
	}
	now := time.Now().UTC()
	count, err := s.ent.AdminGrant.Query().
		Where(
			entadmingrant.Level(adminLevelInstanceSuper),
			entadmingrant.Status("active"),
			entadmingrant.DeletedAtIsNil(),
			entadmingrant.RevokedAtIsNil(),
			entadmingrant.Or(entadmingrant.ExpiresAtIsNil(), entadmingrant.ExpiresAtGT(now)),
		).
		Count(ctx)
	if err != nil {
		return false, err
	}
	return count == 0, nil
}

func registrationTokenMatches(provided, envKey string) bool {
	configured := strings.TrimSpace(os.Getenv(envKey))
	if configured == "" {
		return false
	}
	return constantTimeStringEqual(strings.TrimSpace(provided), configured)
}

func (s *Server) acquireRegistrationLock(ctx context.Context) (func(), error) {
	if s.pool == nil {
		return func() {}, nil
	}
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Exec(ctx, "select pg_advisory_lock($1)", registerLockKey); err != nil {
		conn.Release()
		return nil, err
	}
	return func() {
		_, _ = conn.Exec(context.Background(), "select pg_advisory_unlock($1)", registerLockKey)
		conn.Release()
	}, nil
}

func createSessionForUser(ctx context.Context, client *coreent.Client, r *http.Request, userID, spaceID, memberID, userMemberID string) (string, string, sessionRecord, error) {
	accessToken, err := newToken("ply_at")
	if err != nil {
		return "", "", sessionRecord{}, err
	}
	refreshToken, err := newToken("ply_rt")
	if err != nil {
		return "", "", sessionRecord{}, err
	}
	sessionIDToken, err := newToken("")
	if err != nil {
		return "", "", sessionRecord{}, err
	}
	now := time.Now().UTC()
	session := sessionRecord{
		ID:                 "sess_" + safeIdentifier(sessionIDToken),
		UserID:             userID,
		ActiveSpaceID:      spaceID,
		ActiveMemberID:     memberID,
		ActiveUserMemberID: userMemberID,
		ExpiresAt:          now.Add(accessTokenTTL),
		RefreshExpiresAt:   now.Add(refreshTokenTTL),
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
		Save(ctx)
	if err != nil {
		return "", "", sessionRecord{}, err
	}
	return accessToken, refreshToken, session, nil
}

func displayNameFromRegistration(req authRegisterRequest) string {
	if req.Username != nil && strings.TrimSpace(*req.Username) != "" {
		return strings.TrimSpace(*req.Username)
	}
	local, _, ok := strings.Cut(req.Email, "@")
	if ok && strings.TrimSpace(local) != "" {
		return strings.TrimSpace(local)
	}
	return ""
}

func safeSlug(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	lastDash := false
	for _, r := range value {
		writeDash := false
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
			lastDash = false
		case r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		case r == '-' || r == '_' || r == '.' || r == ' ':
			writeDash = true
		default:
			writeDash = true
		}
		if writeDash && !lastDash && b.Len() > 0 {
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

func (s *Server) handleAuthRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, r)
		return
	}
	var req authRefreshRequest
	if !decodeJSON(w, r, &req) {
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

	accessToken, err := newToken("ply_at")
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to generate access token.", err.Error())
		return
	}
	refreshToken, err := newToken("ply_rt")
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to generate refresh token.", err.Error())
		return
	}
	expiresAt := time.Now().UTC().Add(accessTokenTTL)
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	_, err = client.Session.Update().
		Where(entsession.ID(session.ID)).
		SetAccessTokenHash(tokenHash(accessToken)).
		SetRefreshTokenHash(tokenHash(refreshToken)).
		SetExpiresAt(expiresAt).
		Save(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to rotate access token.", err.Error())
		return
	}
	writeData(w, r, http.StatusOK, map[string]any{
		"access_token":       accessToken,
		"refresh_token":      refreshToken,
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
	if !decodeOptionalJSON(w, r, &req) {
		return
	}
	token := bearerToken(r)
	if token == "" {
		token = req.RefreshToken
	}
	if token != "" {
		client, ok := s.requireEnt(w, r)
		if !ok {
			return
		}
		hashes := tokenHashesForLookup(token)
		if len(hashes) == 0 {
			writeData(w, r, http.StatusOK, map[string]any{"logged_out": true})
			return
		}
		now := time.Now().UTC()
		_, _ = client.Session.Update().
			Where(entsession.Or(
				entsession.AccessTokenHashIn(hashes...),
				entsession.RefreshTokenHashIn(hashes...),
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
	if !decodeJSON(w, r, &req) {
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
