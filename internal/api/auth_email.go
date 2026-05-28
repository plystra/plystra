package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"strings"
	"time"

	entsql "entgo.io/ent/dialect/sql"
	"github.com/jackc/pgx/v5"
	coreent "github.com/plystra/plystra/ent"
	entauthchallenge "github.com/plystra/plystra/ent/authchallenge"
	entuser "github.com/plystra/plystra/ent/user"
)

const (
	authChallengeEmailVerification = "auth.email_verification"
	authChallengeMagicLink         = "auth.magic_link"
	authDeliveryEmailCode          = "email_code"
	authDeliveryMagicLink          = "magic_link"
)

const (
	defaultEmailCodeTTL       = 10 * time.Minute
	defaultMagicLinkTTL       = 10 * time.Minute
	defaultAuthChallengeLimit = 5
	defaultAuthSendLimit      = 3
	defaultAuthLinkBasePath   = "/auth/consume"
	maxAuthMetadataKeys       = 32
	maxAuthMetadataKeyBytes   = 64
	maxAuthMetadataValueBytes = 512
)

type authEmailCodeRequest struct {
	Email       string         `json:"email"`
	RedirectURL string         `json:"redirect_url"`
	Metadata    map[string]any `json:"metadata"`
}

type authVerifyEmailCodeRequest struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

type authMagicLinkRequest struct {
	Email       string         `json:"email"`
	RedirectURL string         `json:"redirect_url"`
	Metadata    map[string]any `json:"metadata"`
}

type authConsumeMagicLinkRequest struct {
	Token string `json:"token"`
}

type authChallengeAcceptedResponse struct {
	Accepted          bool   `json:"accepted"`
	ExpiresAt         string `json:"expires_at" format:"date-time"`
	DeliveryMethod    string `json:"delivery_method"`
	ChallengeID       string `json:"challenge_id,omitempty"`
	EmailProviderID   string `json:"email_provider_message_id,omitempty"`
	EmailDeliveryMode string `json:"email_delivery_mode"`
}

type emailCapabilityAddress struct {
	Address string `json:"address"`
	Name    string `json:"name,omitempty"`
}

type emailCapabilityRequest struct {
	MessageID      string                   `json:"message_id,omitempty"`
	IdempotencyKey string                   `json:"idempotency_key,omitempty"`
	Purpose        string                   `json:"purpose,omitempty"`
	From           emailCapabilityAddress   `json:"from"`
	To             []emailCapabilityAddress `json:"to"`
	Subject        string                   `json:"subject"`
	Text           string                   `json:"text,omitempty"`
	HTML           string                   `json:"html,omitempty"`
	Headers        map[string]string        `json:"headers,omitempty"`
	Metadata       map[string]string        `json:"metadata,omitempty"`
}

type emailCapabilityResponse struct {
	Accepted          bool     `json:"accepted"`
	MessageID         string   `json:"message_id"`
	Provider          string   `json:"provider"`
	ProviderMessageID string   `json:"provider_message_id"`
	ErrorCode         string   `json:"error_code"`
	ErrorMessage      string   `json:"error_message"`
	Delivered         []string `json:"delivered"`
	Queued            []string `json:"queued"`
}

func (s *Server) handleAuthEmailCode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, r)
		return
	}
	var req authEmailCodeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Email = normalizeEmail(req.Email)
	if err := validateEmailAddress(req.Email); err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", err.Error(), nil)
		return
	}
	if err := validateRedirectURL(req.RedirectURL); err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", err.Error(), nil)
		return
	}
	if err := validateAuthChallengeMetadata(req.Metadata); err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", err.Error(), nil)
		return
	}
	if retryAfter := s.authLimiter.retryAfter(challengeThrottleKeys(req.Email, r, "email_code")); retryAfter > 0 {
		writeAuthRateLimited(w, r, retryAfter)
		return
	}
	if retryAfter := s.authLimiter.recordAttempt(challengeThrottleKeys(req.Email, r, "email_code"), intEnv("PLYSTRA_AUTH_EMAIL_SEND_MAX_ATTEMPTS", defaultAuthSendLimit)); retryAfter > 0 {
		writeAuthRateLimited(w, r, retryAfter)
		return
	}
	userID, err := s.findActiveUserIDByEmail(r.Context(), req.Email)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to prepare email verification.", err.Error())
		return
	}
	code, err := newNumericCode(6)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create email verification code.", err.Error())
		return
	}
	expiresAt := time.Now().UTC().Add(durationEnv("PLYSTRA_AUTH_EMAIL_CODE_TTL", defaultEmailCodeTTL))
	challengeID, providerID, err := s.createAndSendAuthChallenge(r.Context(), r, authChallengeEmailVerification, authDeliveryEmailCode, req.Email, userID, "", code, req.RedirectURL, expiresAt, req.Metadata)
	if err != nil {
		writeError(w, r, http.StatusBadGateway, "EMAIL_DELIVERY_FAILED", "Failed to send email verification code.", err.Error())
		return
	}
	writeData(w, r, http.StatusAccepted, authChallengeAcceptedResponse{
		Accepted:          true,
		ExpiresAt:         expiresAt.Format(time.RFC3339),
		DeliveryMethod:    authDeliveryEmailCode,
		ChallengeID:       exposeChallengeID(challengeID),
		EmailProviderID:   providerID,
		EmailDeliveryMode: emailDeliveryMode(),
	})
}

func (s *Server) handleAuthVerifyEmailCode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, r)
		return
	}
	var req authVerifyEmailCodeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Email = normalizeEmail(req.Email)
	code := strings.TrimSpace(req.Code)
	if err := validateEmailAddress(req.Email); err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", err.Error(), nil)
		return
	}
	if !validEmailCode(code) {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "code must be a 6 digit value.", nil)
		return
	}
	throttleKeys := challengeThrottleKeys(req.Email, r, "email_code_verify")
	if retryAfter := s.authLimiter.retryAfter(throttleKeys); retryAfter > 0 {
		writeAuthRateLimited(w, r, retryAfter)
		return
	}
	challenge, err := s.consumeCodeChallenge(r.Context(), req.Email, code)
	if errors.Is(err, pgx.ErrNoRows) {
		_ = s.recordFailedCodeChallengeAttempt(r.Context(), req.Email)
		retryAfter := s.authLimiter.recordFailure(throttleKeys)
		if retryAfter > 0 {
			writeAuthRateLimited(w, r, retryAfter)
			return
		}
		writeError(w, r, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED", "Email verification code is invalid or expired.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to verify email code.", err.Error())
		return
	}
	s.authLimiter.reset(throttleKeys)
	if err := s.markUserEmailVerified(r.Context(), challenge.UserID, req.Email); err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to mark email as verified.", err.Error())
		return
	}
	writeData(w, r, http.StatusOK, map[string]any{
		"verified":     true,
		"email":        req.Email,
		"user_id":      derefString(challenge.UserID),
		"challenge_id": exposeChallengeID(challenge.ID),
	})
}

func (s *Server) handleAuthMagicLink(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, r)
		return
	}
	var req authMagicLinkRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Email = normalizeEmail(req.Email)
	if err := validateEmailAddress(req.Email); err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", err.Error(), nil)
		return
	}
	if err := validateRedirectURL(req.RedirectURL); err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", err.Error(), nil)
		return
	}
	if err := validateAuthChallengeMetadata(req.Metadata); err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", err.Error(), nil)
		return
	}
	if retryAfter := s.authLimiter.retryAfter(challengeThrottleKeys(req.Email, r, "magic_link")); retryAfter > 0 {
		writeAuthRateLimited(w, r, retryAfter)
		return
	}
	if retryAfter := s.authLimiter.recordAttempt(challengeThrottleKeys(req.Email, r, "magic_link"), intEnv("PLYSTRA_AUTH_EMAIL_SEND_MAX_ATTEMPTS", defaultAuthSendLimit)); retryAfter > 0 {
		writeAuthRateLimited(w, r, retryAfter)
		return
	}
	userID, err := s.findActiveUserIDByEmail(r.Context(), req.Email)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to prepare magic link.", err.Error())
		return
	}
	token, err := newToken("ply_ml")
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create magic link token.", err.Error())
		return
	}
	expiresAt := time.Now().UTC().Add(durationEnv("PLYSTRA_AUTH_MAGIC_LINK_TTL", defaultMagicLinkTTL))
	challengeID, providerID, err := s.createAndSendAuthChallenge(r.Context(), r, authChallengeMagicLink, authDeliveryMagicLink, req.Email, userID, token, "", req.RedirectURL, expiresAt, req.Metadata)
	if err != nil {
		writeError(w, r, http.StatusBadGateway, "EMAIL_DELIVERY_FAILED", "Failed to send magic link.", err.Error())
		return
	}
	writeData(w, r, http.StatusAccepted, authChallengeAcceptedResponse{
		Accepted:          true,
		ExpiresAt:         expiresAt.Format(time.RFC3339),
		DeliveryMethod:    authDeliveryMagicLink,
		ChallengeID:       exposeChallengeID(challengeID),
		EmailProviderID:   providerID,
		EmailDeliveryMode: emailDeliveryMode(),
	})
}

func (s *Server) handleAuthConsumeMagicLink(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, r)
		return
	}
	var req authConsumeMagicLinkRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	token := strings.TrimSpace(req.Token)
	if token == "" {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "token is required.", nil)
		return
	}
	throttleKeys := []string{"magic_link_token:" + tokenHash(token), "ip:" + remoteIPFrom(r)}
	if retryAfter := s.authLimiter.retryAfter(throttleKeys); retryAfter > 0 {
		writeAuthRateLimited(w, r, retryAfter)
		return
	}
	challenge, err := s.consumeTokenChallenge(r.Context(), token)
	if errors.Is(err, pgx.ErrNoRows) {
		retryAfter := s.authLimiter.recordFailure(throttleKeys)
		if retryAfter > 0 {
			writeAuthRateLimited(w, r, retryAfter)
			return
		}
		writeError(w, r, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED", "Magic link token is invalid or expired.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to consume magic link.", err.Error())
		return
	}
	s.authLimiter.reset(throttleKeys)
	userID := derefString(challenge.UserID)
	if userID == "" {
		writeError(w, r, http.StatusForbidden, "ACTIVE_MEMBER_REQUIRED", "Magic link is not bound to an active user.", nil)
		return
	}
	u, err := s.ent.User.Query().Where(entuser.ID(userID), entuser.EmailEqualFold(challenge.Email), entuser.DeletedAtIsNil()).Only(r.Context())
	if coreent.IsNotFound(err) {
		writeError(w, r, http.StatusForbidden, "ACTIVE_MEMBER_REQUIRED", "Magic link is not bound to an active user.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load magic link user.", err.Error())
		return
	}
	if u.Status != "active" {
		writeError(w, r, http.StatusForbidden, "ACTIVE_MEMBER_REQUIRED", "Magic link is not bound to an active user.", nil)
		return
	}
	if err := s.markUserEmailVerified(r.Context(), challenge.UserID, challenge.Email); err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to mark email as verified.", err.Error())
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
	accessToken, refreshToken, session, err := createSessionForUser(r.Context(), s.ent, r, userID, stringMapValue(actor, "space_id"), stringMapValue(actor, "member_id"), stringMapValue(actor, "user_member_id"))
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create session.", err.Error())
		return
	}
	now := time.Now().UTC()
	_ = s.ent.User.UpdateOneID(userID).SetLastLoginAt(now).Exec(r.Context())
	writeData(w, r, http.StatusOK, map[string]any{
		"access_token":       accessToken,
		"refresh_token":      refreshToken,
		"token_type":         "Bearer",
		"expires_at":         session.ExpiresAt.UTC().Format(time.RFC3339),
		"refresh_expires_at": session.RefreshExpiresAt.UTC().Format(time.RFC3339),
		"user":               map[string]any{"id": u.ID, "email": u.Email, "status": u.Status},
		"actor":              actor,
		"available_members":  available,
		"challenge_id":       exposeChallengeID(challenge.ID),
	})
}

func (s *Server) createAndSendAuthChallenge(ctx context.Context, r *http.Request, purpose, deliveryMethod, email, userID, secret, code, redirectURL string, expiresAt time.Time, metadata map[string]any) (string, string, error) {
	if s.ent == nil {
		return "", "", errAdminEntNotConfigured
	}
	challengeID := newEntityID("authchal")
	now := time.Now().UTC()
	tokenHashValue := tokenHash(firstNonEmpty(secret, challengeID))
	codeHashValue := ""
	if code != "" {
		codeHashValue = challengeSecretHash(email + ":" + purpose + ":" + code)
	}
	create := s.ent.AuthChallenge.Create().
		SetID(challengeID).
		SetPurpose(purpose).
		SetDeliveryMethod(deliveryMethod).
		SetEmail(email).
		SetSecretHash(tokenHashValue).
		SetNillableCodeHash(optionalString(codeHashValue)).
		SetNillableUserID(optionalString(userID)).
		SetNillableRedirectURL(optionalString(redirectURL)).
		SetNillableRequestIP(optionalString(remoteIPFrom(r))).
		SetNillableRequestUserAgent(optionalString(r.UserAgent())).
		SetAttempts(0).
		SetMaxAttempts(intEnv("PLYSTRA_AUTH_CHALLENGE_MAX_ATTEMPTS", defaultAuthChallengeLimit)).
		SetStatus("pending").
		SetExpiresAt(expiresAt).
		SetMetadata(nonNilMap(metadata))
	if _, err := create.Save(ctx); err != nil {
		return "", "", err
	}
	deliverySecret := firstNonEmpty(secret, code)
	providerID, err := s.sendAuthChallengeEmail(ctx, purpose, deliveryMethod, email, deliverySecret, redirectURL, expiresAt, challengeID)
	if err != nil {
		_ = s.ent.AuthChallenge.UpdateOneID(challengeID).SetStatus("failed").SetRevokedAt(now).Exec(ctx)
		return "", "", err
	}
	if providerID != "" {
		_ = s.ent.AuthChallenge.UpdateOneID(challengeID).SetEmailProviderMessageID(providerID).Exec(ctx)
	}
	return challengeID, providerID, nil
}

func (s *Server) consumeCodeChallenge(ctx context.Context, email, code string) (*coreent.AuthChallenge, error) {
	if s.ent == nil {
		return nil, errAdminEntNotConfigured
	}
	now := time.Now().UTC()
	codeHashValue := challengeSecretHash(email + ":" + authChallengeEmailVerification + ":" + code)
	challenge, err := s.ent.AuthChallenge.Query().
		Where(
			entauthchallenge.Email(email),
			entauthchallenge.Purpose(authChallengeEmailVerification),
			entauthchallenge.DeliveryMethod(authDeliveryEmailCode),
			entauthchallenge.CodeHash(codeHashValue),
			entauthchallenge.Status("pending"),
			entauthchallenge.ExpiresAtGT(now),
			entauthchallenge.ConsumedAtIsNil(),
			entauthchallenge.RevokedAtIsNil(),
			entauthchallenge.DeletedAtIsNil(),
		).
		Order(entauthchallenge.ByCreatedAt(entsql.OrderDesc())).
		First(ctx)
	if coreent.IsNotFound(err) {
		return nil, pgx.ErrNoRows
	}
	if err != nil {
		return nil, err
	}
	if challenge.Attempts >= challenge.MaxAttempts {
		_ = s.ent.AuthChallenge.UpdateOneID(challenge.ID).SetStatus("locked").SetRevokedAt(now).Exec(ctx)
		return nil, pgx.ErrNoRows
	}
	updated, err := s.ent.AuthChallenge.Update().
		Where(
			entauthchallenge.ID(challenge.ID),
			entauthchallenge.Status("pending"),
			entauthchallenge.ConsumedAtIsNil(),
			entauthchallenge.RevokedAtIsNil(),
		).
		SetAttempts(challenge.Attempts + 1).
		SetStatus("consumed").
		SetConsumedAt(now).
		Save(ctx)
	if err != nil {
		return nil, err
	}
	if updated != 1 {
		return nil, pgx.ErrNoRows
	}
	return challenge, nil
}

func (s *Server) consumeTokenChallenge(ctx context.Context, token string) (*coreent.AuthChallenge, error) {
	if s.ent == nil {
		return nil, errAdminEntNotConfigured
	}
	now := time.Now().UTC()
	challenge, err := s.ent.AuthChallenge.Query().
		Where(
			entauthchallenge.Purpose(authChallengeMagicLink),
			entauthchallenge.DeliveryMethod(authDeliveryMagicLink),
			entauthchallenge.SecretHash(tokenHash(token)),
			entauthchallenge.Status("pending"),
			entauthchallenge.ExpiresAtGT(now),
			entauthchallenge.ConsumedAtIsNil(),
			entauthchallenge.RevokedAtIsNil(),
			entauthchallenge.DeletedAtIsNil(),
		).
		Only(ctx)
	if coreent.IsNotFound(err) {
		return nil, pgx.ErrNoRows
	}
	if err != nil {
		return nil, err
	}
	updated, err := s.ent.AuthChallenge.Update().
		Where(
			entauthchallenge.ID(challenge.ID),
			entauthchallenge.Status("pending"),
			entauthchallenge.ConsumedAtIsNil(),
			entauthchallenge.RevokedAtIsNil(),
		).
		SetAttempts(challenge.Attempts + 1).
		SetStatus("consumed").
		SetConsumedAt(now).
		Save(ctx)
	if err != nil {
		return nil, err
	}
	if updated != 1 {
		return nil, pgx.ErrNoRows
	}
	return challenge, nil
}

func (s *Server) recordFailedCodeChallengeAttempt(ctx context.Context, email string) error {
	if s.ent == nil {
		return errAdminEntNotConfigured
	}
	now := time.Now().UTC()
	challenge, err := s.ent.AuthChallenge.Query().
		Where(
			entauthchallenge.Email(email),
			entauthchallenge.Purpose(authChallengeEmailVerification),
			entauthchallenge.DeliveryMethod(authDeliveryEmailCode),
			entauthchallenge.Status("pending"),
			entauthchallenge.ExpiresAtGT(now),
			entauthchallenge.ConsumedAtIsNil(),
			entauthchallenge.RevokedAtIsNil(),
			entauthchallenge.DeletedAtIsNil(),
		).
		Order(entauthchallenge.ByCreatedAt(entsql.OrderDesc())).
		First(ctx)
	if coreent.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	update := s.ent.AuthChallenge.Update().
		Where(
			entauthchallenge.ID(challenge.ID),
			entauthchallenge.Attempts(challenge.Attempts),
			entauthchallenge.Status("pending"),
			entauthchallenge.ConsumedAtIsNil(),
			entauthchallenge.RevokedAtIsNil(),
		).
		SetAttempts(challenge.Attempts + 1)
	if challenge.Attempts+1 >= challenge.MaxAttempts {
		update.SetStatus("locked").SetRevokedAt(now)
	}
	_, err = update.Save(ctx)
	return err
}

func (s *Server) findActiveUserIDByEmail(ctx context.Context, email string) (string, error) {
	if s.ent == nil {
		return "", errAdminEntNotConfigured
	}
	u, err := s.ent.User.Query().Where(entuser.EmailEqualFold(email), entuser.Status("active"), entuser.DeletedAtIsNil()).Only(ctx)
	if coreent.IsNotFound(err) {
		return "", pgx.ErrNoRows
	}
	if err != nil {
		return "", err
	}
	return u.ID, nil
}

func (s *Server) markUserEmailVerified(ctx context.Context, userID *string, email string) error {
	if s.ent == nil || userID == nil || *userID == "" {
		return nil
	}
	now := time.Now().UTC()
	return s.ent.User.UpdateOneID(*userID).Where(entuser.EmailEqualFold(email), entuser.DeletedAtIsNil()).SetEmailVerifiedAt(now).Exec(ctx)
}

func (s *Server) sendAuthChallengeEmail(ctx context.Context, purpose, deliveryMethod, email, secret, redirectURL string, expiresAt time.Time, challengeID string) (string, error) {
	mode := emailDeliveryMode()
	if mode == "log" {
		if productionMode() {
			return "", errors.New("email capability is required in production")
		}
		logAuthChallengeEmail(purpose, deliveryMethod, email, secret, redirectURL, expiresAt, challengeID)
		return "", nil
	}
	endpoint := strings.TrimSpace(firstEnv("PLYSTRA_EMAIL_CAPABILITY_URL", "EMAIL_CAPABILITY_URL"))
	token := strings.TrimSpace(firstEnv("PLYSTRA_EMAIL_CAPABILITY_TOKEN", "EMAIL_CAPABILITY_TOKEN"))
	if endpoint == "" || token == "" {
		return "", errors.New("PLYSTRA_EMAIL_CAPABILITY_URL and PLYSTRA_EMAIL_CAPABILITY_TOKEN are required")
	}
	body := buildAuthEmail(purpose, deliveryMethod, email, secret, redirectURL, expiresAt, challengeID)
	payload, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: durationEnv("PLYSTRA_EMAIL_CAPABILITY_TIMEOUT", 10*time.Second)}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out emailCapabilityResponse
	_ = json.Unmarshal(raw, &out)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || !out.Accepted {
		if out.ErrorMessage != "" {
			return "", errors.New(out.ErrorMessage)
		}
		return "", fmt.Errorf("email capability returned status %d", resp.StatusCode)
	}
	return firstNonEmpty(out.ProviderMessageID, out.MessageID), nil
}

func buildAuthEmail(purpose, deliveryMethod, email, secret, redirectURL string, expiresAt time.Time, challengeID string) emailCapabilityRequest {
	from := firstEnv("PLYSTRA_AUTH_EMAIL_FROM", "EMAIL_FROM")
	fromName := firstNonEmpty(firstEnv("PLYSTRA_AUTH_EMAIL_FROM_NAME"), "Plystra")
	subject := "Verify your email"
	text := "Your Plystra verification code is " + secret + ". It expires at " + expiresAt.Format(time.RFC3339) + "."
	htmlBody := "<p>Your Plystra verification code is <strong>" + html.EscapeString(secret) + "</strong>.</p><p>This code expires at " + html.EscapeString(expiresAt.Format(time.RFC3339)) + ".</p>"
	if deliveryMethod == authDeliveryMagicLink {
		link := magicLinkURL(secret, redirectURL)
		subject = "Sign in to Plystra"
		text = "Open this link to sign in to Plystra: " + link + "\n\nThis link expires at " + expiresAt.Format(time.RFC3339) + "."
		htmlBody = `<p>Open this link to sign in to Plystra:</p><p><a href="` + html.EscapeString(link) + `">Sign in to Plystra</a></p><p>This link expires at ` + html.EscapeString(expiresAt.Format(time.RFC3339)) + `.</p>`
	}
	return emailCapabilityRequest{
		MessageID:      challengeID,
		IdempotencyKey: challengeID,
		Purpose:        purpose,
		From:           emailCapabilityAddress{Address: from, Name: fromName},
		To:             []emailCapabilityAddress{{Address: email}},
		Subject:        subject,
		Text:           text,
		HTML:           htmlBody,
		Headers: map[string]string{
			"X-Plystra-Auth-Challenge": challengeID,
		},
		Metadata: map[string]string{
			"challenge_id":    challengeID,
			"delivery_method": deliveryMethod,
		},
	}
}

func magicLinkURL(token, redirectURL string) string {
	if redirectURL != "" {
		u, err := url.Parse(redirectURL)
		if err == nil && u.Scheme == "https" && authRedirectOriginAllowed(u) {
			q := u.Query()
			q.Set("token", token)
			u.RawQuery = q.Encode()
			return u.String()
		}
	}
	base := strings.TrimRight(firstNonEmpty(firstEnv("PLYSTRA_PUBLIC_APP_URL", "PUBLIC_APP_URL", "SERVER_PUBLIC_URL", "PLYSTRA_SERVER_PUBLIC_URL"), "http://localhost:3000"), "/")
	path := firstNonEmpty(firstEnv("PLYSTRA_AUTH_MAGIC_LINK_PATH"), defaultAuthLinkBasePath)
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	u, _ := url.Parse(base + path)
	q := u.Query()
	q.Set("token", token)
	u.RawQuery = q.Encode()
	return u.String()
}

func validateEmailAddress(value string) error {
	if value == "" {
		return errors.New("email is required")
	}
	parsed, err := mail.ParseAddress(value)
	if err != nil || parsed.Address != value {
		return errors.New("email must be valid")
	}
	return nil
}

func validateRedirectURL(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return errors.New("redirect_url must be an absolute https URL")
	}
	if !authRedirectOriginAllowed(parsed) {
		return errors.New("redirect_url origin is not allowed")
	}
	return nil
}

func validateAuthChallengeMetadata(metadata map[string]any) error {
	if len(metadata) > maxAuthMetadataKeys {
		return fmt.Errorf("metadata must contain <= %d entries", maxAuthMetadataKeys)
	}
	for key, value := range metadata {
		if strings.TrimSpace(key) == "" || hasLineBreak(key) || byteLen(key) > maxAuthMetadataKeyBytes {
			return fmt.Errorf("metadata key %q is invalid", key)
		}
		if text, ok := value.(string); ok {
			if hasLineBreak(text) {
				return fmt.Errorf("metadata %q must not contain line breaks", key)
			}
			if byteLen(text) > maxAuthMetadataValueBytes {
				return fmt.Errorf("metadata %q must be <= %d bytes", key, maxAuthMetadataValueBytes)
			}
		}
	}
	return nil
}

func authRedirectOriginAllowed(parsed *url.URL) bool {
	origin := urlOrigin(parsed)
	for _, configured := range authAllowedRedirectOrigins() {
		if origin == configured {
			return true
		}
	}
	return false
}

func authAllowedRedirectOrigins() []string {
	seen := map[string]struct{}{}
	var origins []string
	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
			return
		}
		origin := urlOrigin(parsed)
		if origin == "" {
			return
		}
		if _, ok := seen[origin]; ok {
			return
		}
		seen[origin] = struct{}{}
		origins = append(origins, origin)
	}
	add(firstEnv("PLYSTRA_PUBLIC_APP_URL", "PUBLIC_APP_URL"))
	add(firstEnv("SERVER_PUBLIC_URL", "PLYSTRA_SERVER_PUBLIC_URL"))
	for _, raw := range strings.Split(firstEnv("PLYSTRA_AUTH_ALLOWED_REDIRECT_ORIGINS"), ",") {
		add(raw)
	}
	return origins
}

func urlOrigin(parsed *url.URL) string {
	if parsed == nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	return strings.ToLower(parsed.Scheme + "://" + parsed.Host)
}

func hasLineBreak(value string) bool {
	return strings.ContainsAny(value, "\r\n")
}

func byteLen(value string) int {
	return len([]byte(value))
}

func challengeThrottleKeys(email string, r *http.Request, scope string) []string {
	keys := loginThrottleKeys(email, r)
	for i, key := range keys {
		keys[i] = scope + ":" + key
	}
	return keys
}

func challengeSecretHash(value string) string {
	return tokenHash("auth_challenge:" + value)
}

func newNumericCode(length int) (string, error) {
	if length < 1 || length > 12 {
		return "", errors.New("invalid code length")
	}
	var b strings.Builder
	var one [1]byte
	for b.Len() < length {
		if _, err := rand.Read(one[:]); err != nil {
			return "", err
		}
		if one[0] >= 250 {
			continue
		}
		b.WriteByte('0' + (one[0] % 10))
	}
	return b.String(), nil
}

func validEmailCode(code string) bool {
	if len(code) != 6 {
		return false
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func emailDeliveryMode() string {
	mode := strings.ToLower(strings.TrimSpace(firstEnv("PLYSTRA_EMAIL_DELIVERY_MODE", "EMAIL_DELIVERY_MODE")))
	if mode == "" {
		if firstEnv("PLYSTRA_EMAIL_CAPABILITY_URL", "EMAIL_CAPABILITY_URL") != "" {
			return "capability"
		}
		return "log"
	}
	return mode
}

func logAuthChallengeEmail(purpose, deliveryMethod, email, secret, redirectURL string, expiresAt time.Time, challengeID string) {
	encoded := base64.RawURLEncoding.EncodeToString([]byte(secret))
	entry := map[string]any{
		"timestamp":       time.Now().UTC().Format(time.RFC3339Nano),
		"level":           "info",
		"message":         "auth email challenge generated",
		"purpose":         purpose,
		"delivery_method": deliveryMethod,
		"email":           email,
		"challenge_id":    challengeID,
		"expires_at":      expiresAt.Format(time.RFC3339),
		"secret_preview":  encoded,
		"redirect_url":    redirectURL,
	}
	_ = json.NewEncoder(os.Stdout).Encode(entry)
}

func exposeChallengeID(id string) string {
	if productionMode() {
		return ""
	}
	return id
}
