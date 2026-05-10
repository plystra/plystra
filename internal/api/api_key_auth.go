package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	coreent "github.com/plystra/plystra/ent"
	entapikey "github.com/plystra/plystra/ent/apikey"

	"github.com/jackc/pgx/v5"
)

const apiKeyBearerPrefix = "ply_ak_"

func (s *Server) adminCredentialAllowed(ctx context.Context, r *http.Request, requirement adminRequirement) (adminPrincipal, bool, error) {
	if token := apiKeyTokenFromRequest(r); token != "" {
		key, err := s.apiKeyFromToken(ctx, token)
		if err != nil {
			return adminPrincipal{}, false, err
		}
		principal := adminPrincipal{CredentialType: "api_key", APIKey: key}
		allowed, err := s.adminPrincipalAllows(ctx, principal, requirement)
		if allowed && err == nil {
			_ = s.ent.ApiKey.UpdateOneID(key.ID).SetLastUsedAt(time.Now().UTC()).Exec(ctx)
		}
		return principal, allowed, err
	}

	session, err := s.sessionFromRequest(ctx, r)
	if err != nil {
		return adminPrincipal{}, false, err
	}
	return s.adminSessionAllowed(ctx, session, requirement)
}

func (s *Server) apiKeyFromToken(ctx context.Context, token string) (*coreent.ApiKey, error) {
	if s.ent == nil {
		return nil, errAdminEntNotConfigured
	}
	id := apiKeyIDFromToken(token)
	if id == "" {
		return nil, pgx.ErrNoRows
	}
	hashes := apiKeyHashesForLookup(token)
	if len(hashes) == 0 {
		return nil, pgx.ErrNoRows
	}
	key, err := s.ent.ApiKey.Query().
		Where(
			entapikey.ID(id),
			entapikey.KeyHashIn(hashes...),
			entapikey.Status("active"),
			entapikey.DeletedAtIsNil(),
			entapikey.RevokedAtIsNil(),
			entapikey.Or(entapikey.ExpiresAtIsNil(), entapikey.ExpiresAtGT(time.Now().UTC())),
		).
		Only(ctx)
	if coreent.IsNotFound(err) {
		return nil, pgx.ErrNoRows
	}
	return key, err
}

func (s *Server) apiKeyAllows(ctx context.Context, key *coreent.ApiKey, requirement adminRequirement) (bool, error) {
	if key == nil || key.Status != "active" || key.RevokedAt != nil {
		return false, nil
	}
	if key.ExpiresAt != nil && !key.ExpiresAt.After(time.Now().UTC()) {
		return false, nil
	}
	if !apiKeyPermissionMatches(key.PermissionKeys, requirement.PermissionKey) {
		return false, nil
	}
	switch key.Level {
	case "instance":
		return true, nil
	case "space":
		if requirement.SpaceID == "" && requirement.GroupID == "" && adminPermissionMayResolveInHandler(requirement.PermissionKey) {
			return true, nil
		}
		keySpaceID := derefString(key.SpaceID)
		return keySpaceID != "" && requirement.SpaceID != "" && keySpaceID == requirement.SpaceID, nil
	case "group":
		if requirement.SpaceID == "" && requirement.GroupID == "" && adminPermissionMayResolveInHandler(requirement.PermissionKey) {
			return true, nil
		}
		keyGroupID := derefString(key.GroupID)
		if keyGroupID == "" || requirement.GroupID == "" {
			return false, nil
		}
		return s.groupGrantCovers(ctx, keyGroupID, requirement.GroupID)
	default:
		return false, nil
	}
}

func apiKeyPermissionMatches(grantKeys []string, requiredKey string) bool {
	for _, grantKey := range grantKeys {
		if adminPermissionMatches(grantKey, requiredKey) {
			return true
		}
	}
	return false
}

func apiKeyTokenFromRequest(r *http.Request) string {
	if value := strings.TrimSpace(r.Header.Get("X-Plystra-API-Key")); value != "" {
		return value
	}
	token := bearerToken(r)
	if strings.HasPrefix(token, apiKeyBearerPrefix) {
		return token
	}
	return ""
}

func apiKeyIDFromToken(token string) string {
	token = strings.TrimSpace(token)
	if !strings.HasPrefix(token, apiKeyBearerPrefix) {
		return ""
	}
	rest := strings.TrimPrefix(token, apiKeyBearerPrefix)
	id, secret, ok := strings.Cut(rest, ".")
	if !ok || id == "" || secret == "" {
		return ""
	}
	return id
}

func newAPIKeyPlaintext(id string) (string, error) {
	secret, err := newToken("")
	if err != nil {
		return "", err
	}
	return apiKeyBearerPrefix + id + "." + secret, nil
}

func apiKeyPrefix(id string) string {
	return apiKeyBearerPrefix + id
}

func apiKeyHash(token string) string {
	hashes := apiKeyHashesForLookup(token)
	if len(hashes) == 0 {
		return ""
	}
	return hashes[0]
}

func apiKeyHashesForLookup(token string) []string {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil
	}
	secrets := apiKeySecrets()
	if len(secrets) == 0 {
		return []string{sha256TokenHash(token)}
	}
	hashes := make([]string, 0, len(secrets))
	seen := map[string]struct{}{}
	for _, secret := range secrets {
		mac := hmac.New(sha256.New, []byte(secret))
		_, _ = mac.Write([]byte(token))
		hash := hex.EncodeToString(mac.Sum(nil))
		if _, ok := seen[hash]; ok {
			continue
		}
		seen[hash] = struct{}{}
		hashes = append(hashes, hash)
	}
	return hashes
}

func apiKeySecrets() []string {
	primary := strings.TrimSpace(firstEnv("PLYSTRA_API_KEY_SECRET", "API_KEY_SECRET"))
	if primary == "" {
		primary = strings.TrimSpace(sessionTokenSecret())
	}
	if primary == "" {
		return nil
	}
	secrets := []string{primary}
	for _, key := range []string{"PLYSTRA_API_KEY_SECRET_PREVIOUS", "API_KEY_SECRET_PREVIOUS"} {
		for _, value := range strings.Split(osEnv(key), ",") {
			value = strings.TrimSpace(value)
			if value != "" {
				secrets = append(secrets, value)
			}
		}
	}
	return secrets
}
