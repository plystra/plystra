package api

import (
	"net/http"
	"strings"
	"time"

	coreent "github.com/plystra/core/ent"
	entspace "github.com/plystra/core/ent/space"
	"github.com/plystra/core/internal/authz"
)

const (
	providerRequestContextMaxTTL = 5 * time.Minute
	providerRequestContextMinTTL = 5 * time.Second
)

type providerRequestContextRequest struct {
	ProviderPluginID        string             `json:"provider_plugin_id"`
	SpaceID                 string             `json:"space_id"`
	Actor                   authz.ActorContext `json:"actor"`
	AuthorizationDecisionID string             `json:"authorization_decision_id"`
	Purpose                 string             `json:"purpose"`
	TTLMS                   int                `json:"ttl_ms"`
	Metadata                map[string]any     `json:"metadata"`
}

func (s *Server) handleProviderRequestContexts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, r)
		return
	}
	var req providerRequestContextRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.ProviderPluginID = strings.TrimSpace(req.ProviderPluginID)
	req.SpaceID = strings.TrimSpace(req.SpaceID)
	req.AuthorizationDecisionID = strings.TrimSpace(req.AuthorizationDecisionID)
	req.Purpose = strings.TrimSpace(req.Purpose)
	if err := validateProviderRequestContextRequest(req); err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", err.Error(), nil)
		return
	}
	principal, ok := adminPrincipalFrom(r)
	if !ok || principal.CredentialType != "api_key" {
		writeError(w, r, http.StatusUnauthorized, "PROVIDER_RUNTIME_API_KEY_REQUIRED", "Provider request contexts require a provider-bound API key.", nil)
		return
	}
	providerID := apiKeyProviderRuntimeID(principal.APIKey)
	if providerID == "" || providerID != req.ProviderPluginID {
		writeError(w, r, http.StatusForbidden, "PROVIDER_CONTEXT_IDENTITY_DENIED", "API key is not bound to the requested provider runtime.", map[string]any{
			"provider_plugin_id": req.ProviderPluginID,
			"api_key_provider":   providerID,
		})
		return
	}
	active, err := s.providerRuntimePluginActive(r.Context(), providerID)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to validate provider runtime status.", err.Error())
		return
	}
	if !active {
		writeError(w, r, http.StatusForbidden, "PROVIDER_RUNTIME_INACTIVE", "Provider runtime is not enabled.", map[string]any{"provider_plugin_id": providerID})
		return
	}
	if _, err := s.ent.Space.Query().Where(entspace.ID(req.SpaceID), entspace.DeletedAtIsNil()).Only(r.Context()); coreent.IsNotFound(err) {
		writeError(w, r, http.StatusNotFound, "SPACE_NOT_FOUND", "Space was not found.", nil)
		return
	} else if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load Space.", err.Error())
		return
	}
	token, err := newToken("ply_prctx")
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to issue provider request context token.", err.Error())
		return
	}
	now := time.Now().UTC()
	expiresAt := now.Add(providerRequestContextTTL(req.TTLMS))
	row, err := s.ent.ProviderRequestContext.Create().
		SetID(newEntityID("prctx")).
		SetTokenHash(sha256TokenHash(token)).
		SetProviderPluginID(providerID).
		SetSpaceID(req.SpaceID).
		SetNillableActorUserID(optionalString(req.Actor.UserID)).
		SetNillableActorMemberID(optionalString(req.Actor.MemberID)).
		SetNillableActorUserMemberID(optionalString(req.Actor.UserMemberID)).
		SetNillableAuthorizationDecisionID(optionalString(req.AuthorizationDecisionID)).
		SetNillableRequestID(optionalString(requestIDFrom(r))).
		SetNillablePurpose(optionalString(req.Purpose)).
		SetStatus("active").
		SetExpiresAt(expiresAt).
		SetMetadata(nonNilMap(req.Metadata)).
		Save(r.Context())
	if err != nil {
		writeError(w, r, http.StatusConflict, "PROVIDER_REQUEST_CONTEXT_CREATE_FAILED", "Failed to create provider request context.", err.Error())
		return
	}
	writeData(w, r, http.StatusCreated, providerRequestContextIssuedMap(row, token))
}

func validateProviderRequestContextRequest(req providerRequestContextRequest) error {
	switch {
	case req.ProviderPluginID == "":
		return validationError("provider_plugin_id is required")
	case req.SpaceID == "":
		return validationError("space_id is required")
	case req.Actor.UserID == "" || req.Actor.MemberID == "" || req.Actor.UserMemberID == "":
		return validationError("actor.user_id, actor.member_id, and actor.user_member_id are required")
	}
	if err := validateGovernedJSONValue("provider_request_context.metadata", nonNilMap(req.Metadata), governedJSONPolicy{MaxBytes: maxGovernedMetadataBytes, RejectSecrets: true}); err != nil {
		return err
	}
	return nil
}

func providerRequestContextTTL(ttlMS int) time.Duration {
	if ttlMS <= 0 {
		return providerRequestContextMaxTTL
	}
	ttl := time.Duration(ttlMS) * time.Millisecond
	if ttl < providerRequestContextMinTTL {
		return providerRequestContextMinTTL
	}
	if ttl > providerRequestContextMaxTTL {
		return providerRequestContextMaxTTL
	}
	return ttl
}

func providerRequestContextIssuedMap(row *coreent.ProviderRequestContext, token string) map[string]any {
	return map[string]any{
		"id":                        row.ID,
		"context_token":             token,
		"provider_plugin_id":        row.ProviderPluginID,
		"space_id":                  row.SpaceID,
		"actor_user_id":             derefString(row.ActorUserID),
		"actor_member_id":           derefString(row.ActorMemberID),
		"actor_user_member_id":      derefString(row.ActorUserMemberID),
		"authorization_decision_id": derefString(row.AuthorizationDecisionID),
		"request_id":                derefString(row.RequestID),
		"purpose":                   derefString(row.Purpose),
		"status":                    row.Status,
		"expires_at":                formatTime(row.ExpiresAt),
		"metadata":                  nonNilMap(row.Metadata),
		"created_at":                formatTime(row.CreatedAt),
		"updated_at":                formatTime(row.UpdatedAt),
	}
}

func providerRequestContextMap(row *coreent.ProviderRequestContext) map[string]any {
	out := providerRequestContextIssuedMap(row, "")
	delete(out, "context_token")
	return out
}
