package api

import (
	"errors"
	"net/http"
	"strings"
	"time"

	coreent "github.com/plystra/core/ent"
	entactionexecution "github.com/plystra/core/ent/actionexecution"
	entcapabilitygrant "github.com/plystra/core/ent/capabilitygrant"
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
	Capability              string             `json:"capability"`
	Operation               string             `json:"operation"`
	Actor                   authz.ActorContext `json:"actor"`
	CapabilityGrantID       string             `json:"capability_grant_id"`
	ActionExecutionID       string             `json:"action_execution_id"`
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
	req.Capability = strings.TrimSpace(req.Capability)
	req.Operation = strings.TrimSpace(req.Operation)
	req.CapabilityGrantID = strings.TrimSpace(req.CapabilityGrantID)
	req.ActionExecutionID = strings.TrimSpace(req.ActionExecutionID)
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
	if ok := s.requireCapabilityGrantPermission(w, r, "capabilities:manage", req.SpaceID); !ok {
		return
	}
	binding, err := s.validateProviderRequestContextBinding(r, req, providerID)
	if err != nil {
		status := http.StatusForbidden
		code := "PROVIDER_CONTEXT_BINDING_DENIED"
		if errors.Is(err, errProviderRequestContextBindingNotFound) {
			status = http.StatusNotFound
			code = "PROVIDER_CONTEXT_BINDING_NOT_FOUND"
		}
		writeError(w, r, status, code, "Provider request context must be bound to an active Core authorization.", err.Error())
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
	expiresAt := providerRequestContextExpiresAt(now, req.TTLMS, binding)
	row, err := s.ent.ProviderRequestContext.Create().
		SetID(newEntityID("prctx")).
		SetTokenHash(sha256TokenHash(token)).
		SetProviderPluginID(providerID).
		SetSpaceID(req.SpaceID).
		SetNillableActorUserID(optionalString(req.Actor.UserID)).
		SetNillableActorMemberID(optionalString(req.Actor.MemberID)).
		SetNillableActorUserMemberID(optionalString(req.Actor.UserMemberID)).
		SetNillableCapability(optionalString(binding.Capability)).
		SetNillableOperation(optionalString(binding.Operation)).
		SetNillableCapabilityGrantID(optionalString(binding.CapabilityGrantID)).
		SetNillableActionExecutionID(optionalString(binding.ActionExecutionID)).
		SetNillableAuthorizationDecisionID(optionalString(binding.AuthorizationDecisionID)).
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
	case req.CapabilityGrantID == "" && req.ActionExecutionID == "":
		return validationError("capability_grant_id or action_execution_id is required")
	case req.CapabilityGrantID != "" && req.ActionExecutionID != "":
		return validationError("capability_grant_id and action_execution_id are mutually exclusive")
	}
	if req.CapabilityGrantID != "" && (req.Capability == "" || req.Operation == "") {
		return validationError("capability and operation are required when capability_grant_id is used")
	}
	if req.ActionExecutionID != "" && (req.Capability != "" || req.Operation != "") {
		return validationError("capability and operation are derived from action_execution_id and must be omitted")
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
		"capability":                derefString(row.Capability),
		"operation":                 derefString(row.Operation),
		"capability_grant_id":       derefString(row.CapabilityGrantID),
		"action_execution_id":       derefString(row.ActionExecutionID),
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

var errProviderRequestContextBindingNotFound = errors.New("provider request context authorization binding was not found")

type providerRequestContextBinding struct {
	Capability              string
	Operation               string
	CapabilityGrantID       string
	ActionExecutionID       string
	AuthorizationDecisionID string
	ExpiresAt               time.Time
}

func (s *Server) validateProviderRequestContextBinding(r *http.Request, req providerRequestContextRequest, providerID string) (providerRequestContextBinding, error) {
	if req.CapabilityGrantID != "" {
		return s.validateProviderRequestContextGrantBinding(r, req, providerID)
	}
	return s.validateProviderRequestContextActionBinding(r, req, providerID)
}

func (s *Server) validateProviderRequestContextGrantBinding(r *http.Request, req providerRequestContextRequest, providerID string) (providerRequestContextBinding, error) {
	row, err := s.ent.CapabilityGrant.Query().Where(
		entcapabilitygrant.ID(req.CapabilityGrantID),
		entcapabilitygrant.SpaceID(req.SpaceID),
	).Only(r.Context())
	if coreent.IsNotFound(err) {
		return providerRequestContextBinding{}, errProviderRequestContextBindingNotFound
	}
	if err != nil {
		return providerRequestContextBinding{}, err
	}
	active, reason := capabilityGrantActive(row, providerID, req.Capability, req.Operation, time.Now().UTC())
	if active {
		active, reason, err = s.capabilityPrincipalActive(r.Context(), capabilityGrantPrincipal{
			UserID:       derefString(row.PrincipalUserID),
			MemberID:     derefString(row.PrincipalMemberID),
			UserMemberID: derefString(row.PrincipalUserMemberID),
		}, row.SpaceID)
	}
	if err != nil {
		return providerRequestContextBinding{}, err
	}
	if active {
		active, reason, err = s.capabilityGrantAuthorizationActive(r, row)
	}
	if err != nil {
		return providerRequestContextBinding{}, err
	}
	if active {
		active, reason, err = s.capabilityGrantBindingActive(r.Context(), row)
	}
	if err != nil {
		return providerRequestContextBinding{}, err
	}
	if !active {
		return providerRequestContextBinding{}, errors.New(reason)
	}
	if err := providerRequestContextActorMatchesGrant(req, row); err != nil {
		return providerRequestContextBinding{}, err
	}
	if req.AuthorizationDecisionID != "" && req.AuthorizationDecisionID != derefString(row.DecisionID) {
		return providerRequestContextBinding{}, errors.New("authorization_decision_id does not match capability grant")
	}
	return providerRequestContextBinding{
		Capability:              row.Capability,
		Operation:               row.Operation,
		CapabilityGrantID:       row.ID,
		AuthorizationDecisionID: derefString(row.DecisionID),
		ExpiresAt:               row.ExpiresAt,
	}, nil
}

func (s *Server) validateProviderRequestContextActionBinding(r *http.Request, req providerRequestContextRequest, providerID string) (providerRequestContextBinding, error) {
	row, err := s.ent.ActionExecution.Query().Where(
		entactionexecution.ID(req.ActionExecutionID),
		entactionexecution.SpaceID(req.SpaceID),
	).Only(r.Context())
	if coreent.IsNotFound(err) {
		return providerRequestContextBinding{}, errProviderRequestContextBindingNotFound
	}
	if err != nil {
		return providerRequestContextBinding{}, err
	}
	if row.ProviderPluginID != providerID {
		return providerRequestContextBinding{}, errors.New("action execution provider does not match provider runtime")
	}
	if row.Status != "running" && row.Status != "pending" {
		return providerRequestContextBinding{}, errors.New("action execution is not active")
	}
	now := time.Now().UTC()
	if !row.TimeoutAt.After(now) {
		return providerRequestContextBinding{}, errors.New("action execution timed out")
	}
	if err := providerRequestContextActorMatchesAction(req, row); err != nil {
		return providerRequestContextBinding{}, err
	}
	active, reason, err := s.capabilityPrincipalActive(r.Context(), capabilityGrantPrincipal{
		UserID:       derefString(row.PrincipalUserID),
		MemberID:     derefString(row.PrincipalMemberID),
		UserMemberID: derefString(row.PrincipalUserMemberID),
	}, row.SpaceID)
	if err != nil {
		return providerRequestContextBinding{}, err
	}
	if !active {
		return providerRequestContextBinding{}, errors.New(reason)
	}
	authorizationContext, err := capabilityGrantAuthorizationContextFromResource(row.Resource)
	if err != nil {
		return providerRequestContextBinding{}, errors.New("action authorization context is invalid")
	}
	decision, err := s.authorizeCapabilityGrantPrincipal(r, capabilityGrantRequest{
		SpaceID:   row.SpaceID,
		Principal: capabilityGrantPrincipal{UserID: derefString(row.PrincipalUserID), MemberID: derefString(row.PrincipalMemberID), UserMemberID: derefString(row.PrincipalUserMemberID)},
	}, authorizationContext)
	if err != nil {
		return providerRequestContextBinding{}, err
	}
	if decision == nil || !decision.IsAllowed() {
		return providerRequestContextBinding{}, errors.New("principal_authorization_revoked")
	}
	if req.AuthorizationDecisionID != "" && req.AuthorizationDecisionID != derefString(row.DecisionID) {
		return providerRequestContextBinding{}, errors.New("authorization_decision_id does not match action execution")
	}
	return providerRequestContextBinding{
		Capability:              row.Capability,
		Operation:               row.Operation,
		ActionExecutionID:       row.ID,
		AuthorizationDecisionID: derefString(row.DecisionID),
		ExpiresAt:               row.TimeoutAt,
	}, nil
}

func providerRequestContextExpiresAt(now time.Time, ttlMS int, binding providerRequestContextBinding) time.Time {
	expiresAt := now.UTC().Add(providerRequestContextTTL(ttlMS))
	if !binding.ExpiresAt.IsZero() && binding.ExpiresAt.Before(expiresAt) {
		return binding.ExpiresAt.UTC()
	}
	return expiresAt.UTC()
}

func providerRequestContextActorMatchesGrant(req providerRequestContextRequest, row *coreent.CapabilityGrant) error {
	if req.Actor.UserID != derefString(row.PrincipalUserID) ||
		req.Actor.MemberID != derefString(row.PrincipalMemberID) ||
		req.Actor.UserMemberID != derefString(row.PrincipalUserMemberID) {
		return errors.New("actor does not match capability grant principal")
	}
	return nil
}

func providerRequestContextActorMatchesAction(req providerRequestContextRequest, row *coreent.ActionExecution) error {
	if req.Actor.UserID != derefString(row.PrincipalUserID) ||
		req.Actor.MemberID != derefString(row.PrincipalMemberID) ||
		req.Actor.UserMemberID != derefString(row.PrincipalUserMemberID) {
		return errors.New("actor does not match action execution principal")
	}
	return nil
}
