package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	coreent "github.com/plystra/core/ent"
	entcapabilitygrant "github.com/plystra/core/ent/capabilitygrant"
	entcapabilityproviderbinding "github.com/plystra/core/ent/capabilityproviderbinding"
	entplugin "github.com/plystra/core/ent/plugin"
	"github.com/plystra/core/internal/authz"
	"github.com/plystra/core/internal/plugins"
)

const (
	capabilityGrantBearerPrefix = "ply_grant_"
	defaultCapabilityGrantTTL   = 30 * time.Second
	maxCapabilityGrantTTL       = 5 * time.Minute

	defaultCapabilityProviderResolverCacheTTL = 30 * time.Second
)

var providerRuntimeMetadataKeys = []string{"provider_plugin_id", "plugin_id", "provider_id"}

type capabilityGrantRequest struct {
	SpaceID        string                   `json:"space_id"`
	Capability     string                   `json:"capability"`
	Operation      string                   `json:"operation"`
	Principal      capabilityGrantPrincipal `json:"principal"`
	Executor       capabilityGrantExecutor  `json:"executor"`
	Resource       map[string]any           `json:"resource"`
	InputSummary   map[string]any           `json:"input_summary"`
	IdempotencyKey string                   `json:"idempotency_key"`
	ParentGrantID  string                   `json:"parent_grant_id"`
	CorrelationID  string                   `json:"correlation_id"`
	TTLMS          int                      `json:"ttl_ms"`
	Metadata       map[string]any           `json:"metadata"`
}

type capabilityGrantAuthorizationContext struct {
	ResourceType string
	ResourceID   string
	Action       string
	Target       *authz.TargetSnapshot
}

type capabilityGrantPrincipal struct {
	UserID       string `json:"user_id"`
	MemberID     string `json:"member_id"`
	UserMemberID string `json:"user_member_id"`
}

type capabilityGrantExecutor struct {
	PluginID string `json:"plugin_id"`
}

type grantIntrospectionRequest struct {
	Grant            string `json:"grant"`
	TargetProviderID string `json:"target_provider_id"`
	Capability       string `json:"capability"`
	Operation        string `json:"operation"`
}

type capabilityOutcomeRequest struct {
	GrantID              string         `json:"grant_id"`
	TargetIdempotencyKey string         `json:"target_idempotency_key"`
	TargetProviderID     string         `json:"target_provider_id"`
	Status               string         `json:"status"`
	ResultRef            map[string]any `json:"result_ref"`
	Events               []any          `json:"events"`
	FinishedAt           *time.Time     `json:"finished_at"`
	OutcomeEventID       string         `json:"outcome_event_id"`
	Metadata             map[string]any `json:"metadata"`
}

type capabilityGrantRevokeRequest struct {
	Reason string `json:"reason"`
}

type capabilityProviderBinding struct {
	PluginKey      string
	ProviderID     string
	AppID          string
	TrustBundleID  string
	Local          bool
	Endpoint       string
	OperationPath  string
	Identity       map[string]any
	BindingEpoch   int
	InvocationMode string
	GrantTTL       time.Duration
	CallGraph      plugins.CapabilityCallGraphDefinition
}

type governedPluginManifest struct {
	Manifest      plugins.Manifest
	Type          string
	Scope         string
	AppID         string
	TrustBundleID string
}

type capabilityProviderResolverCache struct {
	mu      sync.RWMutex
	ttl     time.Duration
	entries map[string]capabilityProviderResolverCacheEntry
}

type capabilityProviderResolverCacheEntry struct {
	provider  capabilityProviderBinding
	expiresAt time.Time
}

func newCapabilityProviderResolverCache(ttl time.Duration) *capabilityProviderResolverCache {
	if ttl <= 0 {
		ttl = defaultCapabilityProviderResolverCacheTTL
	}
	return &capabilityProviderResolverCache{
		ttl:     ttl,
		entries: map[string]capabilityProviderResolverCacheEntry{},
	}
}

func (c *capabilityProviderResolverCache) get(spaceID, capabilityID, operationName string, now time.Time) (capabilityProviderBinding, bool) {
	if c == nil {
		return capabilityProviderBinding{}, false
	}
	key := capabilityProviderResolverCacheKey(spaceID, capabilityID, operationName)
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok || !entry.expiresAt.After(now.UTC()) {
		if ok {
			c.invalidate(spaceID, capabilityID, operationName)
		}
		return capabilityProviderBinding{}, false
	}
	return entry.provider, true
}

func (c *capabilityProviderResolverCache) set(spaceID, capabilityID, operationName string, provider capabilityProviderBinding, now time.Time) {
	if c == nil {
		return
	}
	key := capabilityProviderResolverCacheKey(spaceID, capabilityID, operationName)
	c.mu.Lock()
	c.entries[key] = capabilityProviderResolverCacheEntry{provider: provider, expiresAt: now.UTC().Add(c.ttl)}
	c.mu.Unlock()
}

func (c *capabilityProviderResolverCache) invalidate(spaceID, capabilityID, operationName string) {
	if c == nil {
		return
	}
	key := capabilityProviderResolverCacheKey(spaceID, capabilityID, operationName)
	c.mu.Lock()
	delete(c.entries, key)
	c.mu.Unlock()
}

func capabilityProviderResolverCacheKey(spaceID, capabilityID, operationName string) string {
	return strings.TrimSpace(spaceID) + "\x00" + strings.TrimSpace(capabilityID) + "\x00" + strings.TrimSpace(operationName)
}

func (s *Server) handleCapabilityGrants(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, r)
		return
	}
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	var req capabilityGrantRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.normalize()
	if err := validateCapabilityGrantRequest(req); err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Capability grant request is invalid.", err.Error())
		return
	}
	if ok := s.requireCapabilityGrantPermission(w, r, "capabilities:invoke", req.SpaceID); !ok {
		return
	}
	if !s.requireActiveSpace(w, r, req.SpaceID) {
		return
	}
	if providerRuntimeID := providerRuntimePrincipalID(r); providerRuntimeID != "" {
		if req.Executor.PluginID != providerRuntimeID {
			writeError(w, r, http.StatusForbidden, "CAPABILITY_PROVIDER_IDENTITY_REQUIRED", "Provider runtime capability calls must use the bound provider runtime as executor.", map[string]any{
				"executor_plugin_id": req.Executor.PluginID,
				"api_key_provider":   providerRuntimeID,
			})
			return
		}
		if req.ParentGrantID == "" {
			writeError(w, r, http.StatusForbidden, "CAPABILITY_CALL_GRAPH_DENIED", "Capability call graph policy denied the grant.", "provider-runtime capability calls require parent_grant_id for Core-tracked lineage")
			return
		}
	}
	provider, err := s.resolveCapabilityProvider(r, req.SpaceID, req.Capability, req.Operation)
	if errors.Is(err, errCapabilityProviderNotFound) {
		writeError(w, r, http.StatusNotFound, "CAPABILITY_PROVIDER_NOT_FOUND", "No enabled provider is installed for this capability operation.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to resolve capability provider.", err.Error())
		return
	}
	allowed, err := s.callerPluginRequiresCapability(r, req.Executor.PluginID, req.Capability)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to validate caller capability requirement.", err.Error())
		return
	}
	if !allowed {
		writeError(w, r, http.StatusForbidden, "CAPABILITY_REQUIREMENT_MISSING", "Caller plugin does not declare this required capability.", map[string]any{
			"caller_plugin_id": req.Executor.PluginID,
			"capability":       req.Capability,
		})
		return
	}
	if ok, err := s.callerAllowedForProviderScope(r, req.Executor.PluginID, provider); err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to validate caller provider scope.", err.Error())
		return
	} else if !ok {
		writeError(w, r, http.StatusForbidden, "CAPABILITY_SCOPE_DENIED", "Caller plugin is outside the target capability scope.", map[string]any{
			"caller_plugin_id": req.Executor.PluginID,
			"capability":       req.Capability,
		})
		return
	}
	if active, reason, err := s.capabilityPrincipalActive(r.Context(), req.Principal, req.SpaceID); err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to validate capability principal.", err.Error())
		return
	} else if !active {
		writeError(w, r, http.StatusForbidden, "CAPABILITY_PRINCIPAL_INACTIVE", "Capability principal is not active for this Space.", map[string]any{"reason": reason})
		return
	}
	authorizationContext, err := capabilityGrantAuthorizationContextFromResource(req.Resource)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Capability grant resource authorization context is invalid.", err.Error())
		return
	}
	decision, err := s.authorizeCapabilityGrantPrincipal(r, req, authorizationContext)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to authorize capability grant principal.", err.Error())
		return
	}
	if !decision.IsAllowed() {
		writeError(w, r, http.StatusForbidden, "AUTHORIZATION_DENIED", "Capability grant principal is not authorized for the requested resource action.", decision)
		return
	}
	if err := s.validateCapabilityCallGraph(r, req, provider); err != nil {
		writeError(w, r, http.StatusForbidden, "CAPABILITY_CALL_GRAPH_DENIED", "Capability call graph policy denied the grant.", err.Error())
		return
	}
	existing, err := client.CapabilityGrant.Query().Where(
		entcapabilitygrant.SpaceID(req.SpaceID),
		entcapabilitygrant.CallerPluginID(req.Executor.PluginID),
		entcapabilitygrant.Capability(req.Capability),
		entcapabilitygrant.Operation(req.Operation),
		entcapabilitygrant.IdempotencyKey(req.IdempotencyKey),
	).Only(r.Context())
	if err == nil {
		now := time.Now().UTC()
		if !capabilityGrantReissuable(existing, provider, now) {
			writeError(w, r, http.StatusConflict, "CAPABILITY_GRANT_REISSUE_DENIED", "Existing capability grant cannot be reissued for this idempotency key.", map[string]any{
				"grant_id":         existing.ID,
				"status":           existing.Status,
				"outcome_status":   existing.OutcomeStatus,
				"binding_epoch":    existing.BindingEpoch,
				"provider_epoch":   provider.BindingEpoch,
				"revoked":          existing.RevokedAt != nil,
				"expires_at":       formatTime(existing.ExpiresAt),
				"idempotency_key":  req.IdempotencyKey,
				"caller_plugin_id": req.Executor.PluginID,
			})
			return
		}
		grantToken, tokenErr := newCapabilityGrantToken()
		if tokenErr != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to reissue capability grant token.", tokenErr.Error())
			return
		}
		ttl := req.grantTTL(provider.GrantTTL)
		existing, err = client.CapabilityGrant.UpdateOneID(existing.ID).
			SetTokenHash(capabilityGrantTokenHash(grantToken)).
			SetExpiresAt(now.Add(ttl)).
			SetExpectedOutcomeBy(now.Add(ttl + ttl/2)).
			Save(r.Context())
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to reissue capability grant token.", err.Error())
			return
		}
		writeData(w, r, http.StatusOK, capabilityGrantIssuedMap(existing, grantToken, provider))
		return
	}
	if err != nil && !coreent.IsNotFound(err) {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to check capability grant idempotency.", err.Error())
		return
	}
	now := time.Now().UTC()
	ttl := req.grantTTL(provider.GrantTTL)
	expiresAt := now.Add(ttl)
	grantToken, err := newCapabilityGrantToken()
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to issue capability grant.", err.Error())
		return
	}
	grantID := newEntityID("grt")
	correlationID := firstNonEmpty(req.CorrelationID, newEntityID("cor"))
	targetIdempotencyKey := "tgidem_" + safeIdentifier(req.SpaceID+"_"+provider.ProviderID+"_"+req.Capability+"_"+req.Operation+"_"+req.IdempotencyKey)
	metadata := nonNilMap(req.Metadata)
	metadata["resource"] = nonNilMap(req.Resource)
	metadata["input_summary"] = nonNilMap(req.InputSummary)
	metadata["authorization"] = capabilityGrantDecisionSummary(decision)
	row, err := client.CapabilityGrant.Create().
		SetID(grantID).
		SetTokenHash(capabilityGrantTokenHash(grantToken)).
		SetSpaceID(req.SpaceID).
		SetCapability(req.Capability).
		SetOperation(req.Operation).
		SetNillablePrincipalUserID(optionalString(req.Principal.UserID)).
		SetNillablePrincipalMemberID(optionalString(req.Principal.MemberID)).
		SetNillablePrincipalUserMemberID(optionalString(req.Principal.UserMemberID)).
		SetCallerPluginID(req.Executor.PluginID).
		SetTargetProviderID(provider.ProviderID).
		SetNillableParentGrantID(optionalString(req.ParentGrantID)).
		SetNillableDecisionID(optionalString(decision.Audit.ID)).
		SetCorrelationID(correlationID).
		SetIdempotencyKey(req.IdempotencyKey).
		SetTargetIdempotencyKey(targetIdempotencyKey).
		SetBindingEpoch(provider.BindingEpoch).
		SetStatus("active").
		SetOutcomeStatus("pending").
		SetExpectedOutcomeBy(now.Add(ttl + ttl/2)).
		SetExpiresAt(expiresAt).
		SetMetadata(metadata).
		Save(r.Context())
	if err != nil {
		writeError(w, r, http.StatusConflict, "CAPABILITY_GRANT_CREATE_FAILED", "Failed to create capability grant.", err.Error())
		return
	}
	s.recordCapabilityGrantAudit(r, row, "capability.grant.issued", "Capability grant issued")
	writeData(w, r, http.StatusCreated, capabilityGrantIssuedMap(row, grantToken, provider))
}

func (s *Server) handleCapabilityGrantSubroutes(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/capability-grants/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 2 && parts[0] != "" && parts[1] == "revoke" {
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, r)
			return
		}
		s.revokeCapabilityGrant(w, r, parts[0])
		return
	}
	http.NotFound(w, r)
}

func (s *Server) revokeCapabilityGrant(w http.ResponseWriter, r *http.Request, grantID string) {
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	var req capabilityGrantRevokeRequest
	if !decodeOptionalJSON(w, r, &req) {
		return
	}
	row, err := client.CapabilityGrant.Query().Where(entcapabilitygrant.ID(grantID)).Only(r.Context())
	if coreent.IsNotFound(err) {
		writeError(w, r, http.StatusNotFound, "CAPABILITY_GRANT_NOT_FOUND", "Capability grant was not found.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load capability grant.", err.Error())
		return
	}
	if ok := s.requireCapabilityGrantPermission(w, r, "capabilities:manage", row.SpaceID); !ok {
		return
	}
	if row.Status == "revoked" && row.RevokedAt != nil {
		writeData(w, r, http.StatusOK, capabilityGrantMap(row))
		return
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		reason = "explicit_revoke"
	}
	updated, err := client.CapabilityGrant.UpdateOneID(row.ID).
		SetStatus("revoked").
		SetRevokedAt(time.Now().UTC()).
		SetRevokedReason(reason).
		Save(r.Context())
	if err != nil {
		writeError(w, r, http.StatusConflict, "CAPABILITY_GRANT_REVOKE_FAILED", "Failed to revoke capability grant.", err.Error())
		return
	}
	s.recordCapabilityGrantAudit(r, updated, "capability.grant.revoked", "Capability grant revoked")
	writeData(w, r, http.StatusOK, capabilityGrantMap(updated))
}

func (s *Server) handleGrantIntrospect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, r)
		return
	}
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	var req grantIntrospectionRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Grant = strings.TrimSpace(req.Grant)
	req.TargetProviderID = strings.TrimSpace(req.TargetProviderID)
	req.Capability = strings.TrimSpace(req.Capability)
	req.Operation = strings.TrimSpace(req.Operation)
	if req.Grant == "" || req.TargetProviderID == "" || req.Capability == "" || req.Operation == "" {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "grant, target_provider_id, capability, and operation are required.", nil)
		return
	}
	row, err := client.CapabilityGrant.Query().Where(entcapabilitygrant.TokenHashIn(capabilityGrantTokenHashesForLookup(req.Grant)...)).Only(r.Context())
	if coreent.IsNotFound(err) {
		writeData(w, r, http.StatusOK, map[string]any{"active": false, "reason": "grant_not_found"})
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to introspect grant.", err.Error())
		return
	}
	if ok := s.requireProviderRuntimePrincipal(w, r, req.TargetProviderID); !ok {
		return
	}
	active, reason := capabilityGrantActive(row, req.TargetProviderID, req.Capability, req.Operation, time.Now().UTC())
	if active {
		active, reason, err = s.capabilityPrincipalActive(r.Context(), capabilityGrantPrincipal{
			UserID:       derefString(row.PrincipalUserID),
			MemberID:     derefString(row.PrincipalMemberID),
			UserMemberID: derefString(row.PrincipalUserMemberID),
		}, row.SpaceID)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to validate grant principal.", err.Error())
			return
		}
	}
	if active {
		active, reason, err = s.capabilityGrantAuthorizationActive(r, row)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to validate grant resource authorization.", err.Error())
			return
		}
	}
	if active {
		active, reason, err = s.capabilityGrantBindingActive(r.Context(), row)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to validate grant provider binding.", err.Error())
			return
		}
	}
	out := map[string]any{"active": active}
	if !active {
		out["reason"] = reason
		writeData(w, r, http.StatusOK, out)
		return
	}
	out["grant_id"] = row.ID
	out["space_id"] = row.SpaceID
	out["principal"] = map[string]any{
		"user_id":        derefString(row.PrincipalUserID),
		"member_id":      derefString(row.PrincipalMemberID),
		"user_member_id": derefString(row.PrincipalUserMemberID),
	}
	out["caller"] = map[string]any{"plugin_id": row.CallerPluginID}
	out["target_idempotency_key"] = row.TargetIdempotencyKey
	out["decision_id"] = derefString(row.DecisionID)
	out["correlation_id"] = row.CorrelationID
	out["binding_epoch"] = row.BindingEpoch
	out["expires_at"] = formatTime(row.ExpiresAt)
	writeData(w, r, http.StatusOK, out)
}

func (s *Server) handleCapabilityOutcomes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, r)
		return
	}
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	var req capabilityOutcomeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.GrantID = strings.TrimSpace(req.GrantID)
	req.TargetIdempotencyKey = strings.TrimSpace(req.TargetIdempotencyKey)
	req.TargetProviderID = strings.TrimSpace(req.TargetProviderID)
	req.Status = strings.TrimSpace(req.Status)
	req.OutcomeEventID = strings.TrimSpace(req.OutcomeEventID)
	if req.GrantID == "" || req.TargetIdempotencyKey == "" || req.TargetProviderID == "" || req.OutcomeEventID == "" || !validCapabilityOutcomeStatus(req.Status) {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "grant_id, target_idempotency_key, target_provider_id, outcome_event_id, and a valid status are required.", nil)
		return
	}
	row, err := client.CapabilityGrant.Query().Where(
		entcapabilitygrant.ID(req.GrantID),
		entcapabilitygrant.TargetIdempotencyKey(req.TargetIdempotencyKey),
	).Only(r.Context())
	if coreent.IsNotFound(err) {
		writeError(w, r, http.StatusNotFound, "CAPABILITY_GRANT_NOT_FOUND", "Capability grant was not found.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load capability grant.", err.Error())
		return
	}
	if row.TargetProviderID != req.TargetProviderID {
		writeError(w, r, http.StatusForbidden, "CAPABILITY_OUTCOME_TARGET_MISMATCH", "Capability outcome receipt target does not match the grant audience.", map[string]any{
			"grant_id":           row.ID,
			"target_provider_id": req.TargetProviderID,
			"grant_target":       row.TargetProviderID,
			"target_idempotency": row.TargetIdempotencyKey,
			"capability":         row.Capability,
			"operation":          row.Operation,
		})
		return
	}
	if ok := s.requireProviderRuntimePrincipal(w, r, row.TargetProviderID); !ok {
		return
	}
	metadata := nonNilMap(row.Metadata)
	outcomeEventID := req.OutcomeEventID
	if existingOutcome := mapFromAny(metadata["outcome"]); len(existingOutcome) > 0 {
		existingOutcomeEventID := strings.TrimSpace(stringFromMap(existingOutcome, "outcome_event_id"))
		if outcomeEventID != "" && existingOutcomeEventID == outcomeEventID {
			writeData(w, r, http.StatusOK, capabilityGrantMap(row))
			return
		}
		if row.OutcomeStatus != "" && row.OutcomeStatus != "pending" {
			writeError(w, r, http.StatusConflict, "CAPABILITY_OUTCOME_CONFLICT", "Capability grant already has a different terminal outcome receipt.", map[string]any{
				"grant_id":                  row.ID,
				"target_idempotency_key":    row.TargetIdempotencyKey,
				"existing_outcome_status":   row.OutcomeStatus,
				"existing_outcome_event_id": existingOutcomeEventID,
				"outcome_event_id":          outcomeEventID,
			})
			return
		}
	}
	outcome := map[string]any{
		"status":           req.Status,
		"result_ref":       nonNilMap(req.ResultRef),
		"events":           req.Events,
		"outcome_event_id": outcomeEventID,
		"finished_at":      time.Now().UTC().Format(time.RFC3339),
	}
	if req.FinishedAt != nil {
		outcome["finished_at"] = req.FinishedAt.UTC().Format(time.RFC3339)
	}
	if len(req.Metadata) > 0 {
		outcome["metadata"] = nonNilMap(req.Metadata)
	}
	metadata["outcome"] = outcome
	status := "used"
	if req.Status == "failed" || req.Status == "result_unknown" {
		status = "active"
	}
	updated, err := client.CapabilityGrant.UpdateOneID(row.ID).
		SetOutcomeStatus(req.Status).
		SetStatus(status).
		SetMetadata(metadata).
		Save(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to record capability outcome.", err.Error())
		return
	}
	s.recordCapabilityGrantAudit(r, updated, "capability.outcome.recorded", "Capability outcome recorded")
	writeData(w, r, http.StatusOK, capabilityGrantMap(updated))
}

func (req *capabilityGrantRequest) normalize() {
	req.SpaceID = strings.TrimSpace(req.SpaceID)
	req.Capability = strings.TrimSpace(req.Capability)
	req.Operation = strings.TrimSpace(req.Operation)
	req.Principal.UserID = strings.TrimSpace(req.Principal.UserID)
	req.Principal.MemberID = strings.TrimSpace(req.Principal.MemberID)
	req.Principal.UserMemberID = strings.TrimSpace(req.Principal.UserMemberID)
	req.Executor.PluginID = strings.TrimSpace(req.Executor.PluginID)
	req.IdempotencyKey = strings.TrimSpace(req.IdempotencyKey)
	req.ParentGrantID = strings.TrimSpace(req.ParentGrantID)
	req.CorrelationID = strings.TrimSpace(req.CorrelationID)
}

func (req capabilityGrantRequest) grantTTL(providerTTL time.Duration) time.Duration {
	if req.TTLMS > 0 {
		ttl := time.Duration(req.TTLMS) * time.Millisecond
		if ttl > maxCapabilityGrantTTL {
			return maxCapabilityGrantTTL
		}
		return ttl
	}
	if providerTTL > 0 {
		return providerTTL
	}
	return defaultCapabilityGrantTTL
}

func validateCapabilityGrantRequest(req capabilityGrantRequest) error {
	switch {
	case req.SpaceID == "":
		return errors.New("space_id is required")
	case !pluginsCapabilityIDValid(req.Capability):
		return errors.New("capability must be a dotted capability id")
	case req.Operation == "":
		return errors.New("operation is required")
	case req.Executor.PluginID == "":
		return errors.New("executor.plugin_id is required")
	case req.IdempotencyKey == "":
		return errors.New("idempotency_key is required")
	case req.TTLMS < 0:
		return errors.New("ttl_ms must be non-negative")
	}
	if err := validateGovernedJSONValue("capability_grant.resource", nonNilMap(req.Resource), governedJSONPolicy{MaxBytes: maxPluginSettingValueBytes, RejectSecrets: true}); err != nil {
		return err
	}
	if err := validateGovernedJSONValue("capability_grant.input_summary", nonNilMap(req.InputSummary), governedJSONPolicy{MaxBytes: maxPluginSettingValueBytes, RejectSecrets: true}); err != nil {
		return err
	}
	if err := validateGovernedJSONValue("capability_grant.metadata", nonNilMap(req.Metadata), governedJSONPolicy{MaxBytes: maxPluginSettingValueBytes, RejectSecrets: true}); err != nil {
		return err
	}
	return nil
}

func capabilityGrantAuthorizationContextFromResource(resource map[string]any) (capabilityGrantAuthorizationContext, error) {
	values := nonNilMap(resource)
	resourceType := firstNonEmpty(stringFromMap(values, "resource_type"), stringFromMap(values, "type"))
	resourceID := firstNonEmpty(stringFromMap(values, "resource_id"), stringFromMap(values, "id"), stringFromMap(values, "external_id"))
	action := firstNonEmpty(stringFromMap(values, "action"), stringFromMap(values, "resource_action"))
	if resourceType == "" || resourceID == "" || action == "" {
		return capabilityGrantAuthorizationContext{}, errors.New("resource_type, resource_id, and action are required")
	}
	targetValues := mapFromAny(values["target"])
	if len(targetValues) == 0 && (stringFromMap(values, "space_id") != "" || stringFromMap(values, "group_id") != "" || stringFromMap(values, "group_path") != "" || stringFromMap(values, "owner_member_id") != "") {
		targetValues = values
	}
	out := capabilityGrantAuthorizationContext{
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Action:       action,
	}
	if len(targetValues) > 0 {
		spaceID := stringFromMap(targetValues, "space_id")
		if spaceID == "" {
			return capabilityGrantAuthorizationContext{}, errors.New("inline target requires space_id")
		}
		targetResourceType := firstNonEmpty(stringFromMap(targetValues, "resource_type"), stringFromMap(targetValues, "type"), resourceType)
		if targetResourceType != resourceType {
			return capabilityGrantAuthorizationContext{}, errors.New("inline target resource_type must match resource_type")
		}
		targetResourceID := firstNonEmpty(stringFromMap(targetValues, "resource_id"), stringFromMap(targetValues, "id"), stringFromMap(targetValues, "external_id"), resourceID)
		target := authz.TargetSnapshot{
			Resource: authz.ResourceSnapshot{
				ID:            targetResourceID,
				ExternalID:    firstNonEmpty(stringFromMap(targetValues, "external_id"), targetResourceID),
				Type:          resourceType,
				SpaceID:       spaceID,
				GroupID:       stringFromMap(targetValues, "group_id"),
				GroupPath:     stringFromMap(targetValues, "group_path"),
				OwnerMemberID: stringFromMap(targetValues, "owner_member_id"),
				DisplayName:   stringFromMap(targetValues, "display_name"),
				Visibility:    stringFromMap(targetValues, "visibility"),
				Status:        firstNonEmpty(stringFromMap(targetValues, "status"), "active"),
				Metadata:      mapFromAny(targetValues["metadata"]),
			},
		}
		if target.Resource.GroupID != "" || target.Resource.GroupPath != "" {
			target.Group = &authz.GroupSnapshot{
				ID:      firstNonEmpty(target.Resource.GroupID, "group_inline_"+safeIdentifier(spaceID+"_"+target.Resource.GroupPath)),
				SpaceID: spaceID,
				Path:    firstNonEmpty(target.Resource.GroupPath, target.Resource.GroupID),
				Status:  "active",
			}
		}
		out.Target = &target
	}
	return out, nil
}

func (s *Server) authorizeCapabilityGrantPrincipal(r *http.Request, req capabilityGrantRequest, authorizationContext capabilityGrantAuthorizationContext) (*authz.Decision, error) {
	if s.authzStore == nil {
		return nil, errors.New("authz store is not configured")
	}
	input := authz.CheckInput{
		Actor: authz.ActorContext{
			UserID:       req.Principal.UserID,
			MemberID:     req.Principal.MemberID,
			UserMemberID: req.Principal.UserMemberID,
			SpaceID:      req.SpaceID,
		},
		ResourceType:  authorizationContext.ResourceType,
		ResourceID:    authorizationContext.ResourceID,
		Action:        authorizationContext.Action,
		Target:        authorizationContext.Target,
		InlineContext: authorizationContext.Target != nil,
		RequestID:     requestIDFrom(r),
		IP:            remoteIPFrom(r),
		UserAgent:     r.UserAgent(),
	}
	if s.kernel != nil {
		return s.authzViaKernel(r, input)
	}
	return authz.Check(r.Context(), s.authzStore, input)
}

func capabilityGrantDecisionSummary(decision *authz.Decision) map[string]any {
	if decision == nil {
		return map[string]any{}
	}
	out := map[string]any{
		"decision":      decision.Decision,
		"reason":        decision.Reason,
		"trace_id":      decision.TraceID,
		"audit_log_id":  decision.Audit.ID,
		"resource_type": decision.Audit.ResourceType,
		"resource_id":   decision.Audit.ResourceID,
		"action":        decision.Audit.Action,
	}
	if decision.DenyCode != nil {
		out["deny_code"] = string(*decision.DenyCode)
	}
	return out
}

func capabilityGrantReissuable(row *coreent.CapabilityGrant, provider capabilityProviderBinding, now time.Time) bool {
	if row == nil {
		return false
	}
	if row.Status != "active" || row.OutcomeStatus != "pending" {
		return false
	}
	if row.RevokedAt != nil || !row.ExpiresAt.After(now.UTC()) {
		return false
	}
	return row.TargetProviderID == provider.ProviderID && row.BindingEpoch == provider.BindingEpoch
}

var errCapabilityProviderNotFound = errors.New("capability provider not found")

func (s *Server) resolveCapabilityProvider(r *http.Request, spaceID, capabilityID, operationName string) (capabilityProviderBinding, error) {
	spaceID = strings.TrimSpace(spaceID)
	capabilityID = strings.TrimSpace(capabilityID)
	operationName = strings.TrimSpace(operationName)
	if spaceID == "" && r != nil {
		spaceID = strings.TrimSpace(r.URL.Query().Get("space_id"))
	}
	if spaceID == "" {
		return capabilityProviderBinding{}, errCapabilityProviderNotFound
	}
	if cached, ok := s.capabilityProviderCache.get(spaceID, capabilityID, operationName, time.Now().UTC()); ok {
		return cached, nil
	}
	binding, err := s.ent.CapabilityProviderBinding.Query().Where(
		entcapabilityproviderbinding.SpaceID(spaceID),
		entcapabilityproviderbinding.Capability(capabilityID),
		entcapabilityproviderbinding.Operation(operationName),
		entcapabilityproviderbinding.Status("active"),
	).Only(r.Context())
	if coreent.IsNotFound(err) {
		return capabilityProviderBinding{}, errCapabilityProviderNotFound
	}
	if err != nil {
		return capabilityProviderBinding{}, err
	}
	row, err := s.ent.Plugin.Query().
		Where(entplugin.Key(binding.ProviderPluginID), entplugin.Status("enabled")).
		Only(r.Context())
	if coreent.IsNotFound(err) {
		return capabilityProviderBinding{}, errCapabilityProviderNotFound
	}
	if err != nil {
		return capabilityProviderBinding{}, err
	}
	raw, err := json.Marshal(row.Manifest)
	if err != nil {
		return capabilityProviderBinding{}, err
	}
	var manifest plugins.Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return capabilityProviderBinding{}, err
	}
	for _, capability := range manifestProvidedCapabilities(manifest) {
		if capability.ID != capabilityID {
			continue
		}
		operation, ok := capabilityOperationByName(capability, operationName)
		if !ok {
			continue
		}
		if operation.Invocation.Mode != "revocable_mediated_grant" {
			if operation.Invocation.Mode == "" {
				return capabilityProviderBinding{}, errCapabilityProviderNotFound
			}
			return capabilityProviderBinding{}, fmt.Errorf("capability %s operation %s uses invocation mode %s; /api/v1/capability-grants only issues revocable_mediated_grant grants", capabilityID, operationName, operation.Invocation.Mode)
		}
		if operation.Invocation.Introspection != "required" || operation.Invocation.OutcomeReceipt != "required" || operation.Invocation.Idempotency != "required" {
			return capabilityProviderBinding{}, fmt.Errorf("capability %s operation %s must require introspection, outcome_receipt, and idempotency for mediated grant issuance", capabilityID, operationName)
		}
		if capability.Audit.Enforcement == "controlled_action" {
			return capabilityProviderBinding{}, errCapabilityProviderNotFound
		}
		provider := capabilityProviderBinding{
			PluginKey:      manifest.ID,
			ProviderID:     manifest.ID,
			AppID:          strings.TrimSpace(firstNonEmpty(derefString(row.AppID), manifest.AppID)),
			TrustBundleID:  strings.TrimSpace(firstNonEmpty(derefString(row.TrustBundleID), manifest.TrustBundleID)),
			Local:          capabilityLocalToManifest(manifest, capability.ID),
			Endpoint:       strings.TrimSpace(binding.Endpoint),
			OperationPath:  firstNonEmpty(derefString(binding.OperationPath), capabilityOperationPath(manifest, capabilityID, operationName)),
			Identity:       nonNilMap(binding.Identity),
			BindingEpoch:   binding.BindingEpoch,
			InvocationMode: operation.Invocation.Mode,
			GrantTTL:       time.Duration(operation.Invocation.GrantTTLMS) * time.Millisecond,
			CallGraph:      operation.CallGraph,
		}
		s.capabilityProviderCache.set(spaceID, capabilityID, operationName, provider, time.Now().UTC())
		return provider, nil
	}
	return capabilityProviderBinding{}, errCapabilityProviderNotFound
}

func (s *Server) callerPluginRequiresCapability(r *http.Request, callerPluginID, capabilityID string) (bool, error) {
	row, err := s.ent.Plugin.Query().Where(entplugin.Key(callerPluginID)).Only(r.Context())
	if coreent.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	raw, err := json.Marshal(row.Manifest)
	if err != nil {
		return false, err
	}
	var manifest plugins.Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return false, err
	}
	for _, requirement := range manifest.Requires {
		if requirement.ID == capabilityID {
			return true, nil
		}
	}
	return false, nil
}

func (s *Server) callerAllowedForProviderScope(r *http.Request, callerPluginID string, provider capabilityProviderBinding) (bool, error) {
	if !provider.Local {
		return true, nil
	}
	if callerPluginID == provider.PluginKey {
		return true, nil
	}
	caller, err := s.governedPluginManifestByKey(r.Context(), callerPluginID)
	if coreent.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return pluginsShareTrustBundle(caller, provider.TrustBundleID), nil
}

func (s *Server) pluginManifestByKey(ctx context.Context, pluginKey string) (plugins.Manifest, error) {
	governed, err := s.governedPluginManifestByKey(ctx, pluginKey)
	return governed.Manifest, err
}

func (s *Server) governedPluginManifestByKey(ctx context.Context, pluginKey string) (governedPluginManifest, error) {
	row, err := s.ent.Plugin.Query().Where(entplugin.Key(pluginKey)).Only(ctx)
	if err != nil {
		return governedPluginManifest{}, err
	}
	raw, err := json.Marshal(row.Manifest)
	if err != nil {
		return governedPluginManifest{}, err
	}
	var manifest plugins.Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return governedPluginManifest{}, err
	}
	manifestType, manifestScope, appID, trustBundleID := normalizedPluginGovernance(row, manifest)
	return governedPluginManifest{
		Manifest:      manifest,
		Type:          manifestType,
		Scope:         manifestScope,
		AppID:         appID,
		TrustBundleID: trustBundleID,
	}, nil
}

func normalizedPluginGovernance(row *coreent.Plugin, manifest plugins.Manifest) (string, string, string, string) {
	manifestType := strings.TrimSpace(manifest.Type)
	manifestScope := strings.TrimSpace(manifest.Scope)
	manifestAppID := strings.TrimSpace(manifest.AppID)
	manifestTrustBundleID := strings.TrimSpace(manifest.TrustBundleID)
	rowType := ""
	rowScope := ""
	rowAppID := ""
	rowTrustBundleID := ""
	if row != nil {
		rowType = strings.TrimSpace(row.Type)
		rowScope = strings.TrimSpace(row.Scope)
		rowAppID = strings.TrimSpace(derefString(row.AppID))
		rowTrustBundleID = strings.TrimSpace(derefString(row.TrustBundleID))
	}
	pluginType := firstNonEmpty(rowType, manifestType, "plugin")
	pluginScope := firstNonEmpty(rowScope, manifestScope, "public")
	appID := firstNonEmpty(rowAppID, manifestAppID)
	trustBundleID := firstNonEmpty(rowTrustBundleID, manifestTrustBundleID)
	if manifestType == "app_module" || manifestScope == "app" || manifestAppID != "" {
		pluginType = "app_module"
		pluginScope = "app"
		appID = manifestAppID
		if appID == "" {
			appID = rowAppID
		}
		trustBundleID = manifestTrustBundleID
		if trustBundleID == "" {
			trustBundleID = rowTrustBundleID
		}
	}
	if pluginType != "app_module" && pluginScope != "app" {
		trustBundleID = ""
	}
	return pluginType, pluginScope, appID, trustBundleID
}

func pluginsShareTrustBundle(plugin governedPluginManifest, trustBundleID string) bool {
	trustBundleID = strings.TrimSpace(trustBundleID)
	return plugin.Type == "app_module" && plugin.TrustBundleID != "" && plugin.TrustBundleID == trustBundleID
}

func capabilityOperationByName(capability plugins.CapabilityDefinition, name string) (plugins.CapabilityOperationDefinition, bool) {
	for _, operation := range capability.Operations {
		if operation.Name == name {
			return operation, true
		}
	}
	return plugins.CapabilityOperationDefinition{}, false
}

func capabilityOperationPath(manifest plugins.Manifest, capabilityID, operationName string) string {
	handler := strings.TrimSpace(operationName)
	for _, route := range manifest.Routes {
		if route.Handler == handler {
			return route.Path
		}
	}
	for _, route := range manifest.Routes {
		if strings.Contains(route.Path, strings.ReplaceAll(capabilityID, ".", "/")) || strings.Contains(route.Path, operationName) {
			return route.Path
		}
	}
	return ""
}

func (s *Server) parentGrantActive(r *http.Request, grantID, spaceID string) (*coreent.CapabilityGrant, bool, error) {
	row, err := s.ent.CapabilityGrant.Query().Where(entcapabilitygrant.ID(grantID), entcapabilitygrant.SpaceID(spaceID)).Only(r.Context())
	if coreent.IsNotFound(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return row, row.Status == "active" && row.RevokedAt == nil && row.ExpiresAt.After(time.Now().UTC()), nil
}

func (s *Server) capabilityPrincipalActive(ctx context.Context, principal capabilityGrantPrincipal, spaceID string) (bool, string, error) {
	if strings.TrimSpace(principal.UserID) == "" || strings.TrimSpace(principal.MemberID) == "" || strings.TrimSpace(principal.UserMemberID) == "" {
		return false, "principal_identity_incomplete", nil
	}
	active, err := s.spaceActive(ctx, spaceID)
	if err != nil {
		return false, "", err
	}
	if !active {
		return false, "space_not_active", nil
	}
	bindings, err := s.availableActorBindingsFiltered(ctx, principal.UserID, principal.MemberID, principal.UserMemberID)
	if err != nil {
		return false, "", err
	}
	for _, binding := range bindings {
		if stringAny(binding["space_id"]) == spaceID {
			return true, "", nil
		}
	}
	if len(bindings) == 0 {
		return false, "principal_membership_revoked", nil
	}
	return false, "principal_space_mismatch", nil
}

func (s *Server) capabilityGrantBindingActive(ctx context.Context, row *coreent.CapabilityGrant) (bool, string, error) {
	if row == nil {
		return false, "grant_not_found", nil
	}
	binding, err := s.ent.CapabilityProviderBinding.Query().Where(
		entcapabilityproviderbinding.SpaceID(row.SpaceID),
		entcapabilityproviderbinding.Capability(row.Capability),
		entcapabilityproviderbinding.Operation(row.Operation),
		entcapabilityproviderbinding.Status("active"),
	).Only(ctx)
	if coreent.IsNotFound(err) {
		return false, "provider_binding_revoked", nil
	}
	if err != nil {
		return false, "", err
	}
	if binding.ProviderPluginID != row.TargetProviderID || binding.BindingEpoch != row.BindingEpoch {
		return false, "provider_binding_stale", nil
	}
	return true, "", nil
}

func (s *Server) capabilityGrantAuthorizationActive(r *http.Request, row *coreent.CapabilityGrant) (bool, string, error) {
	if row == nil {
		return false, "grant_not_found", nil
	}
	resource := mapFromAny(nonNilMap(row.Metadata)["resource"])
	if len(resource) == 0 {
		return false, "grant_authorization_context_missing", nil
	}
	authorizationContext, err := capabilityGrantAuthorizationContextFromResource(resource)
	if err != nil {
		return false, "grant_authorization_context_invalid", nil
	}
	decision, err := s.authorizeCapabilityGrantPrincipal(r, capabilityGrantRequest{
		SpaceID:   row.SpaceID,
		Principal: capabilityGrantPrincipal{UserID: derefString(row.PrincipalUserID), MemberID: derefString(row.PrincipalMemberID), UserMemberID: derefString(row.PrincipalUserMemberID)},
	}, authorizationContext)
	if err != nil {
		return false, "", err
	}
	if decision == nil || !decision.IsAllowed() {
		return false, "principal_authorization_revoked", nil
	}
	return true, "", nil
}

func (s *Server) validateCapabilityCallGraph(r *http.Request, req capabilityGrantRequest, provider capabilityProviderBinding) error {
	if len(provider.CallGraph.AllowedCallers) > 0 {
		allowed, err := s.callerAllowedByCallGraph(r, req.Executor.PluginID, provider.CallGraph.AllowedCallers)
		if err != nil {
			return err
		}
		if !allowed {
			return fmt.Errorf("caller %s is not allowed by target call graph", req.Executor.PluginID)
		}
	}
	if req.ParentGrantID == "" {
		if principal, ok := adminPrincipalFrom(r); ok && principal.CredentialType == "api_key" && apiKeyProviderRuntimeID(principal.APIKey) != "" {
			return errors.New("provider-runtime capability calls require parent_grant_id for Core-tracked lineage")
		}
		return nil
	}
	parent, active, err := s.parentGrantActive(r, req.ParentGrantID, req.SpaceID)
	if err != nil {
		return fmt.Errorf("validate parent grant: %w", err)
	}
	if !active {
		return errors.New("parent grant is not active for this Space")
	}
	if parent != nil && parent.TargetProviderID != req.Executor.PluginID {
		return fmt.Errorf("parent grant target provider %s does not match executor %s", parent.TargetProviderID, req.Executor.PluginID)
	}
	if parent != nil && parent.TargetProviderID == provider.ProviderID && !provider.CallGraph.Reentrant {
		return fmt.Errorf("reentrant call to provider %s is not allowed", provider.ProviderID)
	}
	depth, err := s.capabilityGrantLineageDepth(r.Context(), req.ParentGrantID, req.SpaceID)
	if err != nil {
		return fmt.Errorf("compute grant lineage depth: %w", err)
	}
	maxDepth := provider.CallGraph.MaxDepth
	if maxDepth == 0 {
		maxDepth = 4
	}
	if depth+1 > maxDepth {
		return fmt.Errorf("call graph depth %d exceeds max_depth %d", depth+1, maxDepth)
	}
	return nil
}

func (s *Server) callerAllowedByCallGraph(r *http.Request, callerPluginID string, allowedCallers []string) (bool, error) {
	allowed := map[string]struct{}{}
	for _, value := range allowedCallers {
		value = strings.TrimSpace(value)
		if value != "" {
			allowed[value] = struct{}{}
		}
	}
	row, err := s.ent.Plugin.Query().Where(entplugin.Key(callerPluginID)).Only(r.Context())
	if coreent.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	raw, err := json.Marshal(row.Manifest)
	if err != nil {
		return false, err
	}
	var manifest plugins.Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return false, err
	}
	for _, capability := range manifestProvidedCapabilities(manifest) {
		if _, ok := allowed[capability.ID]; ok {
			return true, nil
		}
	}
	return false, nil
}

func manifestProvidedCapabilities(manifest plugins.Manifest) []plugins.CapabilityDefinition {
	if len(manifest.LocalCapabilities) == 0 {
		return manifest.Capabilities
	}
	capabilities := make([]plugins.CapabilityDefinition, 0, len(manifest.Capabilities)+len(manifest.LocalCapabilities))
	capabilities = append(capabilities, manifest.Capabilities...)
	capabilities = append(capabilities, manifest.LocalCapabilities...)
	return capabilities
}

func pluginManifestFromMap(values map[string]any) plugins.Manifest {
	if values == nil {
		return plugins.Manifest{}
	}
	raw, err := json.Marshal(values)
	if err != nil {
		return plugins.Manifest{}
	}
	var manifest plugins.Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return plugins.Manifest{}
	}
	return manifest
}

func capabilityLocalToManifest(manifest plugins.Manifest, capabilityID string) bool {
	for _, capability := range manifest.LocalCapabilities {
		if capability.ID == capabilityID {
			return true
		}
	}
	return false
}

func (s *Server) capabilityGrantLineageDepth(ctx context.Context, grantID, spaceID string) (int, error) {
	depth := 0
	seen := map[string]struct{}{}
	current := strings.TrimSpace(grantID)
	for current != "" {
		if _, ok := seen[current]; ok {
			return depth, errors.New("cycle detected in parent grant lineage")
		}
		seen[current] = struct{}{}
		row, err := s.ent.CapabilityGrant.Query().Where(entcapabilitygrant.ID(current), entcapabilitygrant.SpaceID(spaceID)).Only(ctx)
		if coreent.IsNotFound(err) {
			return depth, errors.New("parent grant lineage is incomplete")
		}
		if err != nil {
			return depth, err
		}
		depth++
		current = derefString(row.ParentGrantID)
		if depth > 64 {
			return depth, errors.New("parent grant lineage exceeds safety limit")
		}
	}
	return depth, nil
}

func (s *Server) requireCapabilityGrantPermission(w http.ResponseWriter, r *http.Request, permissionKey, spaceID string) bool {
	principal, ok := adminPrincipalFrom(r)
	if !ok {
		writeError(w, r, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED", "A valid access token or API key is required.", nil)
		return false
	}
	allowed, err := s.adminPrincipalAllows(r.Context(), principal, adminRequirement{
		PermissionKey: permissionKey,
		SpaceID:       spaceID,
	})
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to evaluate capability grant permission.", err.Error())
		return false
	}
	if !allowed {
		writeError(w, r, http.StatusForbidden, "ADMIN_PERMISSION_REQUIRED", "The current credential cannot use capability grants for this Space.", map[string]any{"permission": permissionKey})
		return false
	}
	return true
}

func (s *Server) requireProviderRuntimePrincipal(w http.ResponseWriter, r *http.Request, targetProviderID string) bool {
	principal, ok := adminPrincipalFrom(r)
	if !ok {
		writeError(w, r, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED", "A valid provider runtime API key is required.", nil)
		return false
	}
	if principal.CredentialType != "api_key" {
		writeError(w, r, http.StatusForbidden, "CAPABILITY_PROVIDER_IDENTITY_REQUIRED", "Capability provider runtime calls require a provider-bound API key.", map[string]any{"target_provider_id": targetProviderID})
		return false
	}
	providerID := apiKeyProviderRuntimeID(principal.APIKey)
	if providerID == "" || providerID != targetProviderID {
		writeError(w, r, http.StatusForbidden, "CAPABILITY_PROVIDER_IDENTITY_REQUIRED", "API key is not bound to the target capability provider.", map[string]any{
			"target_provider_id": targetProviderID,
			"api_key_provider":   providerID,
		})
		return false
	}
	active, err := s.providerRuntimePluginActive(r.Context(), providerID)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to validate capability provider runtime status.", err.Error())
		return false
	}
	if !active {
		writeError(w, r, http.StatusForbidden, "CAPABILITY_PROVIDER_INACTIVE", "Capability provider runtime is not enabled.", map[string]any{
			"target_provider_id": targetProviderID,
			"api_key_provider":   providerID,
		})
		return false
	}
	return true
}

func providerRuntimePrincipalID(r *http.Request) string {
	principal, ok := adminPrincipalFrom(r)
	if !ok || principal.CredentialType != "api_key" {
		return ""
	}
	return apiKeyProviderRuntimeID(principal.APIKey)
}

func apiKeyProviderRuntimeID(key *coreent.ApiKey) string {
	if key == nil {
		return ""
	}
	return strings.TrimSpace(derefString(key.ProviderRuntimePluginID))
}

func capabilityGrantActive(row *coreent.CapabilityGrant, targetProviderID, capabilityID, operationName string, now time.Time) (bool, string) {
	if row == nil {
		return false, "grant_not_found"
	}
	if row.TargetProviderID != targetProviderID || row.Capability != capabilityID || row.Operation != operationName {
		return false, "grant_audience_mismatch"
	}
	if row.RevokedAt != nil || row.Status == "revoked" {
		return false, "grant_revoked"
	}
	if row.Status != "active" {
		return false, "grant_inactive"
	}
	if !row.ExpiresAt.After(now.UTC()) {
		return false, "grant_expired"
	}
	return true, ""
}

func validCapabilityOutcomeStatus(status string) bool {
	switch strings.TrimSpace(status) {
	case "succeeded", "failed", "result_unknown", "missing":
		return true
	default:
		return false
	}
}

func newCapabilityGrantToken() (string, error) {
	secret, err := newToken("")
	if err != nil {
		return "", err
	}
	return capabilityGrantBearerPrefix + secret, nil
}

func capabilityGrantTokenHash(token string) string {
	hashes := capabilityGrantTokenHashesForLookup(token)
	if len(hashes) == 0 {
		return ""
	}
	return hashes[0]
}

func capabilityGrantTokenHashesForLookup(token string) []string {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil
	}
	secrets := capabilityGrantSecrets()
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

func capabilityGrantSecrets() []string {
	primary := strings.TrimSpace(firstEnv("PLYSTRA_CAPABILITY_GRANT_SECRET", "PLYSTRA_SESSION_SECRET"))
	if primary == "" {
		return nil
	}
	secrets := []string{primary}
	for _, key := range []string{"PLYSTRA_CAPABILITY_GRANT_SECRET_PREVIOUS", "PLYSTRA_SESSION_SECRET_PREVIOUS"} {
		for _, value := range strings.Split(osEnv(key), ",") {
			value = strings.TrimSpace(value)
			if value != "" {
				secrets = append(secrets, value)
			}
		}
	}
	return secrets
}

func capabilityGrantIssuedMap(row *coreent.CapabilityGrant, token string, provider capabilityProviderBinding) map[string]any {
	out := capabilityGrantMap(row)
	if token != "" {
		out["grant"] = token
	}
	identity := nonNilMap(provider.Identity)
	if len(identity) == 0 {
		identity["provider_id"] = provider.ProviderID
	}
	out["target"] = map[string]any{
		"provider_id":   provider.ProviderID,
		"endpoint":      provider.Endpoint,
		"operation_url": provider.OperationPath,
		"identity":      identity,
	}
	return out
}

func capabilityGrantMap(row *coreent.CapabilityGrant) map[string]any {
	return map[string]any{
		"grant_id":                 row.ID,
		"space_id":                 row.SpaceID,
		"capability":               row.Capability,
		"operation":                row.Operation,
		"principal_user_id":        derefString(row.PrincipalUserID),
		"principal_member_id":      derefString(row.PrincipalMemberID),
		"principal_user_member_id": derefString(row.PrincipalUserMemberID),
		"caller_plugin_id":         row.CallerPluginID,
		"target_provider_id":       row.TargetProviderID,
		"parent_grant_id":          derefString(row.ParentGrantID),
		"decision_id":              derefString(row.DecisionID),
		"correlation_id":           row.CorrelationID,
		"idempotency_key":          row.IdempotencyKey,
		"target_idempotency_key":   row.TargetIdempotencyKey,
		"binding_epoch":            row.BindingEpoch,
		"status":                   row.Status,
		"outcome_status":           row.OutcomeStatus,
		"expected_outcome_by":      formatTime(row.ExpectedOutcomeBy),
		"expires_at":               formatTime(row.ExpiresAt),
		"revoked_at":               optionalTime(row.RevokedAt),
		"revoked_reason":           derefString(row.RevokedReason),
		"metadata":                 nonNilMap(row.Metadata),
		"created_at":               formatTime(row.CreatedAt),
		"updated_at":               formatTime(row.UpdatedAt),
	}
}

func (s *Server) recordCapabilityGrantAudit(r *http.Request, row *coreent.CapabilityGrant, action, reason string) {
	if row == nil || s.ent == nil {
		return
	}
	actor := authzActorFromCapabilityGrant(row)
	trace := map[string]any{
		"trace_version": traceVersion(),
		"decision":      "allow",
		"reason":        reason,
		"request_id":    requestIDFrom(r),
		"capability":    row.Capability,
		"operation":     row.Operation,
		"caller_plugin": row.CallerPluginID,
		"target":        row.TargetProviderID,
		"grant_id":      row.ID,
		"created_at":    time.Now().UTC().Format(time.RFC3339),
	}
	_, _ = s.ent.AuditLog.Create().
		SetID(newEntityID("audit")).
		SetSpaceID(row.SpaceID).
		SetNillableActorUserID(optionalString(actor.UserID)).
		SetNillableActorMemberID(optionalString(actor.MemberID)).
		SetNillableActorUserMemberID(optionalString(actor.UserMemberID)).
		SetAction(action).
		SetResourceType("capability_grant").
		SetResourceID(row.ID).
		SetDecision("allow").
		SetTrace(trace).
		SetNillableRequestID(optionalString(requestIDFrom(r))).
		SetNillableIPAddress(optionalString(remoteIPFrom(r))).
		SetNillableUserAgent(optionalString(r.UserAgent())).
		Save(r.Context())
}

func authzActorFromCapabilityGrant(row *coreent.CapabilityGrant) authz.ActorContext {
	return authz.ActorContext{
		UserID:       derefString(row.PrincipalUserID),
		MemberID:     derefString(row.PrincipalMemberID),
		UserMemberID: derefString(row.PrincipalUserMemberID),
		SpaceID:      row.SpaceID,
	}
}

func pluginsCapabilityIDValid(value string) bool {
	parts := strings.Split(strings.TrimSpace(value), ".")
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, r := range part {
			switch {
			case r >= 'a' && r <= 'z':
			case r >= '0' && r <= '9':
			case r == '_':
			default:
				return false
			}
		}
	}
	return true
}
