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
	"time"

	coreent "github.com/plystra/core/ent"
	entcapabilitygrant "github.com/plystra/core/ent/capabilitygrant"
	entplugin "github.com/plystra/core/ent/plugin"
	entpluginsettingsvalue "github.com/plystra/core/ent/pluginsettingsvalue"
	"github.com/plystra/core/internal/authz"
	"github.com/plystra/core/internal/plugins"
)

const (
	capabilityGrantBearerPrefix = "ply_grant_"
	defaultCapabilityGrantTTL   = 30 * time.Second
	maxCapabilityGrantTTL       = 5 * time.Minute
)

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
	Status               string         `json:"status"`
	ResultRef            map[string]any `json:"result_ref"`
	Events               []any          `json:"events"`
	FinishedAt           *time.Time     `json:"finished_at"`
	OutcomeEventID       string         `json:"outcome_event_id"`
	Metadata             map[string]any `json:"metadata"`
}

type capabilityProviderBinding struct {
	PluginKey      string
	ProviderID     string
	AppID          string
	Local          bool
	Endpoint       string
	OperationPath  string
	BindingEpoch   int
	InvocationMode string
	GrantTTL       time.Duration
	CallGraph      plugins.CapabilityCallGraphDefinition
}

type governedPluginManifest struct {
	Manifest plugins.Manifest
	Type     string
	Scope    string
	AppID    string
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
	provider, err := s.resolveCapabilityProvider(r, req.Capability, req.Operation)
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
		// Revocation must be durable: an idempotent re-request must never
		// resurrect a grant Core deliberately revoked. The caller needs a fresh
		// idempotency key (and will be re-authorized) to obtain a new grant.
		if existing.RevokedAt != nil || existing.Status == "revoked" {
			writeError(w, r, http.StatusConflict, "CAPABILITY_GRANT_REVOKED", "This idempotency key maps to a revoked grant; request a new grant with a fresh idempotency key.", map[string]any{
				"grant_id":       existing.ID,
				"revoked_reason": derefString(existing.RevokedReason),
			})
			return
		}
		grantToken, tokenErr := newCapabilityGrantToken()
		if tokenErr != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to reissue capability grant token.", tokenErr.Error())
			return
		}
		now := time.Now().UTC()
		ttl := req.grantTTL(provider.GrantTTL)
		existing, err = client.CapabilityGrant.UpdateOneID(existing.ID).
			SetTokenHash(capabilityGrantTokenHash(grantToken)).
			SetStatus("active").
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
		SetNillableDecisionID(optionalString(newEntityID("dec"))).
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
	if ok := s.requireCapabilityGrantPermission(w, r, "capabilities:manage", row.SpaceID); !ok {
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
	req.Status = strings.TrimSpace(req.Status)
	if req.GrantID == "" || req.TargetIdempotencyKey == "" || !validCapabilityOutcomeStatus(req.Status) {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "grant_id, target_idempotency_key, and a valid status are required.", nil)
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
	if ok := s.requireCapabilityGrantPermission(w, r, "capabilities:manage", row.SpaceID); !ok {
		return
	}
	metadata := nonNilMap(row.Metadata)
	outcome := map[string]any{
		"status":           req.Status,
		"result_ref":       nonNilMap(req.ResultRef),
		"events":           req.Events,
		"outcome_event_id": strings.TrimSpace(req.OutcomeEventID),
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

var errCapabilityProviderNotFound = errors.New("capability provider not found")

func (s *Server) resolveCapabilityProvider(r *http.Request, capabilityID, operationName string) (capabilityProviderBinding, error) {
	spaceID := strings.TrimSpace(r.URL.Query().Get("space_id"))
	rows, err := s.ent.Plugin.Query().Where(entplugin.Status("enabled")).All(r.Context())
	if err != nil {
		return capabilityProviderBinding{}, err
	}
	for _, row := range rows {
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
			if operation.Invocation.Mode == "brokered_action_gateway" {
				return capabilityProviderBinding{}, fmt.Errorf("capability %s operation %s requires Action Gateway, not mediated grant issuance", capabilityID, operationName)
			}
			if operation.Invocation.Mode != "revocable_mediated_grant" && operation.Invocation.Mode != "ephemeral_signed_grant" && operation.Invocation.Mode != "query" {
				continue
			}
			provider := capabilityProviderBinding{
				PluginKey:      manifest.ID,
				ProviderID:     manifest.ID,
				AppID:          strings.TrimSpace(firstNonEmpty(derefString(row.AppID), manifest.AppID)),
				Local:          capabilityLocalToManifest(manifest, capability.ID),
				Endpoint:       s.providerEndpointSetting(r, row.ID, manifest.Runtime.EndpointSettingKey),
				OperationPath:  capabilityOperationPath(manifest, capabilityID, operationName),
				BindingEpoch:   s.providerBindingEpoch(r, row.ID, spaceID),
				InvocationMode: operation.Invocation.Mode,
				GrantTTL:       time.Duration(operation.Invocation.GrantTTLMS) * time.Millisecond,
				CallGraph:      operation.CallGraph,
			}
			if spaceID != "" {
				if endpoint := s.providerEndpointSettingForSpace(r, row.ID, manifest.Runtime.EndpointSettingKey, spaceID); endpoint != "" {
					provider.Endpoint = endpoint
				}
			}
			return provider, nil
		}
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
	return caller.Type == "app_module" && caller.AppID != "" && caller.AppID == provider.AppID, nil
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
	manifestType, manifestScope, appID := normalizedPluginGovernance(row, manifest)
	return governedPluginManifest{
		Manifest: manifest,
		Type:     manifestType,
		Scope:    manifestScope,
		AppID:    appID,
	}, nil
}

func normalizedPluginGovernance(row *coreent.Plugin, manifest plugins.Manifest) (string, string, string) {
	manifestType := strings.TrimSpace(manifest.Type)
	manifestScope := strings.TrimSpace(manifest.Scope)
	manifestAppID := strings.TrimSpace(manifest.AppID)
	rowType := ""
	rowScope := ""
	rowAppID := ""
	if row != nil {
		rowType = strings.TrimSpace(row.Type)
		rowScope = strings.TrimSpace(row.Scope)
		rowAppID = strings.TrimSpace(derefString(row.AppID))
	}
	pluginType := firstNonEmpty(rowType, manifestType, "plugin")
	pluginScope := firstNonEmpty(rowScope, manifestScope, "public")
	appID := firstNonEmpty(rowAppID, manifestAppID)
	if manifestType == "app_module" || manifestScope == "app" || manifestAppID != "" {
		pluginType = "app_module"
		pluginScope = "app"
		appID = manifestAppID
		if appID == "" {
			appID = rowAppID
		}
	}
	return pluginType, pluginScope, appID
}

func (s *Server) providerEndpointSetting(r *http.Request, pluginID, settingKey string) string {
	return s.providerEndpointSettingForSpace(r, pluginID, settingKey, "")
}

func (s *Server) providerEndpointSettingForSpace(r *http.Request, pluginID, settingKey, spaceID string) string {
	settingKey = strings.TrimSpace(settingKey)
	if settingKey == "" {
		return ""
	}
	definition, valueSpaceID, err := s.resolvePluginSettingDefinition(r.Context(), pluginID, settingKey, spaceID)
	if err != nil {
		if strings.TrimSpace(spaceID) == "" {
			return ""
		}
		definition, valueSpaceID, err = s.resolvePluginSettingDefinition(r.Context(), pluginID, settingKey, "")
		if err != nil {
			return ""
		}
	}
	value := definition.DefaultValue
	settingValue, err := s.ent.PluginSettingsValue.Query().
		Where(entpluginsettingsvalue.PluginID(pluginID), entpluginsettingsvalue.Key(settingKey), entpluginsettingsvalue.SpaceID(valueSpaceID)).
		Only(r.Context())
	if err == nil && settingValue != nil {
		value = settingValue.Value
	}
	return stringFromMap(value, "value")
}

func (s *Server) providerBindingEpoch(r *http.Request, pluginID, spaceID string) int {
	for _, key := range []string{"provider.binding_epoch", "binding_epoch"} {
		value := s.providerEndpointSettingForSpace(r, pluginID, key, spaceID)
		if epoch, ok := parsePositiveInt(value); ok {
			return epoch
		}
	}
	return 1
}

func parsePositiveInt(value string) (int, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	n := 0
	for _, r := range value {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int(r-'0')
		if n <= 0 {
			return 0, false
		}
	}
	return n, n > 0
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
		return nil
	}
	parent, active, err := s.parentGrantActive(r, req.ParentGrantID, req.SpaceID)
	if err != nil {
		return fmt.Errorf("validate parent grant: %w", err)
	}
	if !active {
		return errors.New("parent grant is not active for this Space")
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
	if row.Status != "active" && row.Status != "used" {
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
	out["target"] = map[string]any{
		"provider_id":   provider.ProviderID,
		"endpoint":      provider.Endpoint,
		"operation_url": provider.OperationPath,
		"identity": map[string]any{
			"provider_id": provider.ProviderID,
		},
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
