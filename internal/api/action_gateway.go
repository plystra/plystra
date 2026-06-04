package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	coreent "github.com/plystra/core/ent"
	entactionexecution "github.com/plystra/core/ent/actionexecution"
	entplugin "github.com/plystra/core/ent/plugin"
)

// actionGatewayIdempotencyRetention is the v0 minimum window during which a
// repeated idempotency key resolves to the same action execution
// (technical-architecture.en.md §II.3 C2: idempotency retention >= 24h).
const actionGatewayIdempotencyRetention = 24 * time.Hour

const maxActionHandlerResponseBytes = 1 << 20

// errActionNotBrokered means the capability operation exists but is not a
// controlled_action (brokered_action_gateway) operation, so it must not be
// invoked through the Action Gateway.
var errActionNotBrokered = errors.New("capability operation is not a controlled action")

type actionGatewayRequest struct {
	SpaceID        string                   `json:"space_id"`
	Capability     string                   `json:"capability"`
	Operation      string                   `json:"operation"`
	Principal      capabilityGrantPrincipal `json:"principal"`
	Executor       capabilityGrantExecutor  `json:"executor"`
	Resource       map[string]any           `json:"resource"`
	Input          map[string]any           `json:"input"`
	IdempotencyKey string                   `json:"idempotency_key"`
	CorrelationID  string                   `json:"correlation_id"`
	ParentGrantID  string                   `json:"parent_grant_id"`
	Metadata       map[string]any           `json:"metadata"`
}

func (req *actionGatewayRequest) normalize() {
	req.SpaceID = strings.TrimSpace(req.SpaceID)
	req.Capability = strings.TrimSpace(req.Capability)
	req.Operation = strings.TrimSpace(req.Operation)
	req.Principal.UserID = strings.TrimSpace(req.Principal.UserID)
	req.Principal.MemberID = strings.TrimSpace(req.Principal.MemberID)
	req.Principal.UserMemberID = strings.TrimSpace(req.Principal.UserMemberID)
	req.Executor.PluginID = strings.TrimSpace(req.Executor.PluginID)
	req.IdempotencyKey = strings.TrimSpace(req.IdempotencyKey)
	req.CorrelationID = strings.TrimSpace(req.CorrelationID)
	req.ParentGrantID = strings.TrimSpace(req.ParentGrantID)
}

func validateActionGatewayRequest(req actionGatewayRequest) error {
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
	}
	for field, value := range map[string]map[string]any{
		"action_gateway.resource": nonNilMap(req.Resource),
		"action_gateway.input":    nonNilMap(req.Input),
		"action_gateway.metadata": nonNilMap(req.Metadata),
	} {
		if err := validateGovernedJSONValue(field, value, governedJSONPolicy{MaxBytes: maxPluginSettingValueBytes, RejectSecrets: true}); err != nil {
			return err
		}
	}
	return nil
}

// actionHandlerResponse is the contract a controlled_action handler returns
// (product-spec §14.6).
type actionHandlerResponse struct {
	OK            bool           `json:"ok"`
	Reason        string         `json:"reason"`
	BusinessEvent map[string]any `json:"business_event"`
	ResultRef     map[string]any `json:"result_ref"`
}

func (s *Server) handleActionGateway(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, r)
		return
	}
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	var req actionGatewayRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.normalize()
	if err := validateActionGatewayRequest(req); err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Action gateway request is invalid.", err.Error())
		return
	}
	if ok := s.requireCapabilityGrantPermission(w, r, "capabilities:invoke", req.SpaceID); !ok {
		return
	}

	provider, timeoutMS, err := s.resolveActionGatewayProvider(r, req.Capability, req.Operation)
	if errors.Is(err, errCapabilityProviderNotFound) {
		writeError(w, r, http.StatusNotFound, "CAPABILITY_PROVIDER_NOT_FOUND", "No enabled provider is installed for this controlled action.", nil)
		return
	}
	if errors.Is(err, errActionNotBrokered) {
		writeError(w, r, http.StatusUnprocessableEntity, "ACTION_NOT_CONTROLLED", "This capability operation is not a controlled action; use the mediated capability-grants endpoint instead.", map[string]any{
			"capability": req.Capability,
			"operation":  req.Operation,
		})
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to resolve controlled action provider.", err.Error())
		return
	}

	if !s.authorizeActionGateway(w, r, req, provider) {
		return
	}

	now := time.Now().UTC()
	existing, err := client.ActionExecution.Query().Where(
		entactionexecution.SpaceID(req.SpaceID),
		entactionexecution.Capability(req.Capability),
		entactionexecution.Operation(req.Operation),
		entactionexecution.IdempotencyKey(req.IdempotencyKey),
	).Only(r.Context())
	if err != nil && !coreent.IsNotFound(err) {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to check action idempotency.", err.Error())
		return
	}
	if err == nil && existing.IdempotencyExpiresAt.After(now) {
		// In-window duplicate resolves to the same action execution.
		writeData(w, r, http.StatusOK, actionExecutionMap(existing))
		return
	}

	decisionID := newEntityID("dec")
	correlationID := firstNonEmpty(req.CorrelationID, newEntityID("cor"))
	metadata := nonNilMap(req.Metadata)
	metadata["resource"] = nonNilMap(req.Resource)

	row, err := s.upsertActionExecution(r.Context(), client, existing, req, provider, decisionID, correlationID, metadata, now)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "ACTION_EXECUTION_CREATE_FAILED", "Failed to record action execution.", err.Error())
		return
	}
	s.recordActionExecutionAudit(r, row, "action_gateway.authorization_decision", "Action authorized; execution attempting")

	handlerResp, status := s.invokeActionHandler(r.Context(), provider, req, row.ID, decisionID, correlationID, timeoutMS)

	resultMeta := nonNilMap(row.Metadata)
	if handlerResp != nil {
		if len(handlerResp.BusinessEvent) > 0 {
			resultMeta["business_event"] = handlerResp.BusinessEvent
		}
		if len(handlerResp.ResultRef) > 0 {
			resultMeta["result_ref"] = handlerResp.ResultRef
		}
		if strings.TrimSpace(handlerResp.Reason) != "" {
			resultMeta["reason"] = handlerResp.Reason
		}
	}
	updated, err := client.ActionExecution.UpdateOneID(row.ID).SetStatus(status).SetMetadata(resultMeta).Save(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to record action execution result.", err.Error())
		return
	}

	s.recordActionExecutionAudit(r, updated, "action_gateway.execution", "Action execution "+status)
	if status == "succeeded" && handlerResp != nil && len(handlerResp.BusinessEvent) > 0 {
		s.recordActionExecutionAudit(r, updated, "business_event", businessEventType(handlerResp.BusinessEvent))
	}

	out := actionExecutionMap(updated)
	if status == "result_unknown" {
		out["reconciliation_required"] = true
	}
	writeData(w, r, http.StatusOK, out)
}

// authorizeActionGateway enforces the AND chain (principal AND caller-requires
// AND caller-scope AND call-graph), writing the appropriate 403 and returning
// false when any leg fails.
func (s *Server) authorizeActionGateway(w http.ResponseWriter, r *http.Request, req actionGatewayRequest, provider capabilityProviderBinding) bool {
	allowed, err := s.callerPluginRequiresCapability(r, req.Executor.PluginID, req.Capability)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to validate caller capability requirement.", err.Error())
		return false
	}
	if !allowed {
		writeError(w, r, http.StatusForbidden, "CAPABILITY_REQUIREMENT_MISSING", "Caller plugin does not declare this required capability.", map[string]any{
			"caller_plugin_id": req.Executor.PluginID,
			"capability":       req.Capability,
		})
		return false
	}
	if ok, err := s.callerAllowedForProviderScope(r, req.Executor.PluginID, provider); err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to validate caller provider scope.", err.Error())
		return false
	} else if !ok {
		writeError(w, r, http.StatusForbidden, "CAPABILITY_SCOPE_DENIED", "Caller plugin is outside the target capability scope.", map[string]any{
			"caller_plugin_id": req.Executor.PluginID,
			"capability":       req.Capability,
		})
		return false
	}
	if active, reason, err := s.capabilityPrincipalActive(r.Context(), req.Principal, req.SpaceID); err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to validate action principal.", err.Error())
		return false
	} else if !active {
		writeError(w, r, http.StatusForbidden, "CAPABILITY_PRINCIPAL_INACTIVE", "Action principal is not active for this Space.", map[string]any{"reason": reason})
		return false
	}
	callGraphReq := capabilityGrantRequest{
		SpaceID:       req.SpaceID,
		Capability:    req.Capability,
		Operation:     req.Operation,
		Executor:      req.Executor,
		ParentGrantID: req.ParentGrantID,
	}
	if err := s.validateCapabilityCallGraph(r, callGraphReq, provider); err != nil {
		writeError(w, r, http.StatusForbidden, "CAPABILITY_CALL_GRAPH_DENIED", "Capability call graph policy denied the action.", err.Error())
		return false
	}
	return true
}

func (s *Server) upsertActionExecution(ctx context.Context, client *coreent.Client, existing *coreent.ActionExecution, req actionGatewayRequest, provider capabilityProviderBinding, decisionID, correlationID string, metadata map[string]any, now time.Time) (*coreent.ActionExecution, error) {
	idempotencyExpiry := now.Add(actionGatewayIdempotencyRetention)
	if existing != nil {
		// The previous execution's idempotency window lapsed; reuse the row for a
		// fresh attempt (post-expiry retries may be treated as new executions).
		return client.ActionExecution.UpdateOneID(existing.ID).
			SetStatus("invoking").
			SetNillableDecisionID(optionalString(decisionID)).
			SetCorrelationID(correlationID).
			SetNillableHandlerEndpoint(optionalString(provider.Endpoint)).
			SetIdempotencyExpiresAt(idempotencyExpiry).
			SetMetadata(metadata).
			Save(ctx)
	}
	return client.ActionExecution.Create().
		SetID(newEntityID("act")).
		SetSpaceID(req.SpaceID).
		SetCapability(req.Capability).
		SetOperation(req.Operation).
		SetNillablePrincipalUserID(optionalString(req.Principal.UserID)).
		SetNillablePrincipalMemberID(optionalString(req.Principal.MemberID)).
		SetNillablePrincipalUserMemberID(optionalString(req.Principal.UserMemberID)).
		SetCallerPluginID(req.Executor.PluginID).
		SetTargetProviderID(provider.ProviderID).
		SetNillableParentGrantID(optionalString(req.ParentGrantID)).
		SetNillableDecisionID(optionalString(decisionID)).
		SetCorrelationID(correlationID).
		SetIdempotencyKey(req.IdempotencyKey).
		SetNillableHandlerEndpoint(optionalString(provider.Endpoint)).
		SetStatus("invoking").
		SetIdempotencyExpiresAt(idempotencyExpiry).
		SetMetadata(metadata).
		Save(ctx)
}

// invokeActionHandler signs and POSTs the action to the provider's handler and
// classifies the outcome. A transport error or timeout yields result_unknown
// (completion cannot be determined); a 5xx yields failed; a non-ok body or 4xx
// yields rejected; a 2xx with ok=true yields succeeded.
func (s *Server) invokeActionHandler(ctx context.Context, provider capabilityProviderBinding, req actionGatewayRequest, actionExecutionID, decisionID, correlationID string, timeoutMS int) (*actionHandlerResponse, string) {
	endpoint := strings.TrimSpace(provider.Endpoint)
	if endpoint == "" {
		return &actionHandlerResponse{Reason: "handler endpoint is not configured"}, "failed"
	}
	url := strings.TrimRight(endpoint, "/") + provider.OperationPath
	payload := map[string]any{
		"action":   req.Operation,
		"resource": nonNilMap(req.Resource),
		"actor": map[string]any{
			"user_id":        req.Principal.UserID,
			"member_id":      req.Principal.MemberID,
			"user_member_id": req.Principal.UserMemberID,
			"space_id":       req.SpaceID,
		},
		"authorization": map[string]any{"decision_id": decisionID, "allow": true},
		"input":         nonNilMap(req.Input),
		"request": map[string]any{
			"correlation_id":      correlationID,
			"idempotency_key":     req.IdempotencyKey,
			"action_execution_id": actionExecutionID,
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return &actionHandlerResponse{Reason: "failed to encode handler payload"}, "failed"
	}
	timeout := time.Duration(timeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return &actionHandlerResponse{Reason: "failed to build handler request"}, "failed"
	}
	timestamp := strconv.FormatInt(time.Now().UTC().Unix(), 10)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Plystra-Action-Execution-Id", actionExecutionID)
	httpReq.Header.Set("X-Plystra-Timestamp", timestamp)
	if signature := signActionRequest(timestamp, body); signature != "" {
		httpReq.Header.Set("X-Plystra-Signature", signature)
	}
	resp, err := (&http.Client{Timeout: timeout}).Do(httpReq)
	if err != nil {
		// We cannot tell whether the handler completed the business action.
		return &actionHandlerResponse{Reason: err.Error()}, "result_unknown"
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxActionHandlerResponseBytes))
	parsed := actionHandlerResponse{}
	_ = json.Unmarshal(respBody, &parsed)
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		if parsed.OK {
			return &parsed, "succeeded"
		}
		return &parsed, "rejected"
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		return &parsed, "rejected"
	default:
		return &parsed, "failed"
	}
}

func signActionRequest(timestamp string, body []byte) string {
	secrets := capabilityGrantSecrets()
	if len(secrets) == 0 {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(secrets[0]))
	_, _ = mac.Write([]byte(timestamp))
	_, _ = mac.Write([]byte("."))
	_, _ = mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *Server) resolveActionGatewayProvider(r *http.Request, capabilityID, operationName string) (capabilityProviderBinding, int, error) {
	spaceID := strings.TrimSpace(r.URL.Query().Get("space_id"))
	rows, err := s.ent.Plugin.Query().Where(entplugin.Status("enabled")).All(r.Context())
	if err != nil {
		return capabilityProviderBinding{}, 0, err
	}
	for _, row := range rows {
		manifest := pluginManifestFromMap(row.Manifest)
		for _, capability := range manifestProvidedCapabilities(manifest) {
			if capability.ID != capabilityID {
				continue
			}
			operation, ok := capabilityOperationByName(capability, operationName)
			if !ok {
				continue
			}
			if operation.Invocation.Mode != "brokered_action_gateway" {
				return capabilityProviderBinding{}, 0, errActionNotBrokered
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
				CallGraph:      operation.CallGraph,
			}
			if spaceID != "" {
				if endpoint := s.providerEndpointSettingForSpace(r, row.ID, manifest.Runtime.EndpointSettingKey, spaceID); endpoint != "" {
					provider.Endpoint = endpoint
				}
			}
			return provider, operation.Invocation.TimeoutMS, nil
		}
	}
	return capabilityProviderBinding{}, 0, errCapabilityProviderNotFound
}

func businessEventType(event map[string]any) string {
	if event == nil {
		return "business event recorded"
	}
	if value, ok := event["type"].(string); ok && strings.TrimSpace(value) != "" {
		return value
	}
	return "business event recorded"
}

func actionExecutionMap(row *coreent.ActionExecution) map[string]any {
	return map[string]any{
		"action_execution_id": row.ID,
		"space_id":            row.SpaceID,
		"capability":          row.Capability,
		"operation":           row.Operation,
		"principal_user_id":   derefString(row.PrincipalUserID),
		"principal_member_id": derefString(row.PrincipalMemberID),
		"caller_plugin_id":    row.CallerPluginID,
		"target_provider_id":  row.TargetProviderID,
		"parent_grant_id":     derefString(row.ParentGrantID),
		"decision_id":         derefString(row.DecisionID),
		"correlation_id":      row.CorrelationID,
		"idempotency_key":     row.IdempotencyKey,
		"status":              row.Status,
		"metadata":            nonNilMap(row.Metadata),
		"created_at":          formatTime(row.CreatedAt),
		"updated_at":          formatTime(row.UpdatedAt),
	}
}

func (s *Server) recordActionExecutionAudit(r *http.Request, row *coreent.ActionExecution, action, reason string) {
	if row == nil || s.ent == nil {
		return
	}
	trace := map[string]any{
		"trace_version":       traceVersion(),
		"decision":            "allow",
		"reason":              reason,
		"request_id":          requestIDFrom(r),
		"capability":          row.Capability,
		"operation":           row.Operation,
		"caller_plugin":       row.CallerPluginID,
		"target":              row.TargetProviderID,
		"action_execution_id": row.ID,
		"decision_id":         derefString(row.DecisionID),
		"correlation_id":      row.CorrelationID,
		"status":              row.Status,
		"created_at":          time.Now().UTC().Format(time.RFC3339),
	}
	_, _ = s.ent.AuditLog.Create().
		SetID(newEntityID("audit")).
		SetSpaceID(row.SpaceID).
		SetNillableActorUserID(optionalString(derefString(row.PrincipalUserID))).
		SetNillableActorMemberID(optionalString(derefString(row.PrincipalMemberID))).
		SetNillableActorUserMemberID(optionalString(derefString(row.PrincipalUserMemberID))).
		SetAction(action).
		SetResourceType("action_execution").
		SetResourceID(row.ID).
		SetDecision("allow").
		SetTrace(trace).
		SetNillableRequestID(optionalString(requestIDFrom(r))).
		SetNillableIPAddress(optionalString(remoteIPFrom(r))).
		SetNillableUserAgent(optionalString(r.UserAgent())).
		Save(r.Context())
}
