package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	coreent "github.com/plystra/core/ent"
	entactionexecution "github.com/plystra/core/ent/actionexecution"
	entplugin "github.com/plystra/core/ent/plugin"
	"github.com/plystra/core/internal/authz"
	"github.com/plystra/core/internal/plugins"
)

const actionExecutionIdempotencyRetention = 24 * time.Hour

type actionExecutionRequest struct {
	SpaceID        string                   `json:"space_id"`
	Capability     string                   `json:"capability"`
	Operation      string                   `json:"operation"`
	Principal      capabilityGrantPrincipal `json:"principal"`
	Executor       capabilityGrantExecutor  `json:"executor"`
	Provider       actionExecutionProvider  `json:"provider"`
	Resource       map[string]any           `json:"resource"`
	InputSummary   map[string]any           `json:"input_summary"`
	IdempotencyKey string                   `json:"idempotency_key"`
	CorrelationID  string                   `json:"correlation_id"`
	Metadata       map[string]any           `json:"metadata"`
}

type actionExecutionProvider struct {
	PluginID string `json:"plugin_id"`
}

type actionExecutionCompleteRequest struct {
	ProviderPluginID string         `json:"provider_plugin_id"`
	Status           string         `json:"status"`
	ResultRef        map[string]any `json:"result_ref"`
	ErrorCode        string         `json:"error_code"`
	ErrorMessage     string         `json:"error_message"`
	Metadata         map[string]any `json:"metadata"`
}

func (s *Server) handleActionExecutions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listActionExecutions(w, r)
	case http.MethodPost:
		s.createActionExecution(w, r)
	default:
		writeMethodNotAllowed(w, r)
	}
}

func (s *Server) handleActionExecutionSubroutes(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/action-executions/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 1 && parts[0] != "" && r.Method == http.MethodGet {
		s.getActionExecution(w, r, parts[0])
		return
	}
	if len(parts) == 2 && parts[0] != "" && parts[1] == "complete" {
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, r)
			return
		}
		s.completeActionExecution(w, r, parts[0])
		return
	}
	http.NotFound(w, r)
}

func (s *Server) createActionExecution(w http.ResponseWriter, r *http.Request) {
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	var req actionExecutionRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.normalize()
	if err := validateActionExecutionRequest(req); err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Action execution request is invalid.", err.Error())
		return
	}
	if ok := s.requireCapabilityGrantPermission(w, r, "capabilities:invoke", req.SpaceID); !ok {
		return
	}
	capability, operation, err := s.validateActionExecutionProvider(r, req.Provider.PluginID, req.Capability, req.Operation)
	if err != nil {
		status := http.StatusBadRequest
		code := "VALIDATION_FAILED"
		if coreent.IsNotFound(err) {
			status = http.StatusNotFound
			code = "ACTION_PROVIDER_NOT_FOUND"
		}
		writeError(w, r, status, code, "Action execution provider is invalid.", err.Error())
		return
	}
	allowed, err := s.callerPluginRequiresCapability(r, req.Executor.PluginID, req.Capability)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to validate caller capability requirement.", err.Error())
		return
	}
	if !allowed {
		writeError(w, r, http.StatusForbidden, "CAPABILITY_REQUIREMENT_MISSING", "Executor plugin does not declare this required capability.", map[string]any{
			"executor_plugin_id": req.Executor.PluginID,
			"capability":         req.Capability,
		})
		return
	}
	if ok, err := s.actionExecutorAllowedForProviderScope(r, req.Executor.PluginID, req.Provider.PluginID); err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to validate executor provider scope.", err.Error())
		return
	} else if !ok {
		writeError(w, r, http.StatusForbidden, "CAPABILITY_SCOPE_DENIED", "Executor plugin is outside the target action provider scope.", map[string]any{
			"executor_plugin_id": req.Executor.PluginID,
			"provider_plugin_id": req.Provider.PluginID,
			"capability":         req.Capability,
		})
		return
	}
	if active, reason, err := s.capabilityPrincipalActive(r.Context(), req.Principal, req.SpaceID); err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to validate action principal.", err.Error())
		return
	} else if !active {
		writeError(w, r, http.StatusForbidden, "ACTION_PRINCIPAL_INACTIVE", "Action principal is not active for this Space.", map[string]any{"reason": reason})
		return
	}
	authorizationContext, err := capabilityGrantAuthorizationContextFromResource(req.Resource)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Action execution resource authorization context is invalid.", err.Error())
		return
	}
	decision, err := s.authorizeActionExecutionPrincipal(r, req, authorizationContext)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to authorize action principal.", err.Error())
		return
	}
	if !decision.IsAllowed() {
		writeError(w, r, http.StatusForbidden, "AUTHORIZATION_DENIED", "Action principal is not authorized for the requested resource action.", decision)
		return
	}
	if err := validateActionExecutionContract(capability, operation); err != nil {
		writeError(w, r, http.StatusBadRequest, "ACTION_GATEWAY_REQUIRED", "Capability operation is not Action Gateway controlled.", err.Error())
		return
	}
	existing, err := client.ActionExecution.Query().Where(
		entactionexecution.SpaceID(req.SpaceID),
		entactionexecution.ExecutorPluginID(req.Executor.PluginID),
		entactionexecution.Capability(req.Capability),
		entactionexecution.Operation(req.Operation),
		entactionexecution.IdempotencyKey(req.IdempotencyKey),
	).Only(r.Context())
	if err == nil {
		if !actionExecutionReplayMatches(existing, req) {
			writeError(w, r, http.StatusConflict, "ACTION_EXECUTION_IDEMPOTENCY_CONFLICT", "Existing action execution does not match this idempotency replay.", map[string]any{
				"action_execution_id": existing.ID,
				"idempotency_key":     req.IdempotencyKey,
				"status":              existing.Status,
			})
			return
		}
		writeData(w, r, http.StatusOK, actionExecutionMap(existing))
		return
	}
	if err != nil && !coreent.IsNotFound(err) {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to check action execution idempotency.", err.Error())
		return
	}
	now := time.Now().UTC()
	correlationID := firstNonEmpty(req.CorrelationID, newEntityID("cor"))
	metadata := nonNilMap(req.Metadata)
	metadata["authorization"] = capabilityGrantDecisionSummary(decision)
	metadata["idempotency_retention_hours"] = int(actionExecutionIdempotencyRetention / time.Hour)
	row, err := client.ActionExecution.Create().
		SetID(newEntityID("act")).
		SetSpaceID(req.SpaceID).
		SetCapability(req.Capability).
		SetOperation(req.Operation).
		SetResourceType(authorizationContext.ResourceType).
		SetResourceID(authorizationContext.ResourceID).
		SetResourceAction(authorizationContext.Action).
		SetNillablePrincipalUserID(optionalString(req.Principal.UserID)).
		SetNillablePrincipalMemberID(optionalString(req.Principal.MemberID)).
		SetNillablePrincipalUserMemberID(optionalString(req.Principal.UserMemberID)).
		SetExecutorPluginID(req.Executor.PluginID).
		SetProviderPluginID(req.Provider.PluginID).
		SetNillableDecisionID(optionalString(decision.Audit.ID)).
		SetCorrelationID(correlationID).
		SetIdempotencyKey(req.IdempotencyKey).
		SetStatus("running").
		SetStartedAt(now).
		SetResource(nonNilMap(req.Resource)).
		SetInputSummary(nonNilMap(req.InputSummary)).
		SetResultRef(map[string]any{}).
		SetMetadata(metadata).
		Save(r.Context())
	if err != nil {
		writeError(w, r, http.StatusConflict, "ACTION_EXECUTION_CREATE_FAILED", "Failed to create action execution.", err.Error())
		return
	}
	s.recordActionExecutionAudit(r, row, "action_execution.started", "Action execution started")
	writeData(w, r, http.StatusCreated, actionExecutionMap(row))
}

func (s *Server) completeActionExecution(w http.ResponseWriter, r *http.Request, actionExecutionID string) {
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	var req actionExecutionCompleteRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.normalize()
	if err := validateActionExecutionCompleteRequest(req); err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Action execution completion is invalid.", err.Error())
		return
	}
	row, err := client.ActionExecution.Query().Where(entactionexecution.ID(actionExecutionID)).Only(r.Context())
	if coreent.IsNotFound(err) {
		writeError(w, r, http.StatusNotFound, "ACTION_EXECUTION_NOT_FOUND", "Action execution was not found.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load action execution.", err.Error())
		return
	}
	if req.ProviderPluginID != row.ProviderPluginID {
		writeError(w, r, http.StatusForbidden, "ACTION_PROVIDER_MISMATCH", "Action execution completion provider does not match the ledger row.", map[string]any{
			"action_execution_id": row.ID,
			"provider_plugin_id":  req.ProviderPluginID,
			"expected_provider":   row.ProviderPluginID,
		})
		return
	}
	if ok := s.requireProviderRuntimePrincipal(w, r, row.ProviderPluginID); !ok {
		return
	}
	if ok := s.requireCapabilityGrantPermission(w, r, "capabilities:manage", row.SpaceID); !ok {
		return
	}
	if actionExecutionTerminal(row.Status) {
		if actionExecutionCompletionMatches(row, req) {
			writeData(w, r, http.StatusOK, actionExecutionMap(row))
			return
		}
		writeError(w, r, http.StatusConflict, "ACTION_EXECUTION_ALREADY_COMPLETED", "Action execution already has a different terminal result.", map[string]any{
			"action_execution_id": row.ID,
			"status":              row.Status,
		})
		return
	}
	if row.Status != "running" && row.Status != "pending" {
		writeError(w, r, http.StatusConflict, "ACTION_EXECUTION_NOT_COMPLETABLE", "Action execution is not in a completable state.", map[string]any{
			"action_execution_id": row.ID,
			"status":              row.Status,
		})
		return
	}
	metadata := nonNilMap(row.Metadata)
	for key, value := range nonNilMap(req.Metadata) {
		metadata[key] = value
	}
	updated, err := client.ActionExecution.UpdateOneID(row.ID).
		SetStatus(req.Status).
		SetCompletedAt(time.Now().UTC()).
		SetResultRef(nonNilMap(req.ResultRef)).
		SetNillableErrorCode(optionalString(req.ErrorCode)).
		SetNillableErrorMessage(optionalString(req.ErrorMessage)).
		SetMetadata(metadata).
		Save(r.Context())
	if err != nil {
		writeError(w, r, http.StatusConflict, "ACTION_EXECUTION_COMPLETE_FAILED", "Failed to complete action execution.", err.Error())
		return
	}
	s.recordActionExecutionAudit(r, updated, "action_execution."+req.Status, "Action execution completed")
	writeData(w, r, http.StatusOK, actionExecutionMap(updated))
}

func (s *Server) getActionExecution(w http.ResponseWriter, r *http.Request, actionExecutionID string) {
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	row, err := client.ActionExecution.Query().Where(entactionexecution.ID(actionExecutionID)).Only(r.Context())
	if coreent.IsNotFound(err) {
		writeError(w, r, http.StatusNotFound, "ACTION_EXECUTION_NOT_FOUND", "Action execution was not found.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load action execution.", err.Error())
		return
	}
	if ok := s.requireCapabilityGrantPermission(w, r, "capabilities:manage", row.SpaceID); !ok {
		return
	}
	writeData(w, r, http.StatusOK, actionExecutionMap(row))
}

func (s *Server) listActionExecutions(w http.ResponseWriter, r *http.Request) {
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	spaceID := strings.TrimSpace(r.URL.Query().Get("space_id"))
	if spaceID == "" {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "space_id is required.", nil)
		return
	}
	if ok := s.requireCapabilityGrantPermission(w, r, "capabilities:manage", spaceID); !ok {
		return
	}
	query := client.ActionExecution.Query().Where(entactionexecution.SpaceID(spaceID))
	if capabilityID := strings.TrimSpace(r.URL.Query().Get("capability")); capabilityID != "" {
		query = query.Where(entactionexecution.Capability(capabilityID))
	}
	if operation := strings.TrimSpace(r.URL.Query().Get("operation")); operation != "" {
		query = query.Where(entactionexecution.Operation(operation))
	}
	if status := strings.TrimSpace(r.URL.Query().Get("status")); status != "" {
		query = query.Where(entactionexecution.Status(status))
	}
	if resourceType := strings.TrimSpace(r.URL.Query().Get("resource_type")); resourceType != "" {
		query = query.Where(entactionexecution.ResourceType(resourceType))
	}
	if resourceID := strings.TrimSpace(r.URL.Query().Get("resource_id")); resourceID != "" {
		query = query.Where(entactionexecution.ResourceID(resourceID))
	}
	rows, err := query.Order(entactionexecution.ByStartedAt()).Limit(limitFrom(r, 50)).All(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list action executions.", err.Error())
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, actionExecutionMap(row))
	}
	writeList(w, r, http.StatusOK, out, limitFrom(r, 50))
}

func (req *actionExecutionRequest) normalize() {
	req.SpaceID = strings.TrimSpace(req.SpaceID)
	req.Capability = strings.TrimSpace(req.Capability)
	req.Operation = strings.TrimSpace(req.Operation)
	req.Principal.UserID = strings.TrimSpace(req.Principal.UserID)
	req.Principal.MemberID = strings.TrimSpace(req.Principal.MemberID)
	req.Principal.UserMemberID = strings.TrimSpace(req.Principal.UserMemberID)
	req.Executor.PluginID = strings.TrimSpace(req.Executor.PluginID)
	req.Provider.PluginID = strings.TrimSpace(req.Provider.PluginID)
	req.IdempotencyKey = strings.TrimSpace(req.IdempotencyKey)
	req.CorrelationID = strings.TrimSpace(req.CorrelationID)
}

func (req *actionExecutionCompleteRequest) normalize() {
	req.ProviderPluginID = strings.TrimSpace(req.ProviderPluginID)
	req.Status = strings.TrimSpace(req.Status)
	req.ErrorCode = strings.TrimSpace(req.ErrorCode)
	req.ErrorMessage = strings.TrimSpace(req.ErrorMessage)
}

func validateActionExecutionRequest(req actionExecutionRequest) error {
	switch {
	case req.SpaceID == "":
		return errors.New("space_id is required")
	case !pluginsCapabilityIDValid(req.Capability):
		return errors.New("capability must be a dotted capability id")
	case req.Operation == "":
		return errors.New("operation is required")
	case req.Principal.UserID == "" || req.Principal.MemberID == "" || req.Principal.UserMemberID == "":
		return errors.New("principal user_id, member_id, and user_member_id are required")
	case req.Executor.PluginID == "":
		return errors.New("executor.plugin_id is required")
	case req.Provider.PluginID == "":
		return errors.New("provider.plugin_id is required")
	case req.IdempotencyKey == "":
		return errors.New("idempotency_key is required")
	}
	if len(req.IdempotencyKey) > 200 {
		return errors.New("idempotency_key must be 200 characters or fewer")
	}
	if err := validateGovernedJSONValue("action_execution.resource", nonNilMap(req.Resource), governedJSONPolicy{MaxBytes: maxPluginSettingValueBytes, RejectSecrets: true}); err != nil {
		return err
	}
	if err := validateGovernedJSONValue("action_execution.input_summary", nonNilMap(req.InputSummary), governedJSONPolicy{MaxBytes: maxPluginSettingValueBytes, RejectSecrets: true}); err != nil {
		return err
	}
	if err := validateGovernedJSONValue("action_execution.metadata", nonNilMap(req.Metadata), governedJSONPolicy{MaxBytes: maxGovernedMetadataBytes, RejectSecrets: true}); err != nil {
		return err
	}
	return nil
}

func validateActionExecutionCompleteRequest(req actionExecutionCompleteRequest) error {
	switch {
	case req.ProviderPluginID == "":
		return errors.New("provider_plugin_id is required")
	case !validActionExecutionTerminalStatus(req.Status):
		return errors.New("status must be succeeded, failed, rejected, cancelled, timeout, or result_unknown")
	}
	if req.Status == "succeeded" && (req.ErrorCode != "" || req.ErrorMessage != "") {
		return errors.New("succeeded completion must not include error_code or error_message")
	}
	if req.Status != "succeeded" && req.ErrorCode == "" {
		return errors.New("non-succeeded completion requires error_code")
	}
	if len(req.ErrorCode) > 120 || len(req.ErrorMessage) > 1024 {
		return errors.New("error_code or error_message is too long")
	}
	if err := validateGovernedJSONValue("action_execution.result_ref", nonNilMap(req.ResultRef), governedJSONPolicy{MaxBytes: maxGovernedMetadataBytes, RejectSecrets: true}); err != nil {
		return err
	}
	if err := validateGovernedJSONValue("action_execution.metadata", nonNilMap(req.Metadata), governedJSONPolicy{MaxBytes: maxGovernedMetadataBytes, RejectSecrets: true}); err != nil {
		return err
	}
	return nil
}

func (s *Server) validateActionExecutionProvider(r *http.Request, providerPluginID, capabilityID, operationName string) (plugins.CapabilityDefinition, plugins.CapabilityOperationDefinition, error) {
	provider, err := s.governedPluginManifestByKey(r.Context(), providerPluginID)
	if err != nil {
		return plugins.CapabilityDefinition{}, plugins.CapabilityOperationDefinition{}, err
	}
	pluginRow, err := s.ent.Plugin.Query().Where(entplugin.Key(providerPluginID)).Only(r.Context())
	if err != nil {
		return plugins.CapabilityDefinition{}, plugins.CapabilityOperationDefinition{}, err
	}
	if pluginRow.Status != "enabled" {
		return plugins.CapabilityDefinition{}, plugins.CapabilityOperationDefinition{}, errors.New("provider plugin is not enabled")
	}
	capability, operation, ok := capabilityOperationFromManifest(provider.Manifest, capabilityID, operationName)
	if !ok {
		return plugins.CapabilityDefinition{}, plugins.CapabilityOperationDefinition{}, errors.New("provider plugin does not provide the requested capability operation")
	}
	if capabilityLocalToManifest(provider.Manifest, capabilityID) && provider.Type != "app_module" {
		return plugins.CapabilityDefinition{}, plugins.CapabilityOperationDefinition{}, errors.New("local capability must be provided by an app module")
	}
	return capability, operation, nil
}

func validateActionExecutionContract(capability plugins.CapabilityDefinition, operation plugins.CapabilityOperationDefinition) error {
	if capability.Audit.Enforcement != "controlled_action" {
		return errors.New("capability audit enforcement must be controlled_action")
	}
	if operation.Invocation.Mode != "brokered_action_gateway" {
		return errors.New("operation invocation mode must be brokered_action_gateway")
	}
	if operation.Invocation.Idempotency != "required" {
		return errors.New("operation idempotency must be required")
	}
	if operation.Invocation.ResultUnknownReconciliation != "required" {
		return errors.New("operation result_unknown_reconciliation must be required")
	}
	return nil
}

func (s *Server) authorizeActionExecutionPrincipal(r *http.Request, req actionExecutionRequest, authorizationContext capabilityGrantAuthorizationContext) (*authz.Decision, error) {
	return s.authorizeCapabilityGrantPrincipal(r, capabilityGrantRequest{
		SpaceID: req.SpaceID,
		Principal: capabilityGrantPrincipal{
			UserID:       req.Principal.UserID,
			MemberID:     req.Principal.MemberID,
			UserMemberID: req.Principal.UserMemberID,
		},
	}, authorizationContext)
}

func (s *Server) actionExecutorAllowedForProviderScope(r *http.Request, executorPluginID, providerPluginID string) (bool, error) {
	provider, err := s.governedPluginManifestByKey(r.Context(), providerPluginID)
	if coreent.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if provider.Type != "app_module" && provider.Scope != "app" {
		return true, nil
	}
	if executorPluginID == providerPluginID {
		return true, nil
	}
	executor, err := s.governedPluginManifestByKey(r.Context(), executorPluginID)
	if coreent.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return executor.Type == "app_module" && executor.AppID != "" && executor.AppID == provider.AppID, nil
}

func actionExecutionReplayMatches(row *coreent.ActionExecution, req actionExecutionRequest) bool {
	if row == nil {
		return false
	}
	resourceContext, err := capabilityGrantAuthorizationContextFromResource(req.Resource)
	if err != nil {
		return false
	}
	return row.SpaceID == req.SpaceID &&
		row.Capability == req.Capability &&
		row.Operation == req.Operation &&
		row.ExecutorPluginID == req.Executor.PluginID &&
		row.ProviderPluginID == req.Provider.PluginID &&
		row.ResourceType == resourceContext.ResourceType &&
		row.ResourceID == resourceContext.ResourceID &&
		row.ResourceAction == resourceContext.Action &&
		derefString(row.PrincipalUserID) == req.Principal.UserID &&
		derefString(row.PrincipalMemberID) == req.Principal.MemberID &&
		derefString(row.PrincipalUserMemberID) == req.Principal.UserMemberID &&
		jsonEqual(row.Resource, nonNilMap(req.Resource)) &&
		jsonEqual(row.InputSummary, nonNilMap(req.InputSummary))
}

func actionExecutionCompletionMatches(row *coreent.ActionExecution, req actionExecutionCompleteRequest) bool {
	if row == nil {
		return false
	}
	return row.ProviderPluginID == req.ProviderPluginID &&
		row.Status == req.Status &&
		derefString(row.ErrorCode) == req.ErrorCode &&
		derefString(row.ErrorMessage) == req.ErrorMessage &&
		jsonEqual(row.ResultRef, nonNilMap(req.ResultRef))
}

func jsonEqual(left, right any) bool {
	leftBytes, leftErr := json.Marshal(left)
	rightBytes, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && string(leftBytes) == string(rightBytes)
}

func actionExecutionTerminal(status string) bool {
	return validActionExecutionTerminalStatus(status)
}

func validActionExecutionTerminalStatus(status string) bool {
	switch strings.TrimSpace(status) {
	case "succeeded", "failed", "rejected", "cancelled", "timeout", "result_unknown":
		return true
	default:
		return false
	}
}

func actionExecutionMap(row *coreent.ActionExecution) map[string]any {
	return map[string]any{
		"action_execution_id":           row.ID,
		"space_id":                      row.SpaceID,
		"capability":                    row.Capability,
		"operation":                     row.Operation,
		"resource_type":                 row.ResourceType,
		"resource_id":                   row.ResourceID,
		"resource_action":               row.ResourceAction,
		"principal_user_id":             derefString(row.PrincipalUserID),
		"principal_member_id":           derefString(row.PrincipalMemberID),
		"principal_user_member_id":      derefString(row.PrincipalUserMemberID),
		"executor_plugin_id":            row.ExecutorPluginID,
		"provider_plugin_id":            row.ProviderPluginID,
		"decision_id":                   derefString(row.DecisionID),
		"correlation_id":                row.CorrelationID,
		"idempotency_key":               row.IdempotencyKey,
		"idempotency_retention_seconds": int(actionExecutionIdempotencyRetention.Seconds()),
		"status":                        row.Status,
		"started_at":                    formatTime(row.StartedAt),
		"completed_at":                  optionalTime(row.CompletedAt),
		"resource":                      nonNilMap(row.Resource),
		"input_summary":                 nonNilMap(row.InputSummary),
		"result_ref":                    nonNilMap(row.ResultRef),
		"error_code":                    derefString(row.ErrorCode),
		"error_message":                 derefString(row.ErrorMessage),
		"metadata":                      nonNilMap(row.Metadata),
		"created_at":                    formatTime(row.CreatedAt),
		"updated_at":                    formatTime(row.UpdatedAt),
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
		"action_execution_id": row.ID,
		"executor_plugin":     row.ExecutorPluginID,
		"provider_plugin":     row.ProviderPluginID,
		"status":              row.Status,
		"resource": map[string]any{
			"type":   row.ResourceType,
			"id":     row.ResourceID,
			"action": row.ResourceAction,
		},
	}
	_, _ = s.ent.AuditLog.Create().
		SetID(newEntityID("audit")).
		SetSpaceID(row.SpaceID).
		SetNillableActorUserID(row.PrincipalUserID).
		SetNillableActorMemberID(row.PrincipalMemberID).
		SetNillableActorUserMemberID(row.PrincipalUserMemberID).
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
