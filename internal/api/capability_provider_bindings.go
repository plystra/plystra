package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	coreent "github.com/plystra/core/ent"
	entcapabilityproviderbinding "github.com/plystra/core/ent/capabilityproviderbinding"
	entplugin "github.com/plystra/core/ent/plugin"
	entspace "github.com/plystra/core/ent/space"
	"github.com/plystra/core/internal/authz"
	"github.com/plystra/core/internal/plugins"
)

type capabilityProviderBindingMutationRequest struct {
	SpaceID          string         `json:"space_id"`
	Capability       string         `json:"capability"`
	Operation        string         `json:"operation"`
	ProviderPluginID string         `json:"provider_plugin_id"`
	Endpoint         string         `json:"endpoint"`
	OperationPath    string         `json:"operation_path"`
	Status           string         `json:"status"`
	Identity         map[string]any `json:"identity"`
	Metadata         map[string]any `json:"metadata"`
}

func (req *capabilityProviderBindingMutationRequest) normalize() {
	req.SpaceID = strings.TrimSpace(req.SpaceID)
	req.Capability = strings.TrimSpace(req.Capability)
	req.Operation = strings.TrimSpace(req.Operation)
	req.ProviderPluginID = strings.TrimSpace(req.ProviderPluginID)
	req.Endpoint = strings.TrimSpace(req.Endpoint)
	req.OperationPath = strings.TrimSpace(req.OperationPath)
	req.Status = strings.TrimSpace(req.Status)
}

func (s *Server) handleCapabilityProviderBindings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleCapabilityProviderBindingList(w, r)
	case http.MethodPost:
		s.handleCapabilityProviderBindingUpsert(w, r)
	default:
		writeMethodNotAllowed(w, r)
	}
}

func (s *Server) handleCapabilityProviderBindingSubroutes(w http.ResponseWriter, r *http.Request) {
	bindingID := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/capability-provider-bindings/"), "/")
	if bindingID == "" {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.handleCapabilityProviderBindingGet(w, r, bindingID)
	case http.MethodPatch:
		s.handleCapabilityProviderBindingPatch(w, r, bindingID)
	case http.MethodDelete:
		s.handleCapabilityProviderBindingDisable(w, r, bindingID)
	default:
		writeMethodNotAllowed(w, r)
	}
}

func (s *Server) handleCapabilityProviderBindingList(w http.ResponseWriter, r *http.Request) {
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	query := client.CapabilityProviderBinding.Query().Order(entcapabilityproviderbinding.BySpaceID(), entcapabilityproviderbinding.ByCapability(), entcapabilityproviderbinding.ByOperation())
	if spaceID := strings.TrimSpace(r.URL.Query().Get("space_id")); spaceID != "" {
		query = query.Where(entcapabilityproviderbinding.SpaceID(spaceID))
	}
	if capabilityID := strings.TrimSpace(r.URL.Query().Get("capability")); capabilityID != "" {
		query = query.Where(entcapabilityproviderbinding.Capability(capabilityID))
	}
	if status := strings.TrimSpace(r.URL.Query().Get("status")); status != "" {
		query = query.Where(entcapabilityproviderbinding.Status(status))
	}
	rows, err := query.Limit(limitFrom(r, 50)).All(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list capability provider bindings.", err.Error())
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, capabilityProviderBindingMap(row))
	}
	writeList(w, r, http.StatusOK, out, limitFrom(r, 50))
}

func (s *Server) handleCapabilityProviderBindingGet(w http.ResponseWriter, r *http.Request, bindingID string) {
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	row, err := client.CapabilityProviderBinding.Query().Where(entcapabilityproviderbinding.ID(bindingID)).Only(r.Context())
	if coreent.IsNotFound(err) {
		writeError(w, r, http.StatusNotFound, "CAPABILITY_PROVIDER_BINDING_NOT_FOUND", "Capability provider binding was not found.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load capability provider binding.", err.Error())
		return
	}
	writeData(w, r, http.StatusOK, capabilityProviderBindingMap(row))
}

func (s *Server) handleCapabilityProviderBindingUpsert(w http.ResponseWriter, r *http.Request) {
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	var req capabilityProviderBindingMutationRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.normalize()
	if req.Status == "" {
		req.Status = "active"
	}
	if err := s.validateCapabilityProviderBindingMutation(r, req); err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Capability provider binding is invalid.", err.Error())
		return
	}
	existing, err := client.CapabilityProviderBinding.Query().Where(
		entcapabilityproviderbinding.SpaceID(req.SpaceID),
		entcapabilityproviderbinding.Capability(req.Capability),
		entcapabilityproviderbinding.Operation(req.Operation),
	).Only(r.Context())
	if err != nil && !coreent.IsNotFound(err) {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load capability provider binding.", err.Error())
		return
	}
	if existing != nil {
		operationPath := optionalString(req.OperationPath)
		if req.OperationPath == "" {
			operationPath = nil
		}
		updated, err := client.CapabilityProviderBinding.UpdateOneID(existing.ID).
			SetProviderPluginID(req.ProviderPluginID).
			SetEndpoint(req.Endpoint).
			SetNillableOperationPath(operationPath).
			SetBindingEpoch(existing.BindingEpoch + 1).
			SetStatus(req.Status).
			SetIdentity(nonNilMap(req.Identity)).
			SetMetadata(nonNilMap(req.Metadata)).
			Save(r.Context())
		if err != nil {
			writeError(w, r, http.StatusConflict, "CAPABILITY_PROVIDER_BINDING_UPDATE_FAILED", "Failed to update capability provider binding.", err.Error())
			return
		}
		s.invalidateCapabilityProviderBindingCache(existing, updated)
		s.recordCapabilityProviderBindingAudit(r, "capability_provider_binding.updated", existing, updated)
		writeData(w, r, http.StatusOK, capabilityProviderBindingMap(updated))
		return
	}
	bindingID := "cpb_" + safeIdentifier(req.SpaceID+"_"+req.Capability+"_"+req.Operation)
	create := client.CapabilityProviderBinding.Create().
		SetID(bindingID).
		SetSpaceID(req.SpaceID).
		SetCapability(req.Capability).
		SetOperation(req.Operation).
		SetProviderPluginID(req.ProviderPluginID).
		SetEndpoint(req.Endpoint).
		SetBindingEpoch(1).
		SetStatus(req.Status).
		SetIdentity(nonNilMap(req.Identity)).
		SetMetadata(nonNilMap(req.Metadata))
	if req.OperationPath != "" {
		create.SetOperationPath(req.OperationPath)
	}
	row, err := create.Save(r.Context())
	if err != nil {
		writeError(w, r, http.StatusConflict, "CAPABILITY_PROVIDER_BINDING_CREATE_FAILED", "Failed to create capability provider binding.", err.Error())
		return
	}
	s.invalidateCapabilityProviderBindingCache(nil, row)
	s.recordCapabilityProviderBindingAudit(r, "capability_provider_binding.created", nil, row)
	writeData(w, r, http.StatusCreated, capabilityProviderBindingMap(row))
}

func (s *Server) handleCapabilityProviderBindingPatch(w http.ResponseWriter, r *http.Request, bindingID string) {
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	existing, err := client.CapabilityProviderBinding.Query().Where(entcapabilityproviderbinding.ID(bindingID)).Only(r.Context())
	if coreent.IsNotFound(err) {
		writeError(w, r, http.StatusNotFound, "CAPABILITY_PROVIDER_BINDING_NOT_FOUND", "Capability provider binding was not found.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load capability provider binding.", err.Error())
		return
	}
	req := capabilityProviderBindingMutationRequest{
		SpaceID:          existing.SpaceID,
		Capability:       existing.Capability,
		Operation:        existing.Operation,
		ProviderPluginID: existing.ProviderPluginID,
		Endpoint:         existing.Endpoint,
		OperationPath:    derefString(existing.OperationPath),
		Status:           existing.Status,
		Identity:         nonNilMap(existing.Identity),
		Metadata:         nonNilMap(existing.Metadata),
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	req.normalize()
	if req.Status == "" {
		req.Status = existing.Status
	}
	if err := s.validateCapabilityProviderBindingMutation(r, req); err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Capability provider binding is invalid.", err.Error())
		return
	}
	operationPath := optionalString(req.OperationPath)
	if req.OperationPath == "" {
		operationPath = nil
	}
	updated, err := client.CapabilityProviderBinding.UpdateOneID(existing.ID).
		SetSpaceID(req.SpaceID).
		SetCapability(req.Capability).
		SetOperation(req.Operation).
		SetProviderPluginID(req.ProviderPluginID).
		SetEndpoint(req.Endpoint).
		SetNillableOperationPath(operationPath).
		SetBindingEpoch(existing.BindingEpoch + 1).
		SetStatus(req.Status).
		SetIdentity(nonNilMap(req.Identity)).
		SetMetadata(nonNilMap(req.Metadata)).
		Save(r.Context())
	if err != nil {
		writeError(w, r, http.StatusConflict, "CAPABILITY_PROVIDER_BINDING_UPDATE_FAILED", "Failed to update capability provider binding.", err.Error())
		return
	}
	s.invalidateCapabilityProviderBindingCache(existing, updated)
	s.recordCapabilityProviderBindingAudit(r, "capability_provider_binding.updated", existing, updated)
	writeData(w, r, http.StatusOK, capabilityProviderBindingMap(updated))
}

func (s *Server) handleCapabilityProviderBindingDisable(w http.ResponseWriter, r *http.Request, bindingID string) {
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	row, err := client.CapabilityProviderBinding.Query().Where(entcapabilityproviderbinding.ID(bindingID)).Only(r.Context())
	if coreent.IsNotFound(err) {
		writeError(w, r, http.StatusNotFound, "CAPABILITY_PROVIDER_BINDING_NOT_FOUND", "Capability provider binding was not found.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load capability provider binding.", err.Error())
		return
	}
	updated, err := client.CapabilityProviderBinding.UpdateOneID(row.ID).
		SetStatus("disabled").
		SetBindingEpoch(row.BindingEpoch + 1).
		Save(r.Context())
	if err != nil {
		writeError(w, r, http.StatusConflict, "CAPABILITY_PROVIDER_BINDING_UPDATE_FAILED", "Failed to disable capability provider binding.", err.Error())
		return
	}
	s.invalidateCapabilityProviderBindingCache(row, updated)
	s.recordCapabilityProviderBindingAudit(r, "capability_provider_binding.disabled", row, updated)
	writeData(w, r, http.StatusOK, capabilityProviderBindingMap(updated))
}

func (s *Server) invalidateCapabilityProviderBindingCache(before, after *coreent.CapabilityProviderBinding) {
	if s == nil || s.capabilityProviderCache == nil {
		return
	}
	if before != nil {
		s.capabilityProviderCache.invalidate(before.SpaceID, before.Capability, before.Operation)
	}
	if after != nil {
		s.capabilityProviderCache.invalidate(after.SpaceID, after.Capability, after.Operation)
	}
}

func (s *Server) invalidateCapabilityProviderCacheForPlugin(ctx context.Context, pluginKey string) {
	if s == nil || s.ent == nil || s.capabilityProviderCache == nil {
		return
	}
	pluginKey = strings.TrimSpace(pluginKey)
	if pluginKey == "" {
		return
	}
	rows, err := s.ent.CapabilityProviderBinding.Query().Where(entcapabilityproviderbinding.ProviderPluginID(pluginKey)).All(ctx)
	if err != nil {
		return
	}
	for _, row := range rows {
		s.capabilityProviderCache.invalidate(row.SpaceID, row.Capability, row.Operation)
	}
}

func (s *Server) validateCapabilityProviderBindingMutation(r *http.Request, req capabilityProviderBindingMutationRequest) error {
	switch {
	case req.SpaceID == "":
		return errors.New("space_id is required")
	case !pluginsCapabilityIDValid(req.Capability):
		return errors.New("capability must be a dotted capability id")
	case req.Operation == "":
		return errors.New("operation is required")
	case req.ProviderPluginID == "":
		return errors.New("provider_plugin_id is required")
	case req.Endpoint == "":
		return errors.New("endpoint is required")
	case req.Status != "active" && req.Status != "disabled":
		return errors.New("status must be active or disabled")
	}
	if err := validateCapabilityProviderEndpoint(req.Endpoint); err != nil {
		return err
	}
	if req.OperationPath != "" {
		if err := validateCapabilityOperationPath(req.OperationPath); err != nil {
			return err
		}
	}
	if err := validateGovernedJSONValue("identity", nonNilMap(req.Identity), governedJSONPolicy{MaxBytes: maxGovernedMetadataBytes, RejectSecrets: true}); err != nil {
		return err
	}
	if err := validateGovernedMetadata("metadata", nonNilMap(req.Metadata)); err != nil {
		return err
	}
	if _, err := s.ent.Space.Query().Where(entspace.ID(req.SpaceID), entspace.DeletedAtIsNil()).Only(r.Context()); coreent.IsNotFound(err) {
		return fmt.Errorf("space %q was not found", req.SpaceID)
	} else if err != nil {
		return err
	}
	provider, err := s.governedPluginManifestByKey(r.Context(), req.ProviderPluginID)
	if coreent.IsNotFound(err) {
		return fmt.Errorf("provider plugin %q was not found", req.ProviderPluginID)
	}
	if err != nil {
		return err
	}
	pluginRow, err := s.ent.Plugin.Query().Where(entplugin.Key(req.ProviderPluginID)).Only(r.Context())
	if coreent.IsNotFound(err) {
		return fmt.Errorf("provider plugin %q was not found", req.ProviderPluginID)
	}
	if err != nil {
		return err
	}
	if pluginRow.Status != "enabled" {
		return fmt.Errorf("provider plugin %q is not enabled", req.ProviderPluginID)
	}
	capability, operation, ok := capabilityOperationFromManifest(provider.Manifest, req.Capability, req.Operation)
	if !ok {
		return fmt.Errorf("provider plugin %q does not provide %s:%s", req.ProviderPluginID, req.Capability, req.Operation)
	}
	if operation.Invocation.Mode == "brokered_action_gateway" && req.Status == "active" {
		return fmt.Errorf("capability %s operation %s requires Action Gateway and cannot be bound for mediated grants", capability.ID, req.Operation)
	}
	if capabilityLocalToManifest(provider.Manifest, req.Capability) && provider.Type != "app_module" {
		return fmt.Errorf("local capability %s must be provided by an app module", req.Capability)
	}
	return nil
}

func capabilityOperationFromManifest(manifest plugins.Manifest, capabilityID, operationName string) (plugins.CapabilityDefinition, plugins.CapabilityOperationDefinition, bool) {
	for _, capability := range manifestProvidedCapabilities(manifest) {
		if capability.ID != capabilityID {
			continue
		}
		operation, ok := capabilityOperationByName(capability, operationName)
		if ok {
			return capability, operation, true
		}
	}
	return plugins.CapabilityDefinition{}, plugins.CapabilityOperationDefinition{}, false
}

func (s *Server) recordCapabilityProviderBindingAudit(r *http.Request, action string, before, after *coreent.CapabilityProviderBinding) {
	if s == nil || s.ent == nil || after == nil {
		return
	}
	details := map[string]any{
		"after": capabilityProviderBindingAuditMap(after),
	}
	if principal, ok := adminPrincipalFrom(r); ok && principal.CredentialType == "api_key" && principal.APIKey != nil {
		details["credential"] = map[string]any{"type": "api_key", "api_key_id": principal.APIKey.ID}
	}
	if before != nil {
		details["before"] = capabilityProviderBindingAuditMap(before)
	}
	s.recordMutationAudit(r.Context(), r, authzActorFromAdminPrincipal(r), after.SpaceID, action, "capability_provider_binding", after.ID, details)
}

func capabilityProviderBindingAuditMap(row *coreent.CapabilityProviderBinding) map[string]any {
	if row == nil {
		return map[string]any{}
	}
	return map[string]any{
		"id":                 row.ID,
		"space_id":           row.SpaceID,
		"capability":         row.Capability,
		"operation":          row.Operation,
		"provider_plugin_id": row.ProviderPluginID,
		"endpoint":           row.Endpoint,
		"operation_path":     derefString(row.OperationPath),
		"binding_epoch":      row.BindingEpoch,
		"status":             row.Status,
		"identity":           nonNilMap(row.Identity),
		"metadata":           nonNilMap(row.Metadata),
	}
}

func authzActorFromAdminPrincipal(r *http.Request) authz.ActorContext {
	principal, ok := adminPrincipalFrom(r)
	if !ok {
		return authz.ActorContext{}
	}
	if principal.CredentialType == "session" {
		return authz.ActorContext{
			UserID:       principal.Session.UserID,
			MemberID:     principal.Session.ActiveMemberID,
			UserMemberID: principal.Session.ActiveUserMemberID,
			SpaceID:      principal.Session.ActiveSpaceID,
		}
	}
	if principal.APIKey != nil {
		return authz.ActorContext{
			SpaceID: derefString(principal.APIKey.SpaceID),
		}
	}
	return authz.ActorContext{}
}

func validateCapabilityProviderEndpoint(value string) error {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.Hostname() == "" {
		return errors.New("endpoint must be an absolute URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return errors.New("endpoint must use http or https")
	}
	if parsed.Scheme == "http" && !localCapabilityProviderHost(parsed.Hostname()) {
		return errors.New("http endpoints are allowed only for localhost or internal service-mesh hosts")
	}
	if parsed.User != nil {
		return errors.New("endpoint must not include credentials")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("endpoint must not include query or fragment")
	}
	if strings.ContainsAny(parsed.Hostname(), " \t\r\n") {
		return errors.New("endpoint host is invalid")
	}
	return nil
}

func localCapabilityProviderHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	return host == "localhost" ||
		host == "127.0.0.1" ||
		host == "::1" ||
		strings.HasSuffix(host, ".internal") ||
		strings.HasSuffix(host, ".local")
}

func validateCapabilityOperationPath(value string) error {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || !strings.HasPrefix(strings.TrimSpace(value), "/") {
		return errors.New("operation_path must be an absolute path")
	}
	if parsed.Scheme != "" || parsed.Host != "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("operation_path must not include scheme, host, credentials, query, or fragment")
	}
	return nil
}

func capabilityProviderBindingMap(row *coreent.CapabilityProviderBinding) map[string]any {
	return map[string]any{
		"id":                 row.ID,
		"space_id":           row.SpaceID,
		"capability":         row.Capability,
		"operation":          row.Operation,
		"provider_plugin_id": row.ProviderPluginID,
		"endpoint":           row.Endpoint,
		"operation_path":     derefString(row.OperationPath),
		"binding_epoch":      row.BindingEpoch,
		"status":             row.Status,
		"identity":           nonNilMap(row.Identity),
		"metadata":           nonNilMap(row.Metadata),
		"created_at":         formatTime(row.CreatedAt),
		"updated_at":         formatTime(row.UpdatedAt),
	}
}
