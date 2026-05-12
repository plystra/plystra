package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	entsql "entgo.io/ent/dialect/sql"
	coreent "github.com/plystra/plystra/ent"
	entapikey "github.com/plystra/plystra/ent/apikey"
	entgroup "github.com/plystra/plystra/ent/group"
	entspace "github.com/plystra/plystra/ent/space"
)

type apiKeyMutationRequest struct {
	ID             string         `json:"id"`
	Name           string         `json:"name"`
	Level          string         `json:"level"`
	SpaceID        string         `json:"space_id"`
	GroupID        string         `json:"group_id"`
	PermissionKeys []string       `json:"permission_keys"`
	Status         string         `json:"status"`
	ExpiresAt      *time.Time     `json:"expires_at"`
	RevokedReason  string         `json:"revoked_reason"`
	Metadata       map[string]any `json:"metadata"`
}

func (s *Server) handleAPIKeys(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listAPIKeys(w, r)
	case http.MethodPost:
		s.createAPIKey(w, r)
	default:
		writeMethodNotAllowed(w, r)
	}
}

func (s *Server) handleAPIKeySubroutes(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/api-keys/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	keyID := parts[0]
	if len(parts) == 1 {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, r)
			return
		}
		s.getAPIKey(w, r, keyID)
		return
	}
	if len(parts) == 2 && parts[1] == "revoke" {
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, r)
			return
		}
		s.revokeAPIKey(w, r, keyID)
		return
	}
	http.NotFound(w, r)
}

func (s *Server) listAPIKeys(w http.ResponseWriter, r *http.Request) {
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	principal, _ := adminPrincipalFrom(r)
	limit := limitFrom(r, 100)
	q := client.ApiKey.Query().Where(entapikey.DeletedAtIsNil())
	if value := strings.TrimSpace(r.URL.Query().Get("level")); value != "" {
		q = q.Where(entapikey.Level(value))
	}
	if value := strings.TrimSpace(r.URL.Query().Get("space_id")); value != "" {
		q = q.Where(entapikey.SpaceID(value))
	}
	if value := strings.TrimSpace(r.URL.Query().Get("group_id")); value != "" {
		q = q.Where(entapikey.GroupID(value))
	}
	if value := strings.TrimSpace(r.URL.Query().Get("status")); value != "" {
		q = q.Where(entapikey.Status(value))
	}
	keys, err := q.Order(entapikey.ByCreatedAt(entsql.OrderDesc())).Limit(limit).All(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list API keys.", err.Error())
		return
	}
	rows := make([]map[string]any, 0, len(keys))
	for _, key := range keys {
		allowed, err := s.principalCanUseAPIKeyScope(r, principal, key, "read")
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to evaluate API key visibility.", err.Error())
			return
		}
		if allowed {
			rows = append(rows, apiKeyMap(key))
		}
	}
	writeList(w, r, http.StatusOK, rows, limit)
}

func (s *Server) getAPIKey(w http.ResponseWriter, r *http.Request, keyID string) {
	key, ok := s.loadAPIKeyForAction(w, r, keyID, "read")
	if !ok {
		return
	}
	writeData(w, r, http.StatusOK, apiKeyMap(key))
}

func (s *Server) createAPIKey(w http.ResponseWriter, r *http.Request) {
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	var req apiKeyMutationRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.normalize()
	if err := s.validateAPIKeyRequest(r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "API key is invalid.", err.Error())
		return
	}
	principal, _ := adminPrincipalFrom(r)
	if allowed, err := s.principalAllowsAPIKeyRequest(r, principal, req, "create"); err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to evaluate API key scope.", err.Error())
		return
	} else if !allowed {
		writeError(w, r, http.StatusForbidden, "ADMIN_PERMISSION_REQUIRED", "The current credential cannot create an API key for this scope.", map[string]any{"permission": "api_keys:create"})
		return
	}
	if allowed, deniedPermission, err := s.principalCanDelegatePermissions(r.Context(), principal, req.PermissionKeys, req.SpaceID, req.GroupID); err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to evaluate delegated API key permissions.", err.Error())
		return
	} else if !allowed {
		writeError(w, r, http.StatusForbidden, "ADMIN_PERMISSION_REQUIRED", "The current credential cannot delegate one or more API key permissions.", map[string]any{"permission": deniedPermission})
		return
	}
	if req.ID == "" {
		req.ID = newEntityID("ak")
	}
	plaintext, err := newAPIKeyPlaintext(req.ID)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to generate API key.", err.Error())
		return
	}
	create := client.ApiKey.Create().
		SetID(req.ID).
		SetName(req.Name).
		SetKeyPrefix(apiKeyPrefix(req.ID)).
		SetKeyHash(apiKeyHash(plaintext)).
		SetLevel(req.Level).
		SetPermissionKeys(req.PermissionKeys).
		SetStatus(firstNonEmpty(req.Status, "active")).
		SetNillableSpaceID(optionalString(req.SpaceID)).
		SetNillableGroupID(optionalString(req.GroupID)).
		SetNillableExpiresAt(req.ExpiresAt).
		SetMetadata(nonNilMap(req.Metadata))
	if principal.CredentialType == "session" {
		create.SetNillableCreatedByUserID(optionalString(principal.Session.UserID))
		create.SetNillableCreatedByMemberID(optionalString(principal.Session.ActiveMemberID))
	}
	key, err := create.Save(r.Context())
	if err != nil {
		writeError(w, r, http.StatusConflict, "API_KEY_CREATE_FAILED", "Failed to create API key.", err.Error())
		return
	}
	out := apiKeyMap(key)
	out["api_key"] = plaintext
	writeData(w, r, http.StatusCreated, out)
}

func (s *Server) revokeAPIKey(w http.ResponseWriter, r *http.Request, keyID string) {
	key, ok := s.loadAPIKeyForAction(w, r, keyID, "revoke")
	if !ok {
		return
	}
	var req apiKeyMutationRequest
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}
	principal, _ := adminPrincipalFrom(r)
	now := time.Now().UTC()
	update := s.ent.ApiKey.UpdateOneID(key.ID).
		SetStatus("revoked").
		SetRevokedAt(now)
	if principal.CredentialType == "session" {
		update.SetNillableRevokedByUserID(optionalString(principal.Session.UserID))
	}
	if reason := strings.TrimSpace(req.RevokedReason); reason != "" {
		update.SetRevokedReason(reason)
	}
	updated, err := update.Save(r.Context())
	if err != nil {
		writeError(w, r, http.StatusConflict, "API_KEY_REVOKE_FAILED", "Failed to revoke API key.", err.Error())
		return
	}
	writeData(w, r, http.StatusOK, apiKeyMap(updated))
}

func (s *Server) loadAPIKeyForAction(w http.ResponseWriter, r *http.Request, keyID, action string) (*coreent.ApiKey, bool) {
	client, ok := s.requireEnt(w, r)
	if !ok {
		return nil, false
	}
	key, err := client.ApiKey.Query().Where(entapikey.ID(keyID), entapikey.DeletedAtIsNil()).Only(r.Context())
	if coreent.IsNotFound(err) {
		writeError(w, r, http.StatusNotFound, "API_KEY_NOT_FOUND", "API key was not found.", nil)
		return nil, false
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load API key.", err.Error())
		return nil, false
	}
	principal, _ := adminPrincipalFrom(r)
	allowed, err := s.principalCanUseAPIKeyScope(r, principal, key, action)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to evaluate API key scope.", err.Error())
		return nil, false
	}
	if !allowed {
		writeError(w, r, http.StatusForbidden, "ADMIN_PERMISSION_REQUIRED", "The current credential cannot access this API key.", map[string]any{"permission": "api_keys:" + action})
		return nil, false
	}
	return key, true
}

func (req *apiKeyMutationRequest) normalize() {
	req.ID = strings.TrimSpace(req.ID)
	req.Name = strings.TrimSpace(req.Name)
	req.Level = strings.TrimSpace(req.Level)
	req.SpaceID = strings.TrimSpace(req.SpaceID)
	req.GroupID = strings.TrimSpace(req.GroupID)
	req.Status = strings.TrimSpace(req.Status)
	req.PermissionKeys = normalizePermissionKeys(req.PermissionKeys)
}

func (s *Server) validateAPIKeyRequest(r *http.Request, req *apiKeyMutationRequest) error {
	if req.Name == "" {
		return validationError("name is required")
	}
	if req.Level == "" {
		return validationError("level is required")
	}
	if len(req.PermissionKeys) == 0 {
		return validationError("permission_keys must contain at least one permission key")
	}
	for _, key := range req.PermissionKeys {
		if !validAdminPermissionKey(key) {
			return validationError("permission_keys entries must be * or domain:action using lowercase letters, digits, hyphen, or underscore")
		}
	}
	if len(apiKeySecrets()) == 0 {
		return validationError("PLYSTRA_API_KEY_SECRET is required before API keys can be created")
	}
	if req.Status != "" && req.Status != "active" && req.Status != "disabled" {
		return validationError("status must be active or disabled")
	}
	if req.ExpiresAt != nil && !req.ExpiresAt.After(time.Now().UTC()) {
		return validationError("expires_at must be in the future")
	}
	client := s.ent
	if client == nil {
		return errAdminEntNotConfigured
	}
	switch req.Level {
	case "instance":
		if req.SpaceID != "" || req.GroupID != "" {
			return validationError("instance API keys must not set space_id or group_id")
		}
	case "space":
		if req.SpaceID == "" {
			return validationError("space API keys require space_id")
		}
		if req.GroupID != "" {
			return validationError("space API keys must not set group_id")
		}
		if _, err := client.Space.Query().Where(entspace.ID(req.SpaceID), entspace.DeletedAtIsNil()).Only(r.Context()); err != nil {
			if coreent.IsNotFound(err) {
				return validationError("space_id does not reference an existing Space")
			}
			return err
		}
	case "group":
		if req.GroupID == "" {
			return validationError("group API keys require group_id")
		}
		group, err := client.Group.Query().Where(entgroup.ID(req.GroupID), entgroup.DeletedAtIsNil()).Only(r.Context())
		if err != nil {
			if coreent.IsNotFound(err) {
				return validationError("group_id does not reference an existing Group")
			}
			return err
		}
		if req.SpaceID == "" {
			req.SpaceID = group.SpaceID
		}
		if req.SpaceID != group.SpaceID {
			return validationError("group_id must belong to space_id")
		}
	default:
		return validationError("level must be instance, space, or group")
	}
	return nil
}

func (s *Server) principalAllowsAPIKeyRequest(r *http.Request, principal adminPrincipal, req apiKeyMutationRequest, action string) (bool, error) {
	return s.adminPrincipalAllows(r.Context(), principal, adminRequirement{
		PermissionKey: "api_keys:" + action,
		SpaceID:       req.SpaceID,
		GroupID:       req.GroupID,
	})
}

func (s *Server) principalCanUseAPIKeyScope(r *http.Request, principal adminPrincipal, key *coreent.ApiKey, action string) (bool, error) {
	return s.adminPrincipalAllows(r.Context(), principal, adminRequirement{
		PermissionKey: "api_keys:" + action,
		SpaceID:       derefString(key.SpaceID),
		GroupID:       derefString(key.GroupID),
	})
}

func normalizePermissionKeys(keys []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		key = strings.ToLower(strings.TrimSpace(key))
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, key)
	}
	return out
}
