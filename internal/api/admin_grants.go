package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	entsql "entgo.io/ent/dialect/sql"
	coreent "github.com/plystra/plystra/ent"
	entadmingrant "github.com/plystra/plystra/ent/admingrant"
	entgroup "github.com/plystra/plystra/ent/group"
	entmember "github.com/plystra/plystra/ent/member"
	entspace "github.com/plystra/plystra/ent/space"
	entuser "github.com/plystra/plystra/ent/user"
)

type adminGrantMutationRequest struct {
	ID            string         `json:"id"`
	UserID        string         `json:"user_id"`
	MemberID      string         `json:"member_id"`
	SpaceID       string         `json:"space_id"`
	GroupID       string         `json:"group_id"`
	Level         string         `json:"level"`
	PermissionKey string         `json:"permission_key"`
	Status        string         `json:"status"`
	ExpiresAt     *time.Time     `json:"expires_at"`
	RevokedReason string         `json:"revoked_reason"`
	Metadata      map[string]any `json:"metadata"`
}

func (s *Server) handleAdminMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, r)
		return
	}
	principal, ok := adminPrincipalFrom(r)
	if !ok {
		writeError(w, r, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED", "A valid access token is required.", nil)
		return
	}
	grants := make([]map[string]any, 0, len(principal.Grants))
	capabilities := map[string]bool{}
	for _, grant := range principal.Grants {
		grants = append(grants, adminGrantMap(grant))
		capabilities[grant.PermissionKey] = true
		if grant.Level == adminLevelInstanceSuper {
			capabilities["*"] = true
		}
	}
	out := map[string]any{
		"credential_type": principal.CredentialType,
		"session_id":      principal.Session.ID,
		"user_id":         principal.Session.UserID,
		"active_space":    principal.Session.ActiveSpaceID,
		"active_member":   principal.Session.ActiveMemberID,
		"grants":          grants,
		"capabilities":    capabilities,
	}
	if principal.CredentialType == "api_key" && principal.APIKey != nil {
		for _, key := range principal.APIKey.PermissionKeys {
			capabilities[key] = true
		}
		out["api_key"] = apiKeyMap(principal.APIKey)
	}
	writeData(w, r, http.StatusOK, out)
}

func (s *Server) handleAdminGrants(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listAdminGrants(w, r)
	case http.MethodPost:
		s.createAdminGrant(w, r)
	default:
		writeMethodNotAllowed(w, r)
	}
}

func (s *Server) handleAdminGrantSubroutes(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/admin/grants/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	grantID := parts[0]
	if len(parts) == 1 {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, r)
			return
		}
		client, ok := s.requireEnt(w, r)
		if !ok {
			return
		}
		grant, err := client.AdminGrant.Query().Where(entadmingrant.ID(grantID), entadmingrant.DeletedAtIsNil()).Only(r.Context())
		if coreent.IsNotFound(err) {
			writeError(w, r, http.StatusNotFound, "ADMIN_GRANT_NOT_FOUND", "AdminGrant was not found.", nil)
			return
		}
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load AdminGrant.", err.Error())
			return
		}
		principal, _ := adminPrincipalFrom(r)
		allowed, err := s.principalCanUseAdminGrant(r.Context(), principal, grant, "read")
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to evaluate AdminGrant visibility.", err.Error())
			return
		}
		if !allowed {
			writeError(w, r, http.StatusForbidden, "ADMIN_PERMISSION_REQUIRED", "The current user cannot access this admin grant.", map[string]any{"permission": "admin_grants:read"})
			return
		}
		writeData(w, r, http.StatusOK, adminGrantMap(grant))
		return
	}
	if len(parts) == 2 && parts[1] == "revoke" {
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, r)
			return
		}
		s.revokeAdminGrant(w, r, grantID)
		return
	}
	http.NotFound(w, r)
}

func (s *Server) listAdminGrants(w http.ResponseWriter, r *http.Request) {
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	limit := limitFrom(r, 100)
	q := client.AdminGrant.Query().Where(entadmingrant.DeletedAtIsNil())
	if value := strings.TrimSpace(r.URL.Query().Get("user_id")); value != "" {
		q = q.Where(entadmingrant.UserID(value))
	}
	if value := strings.TrimSpace(r.URL.Query().Get("level")); value != "" {
		q = q.Where(entadmingrant.Level(value))
	}
	if value := strings.TrimSpace(r.URL.Query().Get("space_id")); value != "" {
		q = q.Where(entadmingrant.SpaceID(value))
	}
	if value := strings.TrimSpace(r.URL.Query().Get("group_id")); value != "" {
		q = q.Where(entadmingrant.GroupID(value))
	}
	if value := strings.TrimSpace(r.URL.Query().Get("status")); value != "" {
		q = q.Where(entadmingrant.Status(value))
	}
	grants, err := q.Order(entadmingrant.ByCreatedAt(entsql.OrderDesc())).Limit(limit).All(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list AdminGrants.", err.Error())
		return
	}
	rows := make([]map[string]any, 0, len(grants))
	principal, _ := adminPrincipalFrom(r)
	for _, grant := range grants {
		allowed, err := s.principalCanUseAdminGrant(r.Context(), principal, grant, "read")
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to evaluate AdminGrant visibility.", err.Error())
			return
		}
		if allowed {
			rows = append(rows, adminGrantMap(grant))
		}
	}
	writeList(w, r, http.StatusOK, rows, limit)
}

func (s *Server) createAdminGrant(w http.ResponseWriter, r *http.Request) {
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	var req adminGrantMutationRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.normalize()
	if err := s.validateAdminGrantRequest(r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "AdminGrant is invalid.", err.Error())
		return
	}
	principal, _ := adminPrincipalFrom(r)
	if principal.CredentialType != "session" {
		writeError(w, r, http.StatusForbidden, "ADMIN_PERMISSION_REQUIRED", "Only an authenticated user session can create admin grants.", nil)
		return
	}
	if !canCreateAdminGrantLevel(principal, req.Level) {
		writeError(w, r, http.StatusForbidden, "ADMIN_PERMISSION_REQUIRED", "Only an instance super admin can create instance-level admin grants.", nil)
		return
	}
	if allowed, err := s.principalCanUseAdminGrantRequest(r.Context(), principal, req, "manage"); err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to evaluate AdminGrant scope.", err.Error())
		return
	} else if !allowed {
		writeError(w, r, http.StatusForbidden, "ADMIN_PERMISSION_REQUIRED", "The current user cannot create admin grants for this scope.", map[string]any{"permission": "admin_grants:manage"})
		return
	}
	if allowed, deniedPermission, err := s.principalCanDelegatePermissions(r.Context(), principal, []string{req.PermissionKey}, req.SpaceID, req.GroupID); err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to evaluate delegated admin permission.", err.Error())
		return
	} else if !allowed {
		writeError(w, r, http.StatusForbidden, "ADMIN_PERMISSION_REQUIRED", "The current user cannot delegate this admin permission.", map[string]any{"permission": deniedPermission})
		return
	}
	if req.ID == "" {
		req.ID = newEntityID("ag")
	}
	grant, err := client.AdminGrant.Create().
		SetID(req.ID).
		SetUserID(req.UserID).
		SetNillableMemberID(optionalString(req.MemberID)).
		SetNillableSpaceID(optionalString(req.SpaceID)).
		SetNillableGroupID(optionalString(req.GroupID)).
		SetLevel(req.Level).
		SetPermissionKey(req.PermissionKey).
		SetStatus(firstNonEmpty(req.Status, "active")).
		SetNillableGrantedByUserID(optionalString(principal.Session.UserID)).
		SetNillableGrantedByMemberID(optionalString(principal.Session.ActiveMemberID)).
		SetNillableExpiresAt(req.ExpiresAt).
		SetMetadata(nonNilMap(req.Metadata)).
		Save(r.Context())
	if err != nil {
		writeError(w, r, http.StatusConflict, "ADMIN_GRANT_CREATE_FAILED", "Failed to create AdminGrant.", err.Error())
		return
	}
	writeData(w, r, http.StatusCreated, adminGrantMap(grant))
}

func (s *Server) revokeAdminGrant(w http.ResponseWriter, r *http.Request, grantID string) {
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	var req adminGrantMutationRequest
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}
	grant, err := client.AdminGrant.Query().Where(entadmingrant.ID(grantID), entadmingrant.DeletedAtIsNil()).Only(r.Context())
	if coreent.IsNotFound(err) {
		writeError(w, r, http.StatusNotFound, "ADMIN_GRANT_NOT_FOUND", "AdminGrant was not found.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load AdminGrant.", err.Error())
		return
	}
	principal, _ := adminPrincipalFrom(r)
	if principal.CredentialType != "session" {
		writeError(w, r, http.StatusForbidden, "ADMIN_PERMISSION_REQUIRED", "Only an authenticated user session can revoke admin grants.", nil)
		return
	}
	if !canCreateAdminGrantLevel(principal, grant.Level) {
		writeError(w, r, http.StatusForbidden, "ADMIN_PERMISSION_REQUIRED", "Only an instance super admin can revoke instance-level admin grants.", nil)
		return
	}
	if allowed, err := s.principalCanUseAdminGrant(r.Context(), principal, grant, "manage"); err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to evaluate AdminGrant scope.", err.Error())
		return
	} else if !allowed {
		writeError(w, r, http.StatusForbidden, "ADMIN_PERMISSION_REQUIRED", "The current user cannot revoke admin grants for this scope.", map[string]any{"permission": "admin_grants:manage"})
		return
	}
	if allowed, deniedPermission, err := s.principalCanDelegatePermissions(r.Context(), principal, []string{grant.PermissionKey}, derefString(grant.SpaceID), derefString(grant.GroupID)); err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to evaluate delegated admin permission.", err.Error())
		return
	} else if !allowed {
		writeError(w, r, http.StatusForbidden, "ADMIN_PERMISSION_REQUIRED", "The current user cannot revoke grants carrying this admin permission.", map[string]any{"permission": deniedPermission})
		return
	}
	if grant.Level == adminLevelInstanceSuper {
		count, err := client.AdminGrant.Query().
			Where(
				entadmingrant.Level(adminLevelInstanceSuper),
				entadmingrant.Status("active"),
				entadmingrant.DeletedAtIsNil(),
				entadmingrant.RevokedAtIsNil(),
			).
			Count(r.Context())
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to verify super admin grants.", err.Error())
			return
		}
		if count <= 1 {
			writeError(w, r, http.StatusConflict, "LAST_SUPER_ADMIN", "The last active instance super admin grant cannot be revoked.", nil)
			return
		}
	}
	now := time.Now().UTC()
	update := client.AdminGrant.UpdateOneID(grantID).
		SetStatus("revoked").
		SetRevokedAt(now)
	if reason := strings.TrimSpace(req.RevokedReason); reason != "" {
		update.SetRevokedReason(reason)
	}
	updated, err := update.Save(r.Context())
	if err != nil {
		writeError(w, r, http.StatusConflict, "ADMIN_GRANT_REVOKE_FAILED", "Failed to revoke AdminGrant.", err.Error())
		return
	}
	writeData(w, r, http.StatusOK, adminGrantMap(updated))
}

func (req *adminGrantMutationRequest) normalize() {
	req.ID = strings.TrimSpace(req.ID)
	req.UserID = strings.TrimSpace(req.UserID)
	req.MemberID = strings.TrimSpace(req.MemberID)
	req.SpaceID = strings.TrimSpace(req.SpaceID)
	req.GroupID = strings.TrimSpace(req.GroupID)
	req.Level = strings.TrimSpace(req.Level)
	req.PermissionKey = strings.ToLower(strings.TrimSpace(req.PermissionKey))
	req.Status = strings.TrimSpace(req.Status)
}

func (s *Server) validateAdminGrantRequest(r *http.Request, req *adminGrantMutationRequest) error {
	if req.UserID == "" {
		return validationError("user_id is required")
	}
	if req.Level == "" {
		return validationError("level is required")
	}
	if req.PermissionKey == "" {
		return validationError("permission_key is required")
	}
	if !validAdminPermissionKey(req.PermissionKey) {
		return validationError("permission_key must be * or domain:action using lowercase letters, digits, hyphen, or underscore")
	}
	client := s.ent
	if client == nil {
		return errAdminEntNotConfigured
	}
	if _, err := client.User.Query().Where(entuser.ID(req.UserID), entuser.DeletedAtIsNil()).Only(r.Context()); err != nil {
		if coreent.IsNotFound(err) {
			return validationError("user_id does not reference an existing User")
		}
		return err
	}
	if req.MemberID != "" {
		if _, err := client.Member.Query().Where(entmember.ID(req.MemberID), entmember.DeletedAtIsNil()).Only(r.Context()); err != nil {
			if coreent.IsNotFound(err) {
				return validationError("member_id does not reference an existing Member")
			}
			return err
		}
	}
	switch req.Level {
	case adminLevelInstanceSuper, adminLevelInstance:
		if req.SpaceID != "" || req.GroupID != "" {
			return validationError("instance admin grants must not set space_id or group_id")
		}
	case adminLevelSpace:
		if req.SpaceID == "" {
			return validationError("space_admin grants require space_id")
		}
		if req.GroupID != "" {
			return validationError("space_admin grants must not set group_id")
		}
		if _, err := client.Space.Query().Where(entspace.ID(req.SpaceID), entspace.DeletedAtIsNil()).Only(r.Context()); err != nil {
			if coreent.IsNotFound(err) {
				return validationError("space_id does not reference an existing Space")
			}
			return err
		}
	case adminLevelGroup:
		if req.GroupID == "" {
			return validationError("group_admin grants require group_id")
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
		return validationError("level must be instance_super_admin, instance_admin, space_admin, or group_admin")
	}
	return nil
}

func adminPrincipalFrom(r *http.Request) (adminPrincipal, bool) {
	value, ok := r.Context().Value(adminPrincipalKey).(adminPrincipal)
	return value, ok
}

func canCreateAdminGrantLevel(principal adminPrincipal, level string) bool {
	if level != adminLevelInstanceSuper && level != adminLevelInstance {
		return true
	}
	return adminPrincipalIsSuper(principal)
}

func (s *Server) principalCanUseAdminGrantRequest(ctx context.Context, principal adminPrincipal, req adminGrantMutationRequest, action string) (bool, error) {
	permissionKey := "admin_grants:" + action
	if req.Level == adminLevelInstanceSuper || req.Level == adminLevelInstance || (req.SpaceID == "" && req.GroupID == "") {
		return adminPrincipalHasInstanceReach(principal, permissionKey), nil
	}
	return s.adminPrincipalAllows(ctx, principal, adminRequirement{
		PermissionKey: permissionKey,
		SpaceID:       req.SpaceID,
		GroupID:       req.GroupID,
	})
}

func (s *Server) principalCanUseAdminGrant(ctx context.Context, principal adminPrincipal, grant *coreent.AdminGrant, action string) (bool, error) {
	if grant == nil {
		return false, nil
	}
	permissionKey := "admin_grants:" + action
	if grant.Level == adminLevelInstanceSuper || grant.Level == adminLevelInstance || (derefString(grant.SpaceID) == "" && derefString(grant.GroupID) == "") {
		return adminPrincipalHasInstanceReach(principal, permissionKey), nil
	}
	return s.adminPrincipalAllows(ctx, principal, adminRequirement{
		PermissionKey: permissionKey,
		SpaceID:       derefString(grant.SpaceID),
		GroupID:       derefString(grant.GroupID),
	})
}

func validationError(message string) error {
	return errors.New(message)
}
