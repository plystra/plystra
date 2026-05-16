package api

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	entpermission "github.com/plystra/plystra/ent/permission"
	entrole "github.com/plystra/plystra/ent/role"
	entrolepermission "github.com/plystra/plystra/ent/rolepermission"

	"github.com/jackc/pgx/v5"
	coreent "github.com/plystra/plystra/ent"
	"github.com/plystra/plystra/internal/authz"
)

func (s *Server) handlePermissions(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		s.handlePermissionCreate(w, r)
		return
	}
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, r)
		return
	}
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	permissions, err := client.Permission.Query().
		Where(entpermission.DeletedAtIsNil()).
		Order(entpermission.ByResource(), entpermission.ByAction(), entpermission.ByScope()).
		All(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list Permissions.", err.Error())
		return
	}
	rows := make([]map[string]any, 0, len(permissions))
	for _, permission := range permissions {
		rows = append(rows, permissionMap(permission))
	}
	writeList(w, r, http.StatusOK, rows, limitFrom(r, 50))
}

func (s *Server) handlePermissionDetail(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/permissions/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	id := parts[0]
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			row, err := s.loadPermission(r.Context(), id)
			if errors.Is(err, pgx.ErrNoRows) {
				writeError(w, r, http.StatusNotFound, "PERMISSION_NOT_FOUND", "Permission was not found.", nil)
				return
			}
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load Permission.", err.Error())
				return
			}
			writeData(w, r, http.StatusOK, row)
		case http.MethodPatch:
			s.handlePermissionUpdate(w, r, id)
		default:
			writeMethodNotAllowed(w, r)
		}
		return
	}
	if len(parts) == 2 && parts[1] == "disable" {
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, r)
			return
		}
		var req permissionMutationRequest
		if !decodeOptionalJSON(w, r, &req) {
			return
		}
		row, err := s.updateStatus(r.Context(), "permissions", id, "disabled")
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to disable Permission.", err.Error())
			return
		}
		s.recordMutationAudit(r.Context(), r, req.Actor, req.AuditSpaceID, "permission.disabled", "permission", id, row)
		writeData(w, r, http.StatusOK, row)
		return
	}
	http.NotFound(w, r)
}

type permissionMutationRequest struct {
	Actor        authz.ActorContext `json:"actor"`
	AuditSpaceID string             `json:"audit_space_id"`
	ID           string             `json:"id"`
	Resource     string             `json:"resource"`
	Action       string             `json:"action"`
	Scope        string             `json:"scope"`
	Description  *string            `json:"description"`
	Status       *string            `json:"status"`
	Metadata     map[string]any     `json:"metadata"`
}

func (s *Server) handlePermissionCreate(w http.ResponseWriter, r *http.Request) {
	var req permissionMutationRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Resource == "" || req.Action == "" || req.Scope == "" {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "resource, action, and scope are required.", nil)
		return
	}
	if req.ID == "" {
		req.ID = newEntityID("perm")
	}
	status := firstNonEmpty(derefString(req.Status), "active")
	if req.Scope == string(authz.ScopeGlobal) {
		status = "disabled"
	}
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	_, err := client.Permission.Create().
		SetID(req.ID).
		SetResource(req.Resource).
		SetAction(req.Action).
		SetScope(req.Scope).
		SetNillableDescription(optionalString(derefString(req.Description))).
		SetStatus(status).
		SetMetadata(nonNilMap(req.Metadata)).
		Save(r.Context())
	if err != nil {
		writeError(w, r, http.StatusConflict, "PERMISSION_CREATE_FAILED", "Failed to create Permission.", err.Error())
		return
	}
	row, err := s.loadPermission(r.Context(), req.ID)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load created Permission.", err.Error())
		return
	}
	s.recordMutationAudit(r.Context(), r, req.Actor, req.AuditSpaceID, "permission.created", "permission", req.ID, row)
	writeData(w, r, http.StatusCreated, row)
}

func (s *Server) handlePermissionUpdate(w http.ResponseWriter, r *http.Request, permissionID string) {
	var req permissionMutationRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	current, err := s.loadPermission(r.Context(), permissionID)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, r, http.StatusNotFound, "PERMISSION_NOT_FOUND", "Permission was not found.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load Permission.", err.Error())
		return
	}
	resourceKey := firstNonEmpty(req.Resource, stringFromMap(current, "resource"))
	actionKey := firstNonEmpty(req.Action, stringFromMap(current, "action"))
	scope := firstNonEmpty(req.Scope, stringFromMap(current, "scope"))
	status := firstNonEmpty(derefString(req.Status), stringFromMap(current, "status"), "active")
	if scope == string(authz.ScopeGlobal) {
		status = "disabled"
	}
	metadata := mapFromAny(current["metadata"])
	if req.Metadata != nil {
		metadata = req.Metadata
	}
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	description := nullableFromRequest(req.Description, stringFromMap(current, "description"))
	update := client.Permission.UpdateOneID(permissionID).
		SetResource(resourceKey).
		SetAction(actionKey).
		SetScope(scope).
		SetStatus(status).
		SetMetadata(nonNilMap(metadata))
	if description == "" {
		update.ClearDescription()
	} else {
		update.SetDescription(description)
	}
	err = update.Exec(r.Context())
	if err != nil {
		writeError(w, r, http.StatusConflict, "PERMISSION_UPDATE_FAILED", "Failed to update Permission.", err.Error())
		return
	}
	row, err := s.loadPermission(r.Context(), permissionID)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load updated Permission.", err.Error())
		return
	}
	s.recordMutationAudit(r.Context(), r, req.Actor, req.AuditSpaceID, "permission.updated", "permission", permissionID, row)
	writeData(w, r, http.StatusOK, row)
}

func (s *Server) loadPermission(ctx context.Context, permissionID string) (map[string]any, error) {
	if s.ent == nil {
		return nil, errors.New("ent client is not configured")
	}
	row, err := s.ent.Permission.Query().Where(entpermission.ID(permissionID), entpermission.DeletedAtIsNil()).Only(ctx)
	if coreent.IsNotFound(err) {
		return nil, pgx.ErrNoRows
	}
	if err != nil {
		return nil, err
	}
	return permissionMap(row), nil
}

type rolePermissionMutationRequest struct {
	Actor        authz.ActorContext `json:"actor"`
	AuditSpaceID string             `json:"audit_space_id"`
	ID           string             `json:"id"`
	RoleID       string             `json:"role_id"`
	PermissionID string             `json:"permission_id"`
	Metadata     map[string]any     `json:"metadata"`
}

func (s *Server) handleRolePermissions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var req rolePermissionMutationRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		if req.RoleID == "" || req.PermissionID == "" {
			writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "role_id and permission_id are required.", nil)
			return
		}
		if req.ID == "" {
			req.ID = newEntityID("rp")
		}
		spaceID, err := s.roleSpaceID(r.Context(), req.RoleID)
		if err != nil {
			writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "role_id is invalid.", err.Error())
			return
		}
		if exists, err := s.permissionExists(r.Context(), req.PermissionID); err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to validate Permission.", err.Error())
			return
		} else if !exists {
			writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "permission_id is invalid.", nil)
			return
		}
		client, ok := s.requireEnt(w, r)
		if !ok {
			return
		}
		existing, err := client.RolePermission.Query().Where(entrolepermission.RoleID(req.RoleID), entrolepermission.PermissionID(req.PermissionID)).Only(r.Context())
		if coreent.IsNotFound(err) {
			_, err = client.RolePermission.Create().
				SetID(req.ID).
				SetRoleID(req.RoleID).
				SetPermissionID(req.PermissionID).
				SetMetadata(nonNilMap(req.Metadata)).
				Save(r.Context())
		} else if err == nil {
			err = client.RolePermission.UpdateOneID(existing.ID).
				ClearDeletedAt().
				SetMetadata(nonNilMap(req.Metadata)).
				Exec(r.Context())
		}
		if err != nil {
			writeError(w, r, http.StatusConflict, "ROLE_PERMISSION_CREATE_FAILED", "Failed to create RolePermission.", err.Error())
			return
		}
		row, err := s.loadRolePermissionByPair(r.Context(), req.RoleID, req.PermissionID)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load RolePermission.", err.Error())
			return
		}
		s.recordMutationAudit(r.Context(), r, req.Actor, firstNonEmpty(req.AuditSpaceID, spaceID), "role_permission.created", "role_permission", stringFromMap(row, "id"), row)
		writeData(w, r, http.StatusCreated, row)
	case http.MethodGet:
		limit := limitFrom(r, 50)
		client, ok := s.requireEnt(w, r)
		if !ok {
			return
		}
		rolePermissions, err := client.RolePermission.Query().
			Where(entrolepermission.DeletedAtIsNil()).
			Limit(limit).
			All(r.Context())
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list RolePermissions.", err.Error())
			return
		}
		rows := make([]map[string]any, 0, len(rolePermissions))
		for _, rolePermission := range rolePermissions {
			row, err := s.rolePermissionMapWithRefs(r.Context(), rolePermission)
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list RolePermissions.", err.Error())
				return
			}
			rows = append(rows, row)
		}
		sort.SliceStable(rows, func(i, j int) bool {
			for _, key := range []string{"space_id", "role_key", "resource", "action", "scope"} {
				left, _ := rows[i][key].(string)
				right, _ := rows[j][key].(string)
				if left != right {
					return left < right
				}
			}
			return false
		})
		writeList(w, r, http.StatusOK, rows, limit)
	default:
		writeMethodNotAllowed(w, r)
	}
}

func (s *Server) handleRolePermissionSubroutes(w http.ResponseWriter, r *http.Request) {
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/role-permissions/"), "/")
	if id == "" {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		row, err := s.loadRolePermission(r.Context(), id)
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, r, http.StatusNotFound, "ROLE_PERMISSION_NOT_FOUND", "RolePermission was not found.", nil)
			return
		}
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load RolePermission.", err.Error())
			return
		}
		writeData(w, r, http.StatusOK, row)
	case http.MethodDelete:
		var req rolePermissionMutationRequest
		if !decodeOptionalJSON(w, r, &req) {
			return
		}
		row, err := s.loadRolePermission(r.Context(), id)
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, r, http.StatusNotFound, "ROLE_PERMISSION_NOT_FOUND", "RolePermission was not found.", nil)
			return
		}
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load RolePermission.", err.Error())
			return
		}
		client, ok := s.requireEnt(w, r)
		if !ok {
			return
		}
		err = client.RolePermission.UpdateOneID(id).SetDeletedAt(time.Now().UTC()).Exec(r.Context())
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to revoke RolePermission.", err.Error())
			return
		}
		s.recordMutationAudit(r.Context(), r, req.Actor, firstNonEmpty(req.AuditSpaceID, stringFromMap(row, "space_id")), "role_permission.revoked", "role_permission", id, row)
		writeData(w, r, http.StatusOK, row)
	default:
		writeMethodNotAllowed(w, r)
	}
}

func (s *Server) loadRolePermission(ctx context.Context, id string) (map[string]any, error) {
	if s.ent == nil {
		return nil, errors.New("ent client is not configured")
	}
	row, err := s.ent.RolePermission.Query().Where(entrolepermission.ID(id), entrolepermission.DeletedAtIsNil()).Only(ctx)
	if coreent.IsNotFound(err) {
		return nil, pgx.ErrNoRows
	}
	if err != nil {
		return nil, err
	}
	return s.rolePermissionMapWithRefs(ctx, row)
}

func (s *Server) loadRolePermissionByPair(ctx context.Context, roleID, permissionID string) (map[string]any, error) {
	if s.ent == nil {
		return nil, errors.New("ent client is not configured")
	}
	row, err := s.ent.RolePermission.Query().Where(entrolepermission.RoleID(roleID), entrolepermission.PermissionID(permissionID), entrolepermission.DeletedAtIsNil()).Only(ctx)
	if coreent.IsNotFound(err) {
		return nil, pgx.ErrNoRows
	}
	if err != nil {
		return nil, err
	}
	return s.rolePermissionMapWithRefs(ctx, row)
}

func (s *Server) roleSpaceID(ctx context.Context, roleID string) (string, error) {
	if s.ent == nil {
		return "", errors.New("ent client is not configured")
	}
	role, err := s.ent.Role.Query().Where(entrole.ID(roleID), entrole.DeletedAtIsNil()).Only(ctx)
	if coreent.IsNotFound(err) {
		return "", pgx.ErrNoRows
	}
	if err != nil {
		return "", err
	}
	return role.SpaceID, nil
}

func (s *Server) permissionExists(ctx context.Context, permissionID string) (bool, error) {
	if s.ent == nil {
		return false, errors.New("ent client is not configured")
	}
	return s.ent.Permission.Query().Where(entpermission.ID(permissionID), entpermission.DeletedAtIsNil()).Exist(ctx)
}

func (s *Server) rolePermissionMapWithRefs(ctx context.Context, row *coreent.RolePermission) (map[string]any, error) {
	roleRecord, err := s.ent.Role.Query().Where(entrole.ID(row.RoleID), entrole.DeletedAtIsNil()).Only(ctx)
	if err != nil {
		if coreent.IsNotFound(err) {
			roleRecord = &coreent.Role{}
		} else {
			return nil, err
		}
	}
	permissionRecord, err := s.ent.Permission.Query().Where(entpermission.ID(row.PermissionID), entpermission.DeletedAtIsNil()).Only(ctx)
	if err != nil {
		if coreent.IsNotFound(err) {
			permissionRecord = &coreent.Permission{}
		} else {
			return nil, err
		}
	}
	return rolePermissionMap(row, roleRecord.SpaceID, roleRecord.Key, permissionRecord), nil
}
