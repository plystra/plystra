package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	entgroup "github.com/plystra/plystra/ent/group"
	entmemberrole "github.com/plystra/plystra/ent/memberrole"
	"github.com/plystra/plystra/ent/predicate"
	entrole "github.com/plystra/plystra/ent/role"

	"github.com/jackc/pgx/v5"
	coreent "github.com/plystra/plystra/ent"
	entmember "github.com/plystra/plystra/ent/member"
	"github.com/plystra/plystra/internal/authz"
)

type roleMutationRequest struct {
	Actor       authz.ActorContext `json:"actor"`
	ID          string             `json:"id"`
	Key         string             `json:"key"`
	Name        string             `json:"name"`
	Description *string            `json:"description"`
	Status      *string            `json:"status"`
	Metadata    map[string]any     `json:"metadata"`
}

func (s *Server) handleSpaceRoles(w http.ResponseWriter, r *http.Request, spaceID string, parts []string) {
	if len(parts) == 0 {
		switch r.Method {
		case http.MethodPost:
			var req roleMutationRequest
			if !decodeJSON(w, r, &req) {
				return
			}
			if req.Key == "" {
				writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "key is required.", nil)
				return
			}
			if req.ID == "" {
				req.ID = newEntityID("role")
			}
			client, ok := s.requireEnt(w, r)
			if !ok {
				return
			}
			_, err := client.Role.Create().
				SetID(req.ID).
				SetSpaceID(spaceID).
				SetKey(req.Key).
				SetName(firstNonEmpty(req.Name, titleFromKey(req.Key))).
				SetNillableDescription(optionalString(derefString(req.Description))).
				SetStatus(firstNonEmpty(derefString(req.Status), "active")).
				SetMetadata(nonNilMap(req.Metadata)).
				Save(r.Context())
			if err != nil {
				writeError(w, r, http.StatusConflict, "ROLE_CREATE_FAILED", "Failed to create Role.", err.Error())
				return
			}
			row, err := s.loadRoleInSpace(r.Context(), spaceID, req.ID)
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load created Role.", err.Error())
				return
			}
			s.recordMutationAudit(r.Context(), r, req.Actor, spaceID, "role.created", "role", req.ID, row)
			writeData(w, r, http.StatusCreated, row)
		case http.MethodGet:
			limit := limitFrom(r, 50)
			client, ok := s.requireEnt(w, r)
			if !ok {
				return
			}
			roles, err := client.Role.Query().
				Where(entrole.SpaceID(spaceID), entrole.DeletedAtIsNil()).
				Order(entrole.ByKey()).
				Limit(limit).
				All(r.Context())
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list Roles.", err.Error())
				return
			}
			rows := make([]map[string]any, 0, len(roles))
			for _, role := range roles {
				rows = append(rows, roleMap(role))
			}
			writeList(w, r, http.StatusOK, rows, limit)
		default:
			writeMethodNotAllowed(w, r)
		}
		return
	}
	roleID := parts[0]
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			row, err := s.loadRoleInSpace(r.Context(), spaceID, roleID)
			if errors.Is(err, pgx.ErrNoRows) {
				writeError(w, r, http.StatusNotFound, "ROLE_NOT_FOUND", "Role was not found.", nil)
				return
			}
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load Role.", err.Error())
				return
			}
			writeData(w, r, http.StatusOK, row)
		case http.MethodPatch:
			s.handleRoleUpdate(w, r, spaceID, roleID)
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
		var req roleMutationRequest
		if !decodeOptionalJSON(w, r, &req) {
			return
		}
		row, err := s.updateScopedStatus(r.Context(), "roles", roleID, spaceID, "disabled")
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to disable Role.", err.Error())
			return
		}
		s.recordMutationAudit(r.Context(), r, req.Actor, spaceID, "role.disabled", "role", roleID, row)
		writeData(w, r, http.StatusOK, row)
		return
	}
	http.NotFound(w, r)
}

func (s *Server) handleRoleUpdate(w http.ResponseWriter, r *http.Request, spaceID, roleID string) {
	var req roleMutationRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	current, err := s.loadRoleInSpace(r.Context(), spaceID, roleID)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, r, http.StatusNotFound, "ROLE_NOT_FOUND", "Role was not found.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load Role.", err.Error())
		return
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
	update := client.Role.UpdateOneID(roleID).
		SetName(firstNonEmpty(req.Name, stringFromMap(current, "name"))).
		SetStatus(firstNonEmpty(derefString(req.Status), stringFromMap(current, "status"), "active")).
		SetMetadata(nonNilMap(metadata))
	if description == "" {
		update.ClearDescription()
	} else {
		update.SetDescription(description)
	}
	err = update.Exec(r.Context())
	if err != nil {
		writeError(w, r, http.StatusConflict, "ROLE_UPDATE_FAILED", "Failed to update Role.", err.Error())
		return
	}
	row, err := s.loadRoleInSpace(r.Context(), spaceID, roleID)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load updated Role.", err.Error())
		return
	}
	s.recordMutationAudit(r.Context(), r, req.Actor, spaceID, "role.updated", "role", roleID, row)
	writeData(w, r, http.StatusOK, row)
}

func (s *Server) loadRoleInSpace(ctx context.Context, spaceID, roleID string) (map[string]any, error) {
	if s.ent == nil {
		return nil, errors.New("ent client is not configured")
	}
	row, err := s.ent.Role.Query().Where(entrole.ID(roleID), entrole.SpaceID(spaceID), entrole.DeletedAtIsNil()).Only(ctx)
	if coreent.IsNotFound(err) {
		return nil, pgx.ErrNoRows
	}
	if err != nil {
		return nil, err
	}
	return roleMap(row), nil
}

type memberRoleMutationRequest struct {
	Actor              authz.ActorContext `json:"actor"`
	ID                 string             `json:"id"`
	MemberID           string             `json:"member_id"`
	RoleID             string             `json:"role_id"`
	ScopeAnchorGroupID *string            `json:"scope_anchor_group_id"`
	Status             *string            `json:"status"`
	Metadata           map[string]any     `json:"metadata"`
}

func (s *Server) handleSpaceMemberRoles(w http.ResponseWriter, r *http.Request, spaceID string, parts []string) {
	if len(parts) == 0 {
		switch r.Method {
		case http.MethodPost:
			var req memberRoleMutationRequest
			if !decodeJSON(w, r, &req) {
				return
			}
			if req.MemberID == "" || req.RoleID == "" {
				writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "member_id and role_id are required.", nil)
				return
			}
			if req.ID == "" {
				req.ID = newEntityID("mr")
			}
			if err := s.validateMemberRoleRefs(r.Context(), spaceID, req.MemberID, req.RoleID, derefString(req.ScopeAnchorGroupID)); err != nil {
				writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "MemberRole references are invalid.", err.Error())
				return
			}
			client, ok := s.requireEnt(w, r)
			if !ok {
				return
			}
			_, err := client.MemberRole.Create().
				SetID(req.ID).
				SetMemberID(req.MemberID).
				SetRoleID(req.RoleID).
				SetSpaceID(spaceID).
				SetNillableScopeAnchorGroupID(optionalString(derefString(req.ScopeAnchorGroupID))).
				SetStatus(firstNonEmpty(derefString(req.Status), "active")).
				SetMetadata(nonNilMap(req.Metadata)).
				Save(r.Context())
			if err != nil {
				writeError(w, r, http.StatusConflict, "MEMBER_ROLE_CREATE_FAILED", "Failed to create MemberRole.", err.Error())
				return
			}
			row, err := s.loadMemberRoleInSpace(r.Context(), spaceID, req.ID)
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load created MemberRole.", err.Error())
				return
			}
			s.recordMutationAudit(r.Context(), r, req.Actor, spaceID, "member_role.created", "member_role", req.ID, row)
			writeData(w, r, http.StatusCreated, row)
		case http.MethodGet:
			s.listMemberRoles(w, r, spaceID)
		default:
			writeMethodNotAllowed(w, r)
		}
		return
	}
	memberRoleID := parts[0]
	if len(parts) == 1 {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, r)
			return
		}
		row, err := s.loadMemberRoleInSpace(r.Context(), spaceID, memberRoleID)
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, r, http.StatusNotFound, "MEMBER_ROLE_NOT_FOUND", "MemberRole was not found.", nil)
			return
		}
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load MemberRole.", err.Error())
			return
		}
		writeData(w, r, http.StatusOK, row)
		return
	}
	if len(parts) == 2 && parts[1] == "revoke" {
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, r)
			return
		}
		var req memberRoleMutationRequest
		if !decodeOptionalJSON(w, r, &req) {
			return
		}
		row, err := s.updateScopedStatus(r.Context(), "member_roles", memberRoleID, spaceID, "revoked")
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to revoke MemberRole.", err.Error())
			return
		}
		s.recordMutationAudit(r.Context(), r, req.Actor, spaceID, "member_role.revoked", "member_role", memberRoleID, row)
		writeData(w, r, http.StatusOK, row)
		return
	}
	http.NotFound(w, r)
}

func (s *Server) listMemberRoles(w http.ResponseWriter, r *http.Request, spaceID string) {
	limit := limitFrom(r, 50)
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	predicates := []predicate.MemberRole{entmemberrole.SpaceID(spaceID), entmemberrole.DeletedAtIsNil()}
	if memberID := strings.TrimSpace(r.URL.Query().Get("member_id")); memberID != "" {
		predicates = append(predicates, entmemberrole.MemberID(memberID))
	}
	if roleID := strings.TrimSpace(r.URL.Query().Get("role_id")); roleID != "" {
		predicates = append(predicates, entmemberrole.RoleID(roleID))
	}
	if status := strings.TrimSpace(r.URL.Query().Get("status")); status != "" {
		predicates = append(predicates, entmemberrole.Status(status))
	}
	memberRoles, err := client.MemberRole.Query().
		Where(predicates...).
		Limit(limit).
		All(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list MemberRoles.", err.Error())
		return
	}
	rows := make([]map[string]any, 0, len(memberRoles))
	for _, memberRole := range memberRoles {
		row, err := s.memberRoleMapWithRefs(r.Context(), memberRole)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list MemberRoles.", err.Error())
			return
		}
		rows = append(rows, row)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		leftMember, _ := rows[i]["member_display_name"].(string)
		rightMember, _ := rows[j]["member_display_name"].(string)
		if leftMember != rightMember {
			return leftMember < rightMember
		}
		leftRole, _ := rows[i]["role_key"].(string)
		rightRole, _ := rows[j]["role_key"].(string)
		return leftRole < rightRole
	})
	writeList(w, r, http.StatusOK, rows, limit)
}

func (s *Server) loadMemberRoleInSpace(ctx context.Context, spaceID, memberRoleID string) (map[string]any, error) {
	if s.ent == nil {
		return nil, errors.New("ent client is not configured")
	}
	row, err := s.ent.MemberRole.Query().Where(entmemberrole.ID(memberRoleID), entmemberrole.SpaceID(spaceID), entmemberrole.DeletedAtIsNil()).Only(ctx)
	if coreent.IsNotFound(err) {
		return nil, pgx.ErrNoRows
	}
	if err != nil {
		return nil, err
	}
	return s.memberRoleMapWithRefs(ctx, row)
}

func (s *Server) validateMemberRoleRefs(ctx context.Context, spaceID, memberID, roleID, anchorID string) error {
	if err := s.validateMemberInSpace(ctx, spaceID, memberID); err != nil {
		return err
	}
	if s.ent == nil {
		return errors.New("ent client is not configured")
	}
	roleExists, err := s.ent.Role.Query().Where(entrole.ID(roleID), entrole.SpaceID(spaceID), entrole.DeletedAtIsNil()).Exist(ctx)
	if err != nil {
		return err
	}
	if !roleExists {
		return fmt.Errorf("role %s is not in space %s", roleID, spaceID)
	}
	if anchorID != "" {
		if _, err := s.loadGroupInSpace(ctx, spaceID, anchorID); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) memberRoleMapWithRefs(ctx context.Context, row *coreent.MemberRole) (map[string]any, error) {
	memberRecord, err := s.ent.Member.Query().Where(entmember.ID(row.MemberID), entmember.DeletedAtIsNil()).Only(ctx)
	if coreent.IsNotFound(err) {
		memberRecord = &coreent.Member{}
	} else if err != nil {
		return nil, err
	}
	roleRecord, err := s.ent.Role.Query().Where(entrole.ID(row.RoleID), entrole.DeletedAtIsNil()).Only(ctx)
	if coreent.IsNotFound(err) {
		roleRecord = &coreent.Role{}
	} else if err != nil {
		return nil, err
	}
	anchorPath := ""
	if anchorID := derefString(row.ScopeAnchorGroupID); anchorID != "" {
		groupRecord, err := s.ent.Group.Query().Where(entgroup.ID(anchorID), entgroup.DeletedAtIsNil()).Only(ctx)
		if err != nil && !coreent.IsNotFound(err) {
			return nil, err
		}
		if groupRecord != nil {
			anchorPath = groupRecord.Path
		}
	}
	return memberRoleMap(row, memberRecord.DisplayName, roleRecord.Key, roleRecord.Name, anchorPath), nil
}
