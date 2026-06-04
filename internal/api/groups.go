package api

import (
	"context"
	"errors"
	"net/http"
	"strings"

	entgroup "github.com/plystra/core/ent/group"

	"github.com/jackc/pgx/v5"
	coreent "github.com/plystra/core/ent"
	"github.com/plystra/core/internal/authz"
)

type groupMutationRequest struct {
	Actor         authz.ActorContext `json:"actor"`
	ID            string             `json:"id"`
	ParentID      *string            `json:"parent_id"`
	ParentGroupID *string            `json:"parent_group_id"`
	Name          string             `json:"name"`
	DisplayName   *string            `json:"display_name"`
	Path          string             `json:"path"`
	SortOrder     *int               `json:"sort_order"`
	Status        *string            `json:"status"`
	Metadata      map[string]any     `json:"metadata"`
}

func (s *Server) handleSpaceGroups(w http.ResponseWriter, r *http.Request, spaceID string, parts []string) {
	if len(parts) == 0 {
		switch r.Method {
		case http.MethodPost:
			var req groupMutationRequest
			if !decodeJSON(w, r, &req) {
				return
			}
			if strings.TrimSpace(req.Path) == "" {
				writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "path is required.", nil)
				return
			}
			if req.ID == "" {
				req.ID = newEntityID("group")
			}
			parentID := firstNonEmpty(derefString(req.ParentGroupID), derefString(req.ParentID))
			if parentID != "" {
				if _, err := s.loadGroupInSpace(r.Context(), spaceID, parentID); err != nil {
					writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "parent_id must belong to the same Space.", err.Error())
					return
				}
			}
			name := firstNonEmpty(req.Name, derefString(req.DisplayName), titleFromKey(lastPathSegment(req.Path)))
			client, ok := s.requireEnt(w, r)
			if !ok {
				return
			}
			_, err := client.Group.Create().
				SetID(req.ID).
				SetSpaceID(spaceID).
				SetNillableParentGroupID(optionalString(parentID)).
				SetName(name).
				SetNillableDisplayName(optionalString(derefString(req.DisplayName))).
				SetPath(req.Path).
				SetDepth(pathDepth(req.Path)).
				SetSortOrder(intValue(req.SortOrder, 1000)).
				SetStatus(firstNonEmpty(derefString(req.Status), "active")).
				SetMetadata(nonNilMap(req.Metadata)).
				Save(r.Context())
			if err != nil {
				writeError(w, r, http.StatusConflict, "GROUP_CREATE_FAILED", "Failed to create Group.", err.Error())
				return
			}
			row, err := s.loadGroupInSpace(r.Context(), spaceID, req.ID)
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load created Group.", err.Error())
				return
			}
			s.recordMutationAudit(r.Context(), r, req.Actor, spaceID, "group.created", "group", req.ID, row)
			writeData(w, r, http.StatusCreated, row)
		case http.MethodGet:
			s.listGroups(w, r, spaceID)
		default:
			writeMethodNotAllowed(w, r)
		}
		return
	}
	if len(parts) == 1 && parts[0] == "tree" {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, r)
			return
		}
		s.listGroups(w, r, spaceID)
		return
	}
	groupID := parts[0]
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			row, err := s.loadGroupInSpace(r.Context(), spaceID, groupID)
			if errors.Is(err, pgx.ErrNoRows) {
				writeError(w, r, http.StatusNotFound, "GROUP_NOT_FOUND", "Group was not found.", nil)
				return
			}
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load Group.", err.Error())
				return
			}
			writeData(w, r, http.StatusOK, row)
		case http.MethodPatch:
			s.handleGroupUpdate(w, r, spaceID, groupID)
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
		var req groupMutationRequest
		if !decodeOptionalJSON(w, r, &req) {
			return
		}
		row, err := s.updateScopedStatus(r.Context(), "groups", groupID, spaceID, "disabled")
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to disable Group.", err.Error())
			return
		}
		s.recordMutationAudit(r.Context(), r, req.Actor, spaceID, "group.disabled", "group", groupID, row)
		writeData(w, r, http.StatusOK, row)
		return
	}
	http.NotFound(w, r)
}

func (s *Server) handleGroupUpdate(w http.ResponseWriter, r *http.Request, spaceID, groupID string) {
	var req groupMutationRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	current, err := s.loadGroupInSpace(r.Context(), spaceID, groupID)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, r, http.StatusNotFound, "GROUP_NOT_FOUND", "Group was not found.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load Group.", err.Error())
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
	displayName := nullableFromRequest(req.DisplayName, stringFromMap(current, "display_name"))
	update := client.Group.UpdateOneID(groupID).
		SetName(firstNonEmpty(req.Name, stringFromMap(current, "name"))).
		SetSortOrder(intValue(req.SortOrder, intFromMap(current, "sort_order", 1000))).
		SetStatus(firstNonEmpty(derefString(req.Status), stringFromMap(current, "status"), "active")).
		SetMetadata(nonNilMap(metadata))
	if displayName == "" {
		update.ClearDisplayName()
	} else {
		update.SetDisplayName(displayName)
	}
	err = update.Exec(r.Context())
	if err != nil {
		writeError(w, r, http.StatusConflict, "GROUP_UPDATE_FAILED", "Failed to update Group.", err.Error())
		return
	}
	row, err := s.loadGroupInSpace(r.Context(), spaceID, groupID)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load updated Group.", err.Error())
		return
	}
	s.recordMutationAudit(r.Context(), r, req.Actor, spaceID, "group.updated", "group", groupID, row)
	writeData(w, r, http.StatusOK, row)
}

func (s *Server) listGroups(w http.ResponseWriter, r *http.Request, spaceID string) {
	limit := limitFrom(r, 200)
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	groups, err := client.Group.Query().
		Where(entgroup.SpaceID(spaceID), entgroup.DeletedAtIsNil()).
		Order(entgroup.ByPath()).
		Limit(limit).
		All(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list Groups.", err.Error())
		return
	}
	rows := make([]map[string]any, 0, len(groups))
	for _, group := range groups {
		rows = append(rows, groupMap(group))
	}
	writeList(w, r, http.StatusOK, rows, limit)
}

func (s *Server) loadGroupInSpace(ctx context.Context, spaceID, groupID string) (map[string]any, error) {
	if s.ent == nil {
		return nil, errors.New("ent client is not configured")
	}
	row, err := s.ent.Group.Query().Where(entgroup.ID(groupID), entgroup.SpaceID(spaceID), entgroup.DeletedAtIsNil()).Only(ctx)
	if coreent.IsNotFound(err) {
		return nil, pgx.ErrNoRows
	}
	if err != nil {
		return nil, err
	}
	return groupMap(row), nil
}
