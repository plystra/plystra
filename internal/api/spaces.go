package api

import (
	"context"
	"errors"
	"net/http"
	"strings"

	entspace "github.com/plystra/core/ent/space"

	"github.com/jackc/pgx/v5"
	coreent "github.com/plystra/core/ent"
	"github.com/plystra/core/internal/authz"
)

func (s *Server) handleSpaces(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		s.handleSpaceCreate(w, r)
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
	spaces, err := client.Space.Query().Where(entspace.DeletedAtIsNil()).Order(entspace.ByName()).All(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list spaces.", err.Error())
		return
	}
	rows := make([]map[string]any, 0, len(spaces))
	for _, space := range spaces {
		rows = append(rows, spaceMap(space))
	}
	writeList(w, r, http.StatusOK, rows, limitFrom(r, 50))
}

func (s *Server) handleSpaceSubroutes(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/spaces/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	spaceID := parts[0]
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			row, err := s.loadSpace(r.Context(), spaceID)
			if errors.Is(err, pgx.ErrNoRows) {
				writeError(w, r, http.StatusNotFound, "SPACE_NOT_FOUND", "Space was not found.", nil)
				return
			}
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load Space.", err.Error())
				return
			}
			writeData(w, r, http.StatusOK, row)
		case http.MethodPatch:
			s.handleSpaceUpdate(w, r, spaceID)
		default:
			writeMethodNotAllowed(w, r)
		}
		return
	}
	if len(parts) == 2 && (parts[1] == "disable" || parts[1] == "restore") {
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, r)
			return
		}
		var req spaceMutationRequest
		if !decodeOptionalJSON(w, r, &req) {
			return
		}
		status := "disabled"
		action := "space.disabled"
		if parts[1] == "restore" {
			status = "active"
			action = "space.restored"
		}
		row, err := s.updateStatus(r.Context(), "spaces", spaceID, status)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to update Space status.", err.Error())
			return
		}
		s.recordMutationAudit(r.Context(), r, req.Actor, spaceID, action, "space", spaceID, row)
		writeData(w, r, http.StatusOK, row)
		return
	}
	switch parts[1] {
	case "groups":
		s.handleSpaceGroups(w, r, spaceID, parts[2:])
	case "members":
		s.handleSpaceMembers(w, r, spaceID, parts[2:])
	case "user-members":
		s.handleSpaceUserMembers(w, r, spaceID, parts[2:])
	case "roles":
		s.handleSpaceRoles(w, r, spaceID, parts[2:])
	case "role-permissions":
		s.handleSpaceRolePermissions(w, r, spaceID, parts[2:])
	case "member-role-grants":
		s.handleSpaceMemberRoles(w, r, spaceID, parts[2:])
	case "member-roles":
		s.handleSpaceMemberRoles(w, r, spaceID, parts[2:])
	case "resources":
		s.handleSpaceResources(w, r, spaceID, parts[2:])
	case "data":
		s.handleSpaceAppData(w, r, spaceID, parts[2:])
	case "audit-logs":
		s.handleSpaceAuditLogs(w, r, spaceID, parts[2:])
	default:
		http.NotFound(w, r)
	}
}

type spaceMutationRequest struct {
	Actor    authz.ActorContext `json:"actor"`
	ID       string             `json:"id"`
	Name     string             `json:"name"`
	Slug     *string            `json:"slug"`
	Type     *string            `json:"type"`
	Status   *string            `json:"status"`
	Metadata map[string]any     `json:"metadata"`
}

func (s *Server) handleSpaceCreate(w http.ResponseWriter, r *http.Request) {
	var req spaceMutationRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "name is required.", nil)
		return
	}
	if req.ID == "" {
		req.ID = newEntityID("space")
	}
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	_, err := client.Space.Create().
		SetID(req.ID).
		SetName(req.Name).
		SetNillableSlug(optionalString(derefString(req.Slug))).
		SetType(firstNonEmpty(derefString(req.Type), "custom")).
		SetStatus(firstNonEmpty(derefString(req.Status), "active")).
		SetMetadata(nonNilMap(req.Metadata)).
		Save(r.Context())
	if err != nil {
		writeError(w, r, http.StatusConflict, "SPACE_CREATE_FAILED", "Failed to create Space.", err.Error())
		return
	}
	row, err := s.loadSpace(r.Context(), req.ID)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load created Space.", err.Error())
		return
	}
	s.recordMutationAudit(r.Context(), r, req.Actor, req.ID, "space.created", "space", req.ID, row)
	writeData(w, r, http.StatusCreated, row)
}

func (s *Server) handleSpaceUpdate(w http.ResponseWriter, r *http.Request, spaceID string) {
	var req spaceMutationRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	current, err := s.loadSpace(r.Context(), spaceID)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, r, http.StatusNotFound, "SPACE_NOT_FOUND", "Space was not found.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load Space.", err.Error())
		return
	}
	name := firstNonEmpty(req.Name, stringFromMap(current, "name"))
	metadata := mapFromAny(current["metadata"])
	if req.Metadata != nil {
		metadata = req.Metadata
	}
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	slug := nullableFromRequest(req.Slug, stringFromMap(current, "slug"))
	update := client.Space.UpdateOneID(spaceID).
		SetName(name).
		SetType(firstNonEmpty(derefString(req.Type), stringFromMap(current, "type"), "custom")).
		SetStatus(firstNonEmpty(derefString(req.Status), stringFromMap(current, "status"), "active")).
		SetMetadata(nonNilMap(metadata))
	if slug == "" {
		update.ClearSlug()
	} else {
		update.SetSlug(slug)
	}
	err = update.Exec(r.Context())
	if err != nil {
		writeError(w, r, http.StatusConflict, "SPACE_UPDATE_FAILED", "Failed to update Space.", err.Error())
		return
	}
	row, err := s.loadSpace(r.Context(), spaceID)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load updated Space.", err.Error())
		return
	}
	s.recordMutationAudit(r.Context(), r, req.Actor, spaceID, "space.updated", "space", spaceID, row)
	writeData(w, r, http.StatusOK, row)
}

func (s *Server) loadSpace(ctx context.Context, id string) (map[string]any, error) {
	if s.ent == nil {
		return nil, errors.New("ent client is not configured")
	}
	row, err := s.ent.Space.Query().Where(entspace.ID(id), entspace.DeletedAtIsNil()).Only(ctx)
	if coreent.IsNotFound(err) {
		return nil, pgx.ErrNoRows
	}
	if err != nil {
		return nil, err
	}
	return spaceMap(row), nil
}
