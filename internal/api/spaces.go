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
	if len(parts) == 3 && parts[1] == "provisioning" {
		switch parts[2] {
		case "activate":
			if r.Method != http.MethodPost {
				writeMethodNotAllowed(w, r)
				return
			}
			s.handleSpaceProvisioningActivate(w, r, spaceID)
			return
		case "fail":
			if r.Method != http.MethodPost {
				writeMethodNotAllowed(w, r)
				return
			}
			s.handleSpaceProvisioningFail(w, r, spaceID)
			return
		default:
			http.NotFound(w, r)
			return
		}
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
		current, err := s.loadSpace(r.Context(), spaceID)
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, r, http.StatusNotFound, "SPACE_NOT_FOUND", "Space was not found.", nil)
			return
		}
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load Space.", err.Error())
			return
		}
		status := "suspended"
		action := "space.suspended"
		if parts[1] == "restore" {
			switch stringFromMap(current, "status") {
			case "suspended", "disabled":
			default:
				writeError(w, r, http.StatusConflict, "SPACE_RESTORE_DENIED", "Only suspended Spaces can be restored directly; provisioning or failed Spaces must resume through space.provisioning.", map[string]any{
					"status": stringFromMap(current, "status"),
				})
				return
			}
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
	status := firstNonEmpty(derefString(req.Status), "provisioning")
	if status != "provisioning" {
		writeError(w, r, http.StatusBadRequest, "SPACE_PROVISIONING_REQUIRED", "Direct Space creation can only create a fail-closed provisioning Space; use space.provisioning to activate it.", map[string]any{"requested_status": status})
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
		SetStatus(status).
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
	s.recordMutationAudit(r.Context(), r, req.Actor, req.ID, "space.provisioning.created", "space", req.ID, row)
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
	status := firstNonEmpty(derefString(req.Status), stringFromMap(current, "status"), "active")
	if err := validateSpaceStatusMutation(stringFromMap(current, "status"), status); err != nil {
		writeError(w, r, http.StatusConflict, "SPACE_STATUS_TRANSITION_DENIED", err.Error(), map[string]any{
			"current_status":   stringFromMap(current, "status"),
			"requested_status": status,
		})
		return
	}
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	slug := nullableFromRequest(req.Slug, stringFromMap(current, "slug"))
	update := client.Space.UpdateOneID(spaceID).
		SetName(name).
		SetType(firstNonEmpty(derefString(req.Type), stringFromMap(current, "type"), "custom")).
		SetStatus(status).
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

func (s *Server) handleSpaceProvisioningActivate(w http.ResponseWriter, r *http.Request, spaceID string) {
	s.handleSpaceProvisioningStatus(w, r, spaceID, "active", "space.provisioning.activated")
}

func (s *Server) handleSpaceProvisioningFail(w http.ResponseWriter, r *http.Request, spaceID string) {
	s.handleSpaceProvisioningStatus(w, r, spaceID, "failed", "space.provisioning.failed")
}

func (s *Server) handleSpaceProvisioningStatus(w http.ResponseWriter, r *http.Request, spaceID, nextStatus, action string) {
	var req spaceMutationRequest
	if !decodeOptionalJSON(w, r, &req) {
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
	currentStatus := stringFromMap(current, "status")
	if !spaceProvisioningStatusTransitionAllowed(currentStatus, nextStatus) {
		writeError(w, r, http.StatusConflict, "SPACE_PROVISIONING_TRANSITION_DENIED", "Space provisioning status transition is not allowed.", map[string]any{
			"current_status":   currentStatus,
			"requested_status": nextStatus,
		})
		return
	}
	row, err := s.updateStatus(r.Context(), "spaces", spaceID, nextStatus)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to update Space provisioning status.", err.Error())
		return
	}
	details := nonNilMap(req.Metadata)
	details["current_status"] = currentStatus
	details["next_status"] = nextStatus
	details["provisioning_mode"] = "manual_alpha_completion"
	s.recordMutationAudit(r.Context(), r, req.Actor, spaceID, action, "space", spaceID, details)
	writeData(w, r, http.StatusOK, row)
}

func validateSpaceStatusMutation(current, next string) error {
	current = strings.TrimSpace(current)
	next = strings.TrimSpace(next)
	if next == "" {
		return nil
	}
	switch next {
	case "active", "provisioning", "failed", "suspended", "archived", "disabled":
	default:
		return validationError("space status must be active, provisioning, failed, suspended, archived, or disabled")
	}
	if next == "active" && current != "active" {
		return validationError("active Space status can only be set by the space.provisioning System Capability")
	}
	if current == "active" && next == "provisioning" {
		return validationError("active Spaces cannot be moved back to provisioning through the direct Space API")
	}
	return nil
}

func spaceProvisioningStatusTransitionAllowed(current, next string) bool {
	current = strings.TrimSpace(current)
	next = strings.TrimSpace(next)
	switch next {
	case "active":
		return current == "provisioning" || current == "failed"
	case "failed":
		return current == "provisioning"
	default:
		return false
	}
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

func (s *Server) spaceActive(ctx context.Context, id string) (bool, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return false, nil
	}
	if s.ent == nil {
		return false, errors.New("ent client is not configured")
	}
	row, err := s.ent.Space.Query().Where(entspace.ID(id), entspace.DeletedAtIsNil()).Only(ctx)
	if coreent.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(row.Status) == "active", nil
}

func (s *Server) requireActiveSpace(w http.ResponseWriter, r *http.Request, id string) bool {
	active, err := s.spaceActive(r.Context(), id)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to evaluate Space lifecycle status.", err.Error())
		return false
	}
	if !active {
		writeError(w, r, http.StatusConflict, "SPACE_NOT_ACTIVE", "Space is not active; normal data and capability operations are fail-closed until space.provisioning activates it.", map[string]any{"space_id": strings.TrimSpace(id)})
		return false
	}
	return true
}
