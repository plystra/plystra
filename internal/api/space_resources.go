package api

import (
	"context"
	"errors"
	"net/http"

	entresource "github.com/plystra/core/ent/resource"

	"github.com/jackc/pgx/v5"
	coreent "github.com/plystra/core/ent"
	"github.com/plystra/core/internal/authz"
)

type resourceMutationRequest struct {
	Actor         authz.ActorContext `json:"actor"`
	ID            string             `json:"id"`
	SpaceID       string             `json:"space_id"`
	ResourceType  string             `json:"resource_type"`
	ExternalID    *string            `json:"external_id"`
	GroupID       *string            `json:"group_id"`
	OwnerMemberID *string            `json:"owner_member_id"`
	DisplayName   *string            `json:"display_name"`
	Visibility    *string            `json:"visibility"`
	Status        *string            `json:"status"`
	Metadata      map[string]any     `json:"metadata"`
}

func (s *Server) handleSpaceResources(w http.ResponseWriter, r *http.Request, spaceID string, parts []string) {
	if !s.requireActiveSpace(w, r, spaceID) {
		return
	}
	if len(parts) == 0 {
		switch r.Method {
		case http.MethodPost:
			var req resourceMutationRequest
			if !decodeJSON(w, r, &req) {
				return
			}
			s.createResource(w, r, spaceID, req)
		case http.MethodGet:
			limit := limitFrom(r, 50)
			client, ok := s.requireEnt(w, r)
			if !ok {
				return
			}
			q := client.Resource.Query().Where(entresource.SpaceID(spaceID), entresource.DeletedAtIsNil())
			if resourceType := r.URL.Query().Get("resource_type"); resourceType != "" {
				q = q.Where(entresource.ResourceType(resourceType))
			}
			resources, err := q.Order(entresource.ByResourceType(), entresource.ByID()).Limit(limit).All(r.Context())
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list Resources.", err.Error())
				return
			}
			rows := make([]map[string]any, 0, len(resources))
			for _, resource := range resources {
				row, err := s.resourceMapWithRefs(r.Context(), resource)
				if err != nil {
					writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list Resources.", err.Error())
					return
				}
				rows = append(rows, row)
			}
			writeList(w, r, http.StatusOK, rows, limit)
		default:
			writeMethodNotAllowed(w, r)
		}
		return
	}
	resourceID := parts[0]
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			row, err := s.loadResourceInSpace(r.Context(), spaceID, resourceID)
			if errors.Is(err, pgx.ErrNoRows) {
				writeError(w, r, http.StatusNotFound, "RESOURCE_NOT_FOUND", "Resource was not found.", nil)
				return
			}
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load Resource.", err.Error())
				return
			}
			writeData(w, r, http.StatusOK, row)
		case http.MethodPatch:
			s.handleResourceUpdate(w, r, spaceID, resourceID)
		default:
			writeMethodNotAllowed(w, r)
		}
		return
	}
	if len(parts) == 2 && parts[1] == "archive" {
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, r)
			return
		}
		var req resourceMutationRequest
		if !decodeOptionalJSON(w, r, &req) {
			return
		}
		row, err := s.updateScopedStatus(r.Context(), "resources", resourceID, spaceID, "archived")
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to archive Resource.", err.Error())
			return
		}
		s.recordMutationAudit(r.Context(), r, req.Actor, spaceID, "resource.archived", stringFromMap(row, "resource_type"), resourceID, row)
		writeData(w, r, http.StatusOK, row)
		return
	}
	http.NotFound(w, r)
}

func (s *Server) handleResourceUpdate(w http.ResponseWriter, r *http.Request, spaceID, resourceID string) {
	var req resourceMutationRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Metadata != nil {
		if err := validateGovernedMetadata("metadata", req.Metadata); err != nil {
			writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", err.Error(), nil)
			return
		}
	}
	current, err := s.loadResourceInSpace(r.Context(), spaceID, resourceID)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, r, http.StatusNotFound, "RESOURCE_NOT_FOUND", "Resource was not found.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load Resource.", err.Error())
		return
	}
	groupID := nullableFromRequest(req.GroupID, stringFromMap(current, "group_id"))
	ownerMemberID := nullableFromRequest(req.OwnerMemberID, stringFromMap(current, "owner_member_id"))
	if err := s.validateResourceRefs(r.Context(), spaceID, groupID, ownerMemberID); err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Resource references are invalid.", err.Error())
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
	externalID := nullableFromRequest(req.ExternalID, stringFromMap(current, "external_id"))
	displayName := nullableFromRequest(req.DisplayName, stringFromMap(current, "display_name"))
	update := client.Resource.UpdateOneID(resourceID).
		SetVisibility(firstNonEmpty(derefString(req.Visibility), stringFromMap(current, "visibility"), "private")).
		SetStatus(firstNonEmpty(derefString(req.Status), stringFromMap(current, "status"), "active")).
		SetMetadata(nonNilMap(metadata))
	if externalID == "" {
		update.ClearExternalID()
	} else {
		update.SetExternalID(externalID)
	}
	if displayName == "" {
		update.ClearDisplayName()
	} else {
		update.SetDisplayName(displayName)
	}
	if groupID == "" {
		update.ClearGroupID()
	} else {
		update.SetGroupID(groupID)
	}
	if ownerMemberID == "" {
		update.ClearOwnerMemberID()
	} else {
		update.SetOwnerMemberID(ownerMemberID)
	}
	err = update.Exec(r.Context())
	if err != nil {
		writeError(w, r, http.StatusConflict, "RESOURCE_UPDATE_FAILED", "Failed to update Resource.", err.Error())
		return
	}
	row, err := s.loadResourceInSpace(r.Context(), spaceID, resourceID)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load updated Resource.", err.Error())
		return
	}
	s.recordMutationAudit(r.Context(), r, req.Actor, spaceID, "resource.updated", stringFromMap(row, "resource_type"), resourceID, row)
	writeData(w, r, http.StatusOK, row)
}

func (s *Server) loadResourceInSpace(ctx context.Context, spaceID, resourceID string) (map[string]any, error) {
	if s.ent == nil {
		return nil, errors.New("ent client is not configured")
	}
	row, err := s.ent.Resource.Query().Where(entresource.ID(resourceID), entresource.SpaceID(spaceID), entresource.DeletedAtIsNil()).Only(ctx)
	if coreent.IsNotFound(err) {
		return nil, pgx.ErrNoRows
	}
	if err != nil {
		return nil, err
	}
	return s.resourceMapWithRefs(ctx, row)
}

func (s *Server) createResource(w http.ResponseWriter, r *http.Request, spaceID string, req resourceMutationRequest) {
	if req.ResourceType == "" {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "resource_type is required.", nil)
		return
	}
	if spaceID == "" {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "space_id is required.", nil)
		return
	}
	if req.ID == "" {
		req.ID = newEntityID(req.ResourceType)
	}
	if req.Metadata != nil {
		if err := validateGovernedMetadata("metadata", req.Metadata); err != nil {
			writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", err.Error(), nil)
			return
		}
	}
	groupID := derefString(req.GroupID)
	ownerMemberID := derefString(req.OwnerMemberID)
	if err := s.validateResourceRefs(r.Context(), spaceID, groupID, ownerMemberID); err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Resource references are invalid.", err.Error())
		return
	}
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	_, err := client.Resource.Create().
		SetID(req.ID).
		SetResourceType(req.ResourceType).
		SetNillableExternalID(optionalString(derefString(req.ExternalID))).
		SetNillableDisplayName(optionalString(derefString(req.DisplayName))).
		SetSpaceID(spaceID).
		SetNillableGroupID(optionalString(groupID)).
		SetNillableOwnerMemberID(optionalString(ownerMemberID)).
		SetVisibility(firstNonEmpty(derefString(req.Visibility), "private")).
		SetStatus(firstNonEmpty(derefString(req.Status), "active")).
		SetMetadata(nonNilMap(req.Metadata)).
		Save(r.Context())
	if err != nil {
		writeError(w, r, http.StatusConflict, "RESOURCE_CREATE_FAILED", "Failed to create Resource.", err.Error())
		return
	}
	row, err := s.loadResourceInSpace(r.Context(), spaceID, req.ID)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load created Resource.", err.Error())
		return
	}
	s.recordMutationAudit(r.Context(), r, req.Actor, spaceID, "resource.created", req.ResourceType, req.ID, row)
	writeData(w, r, http.StatusCreated, row)
}
