package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"

	entresource "github.com/plystra/plystra/ent/resource"
	entresourcetype "github.com/plystra/plystra/ent/resourcetype"

	"github.com/jackc/pgx/v5"
	"github.com/plystra/plystra/internal/authz"
)

func (s *Server) handleDataTables(w http.ResponseWriter, r *http.Request) {
	if !featureEnabled("DATA_CONSOLE_ENABLED") {
		writeError(w, r, http.StatusNotFound, "FEATURE_DISABLED", "Data Console API is disabled.", nil)
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
	mappings, err := client.ResourceMapping.Query().All(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list data tables.", err.Error())
		return
	}
	rows := make([]map[string]any, 0, len(mappings))
	for _, mapping := range mappings {
		rt, err := client.ResourceType.Query().Where(entresourcetype.ID(mapping.ResourceTypeID)).Only(r.Context())
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list data tables.", err.Error())
			return
		}
		row := resourceMappingMap(mapping)
		row["resource_type"] = rt.Key
		row["display_name"] = rt.DisplayName
		row["source"] = rt.Source
		rows = append(rows, row)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		left, _ := rows[i]["resource_type"].(string)
		right, _ := rows[j]["resource_type"].(string)
		return left < right
	})
	writeList(w, r, http.StatusOK, rows, limitFrom(r, 50))
}

func (s *Server) handleDataRows(w http.ResponseWriter, r *http.Request) {
	if !featureEnabled("DATA_CONSOLE_ENABLED") {
		writeError(w, r, http.StatusNotFound, "FEATURE_DISABLED", "Data Console API is disabled.", nil)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/data/rows/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	resourceType := parts[0]
	if len(parts) == 1 && r.Method == http.MethodPost {
		s.handleDataRowCreate(w, r, resourceType)
		return
	}
	if len(parts) == 1 && r.Method == http.MethodGet {
		client, ok := s.requireEnt(w, r)
		if !ok {
			return
		}
		q := client.Resource.Query().Where(entresource.ResourceType(resourceType), entresource.DeletedAtIsNil())
		if spaceID := r.URL.Query().Get("space_id"); spaceID != "" {
			q = q.Where(entresource.SpaceID(spaceID))
		}
		resources, err := q.Order(entresource.ByID()).All(r.Context())
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list data rows.", err.Error())
			return
		}
		rows := make([]map[string]any, 0, len(resources))
		for _, resource := range resources {
			row, err := s.resourceMapWithRefs(r.Context(), resource)
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list data rows.", err.Error())
				return
			}
			rows = append(rows, row)
		}
		writeList(w, r, http.StatusOK, rows, limitFrom(r, 50))
		return
	}
	if len(parts) == 2 && r.Method == http.MethodGet {
		row, err := s.loadResourceRow(r.Context(), resourceType, parts[1])
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, r, http.StatusNotFound, "RESOURCE_NOT_FOUND", "Resource was not found.", nil)
			return
		}
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load data row.", err.Error())
			return
		}
		writeData(w, r, http.StatusOK, row)
		return
	}
	if len(parts) == 2 && r.Method == http.MethodPatch {
		s.handleDataRowUpdate(w, r, resourceType, parts[1])
		return
	}
	if len(parts) == 2 && r.Method == http.MethodDelete {
		s.handleDataRowDelete(w, r, resourceType, parts[1])
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost && r.Method != http.MethodPatch && r.Method != http.MethodDelete {
		writeMethodNotAllowed(w, r)
		return
	}
	http.NotFound(w, r)
}

type dataRowMutationRequest struct {
	Actor         authz.ActorContext `json:"actor"`
	ID            string             `json:"id"`
	SpaceID       string             `json:"space_id"`
	GroupID       *string            `json:"group_id"`
	OwnerMemberID *string            `json:"owner_member_id"`
	DisplayName   *string            `json:"display_name"`
	Visibility    *string            `json:"visibility"`
	Metadata      map[string]any     `json:"metadata"`
	Status        *string            `json:"status"`
}

func (s *Server) handleDataRowCreate(w http.ResponseWriter, r *http.Request, resourceType string) {
	if err := s.requireInternalResourceMapping(r.Context(), resourceType); err != nil {
		s.writeMappingError(w, r, err)
		return
	}
	var req dataRowMutationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Request body is invalid JSON.", err.Error())
		return
	}
	if req.SpaceID == "" {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "space_id is required.", nil)
		return
	}
	actor := req.Actor
	if actor.SpaceID == "" {
		actor.SpaceID = req.SpaceID
	}
	if req.ID == "" {
		req.ID = newEntityID(resourceType)
	}
	if exists, err := s.resourceExists(r.Context(), resourceType, req.ID); err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to check resource id.", err.Error())
		return
	} else if exists {
		writeError(w, r, http.StatusConflict, "RESOURCE_ALREADY_EXISTS", "Resource id already exists.", map[string]string{"resource_id": req.ID})
		return
	}

	groupID := derefString(req.GroupID)
	ownerMemberID := derefString(req.OwnerMemberID)
	if ownerMemberID == "" {
		ownerMemberID = actor.MemberID
	}
	if err := s.validateResourceRefs(r.Context(), req.SpaceID, groupID, ownerMemberID); err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Resource references are invalid.", err.Error())
		return
	}
	target, err := s.proposedResourceTarget(r.Context(), resourceType, req.ID, req.SpaceID, groupID, ownerMemberID, derefString(req.DisplayName), firstNonEmpty(derefString(req.Visibility), "private"), firstNonEmpty(derefString(req.Status), "active"), req.Metadata)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Failed to build proposed target.", err.Error())
		return
	}
	decision, ok := s.authorizeTarget(w, r, actor, resourceType, req.ID, "create", target)
	if !ok {
		return
	}

	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	_, err = client.Resource.Create().
		SetID(req.ID).
		SetResourceType(resourceType).
		SetNillableDisplayName(optionalString(derefString(req.DisplayName))).
		SetSpaceID(req.SpaceID).
		SetNillableGroupID(optionalString(groupID)).
		SetNillableOwnerMemberID(optionalString(ownerMemberID)).
		SetVisibility(firstNonEmpty(derefString(req.Visibility), "private")).
		SetMetadata(nonNilMap(req.Metadata)).
		SetStatus(firstNonEmpty(derefString(req.Status), "active")).
		Save(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create data row.", err.Error())
		return
	}
	row, err := s.loadResourceRow(r.Context(), resourceType, req.ID)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load created data row.", err.Error())
		return
	}
	writeData(w, r, http.StatusCreated, map[string]any{"row": row, "authorization": decision})
}

func (s *Server) handleDataRowUpdate(w http.ResponseWriter, r *http.Request, resourceType, resourceID string) {
	if err := s.requireInternalResourceMapping(r.Context(), resourceType); err != nil {
		s.writeMappingError(w, r, err)
		return
	}
	var req dataRowMutationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Request body is invalid JSON.", err.Error())
		return
	}
	current, err := s.loadResourceTarget(r.Context(), resourceType, resourceID)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, r, http.StatusNotFound, "RESOURCE_NOT_FOUND", "Resource was not found.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load data row.", err.Error())
		return
	}
	actor := req.Actor
	if actor.SpaceID == "" {
		actor.SpaceID = current.Resource.SpaceID
	}

	proposed := current
	if req.GroupID != nil {
		proposed.Resource.GroupID = *req.GroupID
		group, err := s.loadGroupSnapshot(r.Context(), current.Resource.SpaceID, *req.GroupID)
		if err != nil {
			writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "group_id is invalid for the resource space.", err.Error())
			return
		}
		proposed.Group = group
	}
	if req.OwnerMemberID != nil {
		if err := s.validateMemberInSpace(r.Context(), current.Resource.SpaceID, *req.OwnerMemberID); err != nil {
			writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "owner_member_id is invalid for the resource space.", err.Error())
			return
		}
		proposed.Resource.OwnerMemberID = *req.OwnerMemberID
	}
	if req.DisplayName != nil {
		proposed.Resource.DisplayName = *req.DisplayName
	}
	if req.Visibility != nil {
		proposed.Resource.Visibility = *req.Visibility
	}
	if req.Status != nil {
		proposed.Resource.Status = *req.Status
	}
	if req.Metadata != nil {
		proposed.Resource.Metadata = req.Metadata
	}

	decision, ok := s.authorizeTarget(w, r, actor, resourceType, resourceID, "update", proposed)
	if !ok {
		return
	}
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	update := client.Resource.UpdateOneID(resourceID).
		SetVisibility(firstNonEmpty(proposed.Resource.Visibility, "private")).
		SetMetadata(nonNilMap(proposed.Resource.Metadata)).
		SetStatus(firstNonEmpty(proposed.Resource.Status, "active"))
	if proposed.Resource.DisplayName == "" {
		update.ClearDisplayName()
	} else {
		update.SetDisplayName(proposed.Resource.DisplayName)
	}
	if proposed.Resource.GroupID == "" {
		update.ClearGroupID()
	} else {
		update.SetGroupID(proposed.Resource.GroupID)
	}
	if proposed.Resource.OwnerMemberID == "" {
		update.ClearOwnerMemberID()
	} else {
		update.SetOwnerMemberID(proposed.Resource.OwnerMemberID)
	}
	err = update.Exec(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to update data row.", err.Error())
		return
	}
	row, err := s.loadResourceRow(r.Context(), resourceType, resourceID)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load updated data row.", err.Error())
		return
	}
	writeData(w, r, http.StatusOK, map[string]any{"row": row, "authorization": decision})
}

func (s *Server) handleDataRowDelete(w http.ResponseWriter, r *http.Request, resourceType, resourceID string) {
	if err := s.requireInternalResourceMapping(r.Context(), resourceType); err != nil {
		s.writeMappingError(w, r, err)
		return
	}
	var req dataRowMutationRequest
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}
	current, err := s.loadResourceTarget(r.Context(), resourceType, resourceID)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, r, http.StatusNotFound, "RESOURCE_NOT_FOUND", "Resource was not found.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load data row.", err.Error())
		return
	}
	actor := req.Actor
	if actor.SpaceID == "" {
		actor.SpaceID = current.Resource.SpaceID
	}
	decision, ok := s.authorizeTarget(w, r, actor, resourceType, resourceID, "delete", current)
	if !ok {
		return
	}
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	err = client.Resource.UpdateOneID(resourceID).SetStatus("deleted").Exec(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to soft-delete data row.", err.Error())
		return
	}
	row, err := s.loadResourceRow(r.Context(), resourceType, resourceID)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load deleted data row.", err.Error())
		return
	}
	writeData(w, r, http.StatusOK, map[string]any{"row": row, "authorization": decision})
}
