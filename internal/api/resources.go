package api

import (
	"net/http"
	"strings"

	entresource "github.com/plystra/plystra/ent/resource"

	coreent "github.com/plystra/plystra/ent"
)

func (s *Server) handleResources(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var req resourceMutationRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		s.createResource(w, r, req.SpaceID, req)
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
	q := client.Resource.Query().Where(entresource.DeletedAtIsNil())
	if spaceID := r.URL.Query().Get("space_id"); spaceID != "" {
		q = q.Where(entresource.SpaceID(spaceID))
	}
	if resourceType := r.URL.Query().Get("resource_type"); resourceType != "" {
		q = q.Where(entresource.ResourceType(resourceType))
	}
	resources, err := q.Order(entresource.ByResourceType(), entresource.ByID()).All(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list resources.", err.Error())
		return
	}
	rows := make([]map[string]any, 0, len(resources))
	for _, resource := range resources {
		row, err := s.resourceMapWithRefs(r.Context(), resource)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list resources.", err.Error())
			return
		}
		rows = append(rows, row)
	}
	writeList(w, r, http.StatusOK, rows, limitFrom(r, 50))
}

func (s *Server) handleResourceDetail(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/resources/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 2 {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, r)
			return
		}
		if s.ent == nil {
			writeError(w, r, http.StatusServiceUnavailable, "NOT_READY", "Ent client is not configured.", nil)
			return
		}
		resourceRow, err := s.ent.Resource.Query().Where(entresource.ResourceType(parts[0]), entresource.ID(parts[1]), entresource.DeletedAtIsNil()).Only(r.Context())
		if coreent.IsNotFound(err) {
			writeError(w, r, http.StatusNotFound, "RESOURCE_NOT_FOUND", "Resource was not found.", nil)
			return
		}
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load Resource.", err.Error())
			return
		}
		row, err := s.resourceMapWithRefs(r.Context(), resourceRow)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load Resource.", err.Error())
			return
		}
		writeData(w, r, http.StatusOK, row)
		return
	}
	http.NotFound(w, r)
}
