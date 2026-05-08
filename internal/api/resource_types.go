package api

import (
	"context"
	"errors"
	"net/http"
	"strings"

	entresourceaction "github.com/plystra/plystra/ent/resourceaction"
	entresourcemapping "github.com/plystra/plystra/ent/resourcemapping"
	entresourcetype "github.com/plystra/plystra/ent/resourcetype"

	"github.com/jackc/pgx/v5"
	coreent "github.com/plystra/plystra/ent"
)

func (s *Server) handleResourceTypes(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		client, ok := s.requireEnt(w, r)
		if !ok {
			return
		}
		var req resourceTypeMutationRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		if req.Key == "" || req.DisplayName == "" {
			writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "key and display_name are required.", nil)
			return
		}
		if req.ID == "" {
			req.ID = newEntityID("rt")
		}
		existing, err := client.ResourceType.Query().Where(entresourcetype.Key(req.Key)).Only(r.Context())
		if coreent.IsNotFound(err) {
			_, err = client.ResourceType.Create().
				SetID(req.ID).
				SetKey(req.Key).
				SetDisplayName(req.DisplayName).
				SetNillableDescription(optionalString(derefString(req.Description))).
				SetStatus(firstNonEmpty(derefString(req.Status), "active")).
				SetSource(firstNonEmpty(req.Source, "core")).
				SetMetadata(nonNilMap(req.Metadata)).
				Save(r.Context())
		} else if err == nil {
			err = client.ResourceType.UpdateOneID(existing.ID).
				SetDisplayName(req.DisplayName).
				SetNillableDescription(optionalString(derefString(req.Description))).
				SetStatus(firstNonEmpty(derefString(req.Status), "active")).
				SetSource(firstNonEmpty(req.Source, "core")).
				SetMetadata(nonNilMap(req.Metadata)).
				Exec(r.Context())
		}
		if err != nil {
			writeError(w, r, http.StatusConflict, "RESOURCE_TYPE_UPSERT_FAILED", "Failed to register ResourceType.", err.Error())
			return
		}
		row, err := s.loadResourceTypeByKey(r.Context(), req.Key)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load ResourceType.", err.Error())
			return
		}
		writeData(w, r, http.StatusCreated, row)
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
	resourceTypes, err := client.ResourceType.Query().Order(entresourcetype.ByKey()).All(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list resource types.", err.Error())
		return
	}
	rows := make([]map[string]any, 0, len(resourceTypes))
	for _, resourceType := range resourceTypes {
		rows = append(rows, resourceTypeMap(resourceType))
	}
	writeList(w, r, http.StatusOK, rows, limitFrom(r, 50))
}

type resourceTypeMutationRequest struct {
	ID          string         `json:"id"`
	Key         string         `json:"key"`
	DisplayName string         `json:"display_name"`
	Description *string        `json:"description"`
	Status      *string        `json:"status"`
	Source      string         `json:"source"`
	Metadata    map[string]any `json:"metadata"`
}

type resourceActionMutationRequest struct {
	ID           string         `json:"id"`
	Key          string         `json:"key"`
	DisplayName  string         `json:"display_name"`
	Description  *string        `json:"description"`
	RiskLevel    string         `json:"risk_level"`
	AuditDefault *bool          `json:"audit_default"`
	Metadata     map[string]any `json:"metadata"`
}

type resourceMappingMutationRequest struct {
	ID               string         `json:"id"`
	StorageKind      string         `json:"storage_kind"`
	TableName        *string        `json:"table_name"`
	IDField          string         `json:"id_field"`
	SpaceField       string         `json:"space_field"`
	GroupField       *string        `json:"group_field"`
	OwnerMemberField *string        `json:"owner_member_field"`
	VisibilityField  *string        `json:"visibility_field"`
	MetadataField    *string        `json:"metadata_field"`
	Status           *string        `json:"status"`
	Metadata         map[string]any `json:"metadata"`
}

func (s *Server) handleResourceTypeSubroutes(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/resource-types/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	key := parts[0]
	switch {
	case len(parts) == 1:
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, r)
			return
		}
		row, err := s.loadResourceTypeByKey(r.Context(), key)
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, r, http.StatusNotFound, "RESOURCE_TYPE_NOT_FOUND", "ResourceType was not found.", nil)
			return
		}
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load ResourceType.", err.Error())
			return
		}
		writeData(w, r, http.StatusOK, row)
	case len(parts) == 2 && parts[1] == "actions":
		if r.Method == http.MethodPost {
			s.handleResourceActionUpsert(w, r, key)
			return
		}
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, r)
			return
		}
		rt, err := s.loadResourceTypeEntityByKey(r.Context(), key)
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, r, http.StatusNotFound, "RESOURCE_TYPE_NOT_FOUND", "ResourceType was not found.", nil)
			return
		}
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load ResourceType.", err.Error())
			return
		}
		actions, err := s.ent.ResourceAction.Query().Where(entresourceaction.ResourceTypeID(rt.ID)).Order(entresourceaction.ByKey()).All(r.Context())
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list resource actions.", err.Error())
			return
		}
		rows := make([]map[string]any, 0, len(actions))
		for _, action := range actions {
			rows = append(rows, resourceActionMap(action))
		}
		writeList(w, r, http.StatusOK, rows, limitFrom(r, 50))
	case len(parts) == 2 && parts[1] == "mapping":
		if r.Method == http.MethodPost || r.Method == http.MethodPatch || r.Method == http.MethodPut {
			s.handleResourceMappingUpsert(w, r, key)
			return
		}
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, r)
			return
		}
		row, err := s.loadResourceMappingByTypeKey(r.Context(), key)
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, r, http.StatusNotFound, "RESOURCE_MAPPING_NOT_FOUND", "ResourceMapping was not found.", nil)
			return
		}
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load ResourceMapping.", err.Error())
			return
		}
		writeData(w, r, http.StatusOK, row)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleResourceActionUpsert(w http.ResponseWriter, r *http.Request, resourceTypeKey string) {
	var req resourceActionMutationRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Key == "" || req.DisplayName == "" {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "key and display_name are required.", nil)
		return
	}
	rt, err := s.loadResourceTypeByKey(r.Context(), resourceTypeKey)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "RESOURCE_TYPE_NOT_FOUND", "ResourceType was not found.", err.Error())
		return
	}
	if req.ID == "" {
		req.ID = newEntityID("ra")
	}
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	resourceTypeID := stringFromMap(rt, "id")
	existing, err := client.ResourceAction.Query().Where(entresourceaction.ResourceTypeID(resourceTypeID), entresourceaction.Key(req.Key)).Only(r.Context())
	if coreent.IsNotFound(err) {
		_, err = client.ResourceAction.Create().
			SetID(req.ID).
			SetResourceTypeID(resourceTypeID).
			SetKey(req.Key).
			SetDisplayName(req.DisplayName).
			SetNillableDescription(optionalString(derefString(req.Description))).
			SetRiskLevel(firstNonEmpty(req.RiskLevel, "normal")).
			SetAuditDefault(boolValue(req.AuditDefault, true)).
			SetMetadata(nonNilMap(req.Metadata)).
			Save(r.Context())
	} else if err == nil {
		err = client.ResourceAction.UpdateOneID(existing.ID).
			SetDisplayName(req.DisplayName).
			SetNillableDescription(optionalString(derefString(req.Description))).
			SetRiskLevel(firstNonEmpty(req.RiskLevel, "normal")).
			SetAuditDefault(boolValue(req.AuditDefault, true)).
			SetMetadata(nonNilMap(req.Metadata)).
			Exec(r.Context())
	}
	if err != nil {
		writeError(w, r, http.StatusConflict, "RESOURCE_ACTION_UPSERT_FAILED", "Failed to register ResourceAction.", err.Error())
		return
	}
	row, err := client.ResourceAction.Query().Where(entresourceaction.ResourceTypeID(resourceTypeID), entresourceaction.Key(req.Key)).Only(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load ResourceAction.", err.Error())
		return
	}
	writeData(w, r, http.StatusCreated, resourceActionMap(row))
}

func (s *Server) handleResourceMappingUpsert(w http.ResponseWriter, r *http.Request, resourceTypeKey string) {
	var req resourceMappingMutationRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	rt, err := s.loadResourceTypeByKey(r.Context(), resourceTypeKey)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "RESOURCE_TYPE_NOT_FOUND", "ResourceType was not found.", err.Error())
		return
	}
	if req.ID == "" {
		req.ID = newEntityID("rm")
	}
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	resourceTypeID := stringFromMap(rt, "id")
	existing, err := client.ResourceMapping.Query().Where(entresourcemapping.ResourceTypeID(resourceTypeID)).Only(r.Context())
	if coreent.IsNotFound(err) {
		_, err = client.ResourceMapping.Create().
			SetID(req.ID).
			SetResourceTypeID(resourceTypeID).
			SetStorageKind(firstNonEmpty(req.StorageKind, "internal_table")).
			SetNillableTableName(optionalString(derefString(req.TableName))).
			SetIDField(firstNonEmpty(req.IDField, "id")).
			SetSpaceField(firstNonEmpty(req.SpaceField, "space_id")).
			SetNillableGroupField(optionalString(derefString(req.GroupField))).
			SetNillableOwnerMemberField(optionalString(derefString(req.OwnerMemberField))).
			SetNillableVisibilityField(optionalString(derefString(req.VisibilityField))).
			SetNillableMetadataField(optionalString(derefString(req.MetadataField))).
			SetStatus(firstNonEmpty(derefString(req.Status), "active")).
			SetMetadata(nonNilMap(req.Metadata)).
			Save(r.Context())
	} else if err == nil {
		err = client.ResourceMapping.UpdateOneID(existing.ID).
			SetStorageKind(firstNonEmpty(req.StorageKind, "internal_table")).
			SetNillableTableName(optionalString(derefString(req.TableName))).
			SetIDField(firstNonEmpty(req.IDField, "id")).
			SetSpaceField(firstNonEmpty(req.SpaceField, "space_id")).
			SetNillableGroupField(optionalString(derefString(req.GroupField))).
			SetNillableOwnerMemberField(optionalString(derefString(req.OwnerMemberField))).
			SetNillableVisibilityField(optionalString(derefString(req.VisibilityField))).
			SetNillableMetadataField(optionalString(derefString(req.MetadataField))).
			SetStatus(firstNonEmpty(derefString(req.Status), "active")).
			SetMetadata(nonNilMap(req.Metadata)).
			Exec(r.Context())
	}
	if err != nil {
		writeError(w, r, http.StatusConflict, "RESOURCE_MAPPING_UPSERT_FAILED", "Failed to register ResourceMapping.", err.Error())
		return
	}
	row, err := s.loadResourceMappingByTypeKey(r.Context(), resourceTypeKey)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load ResourceMapping.", err.Error())
		return
	}
	writeData(w, r, http.StatusCreated, row)
}

func (s *Server) loadResourceTypeByKey(ctx context.Context, key string) (map[string]any, error) {
	row, err := s.loadResourceTypeEntityByKey(ctx, key)
	if err != nil {
		return nil, err
	}
	return resourceTypeMap(row), nil
}

func (s *Server) loadResourceTypeEntityByKey(ctx context.Context, key string) (*coreent.ResourceType, error) {
	if s.ent == nil {
		return nil, errors.New("ent client is not configured")
	}
	row, err := s.ent.ResourceType.Query().Where(entresourcetype.Key(key)).Only(ctx)
	if coreent.IsNotFound(err) {
		return nil, pgx.ErrNoRows
	}
	return row, err
}

func (s *Server) loadResourceMappingByTypeKey(ctx context.Context, key string) (map[string]any, error) {
	rt, err := s.loadResourceTypeEntityByKey(ctx, key)
	if err != nil {
		return nil, err
	}
	row, err := s.ent.ResourceMapping.Query().Where(entresourcemapping.ResourceTypeID(rt.ID)).Only(ctx)
	if coreent.IsNotFound(err) {
		return nil, pgx.ErrNoRows
	}
	if err != nil {
		return nil, err
	}
	return resourceMappingMap(row), nil
}
