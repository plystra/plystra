package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqljson"
	coreent "github.com/plystra/plystra/ent"
	entappdatamodel "github.com/plystra/plystra/ent/appdatamodel"
	entappdatarecord "github.com/plystra/plystra/ent/appdatarecord"
	entappdatarecordrevision "github.com/plystra/plystra/ent/appdatarecordrevision"
	entpermission "github.com/plystra/plystra/ent/permission"
	"github.com/plystra/plystra/ent/predicate"
	entresourceaction "github.com/plystra/plystra/ent/resourceaction"
	entresourcemapping "github.com/plystra/plystra/ent/resourcemapping"
	entresourcetype "github.com/plystra/plystra/ent/resourcetype"
	"github.com/plystra/plystra/internal/authz"

	"github.com/jackc/pgx/v5"
)

const appDataRecordBaseResourceType = "app_data_record"
const maxAppDataBatchOperations = 25

var appDataModelKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
var appDataDataFieldPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)

var appDataReservedListQueryKeys = map[string]bool{
	"limit":           true,
	"cursor":          true,
	"status":          true,
	"group_id":        true,
	"owner_member_id": true,
	"visibility":      true,
	"search":          true,
	"sort":            true,
	"order":           true,
}

var appDataSearchDataFields = []string{
	"name",
	"title",
	"full_name",
	"display_name",
	"email",
	"description",
	"status",
	"current_status",
	"developer_id",
	"project_id",
	"task_id",
}

var appDataRecordSortColumns = map[string]string{
	"id":         entappdatarecord.FieldID,
	"created_at": entappdatarecord.FieldCreatedAt,
	"updated_at": entappdatarecord.FieldUpdatedAt,
	"status":     entappdatarecord.FieldStatus,
	"visibility": entappdatarecord.FieldVisibility,
}

type appDataRecordListOptions struct {
	Limit     int
	Sort      string
	SortField string
	Order     string
	Cursor    *appDataRecordCursor
}

type appDataRecordCursor struct {
	Version   int    `json:"v"`
	Sort      string `json:"sort"`
	Order     string `json:"order"`
	Value     string `json:"value"`
	Tiebreak  string `json:"id"`
	ValueKind string `json:"kind"`
}

type appDataModelMutationRequest struct {
	Actor       authz.ActorContext `json:"actor"`
	ID          string             `json:"id"`
	Key         string             `json:"key"`
	DisplayName string             `json:"display_name"`
	Description *string            `json:"description"`
	Source      *string            `json:"source"`
	Status      *string            `json:"status"`
	Schema      map[string]any     `json:"schema"`
	Metadata    map[string]any     `json:"metadata"`
}

type appDataRecordMutationRequest struct {
	Actor         authz.ActorContext `json:"actor"`
	ID            string             `json:"id"`
	GroupID       *string            `json:"group_id"`
	OwnerMemberID *string            `json:"owner_member_id"`
	DisplayName   *string            `json:"display_name"`
	Visibility    *string            `json:"visibility"`
	Status        *string            `json:"status"`
	Data          map[string]any     `json:"data"`
	Metadata      map[string]any     `json:"metadata"`
}

type appDataRecordBatchRequest struct {
	Actor      authz.ActorContext            `json:"actor"`
	Operations []appDataRecordBatchOperation `json:"operations"`
}

type appDataRecordBatchOperation struct {
	Operation string                       `json:"operation"`
	ModelKey  string                       `json:"model_key"`
	RecordID  string                       `json:"record_id"`
	Request   appDataRecordMutationRequest `json:"request"`
}

func (s *Server) handleSpaceAppData(w http.ResponseWriter, r *http.Request, spaceID string, parts []string) {
	if len(parts) == 0 {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, r)
			return
		}
		writeData(w, r, http.StatusOK, map[string]any{
			"base_path":       "/api/v1/spaces/" + spaceID + "/data",
			"record_resource": appDataRecordBaseResourceType,
			"model_path":      "/api/v1/spaces/" + spaceID + "/data/models",
		})
		return
	}
	if parts[0] == "records" {
		if len(parts) == 2 && parts[1] == "batch" {
			if r.Method != http.MethodPost {
				writeMethodNotAllowed(w, r)
				return
			}
			s.batchAppDataRecords(w, r, spaceID)
			return
		}
		http.NotFound(w, r)
		return
	}
	if parts[0] != "models" {
		http.NotFound(w, r)
		return
	}
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			s.listAppDataModels(w, r, spaceID)
		case http.MethodPost:
			s.createAppDataModel(w, r, spaceID)
		default:
			writeMethodNotAllowed(w, r)
		}
		return
	}
	modelKey := parts[1]
	if !validAppDataModelKey(modelKey) {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "model key is invalid.", nil)
		return
	}
	if len(parts) == 2 {
		switch r.Method {
		case http.MethodGet:
			model, err := s.loadAppDataModelByKey(r.Context(), spaceID, modelKey)
			if errors.Is(err, pgx.ErrNoRows) {
				writeError(w, r, http.StatusNotFound, "APP_DATA_MODEL_NOT_FOUND", "App data model was not found.", nil)
				return
			}
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load app data model.", err.Error())
				return
			}
			writeData(w, r, http.StatusOK, appDataModelMap(model))
		case http.MethodPatch:
			s.updateAppDataModel(w, r, spaceID, modelKey)
		default:
			writeMethodNotAllowed(w, r)
		}
		return
	}
	if len(parts) >= 3 && parts[2] == "records" {
		s.handleAppDataRecords(w, r, spaceID, modelKey, parts[3:])
		return
	}
	http.NotFound(w, r)
}

func (s *Server) handleAppDataResourceLookup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, r)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/app-data/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		http.NotFound(w, r)
		return
	}
	modelKey, recordID := parts[0], parts[1]
	if !validAppDataModelKey(modelKey) {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "model key is invalid.", nil)
		return
	}
	record, err := s.loadAppDataRecordByID(r.Context(), "", modelKey, recordID)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, r, http.StatusNotFound, "APP_DATA_RECORD_NOT_FOUND", "App data record was not found.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load app data record.", err.Error())
		return
	}
	decision, ok := s.authorizeAppDataRecord(w, r, appDataActorFromRequest(r, authz.ActorContext{SpaceID: record.SpaceID}), "read", record)
	if !ok {
		return
	}
	writeData(w, r, http.StatusOK, map[string]any{
		"record":        appDataRecordMap(record),
		"authorization": decision,
	})
}

func (s *Server) listAppDataModels(w http.ResponseWriter, r *http.Request, spaceID string) {
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	q := client.AppDataModel.Query().Where(entappdatamodel.SpaceID(spaceID), entappdatamodel.DeletedAtIsNil())
	if status := strings.TrimSpace(r.URL.Query().Get("status")); status != "" {
		q = q.Where(entappdatamodel.Status(status))
	}
	models, err := q.Order(entappdatamodel.ByKey()).Limit(limitFrom(r, 50)).All(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list app data models.", err.Error())
		return
	}
	rows := make([]map[string]any, 0, len(models))
	for _, model := range models {
		rows = append(rows, appDataModelMap(model))
	}
	writeList(w, r, http.StatusOK, rows, limitFrom(r, 50))
}

func (s *Server) createAppDataModel(w http.ResponseWriter, r *http.Request, spaceID string) {
	var req appDataModelMutationRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Key = strings.ToLower(strings.TrimSpace(req.Key))
	if err := validateAppDataModelMutation(req, true); err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", err.Error(), nil)
		return
	}
	if req.ID == "" {
		req.ID = newEntityID("model_" + req.Key)
	}
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	_, err := client.AppDataModel.Create().
		SetID(req.ID).
		SetSpaceID(spaceID).
		SetKey(req.Key).
		SetDisplayName(strings.TrimSpace(req.DisplayName)).
		SetNillableDescription(optionalString(derefString(req.Description))).
		SetSource(firstNonEmpty(derefString(req.Source), "app")).
		SetStatus(firstNonEmpty(derefString(req.Status), "active")).
		SetSchema(nonNilMap(req.Schema)).
		SetMetadata(nonNilMap(req.Metadata)).
		Save(r.Context())
	if err != nil {
		writeError(w, r, http.StatusConflict, "APP_DATA_MODEL_CREATE_FAILED", "Failed to create app data model.", err.Error())
		return
	}
	model, err := s.loadAppDataModelByKey(r.Context(), spaceID, req.Key)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load created app data model.", err.Error())
		return
	}
	if err := s.ensureAppDataModelResourceRegistration(r.Context(), model); err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to register app data authorization resource.", err.Error())
		return
	}
	if err := s.ensureAppDataModelPermissions(r.Context(), model); err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to register app data permissions.", err.Error())
		return
	}
	s.recordMutationAudit(r.Context(), r, req.Actor, spaceID, "app_data.model.created", "app_data_model", model.ID, appDataAuditDetails("model_create", model.Key, "", req.Schema, req.Metadata))
	writeData(w, r, http.StatusCreated, appDataModelMap(model))
}

func (s *Server) updateAppDataModel(w http.ResponseWriter, r *http.Request, spaceID, modelKey string) {
	var req appDataModelMutationRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Key != "" && req.Key != modelKey {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "model key cannot be changed.", nil)
		return
	}
	if err := validateAppDataModelMutation(req, false); err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", err.Error(), nil)
		return
	}
	current, err := s.loadAppDataModelByKey(r.Context(), spaceID, modelKey)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, r, http.StatusNotFound, "APP_DATA_MODEL_NOT_FOUND", "App data model was not found.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load app data model.", err.Error())
		return
	}
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	displayName := current.DisplayName
	if strings.TrimSpace(req.DisplayName) != "" {
		displayName = strings.TrimSpace(req.DisplayName)
	}
	description := nullableFromRequest(req.Description, derefString(current.Description))
	source := firstNonEmpty(derefString(req.Source), current.Source, "app")
	status := firstNonEmpty(derefString(req.Status), current.Status, "active")
	schemaValue := current.Schema
	if req.Schema != nil {
		schemaValue = req.Schema
	}
	metadata := current.Metadata
	if req.Metadata != nil {
		metadata = req.Metadata
	}
	update := client.AppDataModel.UpdateOneID(current.ID).
		SetDisplayName(displayName).
		SetSource(source).
		SetStatus(status).
		SetSchema(nonNilMap(schemaValue)).
		SetMetadata(nonNilMap(metadata))
	if description == "" {
		update.ClearDescription()
	} else {
		update.SetDescription(description)
	}
	if err := update.Exec(r.Context()); err != nil {
		writeError(w, r, http.StatusConflict, "APP_DATA_MODEL_UPDATE_FAILED", "Failed to update app data model.", err.Error())
		return
	}
	model, err := s.loadAppDataModelByKey(r.Context(), spaceID, modelKey)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load updated app data model.", err.Error())
		return
	}
	if err := s.ensureAppDataModelResourceRegistration(r.Context(), model); err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to register app data authorization resource.", err.Error())
		return
	}
	if err := s.ensureAppDataModelPermissions(r.Context(), model); err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to register app data permissions.", err.Error())
		return
	}
	s.recordMutationAudit(r.Context(), r, req.Actor, spaceID, "app_data.model.updated", "app_data_model", model.ID, appDataAuditDetails("model_update", model.Key, "", schemaValue, metadata))
	writeData(w, r, http.StatusOK, appDataModelMap(model))
}

func (s *Server) handleAppDataRecords(w http.ResponseWriter, r *http.Request, spaceID, modelKey string, parts []string) {
	model, err := s.loadAppDataModelByKey(r.Context(), spaceID, modelKey)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, r, http.StatusNotFound, "APP_DATA_MODEL_NOT_FOUND", "App data model was not found.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load app data model.", err.Error())
		return
	}
	if err := s.ensureAppDataModelResourceRegistration(r.Context(), model); err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to register app data authorization resource.", err.Error())
		return
	}
	if err := s.ensureAppDataModelPermissions(r.Context(), model); err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to register app data permissions.", err.Error())
		return
	}
	if len(parts) == 0 {
		switch r.Method {
		case http.MethodGet:
			s.listAppDataRecords(w, r, model)
		case http.MethodPost:
			s.createAppDataRecord(w, r, model)
		default:
			writeMethodNotAllowed(w, r)
		}
		return
	}
	recordID := parts[0]
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			s.getAppDataRecord(w, r, model, recordID)
		case http.MethodPatch:
			s.updateAppDataRecord(w, r, model, recordID)
		case http.MethodDelete:
			s.deleteAppDataRecord(w, r, model, recordID)
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
		s.archiveAppDataRecord(w, r, model, recordID)
		return
	}
	if len(parts) == 2 && parts[1] == "revisions" {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, r)
			return
		}
		s.listAppDataRecordRevisions(w, r, model, recordID)
		return
	}
	http.NotFound(w, r)
}

func (s *Server) listAppDataRecords(w http.ResponseWriter, r *http.Request, model *coreent.AppDataModel) {
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	listOptions, err := appDataRecordListOptionsFromRequest(r)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", err.Error(), nil)
		return
	}
	q := client.AppDataRecord.Query().Where(entappdatarecord.SpaceID(model.SpaceID), entappdatarecord.ModelID(model.ID), entappdatarecord.DeletedAtIsNil())
	if status := strings.TrimSpace(r.URL.Query().Get("status")); status != "" {
		q = q.Where(entappdatarecord.Status(status))
	}
	if groupID := strings.TrimSpace(r.URL.Query().Get("group_id")); groupID != "" {
		q = q.Where(entappdatarecord.GroupID(groupID))
	}
	if ownerMemberID := strings.TrimSpace(r.URL.Query().Get("owner_member_id")); ownerMemberID != "" {
		q = q.Where(entappdatarecord.OwnerMemberID(ownerMemberID))
	}
	if visibility := strings.TrimSpace(r.URL.Query().Get("visibility")); visibility != "" {
		q = q.Where(entappdatarecord.Visibility(visibility))
	}
	predicates, err := appDataRecordQueryPredicates(r.URL.Query())
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", err.Error(), nil)
		return
	}
	if len(predicates) > 0 {
		q = q.Where(predicates...)
	}
	if listOptions.Cursor != nil {
		q = q.Where(appDataRecordCursorPredicate(listOptions))
	}
	q = q.Order(appDataRecordOrderOptions(listOptions)...)
	records, err := q.Limit(listOptions.Limit + 1).All(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list app data records.", err.Error())
		return
	}
	hasMore := len(records) > listOptions.Limit
	if hasMore {
		records = records[:listOptions.Limit]
	}
	actor := appDataActorFromRequest(r, authz.ActorContext{SpaceID: model.SpaceID})
	serviceAuthorized := s.appDataServiceAuthorized(r, "read", model.SpaceID)
	rows := make([]map[string]any, 0, len(records))
	for _, record := range records {
		var decision any
		if serviceAuthorized {
			decision = appDataServiceDecision(r, actor, "read", record)
		} else {
			checked, ok := s.authorizeAppDataRecord(w, r, actor, "read", record)
			if !ok {
				return
			}
			decision = checked
		}
		row := appDataRecordMap(record)
		row["authorization"] = decision
		rows = append(rows, row)
	}
	var nextCursor *string
	if hasMore && len(records) > 0 {
		cursor, err := encodeAppDataRecordCursor(listOptions, records[len(records)-1])
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to build app data pagination cursor.", err.Error())
			return
		}
		nextCursor = &cursor
	}
	writeListPage(w, r, http.StatusOK, rows, listOptions.Limit, nextCursor, hasMore)
}

func (s *Server) batchAppDataRecords(w http.ResponseWriter, r *http.Request, spaceID string) {
	var req appDataRecordBatchRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if len(req.Operations) == 0 {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "operations is required.", nil)
		return
	}
	if len(req.Operations) > maxAppDataBatchOperations {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", fmt.Sprintf("operations cannot contain more than %d items.", maxAppDataBatchOperations), nil)
		return
	}
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	models := map[string]*coreent.AppDataModel{}
	for i := range req.Operations {
		normalized, err := normalizeAppDataBatchOperation(req.Operations[i])
		if err != nil {
			writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Batch operation is invalid.", appDataBatchErrorDetails(i, req.Operations[i], err.Error()))
			return
		}
		req.Operations[i] = normalized
		if _, exists := models[normalized.ModelKey]; exists {
			continue
		}
		model, err := s.loadAppDataModelByKey(r.Context(), spaceID, normalized.ModelKey)
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, r, http.StatusNotFound, "APP_DATA_MODEL_NOT_FOUND", "App data model was not found.", appDataBatchErrorDetails(i, normalized, "model was not found"))
			return
		}
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load app data model.", err.Error())
			return
		}
		if err := s.ensureAppDataModelResourceRegistration(r.Context(), model); err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to register app data authorization resource.", err.Error())
			return
		}
		if err := s.ensureAppDataModelPermissions(r.Context(), model); err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to register app data permissions.", err.Error())
			return
		}
		models[normalized.ModelKey] = model
	}

	actor := appDataActorFromRequest(r, req.Actor)
	if actor.SpaceID == "" {
		actor.SpaceID = spaceID
	}
	if actor.SpaceID != spaceID {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "actor.space_id must match the path space_id.", nil)
		return
	}

	tx, err := client.Tx(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to start app data transaction.", err.Error())
		return
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	txClient := tx.Client()
	serviceAuthorized := s.appDataServiceAuthorized(r, "manage", spaceID)
	results := make([]map[string]any, 0, len(req.Operations))
	for i, op := range req.Operations {
		result, batchErr := s.applyAppDataBatchOperation(r.Context(), r, txClient, models[op.ModelKey], actor, op, i, serviceAuthorized)
		if batchErr != nil {
			writeError(w, r, batchErr.Status, batchErr.Code, batchErr.Message, batchErr.Details)
			return
		}
		results = append(results, result)
	}
	if err := tx.Commit(); err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to commit app data transaction.", err.Error())
		return
	}
	committed = true
	writeData(w, r, http.StatusOK, map[string]any{
		"operation_count": len(results),
		"results":         results,
	})
}

func (s *Server) applyAppDataBatchOperation(ctx context.Context, r *http.Request, client *coreent.Client, model *coreent.AppDataModel, actor authz.ActorContext, op appDataRecordBatchOperation, index int, serviceAuthorized bool) (map[string]any, *appDataBatchError) {
	switch op.Operation {
	case "create":
		return s.applyAppDataBatchCreate(ctx, r, client, model, actor, op, index, serviceAuthorized)
	case "update":
		return s.applyAppDataBatchUpdate(ctx, r, client, model, actor, op, index, serviceAuthorized)
	case "archive":
		return s.applyAppDataBatchStatus(ctx, r, client, model, actor, op, index, serviceAuthorized, "archived", "archive")
	case "delete":
		return s.applyAppDataBatchStatus(ctx, r, client, model, actor, op, index, serviceAuthorized, "deleted", "delete")
	default:
		return nil, newAppDataBatchError(index, op, http.StatusBadRequest, "VALIDATION_FAILED", "Batch operation is invalid.", "operation is unsupported")
	}
}

func (s *Server) applyAppDataBatchCreate(ctx context.Context, r *http.Request, client *coreent.Client, model *coreent.AppDataModel, actor authz.ActorContext, op appDataRecordBatchOperation, index int, serviceAuthorized bool) (map[string]any, *appDataBatchError) {
	req := op.Request
	if req.ID == "" {
		req.ID = newEntityID(model.Key)
	}
	groupID := derefString(req.GroupID)
	ownerMemberID := derefString(req.OwnerMemberID)
	if ownerMemberID == "" {
		ownerMemberID = actor.MemberID
	}
	if err := s.validateResourceRefs(ctx, model.SpaceID, groupID, ownerMemberID); err != nil {
		return nil, newAppDataBatchError(index, op, http.StatusBadRequest, "VALIDATION_FAILED", "Record references are invalid.", err.Error())
	}
	resourceType := appDataModelResourceType(model.Key)
	visibility := firstNonEmpty(derefString(req.Visibility), "private")
	status := firstNonEmpty(derefString(req.Status), "active")
	target, err := s.proposedResourceTarget(ctx, resourceType, req.ID, model.SpaceID, groupID, ownerMemberID, derefString(req.DisplayName), visibility, status, req.Metadata)
	if err != nil {
		return nil, newAppDataBatchError(index, op, http.StatusBadRequest, "VALIDATION_FAILED", "Failed to build proposed target.", err.Error())
	}
	var decision any
	if serviceAuthorized {
		decision = appDataServiceDecisionForTarget(r, actor, "create", req.ID, target)
	} else {
		checked, batchErr := s.authorizeAppDataBatchTarget(ctx, r, actor, resourceType, req.ID, "create", target, index, op)
		if batchErr != nil {
			return nil, batchErr
		}
		decision = checked
	}
	if _, err := client.AppDataRecord.Create().
		SetID(req.ID).
		SetSpaceID(model.SpaceID).
		SetModelID(model.ID).
		SetModelKey(model.Key).
		SetNillableGroupID(optionalString(groupID)).
		SetNillableOwnerMemberID(optionalString(ownerMemberID)).
		SetNillableDisplayName(optionalString(derefString(req.DisplayName))).
		SetVisibility(visibility).
		SetStatus(status).
		SetData(nonNilMap(req.Data)).
		SetMetadata(nonNilMap(req.Metadata)).
		Save(ctx); err != nil {
		return nil, newAppDataBatchError(index, op, http.StatusConflict, "APP_DATA_RECORD_CREATE_FAILED", "Failed to create app data record.", err.Error())
	}
	record, err := loadAppDataRecordByIDFromClient(ctx, client, model.SpaceID, model.Key, req.ID)
	if err != nil {
		return nil, newAppDataBatchError(index, op, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load created app data record.", err.Error())
	}
	if err := writeAppDataRecordRevisionWithClient(ctx, client, r, actor, record, "create"); err != nil {
		return nil, newAppDataBatchError(index, op, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to write app data revision.", err.Error())
	}
	if err := s.recordMutationAuditWithClient(ctx, client, r, actor, model.SpaceID, "app_data.record.created", resourceType, record.ID, appDataAuditDetails("record_create", model.Key, record.ID, record.Data, record.Metadata)); err != nil {
		return nil, newAppDataBatchError(index, op, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to write app data audit log.", err.Error())
	}
	return appDataBatchResult(index, op.Operation, model.Key, record, decision), nil
}

func (s *Server) applyAppDataBatchUpdate(ctx context.Context, r *http.Request, client *coreent.Client, model *coreent.AppDataModel, actor authz.ActorContext, op appDataRecordBatchOperation, index int, serviceAuthorized bool) (map[string]any, *appDataBatchError) {
	req := op.Request
	current, err := loadAppDataRecordByIDFromClient(ctx, client, model.SpaceID, model.Key, op.RecordID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, newAppDataBatchError(index, op, http.StatusNotFound, "APP_DATA_RECORD_NOT_FOUND", "App data record was not found.", "record was not found")
	}
	if err != nil {
		return nil, newAppDataBatchError(index, op, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load app data record.", err.Error())
	}
	proposed, err := s.appDataRecordTarget(ctx, current)
	if err != nil {
		return nil, newAppDataBatchError(index, op, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to build app data authorization target.", err.Error())
	}
	if req.GroupID != nil {
		proposed.Resource.GroupID = *req.GroupID
		group, err := s.loadGroupSnapshot(ctx, model.SpaceID, *req.GroupID)
		if err != nil {
			return nil, newAppDataBatchError(index, op, http.StatusBadRequest, "VALIDATION_FAILED", "group_id is invalid for the record space.", err.Error())
		}
		proposed.Group = group
	}
	if req.OwnerMemberID != nil {
		if err := s.validateMemberInSpace(ctx, model.SpaceID, *req.OwnerMemberID); err != nil {
			return nil, newAppDataBatchError(index, op, http.StatusBadRequest, "VALIDATION_FAILED", "owner_member_id is invalid for the record space.", err.Error())
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
	resourceType := appDataModelResourceType(model.Key)
	var decision any
	if serviceAuthorized {
		decision = appDataServiceDecisionForTarget(r, actor, "update", current.ID, proposed)
	} else {
		checked, batchErr := s.authorizeAppDataBatchTarget(ctx, r, actor, resourceType, current.ID, "update", proposed, index, op)
		if batchErr != nil {
			return nil, batchErr
		}
		decision = checked
	}
	data := current.Data
	if req.Data != nil {
		data = req.Data
	}
	update := client.AppDataRecord.UpdateOneID(current.ID).
		SetVisibility(firstNonEmpty(proposed.Resource.Visibility, "private")).
		SetStatus(firstNonEmpty(proposed.Resource.Status, "active")).
		SetData(nonNilMap(data)).
		SetMetadata(nonNilMap(proposed.Resource.Metadata))
	setOptionalRecordString(update.SetGroupID, update.ClearGroupID, proposed.Resource.GroupID)
	setOptionalRecordString(update.SetOwnerMemberID, update.ClearOwnerMemberID, proposed.Resource.OwnerMemberID)
	setOptionalRecordString(update.SetDisplayName, update.ClearDisplayName, proposed.Resource.DisplayName)
	if err := update.Exec(ctx); err != nil {
		return nil, newAppDataBatchError(index, op, http.StatusConflict, "APP_DATA_RECORD_UPDATE_FAILED", "Failed to update app data record.", err.Error())
	}
	record, err := loadAppDataRecordByIDFromClient(ctx, client, model.SpaceID, model.Key, current.ID)
	if err != nil {
		return nil, newAppDataBatchError(index, op, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load updated app data record.", err.Error())
	}
	if err := writeAppDataRecordRevisionWithClient(ctx, client, r, actor, record, "update"); err != nil {
		return nil, newAppDataBatchError(index, op, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to write app data revision.", err.Error())
	}
	if err := s.recordMutationAuditWithClient(ctx, client, r, actor, model.SpaceID, "app_data.record.updated", resourceType, record.ID, appDataAuditDetails("record_update", model.Key, record.ID, record.Data, record.Metadata)); err != nil {
		return nil, newAppDataBatchError(index, op, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to write app data audit log.", err.Error())
	}
	return appDataBatchResult(index, op.Operation, model.Key, record, decision), nil
}

func (s *Server) applyAppDataBatchStatus(ctx context.Context, r *http.Request, client *coreent.Client, model *coreent.AppDataModel, actor authz.ActorContext, op appDataRecordBatchOperation, index int, serviceAuthorized bool, status, action string) (map[string]any, *appDataBatchError) {
	record, err := loadAppDataRecordByIDFromClient(ctx, client, model.SpaceID, model.Key, op.RecordID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, newAppDataBatchError(index, op, http.StatusNotFound, "APP_DATA_RECORD_NOT_FOUND", "App data record was not found.", "record was not found")
	}
	if err != nil {
		return nil, newAppDataBatchError(index, op, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load app data record.", err.Error())
	}
	resourceType := appDataModelResourceType(model.Key)
	var decision any
	if serviceAuthorized {
		decision = appDataServiceDecision(r, actor, action, record)
	} else {
		target, err := s.appDataRecordTarget(ctx, record)
		if err != nil {
			return nil, newAppDataBatchError(index, op, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to build app data authorization target.", err.Error())
		}
		checked, batchErr := s.authorizeAppDataBatchTarget(ctx, r, actor, resourceType, record.ID, action, target, index, op)
		if batchErr != nil {
			return nil, batchErr
		}
		decision = checked
	}
	update := client.AppDataRecord.UpdateOneID(record.ID).SetStatus(status)
	if status == "deleted" {
		update.SetDeletedAt(time.Now().UTC())
	}
	if err := update.Exec(ctx); err != nil {
		return nil, newAppDataBatchError(index, op, http.StatusConflict, "APP_DATA_RECORD_STATUS_FAILED", "Failed to update app data record status.", err.Error())
	}
	updated, err := loadAppDataRecordForRevisionFromClient(ctx, client, record.ID)
	if err != nil {
		return nil, newAppDataBatchError(index, op, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load updated app data record.", err.Error())
	}
	if err := writeAppDataRecordRevisionWithClient(ctx, client, r, actor, updated, action); err != nil {
		return nil, newAppDataBatchError(index, op, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to write app data revision.", err.Error())
	}
	if err := s.recordMutationAuditWithClient(ctx, client, r, actor, model.SpaceID, "app_data.record."+action+"d", resourceType, updated.ID, appDataAuditDetails("record_"+action, model.Key, updated.ID, updated.Data, updated.Metadata)); err != nil {
		return nil, newAppDataBatchError(index, op, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to write app data audit log.", err.Error())
	}
	return appDataBatchResult(index, op.Operation, model.Key, updated, decision), nil
}

type appDataBatchError struct {
	Status  int
	Code    string
	Message string
	Details any
}

func newAppDataBatchError(index int, op appDataRecordBatchOperation, status int, code, message, reason string) *appDataBatchError {
	return &appDataBatchError{
		Status:  status,
		Code:    code,
		Message: message,
		Details: appDataBatchErrorDetails(index, op, reason),
	}
}

func appDataBatchErrorDetails(index int, op appDataRecordBatchOperation, reason string) map[string]any {
	return map[string]any{
		"operation_index": index,
		"operation":       strings.ToLower(strings.TrimSpace(op.Operation)),
		"model_key":       strings.ToLower(strings.TrimSpace(op.ModelKey)),
		"record_id":       strings.TrimSpace(op.RecordID),
		"reason":          reason,
	}
}

func normalizeAppDataBatchOperation(op appDataRecordBatchOperation) (appDataRecordBatchOperation, error) {
	op.Operation = strings.ToLower(strings.TrimSpace(op.Operation))
	op.ModelKey = strings.ToLower(strings.TrimSpace(op.ModelKey))
	op.RecordID = strings.TrimSpace(op.RecordID)
	op.Request.ID = strings.TrimSpace(op.Request.ID)
	if !validAppDataModelKey(op.ModelKey) {
		return op, fmt.Errorf("model_key must match %s", appDataModelKeyPattern.String())
	}
	switch op.Operation {
	case "create":
		if op.RecordID != "" {
			if op.Request.ID != "" && op.Request.ID != op.RecordID {
				return op, errors.New("record_id must match request.id")
			}
			op.Request.ID = op.RecordID
		}
		if err := validateAppDataRecordMutation(op.Request, true); err != nil {
			return op, err
		}
	case "update":
		if op.RecordID == "" {
			return op, errors.New("record_id is required")
		}
		if op.Request.ID != "" && op.Request.ID != op.RecordID {
			return op, errors.New("request.id must match record_id")
		}
		if err := validateAppDataRecordMutation(op.Request, false); err != nil {
			return op, err
		}
	case "archive", "delete":
		if op.RecordID == "" {
			return op, errors.New("record_id is required")
		}
		if op.Request.ID != "" && op.Request.ID != op.RecordID {
			return op, errors.New("request.id must match record_id")
		}
	default:
		return op, errors.New("operation must be create, update, archive, or delete")
	}
	return op, nil
}

func (s *Server) authorizeAppDataBatchTarget(ctx context.Context, r *http.Request, actor authz.ActorContext, resourceType, resourceID, action string, target authz.TargetSnapshot, index int, op appDataRecordBatchOperation) (*authz.Decision, *appDataBatchError) {
	decision, err := authz.Check(ctx, s.authzStore, authz.CheckInput{
		Actor:        actor,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Action:       action,
		Target:       &target,
		RequestID:    requestIDFrom(r),
		IP:           remoteIPFrom(r),
		UserAgent:    r.UserAgent(),
	})
	if err != nil {
		return nil, newAppDataBatchError(index, op, http.StatusInternalServerError, "INTERNAL_ERROR", "Authorization check failed.", err.Error())
	}
	if !decision.IsAllowed() {
		return nil, &appDataBatchError{
			Status:  http.StatusForbidden,
			Code:    "AUTHORIZATION_DENIED",
			Message: "Batch operation is not allowed.",
			Details: decision,
		}
	}
	return decision, nil
}

func loadAppDataRecordByIDFromClient(ctx context.Context, client *coreent.Client, spaceID, modelKey, recordID string) (*coreent.AppDataRecord, error) {
	q := client.AppDataRecord.Query().
		Where(entappdatarecord.ModelKey(modelKey), entappdatarecord.ID(recordID))
	if spaceID != "" {
		q = q.Where(entappdatarecord.SpaceID(spaceID), entappdatarecord.DeletedAtIsNil())
	} else {
		q = q.Where(entappdatarecord.DeletedAtIsNil())
	}
	row, err := q.Only(ctx)
	if coreent.IsNotFound(err) {
		return nil, pgx.ErrNoRows
	}
	return row, err
}

func loadAppDataRecordForRevisionFromClient(ctx context.Context, client *coreent.Client, recordID string) (*coreent.AppDataRecord, error) {
	row, err := client.AppDataRecord.Query().Where(entappdatarecord.ID(recordID)).Only(ctx)
	if coreent.IsNotFound(err) {
		return nil, pgx.ErrNoRows
	}
	return row, err
}

func writeAppDataRecordRevisionWithClient(ctx context.Context, client *coreent.Client, r *http.Request, actor authz.ActorContext, record *coreent.AppDataRecord, operation string) error {
	count, err := client.AppDataRecordRevision.Query().Where(entappdatarecordrevision.RecordID(record.ID)).Count(ctx)
	if err != nil {
		return err
	}
	revision := count + 1
	_, err = client.AppDataRecordRevision.Create().
		SetID(newEntityID("rev")).
		SetRecordID(record.ID).
		SetSpaceID(record.SpaceID).
		SetModelID(record.ModelID).
		SetModelKey(record.ModelKey).
		SetRevision(revision).
		SetOperation(operation).
		SetNillableActorUserID(optionalString(actor.UserID)).
		SetNillableActorMemberID(optionalString(actor.MemberID)).
		SetNillableActorUserMemberID(optionalString(actor.UserMemberID)).
		SetData(nonNilMap(record.Data)).
		SetMetadata(map[string]any{
			"request_id": requestIDFrom(r),
			"status":     record.Status,
			"visibility": record.Visibility,
			"data_keys":  sortedMapKeys(record.Data),
		}).
		Save(ctx)
	return err
}

func (s *Server) recordMutationAuditWithClient(ctx context.Context, client *coreent.Client, r *http.Request, actor authz.ActorContext, spaceID, action, resourceType, resourceID string, details any) error {
	if spaceID == "" {
		return nil
	}
	actor = auditActorFromRequest(r, actor, spaceID)
	trace := map[string]any{
		"trace_version": traceVersion(),
		"decision":      authz.DecisionAllow,
		"reason":        "Core management API mutation was accepted",
		"request_id":    requestIDFrom(r),
		"actor": map[string]any{
			"user_id":        actor.UserID,
			"member_id":      actor.MemberID,
			"user_member_id": actor.UserMemberID,
			"space_id":       firstNonEmpty(actor.SpaceID, spaceID),
		},
		"target": map[string]any{
			"resource_type": resourceType,
			"resource_id":   resourceID,
		},
		"details":    details,
		"created_at": time.Now().UTC().Format(time.RFC3339),
	}
	_, err := client.AuditLog.Create().
		SetID(newEntityID("audit")).
		SetSpaceID(spaceID).
		SetNillableActorUserID(optionalString(actor.UserID)).
		SetNillableActorMemberID(optionalString(actor.MemberID)).
		SetNillableActorUserMemberID(optionalString(actor.UserMemberID)).
		SetAction(action).
		SetResourceType(resourceType).
		SetResourceID(resourceID).
		SetDecision(string(authz.DecisionAllow)).
		SetTrace(trace).
		SetNillableRequestID(optionalString(requestIDFrom(r))).
		SetNillableIPAddress(optionalString(remoteIPFrom(r))).
		SetNillableUserAgent(optionalString(r.UserAgent())).
		Save(ctx)
	return err
}

func appDataBatchResult(index int, operation, modelKey string, record *coreent.AppDataRecord, decision any) map[string]any {
	return map[string]any{
		"operation_index": index,
		"operation":       operation,
		"model_key":       modelKey,
		"record":          appDataRecordMap(record),
		"authorization":   decision,
	}
}

func (s *Server) createAppDataRecord(w http.ResponseWriter, r *http.Request, model *coreent.AppDataModel) {
	var req appDataRecordMutationRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := validateAppDataRecordMutation(req, true); err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", err.Error(), nil)
		return
	}
	if req.ID == "" {
		req.ID = newEntityID(model.Key)
	}
	groupID := derefString(req.GroupID)
	ownerMemberID := derefString(req.OwnerMemberID)
	actor := appDataActorFromRequest(r, req.Actor)
	if actor.SpaceID == "" {
		actor.SpaceID = model.SpaceID
	}
	if ownerMemberID == "" {
		ownerMemberID = actor.MemberID
	}
	if err := s.validateResourceRefs(r.Context(), model.SpaceID, groupID, ownerMemberID); err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Record references are invalid.", err.Error())
		return
	}
	resourceType := appDataModelResourceType(model.Key)
	target, err := s.proposedResourceTarget(r.Context(), resourceType, req.ID, model.SpaceID, groupID, ownerMemberID, derefString(req.DisplayName), firstNonEmpty(derefString(req.Visibility), "private"), firstNonEmpty(derefString(req.Status), "active"), req.Metadata)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Failed to build proposed target.", err.Error())
		return
	}
	var decision any
	if s.appDataServiceAuthorized(r, "manage", model.SpaceID) {
		decision = appDataServiceDecisionForTarget(r, actor, "create", req.ID, target)
	} else {
		checked, ok := s.authorizeTarget(w, r, actor, resourceType, req.ID, "create", target)
		if !ok {
			return
		}
		decision = checked
	}
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	_, err = client.AppDataRecord.Create().
		SetID(req.ID).
		SetSpaceID(model.SpaceID).
		SetModelID(model.ID).
		SetModelKey(model.Key).
		SetNillableGroupID(optionalString(groupID)).
		SetNillableOwnerMemberID(optionalString(ownerMemberID)).
		SetNillableDisplayName(optionalString(derefString(req.DisplayName))).
		SetVisibility(firstNonEmpty(derefString(req.Visibility), "private")).
		SetStatus(firstNonEmpty(derefString(req.Status), "active")).
		SetData(nonNilMap(req.Data)).
		SetMetadata(nonNilMap(req.Metadata)).
		Save(r.Context())
	if err != nil {
		writeError(w, r, http.StatusConflict, "APP_DATA_RECORD_CREATE_FAILED", "Failed to create app data record.", err.Error())
		return
	}
	record, err := s.loadAppDataRecordByID(r.Context(), model.SpaceID, model.Key, req.ID)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load created app data record.", err.Error())
		return
	}
	if err := s.writeAppDataRecordRevision(r.Context(), r, actor, record, "create"); err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to write app data revision.", err.Error())
		return
	}
	s.recordMutationAudit(r.Context(), r, actor, model.SpaceID, "app_data.record.created", resourceType, record.ID, appDataAuditDetails("record_create", model.Key, record.ID, record.Data, record.Metadata))
	writeData(w, r, http.StatusCreated, map[string]any{
		"record":        appDataRecordMap(record),
		"authorization": decision,
	})
}

func (s *Server) getAppDataRecord(w http.ResponseWriter, r *http.Request, model *coreent.AppDataModel, recordID string) {
	record, err := s.loadAppDataRecordByID(r.Context(), model.SpaceID, model.Key, recordID)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, r, http.StatusNotFound, "APP_DATA_RECORD_NOT_FOUND", "App data record was not found.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load app data record.", err.Error())
		return
	}
	actor := appDataActorFromRequest(r, authz.ActorContext{SpaceID: model.SpaceID})
	var decision any
	if s.appDataServiceAuthorized(r, "read", model.SpaceID) {
		decision = appDataServiceDecision(r, actor, "read", record)
	} else {
		checked, ok := s.authorizeAppDataRecord(w, r, actor, "read", record)
		if !ok {
			return
		}
		decision = checked
	}
	writeData(w, r, http.StatusOK, map[string]any{
		"record":        appDataRecordMap(record),
		"authorization": decision,
	})
}

func (s *Server) updateAppDataRecord(w http.ResponseWriter, r *http.Request, model *coreent.AppDataModel, recordID string) {
	var req appDataRecordMutationRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := validateAppDataRecordMutation(req, false); err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", err.Error(), nil)
		return
	}
	current, err := s.loadAppDataRecordByID(r.Context(), model.SpaceID, model.Key, recordID)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, r, http.StatusNotFound, "APP_DATA_RECORD_NOT_FOUND", "App data record was not found.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load app data record.", err.Error())
		return
	}
	actor := appDataActorFromRequest(r, req.Actor)
	if actor.SpaceID == "" {
		actor.SpaceID = model.SpaceID
	}
	proposed, err := s.appDataRecordTarget(r.Context(), current)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to build app data authorization target.", err.Error())
		return
	}
	if req.GroupID != nil {
		proposed.Resource.GroupID = *req.GroupID
		group, err := s.loadGroupSnapshot(r.Context(), model.SpaceID, *req.GroupID)
		if err != nil {
			writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "group_id is invalid for the record space.", err.Error())
			return
		}
		proposed.Group = group
	}
	if req.OwnerMemberID != nil {
		if err := s.validateMemberInSpace(r.Context(), model.SpaceID, *req.OwnerMemberID); err != nil {
			writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "owner_member_id is invalid for the record space.", err.Error())
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
	resourceType := appDataModelResourceType(model.Key)
	var decision any
	if s.appDataServiceAuthorized(r, "manage", model.SpaceID) {
		decision = appDataServiceDecisionForTarget(r, actor, "update", current.ID, proposed)
	} else {
		checked, ok := s.authorizeTarget(w, r, actor, resourceType, current.ID, "update", proposed)
		if !ok {
			return
		}
		decision = checked
	}
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	data := current.Data
	if req.Data != nil {
		data = req.Data
	}
	update := client.AppDataRecord.UpdateOneID(current.ID).
		SetVisibility(firstNonEmpty(proposed.Resource.Visibility, "private")).
		SetStatus(firstNonEmpty(proposed.Resource.Status, "active")).
		SetData(nonNilMap(data)).
		SetMetadata(nonNilMap(proposed.Resource.Metadata))
	setOptionalRecordString(update.SetGroupID, update.ClearGroupID, proposed.Resource.GroupID)
	setOptionalRecordString(update.SetOwnerMemberID, update.ClearOwnerMemberID, proposed.Resource.OwnerMemberID)
	setOptionalRecordString(update.SetDisplayName, update.ClearDisplayName, proposed.Resource.DisplayName)
	if err := update.Exec(r.Context()); err != nil {
		writeError(w, r, http.StatusConflict, "APP_DATA_RECORD_UPDATE_FAILED", "Failed to update app data record.", err.Error())
		return
	}
	record, err := s.loadAppDataRecordByID(r.Context(), model.SpaceID, model.Key, current.ID)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load updated app data record.", err.Error())
		return
	}
	if err := s.writeAppDataRecordRevision(r.Context(), r, actor, record, "update"); err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to write app data revision.", err.Error())
		return
	}
	s.recordMutationAudit(r.Context(), r, actor, model.SpaceID, "app_data.record.updated", resourceType, record.ID, appDataAuditDetails("record_update", model.Key, record.ID, record.Data, record.Metadata))
	writeData(w, r, http.StatusOK, map[string]any{
		"record":        appDataRecordMap(record),
		"authorization": decision,
	})
}

func (s *Server) archiveAppDataRecord(w http.ResponseWriter, r *http.Request, model *coreent.AppDataModel, recordID string) {
	s.updateAppDataRecordStatus(w, r, model, recordID, "archived", "archive")
}

func (s *Server) deleteAppDataRecord(w http.ResponseWriter, r *http.Request, model *coreent.AppDataModel, recordID string) {
	s.updateAppDataRecordStatus(w, r, model, recordID, "deleted", "delete")
}

func (s *Server) updateAppDataRecordStatus(w http.ResponseWriter, r *http.Request, model *coreent.AppDataModel, recordID, status, action string) {
	var req appDataRecordMutationRequest
	if !decodeOptionalJSON(w, r, &req) {
		return
	}
	record, err := s.loadAppDataRecordByID(r.Context(), model.SpaceID, model.Key, recordID)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, r, http.StatusNotFound, "APP_DATA_RECORD_NOT_FOUND", "App data record was not found.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load app data record.", err.Error())
		return
	}
	actor := appDataActorFromRequest(r, req.Actor)
	if actor.SpaceID == "" {
		actor.SpaceID = model.SpaceID
	}
	authAction := action
	if action == "archive" {
		authAction = "archive"
	}
	var decision any
	if s.appDataServiceAuthorized(r, "manage", model.SpaceID) {
		decision = appDataServiceDecision(r, actor, authAction, record)
	} else {
		checked, ok := s.authorizeAppDataRecord(w, r, actor, authAction, record)
		if !ok {
			return
		}
		decision = checked
	}
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	update := client.AppDataRecord.UpdateOneID(record.ID).SetStatus(status)
	if status == "deleted" {
		update.SetDeletedAt(time.Now().UTC())
	}
	if err := update.Exec(r.Context()); err != nil {
		writeError(w, r, http.StatusConflict, "APP_DATA_RECORD_STATUS_FAILED", "Failed to update app data record status.", err.Error())
		return
	}
	updated, err := s.loadAppDataRecordForRevision(r.Context(), record.ID)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load updated app data record.", err.Error())
		return
	}
	if err := s.writeAppDataRecordRevision(r.Context(), r, actor, updated, action); err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to write app data revision.", err.Error())
		return
	}
	s.recordMutationAudit(r.Context(), r, actor, model.SpaceID, "app_data.record."+action+"d", appDataModelResourceType(model.Key), updated.ID, appDataAuditDetails("record_"+action, model.Key, updated.ID, updated.Data, updated.Metadata))
	writeData(w, r, http.StatusOK, map[string]any{
		"record":        appDataRecordMap(updated),
		"authorization": decision,
	})
}

func (s *Server) listAppDataRecordRevisions(w http.ResponseWriter, r *http.Request, model *coreent.AppDataModel, recordID string) {
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	revisions, err := client.AppDataRecordRevision.Query().
		Where(
			entappdatarecordrevision.SpaceID(model.SpaceID),
			entappdatarecordrevision.ModelID(model.ID),
			entappdatarecordrevision.RecordID(recordID),
		).
		Order(entappdatarecordrevision.ByRevision()).
		Limit(limitFrom(r, 50)).
		All(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list app data revisions.", err.Error())
		return
	}
	rows := make([]map[string]any, 0, len(revisions))
	for _, revision := range revisions {
		rows = append(rows, appDataRevisionMap(revision))
	}
	writeList(w, r, http.StatusOK, rows, limitFrom(r, 50))
}

func (s *Server) loadAppDataModelByKey(ctx context.Context, spaceID, modelKey string) (*coreent.AppDataModel, error) {
	if s.ent == nil {
		return nil, errors.New("ent client is not configured")
	}
	row, err := s.ent.AppDataModel.Query().
		Where(entappdatamodel.SpaceID(spaceID), entappdatamodel.Key(modelKey), entappdatamodel.DeletedAtIsNil()).
		Only(ctx)
	if coreent.IsNotFound(err) {
		return nil, pgx.ErrNoRows
	}
	return row, err
}

func (s *Server) loadAppDataRecordByID(ctx context.Context, spaceID, modelKey, recordID string) (*coreent.AppDataRecord, error) {
	if s.ent == nil {
		return nil, errors.New("ent client is not configured")
	}
	q := s.ent.AppDataRecord.Query().
		Where(entappdatarecord.ModelKey(modelKey), entappdatarecord.ID(recordID))
	if spaceID != "" {
		q = q.Where(entappdatarecord.SpaceID(spaceID), entappdatarecord.DeletedAtIsNil())
	} else {
		q = q.Where(entappdatarecord.DeletedAtIsNil())
	}
	row, err := q.Only(ctx)
	if coreent.IsNotFound(err) {
		return nil, pgx.ErrNoRows
	}
	return row, err
}

func (s *Server) loadAppDataRecordForRevision(ctx context.Context, recordID string) (*coreent.AppDataRecord, error) {
	if s.ent == nil {
		return nil, errors.New("ent client is not configured")
	}
	row, err := s.ent.AppDataRecord.Query().Where(entappdatarecord.ID(recordID)).Only(ctx)
	if coreent.IsNotFound(err) {
		return nil, pgx.ErrNoRows
	}
	return row, err
}

func (s *Server) ensureAppDataModelResourceRegistration(ctx context.Context, model *coreent.AppDataModel) error {
	if s.ent == nil {
		return errors.New("ent client is not configured")
	}
	resourceType := appDataModelResourceType(model.Key)
	rtID := "rt_" + resourceType
	existing, err := s.ent.ResourceType.Query().Where(entresourcetype.Key(resourceType)).Only(ctx)
	if err != nil && !coreent.IsNotFound(err) {
		return err
	}
	if coreent.IsNotFound(err) {
		existing, err = s.ent.ResourceType.Create().
			SetID(rtID).
			SetKey(resourceType).
			SetDisplayName(model.DisplayName).
			SetNillableDescription(optionalString("Application data model: " + model.Key)).
			SetSource("core.app_data").
			SetStatus(model.Status).
			SetMetadata(map[string]any{
				"app_data_model_id":  model.ID,
				"app_data_model_key": model.Key,
				"base_resource_type": appDataRecordBaseResourceType,
			}).
			Save(ctx)
		if err != nil {
			return err
		}
	} else {
		update := s.ent.ResourceType.UpdateOneID(existing.ID).
			SetDisplayName(model.DisplayName).
			SetSource("core.app_data").
			SetStatus(model.Status).
			SetMetadata(map[string]any{
				"app_data_model_id":  model.ID,
				"app_data_model_key": model.Key,
				"base_resource_type": appDataRecordBaseResourceType,
			})
		update.SetDescription("Application data model: " + model.Key)
		existing, err = update.Save(ctx)
		if err != nil {
			return err
		}
	}
	for _, action := range appDataModelActions(model.DisplayName) {
		row, err := s.ent.ResourceAction.Query().
			Where(entresourceaction.ResourceTypeID(existing.ID), entresourceaction.Key(action.key)).
			Only(ctx)
		if err != nil && !coreent.IsNotFound(err) {
			return err
		}
		if coreent.IsNotFound(err) {
			if _, err := s.ent.ResourceAction.Create().
				SetID(newEntityID("ra_" + resourceType + "_" + action.key)).
				SetResourceTypeID(existing.ID).
				SetKey(action.key).
				SetDisplayName(action.displayName).
				SetNillableDescription(optionalString("App data " + action.key + " action for " + model.Key)).
				SetRiskLevel(action.riskLevel).
				SetAuditDefault(true).
				SetMetadata(map[string]any{"app_data_model_key": model.Key}).
				Save(ctx); err != nil {
				return err
			}
			continue
		}
		if _, err := s.ent.ResourceAction.UpdateOneID(row.ID).
			SetDisplayName(action.displayName).
			SetRiskLevel(action.riskLevel).
			SetAuditDefault(true).
			SetMetadata(map[string]any{"app_data_model_key": model.Key}).
			Save(ctx); err != nil {
			return err
		}
	}
	mapping, err := s.ent.ResourceMapping.Query().Where(entresourcemapping.ResourceTypeID(existing.ID)).Only(ctx)
	if err != nil && !coreent.IsNotFound(err) {
		return err
	}
	if coreent.IsNotFound(err) {
		_, err = s.ent.ResourceMapping.Create().
			SetID(newEntityID("rm_" + resourceType)).
			SetResourceTypeID(existing.ID).
			SetStorageKind("internal_table").
			SetTableName("app_data_records").
			SetIDField("id").
			SetSpaceField("space_id").
			SetGroupField("group_id").
			SetOwnerMemberField("owner_member_id").
			SetVisibilityField("visibility").
			SetMetadataField("metadata").
			SetStatus("active").
			SetMetadata(map[string]any{
				"app_data_model_key": model.Key,
				"model_field":        "model_key",
				"data_field":         "data",
			}).
			Save(ctx)
		return err
	}
	_, err = s.ent.ResourceMapping.UpdateOneID(mapping.ID).
		SetStorageKind("internal_table").
		SetTableName("app_data_records").
		SetIDField("id").
		SetSpaceField("space_id").
		SetGroupField("group_id").
		SetOwnerMemberField("owner_member_id").
		SetVisibilityField("visibility").
		SetMetadataField("metadata").
		SetStatus("active").
		SetMetadata(map[string]any{
			"app_data_model_key": model.Key,
			"model_field":        "model_key",
			"data_field":         "data",
		}).
		Save(ctx)
	return err
}

func (s *Server) ensureAppDataModelPermissions(ctx context.Context, model *coreent.AppDataModel) error {
	if s.ent == nil {
		return errors.New("ent client is not configured")
	}
	resourceType := appDataModelResourceType(model.Key)
	for _, action := range appDataModelActions(model.DisplayName) {
		row, err := s.ent.Permission.Query().
			Where(
				entpermission.Resource(resourceType),
				entpermission.Action(action.key),
				entpermission.Scope(string(authz.ScopeSpace)),
			).
			Only(ctx)
		if err != nil && !coreent.IsNotFound(err) {
			return err
		}
		metadata := map[string]any{
			"app_data_model_id":  model.ID,
			"app_data_model_key": model.Key,
			"managed_by":         "core.app_data",
		}
		description := "App data " + action.key + " permission for " + model.Key + "."
		if coreent.IsNotFound(err) {
			if _, err := s.ent.Permission.Create().
				SetID(appDataModelPermissionID(resourceType, action.key)).
				SetResource(resourceType).
				SetAction(action.key).
				SetScope(string(authz.ScopeSpace)).
				SetDescription(description).
				SetStatus(permissionStatusForModel(model.Status)).
				SetMetadata(metadata).
				Save(ctx); err != nil {
				return err
			}
			continue
		}
		update := s.ent.Permission.UpdateOneID(row.ID).
			SetDescription(description).
			SetStatus(permissionStatusForModel(model.Status)).
			SetMetadata(metadata)
		if err := update.Exec(ctx); err != nil {
			return err
		}
	}
	return nil
}

type appDataModelAction struct {
	key         string
	displayName string
	riskLevel   string
}

func appDataModelActions(displayName string) []appDataModelAction {
	return []appDataModelAction{
		{key: "read", displayName: "Read " + displayName, riskLevel: "normal"},
		{key: "create", displayName: "Create " + displayName, riskLevel: "normal"},
		{key: "update", displayName: "Update " + displayName, riskLevel: "high"},
		{key: "delete", displayName: "Delete " + displayName, riskLevel: "high"},
		{key: "archive", displayName: "Archive " + displayName, riskLevel: "normal"},
	}
}

func permissionStatusForModel(status string) string {
	switch strings.TrimSpace(status) {
	case "active":
		return "active"
	default:
		return "disabled"
	}
}

func (s *Server) authorizeAppDataRecord(w http.ResponseWriter, r *http.Request, actor authz.ActorContext, action string, record *coreent.AppDataRecord) (*authz.Decision, bool) {
	target, err := s.appDataRecordTarget(r.Context(), record)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to build app data authorization target.", err.Error())
		return nil, false
	}
	if actor.SpaceID == "" {
		actor.SpaceID = record.SpaceID
	}
	return s.authorizeTarget(w, r, actor, appDataModelResourceType(record.ModelKey), record.ID, action, target)
}

func appDataRecordListOptionsFromRequest(r *http.Request) (appDataRecordListOptions, error) {
	opts := appDataRecordListOptions{
		Limit: limitFrom(r, 50),
		Sort:  "updated_at",
		Order: "desc",
	}
	if sortKey := strings.TrimSpace(r.URL.Query().Get("sort")); sortKey != "" {
		opts.Sort = sortKey
	}
	sortField, ok := appDataRecordSortColumns[opts.Sort]
	if !ok {
		return opts, fmt.Errorf("sort must be one of %s", strings.Join(appDataRecordAllowedSorts(), ", "))
	}
	opts.SortField = sortField
	if order := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("order"))); order != "" {
		opts.Order = order
	}
	if opts.Order != "asc" && opts.Order != "desc" {
		return opts, errors.New("order must be asc or desc")
	}
	if rawCursor := strings.TrimSpace(r.URL.Query().Get("cursor")); rawCursor != "" {
		cursor, err := decodeAppDataRecordCursor(rawCursor)
		if err != nil {
			return opts, err
		}
		if cursor.Sort != opts.Sort || cursor.Order != opts.Order {
			return opts, errors.New("cursor does not match requested sort and order")
		}
		opts.Cursor = cursor
	}
	return opts, nil
}

func appDataRecordAllowedSorts() []string {
	keys := make([]string, 0, len(appDataRecordSortColumns))
	for key := range appDataRecordSortColumns {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func appDataRecordOrderOptions(opts appDataRecordListOptions) []entappdatarecord.OrderOption {
	orderOpts := []sql.OrderTermOption{sql.OrderDesc()}
	if opts.Order == "asc" {
		orderOpts = []sql.OrderTermOption{sql.OrderAsc()}
	}
	tiebreaker := entappdatarecord.ByID(orderOpts...)
	switch opts.Sort {
	case "created_at":
		return []entappdatarecord.OrderOption{entappdatarecord.ByCreatedAt(orderOpts...), tiebreaker}
	case "id":
		return []entappdatarecord.OrderOption{tiebreaker}
	case "status":
		return []entappdatarecord.OrderOption{entappdatarecord.ByStatus(orderOpts...), tiebreaker}
	case "visibility":
		return []entappdatarecord.OrderOption{entappdatarecord.ByVisibility(orderOpts...), tiebreaker}
	default:
		return []entappdatarecord.OrderOption{entappdatarecord.ByUpdatedAt(orderOpts...), tiebreaker}
	}
}

func appDataRecordCursorPredicate(opts appDataRecordListOptions) predicate.AppDataRecord {
	return predicate.AppDataRecord(func(selector *sql.Selector) {
		if opts.Cursor == nil {
			return
		}
		sortColumn := selector.C(opts.SortField)
		idColumn := selector.C(entappdatarecord.FieldID)
		sortValuePredicate, sortEqualPredicate := appDataRecordCursorValuePredicates(opts)
		idPredicate := sql.LT(idColumn, opts.Cursor.Tiebreak)
		if opts.Order == "asc" {
			idPredicate = sql.GT(idColumn, opts.Cursor.Tiebreak)
		}
		selector.Where(sql.Or(
			sortValuePredicate(sortColumn),
			sql.And(sortEqualPredicate(sortColumn), idPredicate),
		))
	})
}

func appDataRecordCursorValuePredicates(opts appDataRecordListOptions) (func(string) *sql.Predicate, func(string) *sql.Predicate) {
	if opts.Cursor.ValueKind == "time" {
		value, _ := time.Parse(time.RFC3339Nano, opts.Cursor.Value)
		if opts.Order == "asc" {
			return func(column string) *sql.Predicate { return sql.GT(column, value) }, func(column string) *sql.Predicate { return sql.EQ(column, value) }
		}
		return func(column string) *sql.Predicate { return sql.LT(column, value) }, func(column string) *sql.Predicate { return sql.EQ(column, value) }
	}
	if opts.Order == "asc" {
		return func(column string) *sql.Predicate { return sql.GT(column, opts.Cursor.Value) }, func(column string) *sql.Predicate { return sql.EQ(column, opts.Cursor.Value) }
	}
	return func(column string) *sql.Predicate { return sql.LT(column, opts.Cursor.Value) }, func(column string) *sql.Predicate { return sql.EQ(column, opts.Cursor.Value) }
}

func encodeAppDataRecordCursor(opts appDataRecordListOptions, record *coreent.AppDataRecord) (string, error) {
	value, valueKind, err := appDataRecordCursorValue(opts.Sort, record)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(appDataRecordCursor{
		Version:   1,
		Sort:      opts.Sort,
		Order:     opts.Order,
		Value:     value,
		Tiebreak:  record.ID,
		ValueKind: valueKind,
	})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(payload), nil
}

func decodeAppDataRecordCursor(raw string) (*appDataRecordCursor, error) {
	payload, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, errors.New("cursor is invalid")
	}
	if len(payload) > 512 {
		return nil, errors.New("cursor is invalid")
	}
	var cursor appDataRecordCursor
	if err := json.Unmarshal(payload, &cursor); err != nil {
		return nil, errors.New("cursor is invalid")
	}
	if cursor.Version != 1 || cursor.Tiebreak == "" || cursor.Value == "" {
		return nil, errors.New("cursor is invalid")
	}
	if _, ok := appDataRecordSortColumns[cursor.Sort]; !ok {
		return nil, errors.New("cursor is invalid")
	}
	if cursor.Order != "asc" && cursor.Order != "desc" {
		return nil, errors.New("cursor is invalid")
	}
	if cursor.ValueKind != "time" && cursor.ValueKind != "string" {
		return nil, errors.New("cursor is invalid")
	}
	if cursor.ValueKind != appDataRecordCursorValueKind(cursor.Sort) {
		return nil, errors.New("cursor is invalid")
	}
	if cursor.ValueKind == "time" {
		if _, err := time.Parse(time.RFC3339Nano, cursor.Value); err != nil {
			return nil, errors.New("cursor is invalid")
		}
	}
	if len(cursor.Tiebreak) > 256 || len(cursor.Value) > 256 {
		return nil, errors.New("cursor is invalid")
	}
	return &cursor, nil
}

func appDataRecordCursorValueKind(sortKey string) string {
	switch sortKey {
	case "created_at", "updated_at":
		return "time"
	default:
		return "string"
	}
}

func appDataRecordCursorValue(sortKey string, record *coreent.AppDataRecord) (string, string, error) {
	switch sortKey {
	case "created_at":
		return record.CreatedAt.UTC().Format(time.RFC3339Nano), "time", nil
	case "updated_at":
		return record.UpdatedAt.UTC().Format(time.RFC3339Nano), "time", nil
	case "status":
		return record.Status, "string", nil
	case "visibility":
		return record.Visibility, "string", nil
	case "id":
		return record.ID, "string", nil
	default:
		return "", "", fmt.Errorf("sort %q is not supported", sortKey)
	}
}

func appDataRecordQueryPredicates(query map[string][]string) ([]predicate.AppDataRecord, error) {
	predicates := []predicate.AppDataRecord{}
	for key, values := range query {
		key = strings.TrimSpace(key)
		if key == "" || appDataReservedListQueryKeys[key] {
			continue
		}
		field := strings.TrimPrefix(key, "data.")
		if !validAppDataDataField(field) {
			return nil, fmt.Errorf("data filter field %q is invalid", key)
		}
		expected := compactQueryValues(values)
		if len(expected) == 0 {
			continue
		}
		predicates = append(predicates, appDataJSONFieldFilterPredicate(field, expected))
	}
	if search := strings.TrimSpace(firstQueryValue(query, "search")); search != "" {
		if len(search) > 128 {
			return nil, errors.New("search must be 128 characters or fewer")
		}
		predicates = append(predicates, appDataSearchPredicate(search))
	}
	return predicates, nil
}

func appDataJSONFieldFilterPredicate(field string, expected []string) predicate.AppDataRecord {
	return predicate.AppDataRecord(func(selector *sql.Selector) {
		ors := make([]*sql.Predicate, 0, len(expected)*2)
		for _, value := range expected {
			ors = append(ors,
				sqljson.ValueEQ(entappdatarecord.FieldData, value, sqljson.Path(field)),
				sqljson.ValueContains(entappdatarecord.FieldData, value, sqljson.Path(field)),
			)
			if parsed, ok := parseQueryScalar(value); ok {
				ors = append(ors,
					sqljson.ValueEQ(entappdatarecord.FieldData, parsed, sqljson.Path(field)),
					sqljson.ValueContains(entappdatarecord.FieldData, parsed, sqljson.Path(field)),
				)
			}
		}
		if len(ors) > 0 {
			selector.Where(sql.Or(ors...))
		}
	})
}

func appDataSearchPredicate(search string) predicate.AppDataRecord {
	return predicate.AppDataRecord(func(selector *sql.Selector) {
		needle := strings.TrimSpace(search)
		ors := []*sql.Predicate{
			sql.ContainsFold(selector.C(entappdatarecord.FieldID), needle),
			sql.ContainsFold(selector.C(entappdatarecord.FieldDisplayName), needle),
			sql.ContainsFold(selector.C(entappdatarecord.FieldStatus), needle),
		}
		for _, field := range appDataSearchDataFields {
			ors = append(ors, appDataJSONTextContainsFold(entappdatarecord.FieldData, field, needle))
		}
		selector.Where(sql.Or(ors...))
	})
}

func appDataJSONTextContainsFold(column, field, needle string) *sql.Predicate {
	return sql.P(func(builder *sql.Builder) {
		switch builder.Dialect() {
		case dialect.Postgres:
			builder.WriteString("LOWER(")
			builder.Join(sqljson.ValuePath(column, sqljson.Path(field), sqljson.Unquote(true)))
			builder.WriteString(") LIKE LOWER(")
			builder.Arg("%" + needle + "%")
			builder.WriteByte(')')
		default:
			builder.WriteString("LOWER(")
			builder.Join(sqljson.ValuePath(column, sqljson.Path(field), sqljson.Unquote(true)))
			builder.WriteString(") LIKE LOWER(")
			builder.Arg("%" + needle + "%")
			builder.WriteByte(')')
		}
	})
}

func validAppDataDataField(field string) bool {
	return appDataDataFieldPattern.MatchString(field)
}

func compactQueryValues(values []string) []string {
	out := []string{}
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			if item := strings.TrimSpace(part); item != "" {
				out = append(out, item)
			}
		}
	}
	return out
}

func firstQueryValue(query map[string][]string, key string) string {
	values := query[key]
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func parseQueryScalar(value string) (any, bool) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	switch normalized {
	case "true":
		return true, true
	case "false":
		return false, true
	}
	if parsed, err := strconv.ParseInt(normalized, 10, 64); err == nil {
		return parsed, true
	}
	if parsed, err := strconv.ParseFloat(normalized, 64); err == nil {
		return parsed, true
	}
	return nil, false
}

func (s *Server) appDataServiceAuthorized(r *http.Request, action, spaceID string) bool {
	if r == nil {
		return false
	}
	principal, ok := adminPrincipalFrom(r)
	if !ok {
		return false
	}
	return s.appDataServicePrincipalAllowed(r.Context(), principal, action, spaceID)
}

func (s *Server) appDataServicePrincipalAllowed(ctx context.Context, principal adminPrincipal, action, spaceID string) bool {
	if principal.CredentialType != "api_key" {
		return false
	}
	permission := "data:read"
	if action != "read" {
		permission = "data:manage"
	}
	allowed, err := s.adminPrincipalAllows(ctx, principal, adminRequirement{PermissionKey: permission, SpaceID: spaceID})
	return err == nil && allowed
}

func appDataServiceDecision(r *http.Request, actor authz.ActorContext, action string, record *coreent.AppDataRecord) map[string]any {
	return appDataServiceDecisionForTarget(r, actor, action, record.ID, authz.TargetSnapshot{
		Resource: authz.ResourceSnapshot{
			ID:            record.ID,
			Type:          appDataModelResourceType(record.ModelKey),
			SpaceID:       record.SpaceID,
			GroupID:       derefString(record.GroupID),
			OwnerMemberID: derefString(record.OwnerMemberID),
			DisplayName:   derefString(record.DisplayName),
			Visibility:    record.Visibility,
			Status:        record.Status,
			Metadata:      nonNilMap(record.Metadata),
		},
	})
}

func appDataServiceDecisionForTarget(r *http.Request, actor authz.ActorContext, action, resourceID string, target authz.TargetSnapshot) map[string]any {
	return map[string]any{
		"decision":     "allow",
		"reason":       "server-side API key authorized for app data " + action,
		"service_auth": true,
		"actor": map[string]any{
			"user_id":        actor.UserID,
			"member_id":      actor.MemberID,
			"user_member_id": actor.UserMemberID,
			"space_id":       firstNonEmpty(actor.SpaceID, target.Resource.SpaceID),
		},
		"target": map[string]any{
			"resource_id":   resourceID,
			"resource_type": target.Resource.Type,
			"space_id":      target.Resource.SpaceID,
		},
		"request_id": requestIDFrom(r),
	}
}

func appDataModelResourceType(modelKey string) string {
	return "data_" + strings.ToLower(strings.TrimSpace(modelKey))
}

func appDataActorFromRequest(r *http.Request, fallback authz.ActorContext) authz.ActorContext {
	if principal, ok := adminPrincipalFrom(r); ok && principal.CredentialType == "session" {
		if fallback.UserID == "" {
			fallback.UserID = principal.Session.UserID
		}
		if fallback.SpaceID == "" {
			fallback.SpaceID = principal.Session.ActiveSpaceID
		}
		if fallback.MemberID == "" {
			fallback.MemberID = principal.Session.ActiveMemberID
		}
		if fallback.UserMemberID == "" {
			fallback.UserMemberID = principal.Session.ActiveUserMemberID
		}
	}
	return fallback
}

func (s *Server) writeAppDataRecordRevision(ctx context.Context, r *http.Request, actor authz.ActorContext, record *coreent.AppDataRecord, operation string) error {
	if s.ent == nil {
		return errors.New("ent client is not configured")
	}
	count, err := s.ent.AppDataRecordRevision.Query().Where(entappdatarecordrevision.RecordID(record.ID)).Count(ctx)
	if err != nil {
		return err
	}
	revision := count + 1
	_, err = s.ent.AppDataRecordRevision.Create().
		SetID(newEntityID("rev")).
		SetRecordID(record.ID).
		SetSpaceID(record.SpaceID).
		SetModelID(record.ModelID).
		SetModelKey(record.ModelKey).
		SetRevision(revision).
		SetOperation(operation).
		SetNillableActorUserID(optionalString(actor.UserID)).
		SetNillableActorMemberID(optionalString(actor.MemberID)).
		SetNillableActorUserMemberID(optionalString(actor.UserMemberID)).
		SetData(nonNilMap(record.Data)).
		SetMetadata(map[string]any{
			"request_id": requestIDFrom(r),
			"status":     record.Status,
			"visibility": record.Visibility,
			"data_keys":  sortedMapKeys(record.Data),
		}).
		Save(ctx)
	return err
}

func validateAppDataModelMutation(req appDataModelMutationRequest, creating bool) error {
	if creating {
		if !validAppDataModelKey(req.Key) {
			return fmt.Errorf("key must match %s", appDataModelKeyPattern.String())
		}
		if strings.TrimSpace(req.DisplayName) == "" {
			return fmt.Errorf("display_name is required")
		}
	}
	if req.Status != nil && !validAppDataModelStatus(*req.Status) {
		return fmt.Errorf("status must be active, disabled, or archived")
	}
	return nil
}

func validateAppDataRecordMutation(req appDataRecordMutationRequest, creating bool) error {
	if creating && strings.TrimSpace(req.ID) != "" && len(req.ID) > 160 {
		return fmt.Errorf("id is too long")
	}
	if req.Visibility != nil && !validAppDataVisibility(*req.Visibility) {
		return fmt.Errorf("visibility must be private, group, space, or public")
	}
	if req.Status != nil && !validAppDataRecordStatus(*req.Status) {
		return fmt.Errorf("status must be active, disabled, archived, or deleted")
	}
	if creating && req.Data == nil {
		return fmt.Errorf("data is required")
	}
	return nil
}

func validAppDataModelKey(value string) bool {
	return appDataModelKeyPattern.MatchString(strings.TrimSpace(value))
}

func validAppDataModelStatus(value string) bool {
	switch strings.TrimSpace(value) {
	case "active", "disabled", "archived":
		return true
	default:
		return false
	}
}

func validAppDataRecordStatus(value string) bool {
	switch strings.TrimSpace(value) {
	case "active", "disabled", "archived", "deleted":
		return true
	default:
		return false
	}
}

func validAppDataVisibility(value string) bool {
	switch strings.TrimSpace(value) {
	case "private", "group", "space", "public":
		return true
	default:
		return false
	}
}

func appDataModelMap(row *coreent.AppDataModel) map[string]any {
	return map[string]any{
		"id":           row.ID,
		"space_id":     row.SpaceID,
		"key":          row.Key,
		"display_name": row.DisplayName,
		"description":  derefString(row.Description),
		"source":       row.Source,
		"status":       row.Status,
		"schema":       nonNilMap(row.Schema),
		"metadata":     nonNilMap(row.Metadata),
		"permissions":  appDataModelPermissionSummaries(row),
		"created_at":   formatTime(row.CreatedAt),
		"updated_at":   formatTime(row.UpdatedAt),
		"deleted_at":   optionalTime(row.DeletedAt),
	}
}

func appDataModelPermissionSummaries(row *coreent.AppDataModel) []map[string]any {
	permissions := make([]map[string]any, 0, 5)
	resourceType := appDataModelResourceType(row.Key)
	for _, action := range appDataModelActions(row.DisplayName) {
		permissions = append(permissions, map[string]any{
			"id":       appDataModelPermissionID(resourceType, action.key),
			"resource": resourceType,
			"action":   action.key,
			"scope":    string(authz.ScopeSpace),
			"status":   permissionStatusForModel(row.Status),
		})
	}
	return permissions
}

func appDataModelPermissionID(resourceType, action string) string {
	return safeIdentifier("perm_" + resourceType + "_" + action + "_space")
}

func appDataRecordMap(row *coreent.AppDataRecord) map[string]any {
	return map[string]any{
		"id":              row.ID,
		"space_id":        row.SpaceID,
		"model_id":        row.ModelID,
		"model_key":       row.ModelKey,
		"group_id":        derefString(row.GroupID),
		"owner_member_id": derefString(row.OwnerMemberID),
		"display_name":    derefString(row.DisplayName),
		"visibility":      row.Visibility,
		"status":          row.Status,
		"data":            nonNilMap(row.Data),
		"metadata":        nonNilMap(row.Metadata),
		"created_at":      formatTime(row.CreatedAt),
		"updated_at":      formatTime(row.UpdatedAt),
		"deleted_at":      optionalTime(row.DeletedAt),
	}
}

func appDataRevisionMap(row *coreent.AppDataRecordRevision) map[string]any {
	return map[string]any{
		"id":                   row.ID,
		"record_id":            row.RecordID,
		"space_id":             row.SpaceID,
		"model_id":             row.ModelID,
		"model_key":            row.ModelKey,
		"revision":             row.Revision,
		"operation":            row.Operation,
		"actor_user_id":        derefString(row.ActorUserID),
		"actor_member_id":      derefString(row.ActorMemberID),
		"actor_user_member_id": derefString(row.ActorUserMemberID),
		"data":                 nonNilMap(row.Data),
		"metadata":             nonNilMap(row.Metadata),
		"created_at":           formatTime(row.CreatedAt),
	}
}

func appDataAuditDetails(operation, modelKey, recordID string, data, metadata map[string]any) map[string]any {
	return map[string]any{
		"operation":     operation,
		"model_key":     modelKey,
		"record_id":     recordID,
		"data_keys":     sortedMapKeys(data),
		"metadata_keys": sortedMapKeys(metadata),
	}
}

func sortedMapKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func setOptionalRecordString(set func(string) *coreent.AppDataRecordUpdateOne, clear func() *coreent.AppDataRecordUpdateOne, value string) {
	if strings.TrimSpace(value) == "" {
		clear()
		return
	}
	set(value)
}
