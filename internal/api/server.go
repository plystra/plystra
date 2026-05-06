package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/plystra/plystra/internal/authz"
	"github.com/plystra/plystra/internal/plugins"
	"github.com/plystra/plystra/internal/store"
)

type Server struct {
	pool        *pgxpool.Pool
	authzStore  authz.Store
	coreVersion string
}

func NewServer(pool *pgxpool.Pool, authzStore authz.Store, coreVersion string) *Server {
	if authzStore == nil {
		authzStore = store.NewPostgresStore(pool)
	}
	return &Server{
		pool:        pool,
		authzStore:  authzStore,
		coreVersion: coreVersion,
	}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/health", s.handleHealth)
	mux.HandleFunc("/api/v1/ready", s.handleReady)
	mux.HandleFunc("/api/v1/version", s.handleVersion)
	mux.HandleFunc("/api/v1/system/health", s.handleHealth)
	mux.HandleFunc("/api/v1/system/ready", s.handleReady)
	mux.HandleFunc("/api/v1/system/version", s.handleVersion)
	mux.HandleFunc("/system/health", s.handleHealth)
	mux.HandleFunc("/system/ready", s.handleReady)
	mux.HandleFunc("/system/version", s.handleVersion)
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/api/v1/console/overview", s.handleOverview)
	mux.HandleFunc("/api/v1/auth/login", s.handleAuthLogin)
	mux.HandleFunc("/api/v1/auth/logout", s.handleAuthLogout)
	mux.HandleFunc("/api/v1/auth/refresh", s.handleAuthRefresh)
	mux.HandleFunc("/api/v1/actor/context", s.handleActorContext)
	mux.HandleFunc("/api/v1/actor/switch-member", s.handleActorSwitchMember)
	mux.HandleFunc("/api/v1/authz/check", s.handleAuthzCheck)
	mux.HandleFunc("/api/v1/authz/explain", s.handleAuthzExplain)
	mux.HandleFunc("/api/v1/audit/logs", s.handleAuditLogs)
	mux.HandleFunc("/api/v1/audit/logs/", s.handleAuditLogDetail)
	mux.HandleFunc("/api/v1/audit-logs", s.handleAuditLogs)
	mux.HandleFunc("/api/v1/audit-logs/", s.handleAuditLogDetail)
	mux.HandleFunc("/api/v1/resource-types", s.handleResourceTypes)
	mux.HandleFunc("/api/v1/resource-types/", s.handleResourceTypeSubroutes)
	mux.HandleFunc("/api/v1/users", s.handleUsers)
	mux.HandleFunc("/api/v1/users/", s.handleUserSubroutes)
	mux.HandleFunc("/api/v1/spaces", s.handleSpaces)
	mux.HandleFunc("/api/v1/spaces/", s.handleSpaceSubroutes)
	mux.HandleFunc("/api/v1/groups/", s.handleGroupDetail)
	mux.HandleFunc("/api/v1/members/", s.handleMemberDetail)
	mux.HandleFunc("/api/v1/user-members/", s.handleUserMemberDetail)
	mux.HandleFunc("/api/v1/permissions", s.handlePermissions)
	mux.HandleFunc("/api/v1/permissions/", s.handlePermissionDetail)
	mux.HandleFunc("/api/v1/role-permissions", s.handleRolePermissions)
	mux.HandleFunc("/api/v1/role-permissions/", s.handleRolePermissionSubroutes)
	mux.HandleFunc("/api/v1/roles/", s.handleRoleDetail)
	mux.HandleFunc("/api/v1/resources", s.handleResources)
	mux.HandleFunc("/api/v1/resources/", s.handleResourceDetail)
	mux.HandleFunc("/api/v1/data/tables", s.handleDataTables)
	mux.HandleFunc("/api/v1/data/rows/", s.handleDataRows)
	mux.HandleFunc("/api/v1/plugins/validate-manifest", s.handlePluginManifestValidation)
	mux.HandleFunc("/api/v1/plugins/install", s.handlePluginInstall)
	mux.HandleFunc("/api/v1/plugins", s.handlePlugins)
	mux.HandleFunc("/api/v1/plugins/", s.handlePluginSubroutes)
	mux.HandleFunc("/api/v1/templates", s.handleTemplates)
	mux.HandleFunc("/api/v1/templates/", s.handleTemplateSubroutes)
	return requestMiddleware(mux)
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if !featureEnabled("METRICS_ENABLED") {
		writeError(w, r, http.StatusNotFound, "FEATURE_DISABLED", "Metrics endpoint is disabled.", nil)
		return
	}
	if !metricsAuthorized(r) {
		writeError(w, r, http.StatusUnauthorized, "METRICS_TOKEN_REQUIRED", "A valid metrics token is required.", nil)
		return
	}
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, r)
		return
	}
	var auditLogs int64
	var authzDenies int64
	_ = s.pool.QueryRow(r.Context(), `SELECT count(*) FROM audit_logs`).Scan(&auditLogs)
	_ = s.pool.QueryRow(r.Context(), `SELECT count(*) FROM audit_logs WHERE decision = 'deny'`).Scan(&authzDenies)
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "audit_logs_written_total %d\n", auditLogs)
	fmt.Fprintf(w, "authz_denies_total %d\n", authzDenies)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, r)
		return
	}
	writeData(w, r, http.StatusOK, map[string]any{"status": "ok"})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, r)
		return
	}
	if err := s.pool.Ping(r.Context()); err != nil {
		writeError(w, r, http.StatusServiceUnavailable, "NOT_READY", "Database is not reachable.", err.Error())
		return
	}
	schemaVersion, expectedSchemaVersion, err := s.readySchemaVersions(r.Context())
	if err != nil {
		writeError(w, r, http.StatusServiceUnavailable, "NOT_READY", "Database migrations are not current or schema_migrations is unavailable.", err.Error())
		return
	}
	writeData(w, r, http.StatusOK, map[string]any{
		"status":                  "ready",
		"schema_version":          schemaVersion,
		"expected_schema_version": expectedSchemaVersion,
		"trace_version":           traceVersion(),
	})
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, r)
		return
	}
	schemaVersion, _ := s.latestSchemaVersion(r.Context())
	expectedSchemaVersion, _ := latestMigrationVersion("migrations")
	writeData(w, r, http.StatusOK, map[string]any{
		"core_version":              s.coreVersion,
		"api_version":               "v1",
		"schema_version":            schemaVersion,
		"expected_schema_version":   expectedSchemaVersion,
		"trace_version":             traceVersion(),
		"plugin_api_version":        "1.0",
		"resource_registry_version": "1.0",
		"build_time":                time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) latestSchemaVersion(ctx context.Context) (string, error) {
	var version string
	err := s.pool.QueryRow(ctx, `SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1`).Scan(&version)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("no migrations have been applied")
	}
	return version, err
}

func (s *Server) readySchemaVersions(ctx context.Context) (string, string, error) {
	appliedVersion, err := s.latestSchemaVersion(ctx)
	if err != nil {
		return "", "", err
	}
	expectedVersions, err := migrationVersions("migrations")
	if err != nil {
		return "", "", err
	}
	expectedVersion := expectedVersions[len(expectedVersions)-1]
	missing, err := s.missingMigrationVersions(ctx, expectedVersions)
	if err != nil {
		return "", "", err
	}
	if len(missing) > 0 {
		return appliedVersion, expectedVersion, fmt.Errorf("pending migrations: %s", strings.Join(missing, ", "))
	}
	if appliedVersion != expectedVersion {
		return appliedVersion, expectedVersion, fmt.Errorf("schema version %s is not current; expected %s", appliedVersion, expectedVersion)
	}
	return appliedVersion, expectedVersion, nil
}

func (s *Server) missingMigrationVersions(ctx context.Context, expectedVersions []string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	applied := map[string]struct{}{}
	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			return nil, err
		}
		applied[version] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	missing := []string{}
	for _, version := range expectedVersions {
		if _, ok := applied[version]; !ok {
			missing = append(missing, version)
		}
	}
	return missing, nil
}

func latestMigrationVersion(dir string) (string, error) {
	versions, err := migrationVersions(dir)
	if err != nil {
		return "", err
	}
	return versions[len(versions)-1], nil
}

func migrationVersions(dir string) ([]string, error) {
	candidates := []string{dir, filepath.Join("..", "..", dir)}
	var lastErr error
	for _, candidate := range candidates {
		version, err := migrationVersionsInDir(candidate)
		if err == nil {
			return version, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func migrationVersionsInDir(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	versions := []string{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		version, _, _ := strings.Cut(strings.TrimSuffix(entry.Name(), ".sql"), "_")
		versions = append(versions, version)
	}
	if len(versions) == 0 {
		return nil, fmt.Errorf("no migration files found in %s", dir)
	}
	sort.Strings(versions)
	return versions, nil
}

func traceVersion() string {
	if value := os.Getenv("TRACE_VERSION"); value != "" {
		return value
	}
	return "1.0"
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, r)
		return
	}
	ctx := r.Context()
	counts := map[string]int64{}
	for key, table := range map[string]string{
		"spaces":               "spaces",
		"users":                "users",
		"members":              "members",
		"user_member_bindings": "user_members",
		"groups":               "groups",
		"roles":                "roles",
		"permissions":          "permissions",
		"resource_types":       "resource_types",
		"resources":            "resources",
		"audit_logs":           "audit_logs",
	} {
		var count int64
		if err := s.pool.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&count); err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load overview counts.", err.Error())
			return
		}
		counts[key] = count
	}

	recent, err := queryMaps(ctx, s.pool, `
		SELECT id, created_at, decision, COALESCE(deny_code, '') AS deny_code,
			actor_user_id, actor_member_id, resource_type, resource_id, action
		FROM audit_logs
		ORDER BY created_at DESC
		LIMIT 10
	`)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load recent audit logs.", err.Error())
		return
	}

	writeData(w, r, http.StatusOK, map[string]any{
		"counts":            counts,
		"recent_audit_logs": recent,
	})
}

type authzRequest struct {
	Actor             authz.ActorContext `json:"actor"`
	ActorUserID       string             `json:"actor_user_id"`
	ActorMemberID     string             `json:"actor_member_id"`
	ActorUserMemberID string             `json:"actor_user_member_id"`
	SpaceID           string             `json:"space_id"`
	ResourceType      string             `json:"resource_type"`
	ResourceID        string             `json:"resource_id"`
	Resource          struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	} `json:"resource"`
	Action    string `json:"action"`
	Explain   bool   `json:"explain"`
	RequestID string `json:"request_id"`
	IP        string `json:"ip"`
	UserAgent string `json:"user_agent"`
}

func (req authzRequest) CheckInput() authz.CheckInput {
	resourceType := req.ResourceType
	if resourceType == "" {
		resourceType = req.Resource.Type
	}
	resourceID := req.ResourceID
	if resourceID == "" {
		resourceID = req.Resource.ID
	}
	return authz.CheckInput{
		Actor:             req.Actor,
		ActorUserID:       req.ActorUserID,
		ActorMemberID:     req.ActorMemberID,
		ActorUserMemberID: req.ActorUserMemberID,
		SpaceID:           req.SpaceID,
		ResourceType:      resourceType,
		ResourceID:        resourceID,
		Action:            req.Action,
		Explain:           req.Explain,
		RequestID:         req.RequestID,
		IP:                req.IP,
		UserAgent:         req.UserAgent,
	}
}

func (s *Server) handleAuthzCheck(w http.ResponseWriter, r *http.Request) {
	s.handleAuthz(w, r, false)
}

func (s *Server) handleAuthzExplain(w http.ResponseWriter, r *http.Request) {
	s.handleAuthz(w, r, true)
}

func (s *Server) handleAuthz(w http.ResponseWriter, r *http.Request, explain bool) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, r)
		return
	}
	var req authzRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Request body is invalid JSON.", err.Error())
		return
	}
	input := req.CheckInput()
	input.RequestID = requestIDFrom(r)
	input.IP = remoteIPFrom(r)
	input.UserAgent = r.UserAgent()
	input.Explain = explain || req.Explain

	decision, err := authz.Check(r.Context(), s.authzStore, input)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Authorization check failed.", err.Error())
		return
	}
	w.Header().Set("X-Plystra-Trace-ID", decision.TraceID)
	if decision.Audit.ID != "" {
		w.Header().Set("X-Plystra-Audit-Log-ID", decision.Audit.ID)
	}
	if input.Explain {
		writeData(w, r, http.StatusOK, decision)
		return
	}
	writeData(w, r, http.StatusOK, map[string]any{
		"allow":        decision.IsAllowed(),
		"decision":     decision.Decision,
		"deny_code":    decision.DenyCode,
		"reason":       decision.Reason,
		"trace_id":     decision.TraceID,
		"audit_log_id": decision.Audit.ID,
		"audit":        decision.Audit,
	})
}

func (s *Server) handleAuditLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, r)
		return
	}
	limit := limitFrom(r, 50)
	sql := `SELECT id, space_id, actor_user_id, actor_member_id, actor_user_member_id, action, resource_type, resource_id, decision, COALESCE(deny_code, '') AS deny_code, request_id, ip_address, user_agent, created_at FROM audit_logs`
	args := []any{}
	where := []string{}
	for _, filter := range []string{"space_id", "actor_user_id", "actor_member_id", "actor_user_member_id", "resource_type", "resource_id", "decision", "deny_code", "request_id"} {
		if value := r.URL.Query().Get(filter); value != "" {
			args = append(args, value)
			where = append(where, fmt.Sprintf("%s = $%d", filter, len(args)))
		}
	}
	if from := r.URL.Query().Get("created_at_from"); from != "" {
		args = append(args, from)
		where = append(where, fmt.Sprintf("created_at >= $%d::timestamptz", len(args)))
	}
	if to := r.URL.Query().Get("created_at_to"); to != "" {
		args = append(args, to)
		where = append(where, fmt.Sprintf("created_at <= $%d::timestamptz", len(args)))
	}
	if len(where) > 0 {
		sql += " WHERE " + strings.Join(where, " AND ")
	}
	args = append(args, limit)
	sql += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d", len(args))
	rows, err := queryMaps(r.Context(), s.pool, sql, args...)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list audit logs.", err.Error())
		return
	}
	writeList(w, r, http.StatusOK, rows, limit)
}

func (s *Server) handleAuditLogDetail(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/audit/logs/")
	if id == r.URL.Path {
		id = strings.TrimPrefix(r.URL.Path, "/api/v1/audit-logs/")
	}
	s.handleSingleByID(w, r, `SELECT * FROM audit_logs WHERE id = $1`, id, "AUDIT_LOG_NOT_FOUND")
}

func (s *Server) handleResourceTypes(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
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
		metadata, err := json.Marshal(nonNilMap(req.Metadata))
		if err != nil {
			writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "metadata must be JSON serializable.", err.Error())
			return
		}
		_, err = s.pool.Exec(r.Context(), `
			INSERT INTO resource_types (id, key, display_name, description, status, source, metadata)
			VALUES ($1, $2, $3, NULLIF($4, ''), $5, $6, $7::jsonb)
			ON CONFLICT (key)
			DO UPDATE SET display_name = EXCLUDED.display_name,
				description = EXCLUDED.description,
				status = EXCLUDED.status,
				source = EXCLUDED.source,
				metadata = EXCLUDED.metadata,
				updated_at = now()
		`, req.ID, req.Key, req.DisplayName, derefString(req.Description), firstNonEmpty(derefString(req.Status), "active"), firstNonEmpty(req.Source, "core"), metadata)
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
	rows, err := queryMaps(r.Context(), s.pool, `SELECT id, key, display_name, description, status, source, metadata, created_at, updated_at FROM resource_types ORDER BY key`)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list resource types.", err.Error())
		return
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
		s.handleSingleByID(w, r, `SELECT id, key, display_name, description, status, source, metadata, created_at, updated_at FROM resource_types WHERE key = $1`, key, "RESOURCE_TYPE_NOT_FOUND")
	case len(parts) == 2 && parts[1] == "actions":
		if r.Method == http.MethodPost {
			s.handleResourceActionUpsert(w, r, key)
			return
		}
		rows, err := queryMaps(r.Context(), s.pool, `
			SELECT ra.id, ra.key, ra.display_name, ra.description, ra.risk_level, ra.audit_default, ra.metadata
			FROM resource_actions ra
			JOIN resource_types rt ON rt.id = ra.resource_type_id
			WHERE rt.key = $1
			ORDER BY ra.key
		`, key)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list resource actions.", err.Error())
			return
		}
		writeList(w, r, http.StatusOK, rows, limitFrom(r, 50))
	case len(parts) == 2 && parts[1] == "mapping":
		if r.Method == http.MethodPost || r.Method == http.MethodPatch || r.Method == http.MethodPut {
			s.handleResourceMappingUpsert(w, r, key)
			return
		}
		s.handleSingleByID(w, r, `
			SELECT rm.*
			FROM resource_mappings rm
			JOIN resource_types rt ON rt.id = rm.resource_type_id
			WHERE rt.key = $1
		`, key, "RESOURCE_MAPPING_NOT_FOUND")
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
	metadata, err := json.Marshal(nonNilMap(req.Metadata))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "metadata must be JSON serializable.", err.Error())
		return
	}
	_, err = s.pool.Exec(r.Context(), `
		INSERT INTO resource_actions (id, resource_type_id, key, display_name, description, risk_level, audit_default, metadata)
		VALUES ($1, $2, $3, $4, NULLIF($5, ''), $6, $7, $8::jsonb)
		ON CONFLICT (resource_type_id, key)
		DO UPDATE SET display_name = EXCLUDED.display_name,
			description = EXCLUDED.description,
			risk_level = EXCLUDED.risk_level,
			audit_default = EXCLUDED.audit_default,
			metadata = EXCLUDED.metadata,
			updated_at = now()
	`, req.ID, stringFromMap(rt, "id"), req.Key, req.DisplayName, derefString(req.Description), firstNonEmpty(req.RiskLevel, "normal"), boolValue(req.AuditDefault, true), metadata)
	if err != nil {
		writeError(w, r, http.StatusConflict, "RESOURCE_ACTION_UPSERT_FAILED", "Failed to register ResourceAction.", err.Error())
		return
	}
	row, err := queryOneMap(r.Context(), s.pool, `
		SELECT ra.id, ra.key, ra.display_name, ra.description, ra.risk_level, ra.audit_default, ra.metadata
		FROM resource_actions ra
		WHERE ra.resource_type_id = $1 AND ra.key = $2
	`, stringFromMap(rt, "id"), req.Key)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load ResourceAction.", err.Error())
		return
	}
	writeData(w, r, http.StatusCreated, row)
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
	metadata, err := json.Marshal(nonNilMap(req.Metadata))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "metadata must be JSON serializable.", err.Error())
		return
	}
	_, err = s.pool.Exec(r.Context(), `
		INSERT INTO resource_mappings (id, resource_type_id, storage_kind, table_name, id_field, space_field, group_field, owner_member_field, visibility_field, metadata_field, status, metadata)
		VALUES ($1, $2, $3, NULLIF($4, ''), $5, $6, NULLIF($7, ''), NULLIF($8, ''), NULLIF($9, ''), NULLIF($10, ''), $11, $12::jsonb)
		ON CONFLICT (resource_type_id)
		DO UPDATE SET storage_kind = EXCLUDED.storage_kind,
			table_name = EXCLUDED.table_name,
			id_field = EXCLUDED.id_field,
			space_field = EXCLUDED.space_field,
			group_field = EXCLUDED.group_field,
			owner_member_field = EXCLUDED.owner_member_field,
			visibility_field = EXCLUDED.visibility_field,
			metadata_field = EXCLUDED.metadata_field,
			status = EXCLUDED.status,
			metadata = EXCLUDED.metadata,
			updated_at = now()
	`, req.ID, stringFromMap(rt, "id"), firstNonEmpty(req.StorageKind, "internal_table"), derefString(req.TableName), firstNonEmpty(req.IDField, "id"), firstNonEmpty(req.SpaceField, "space_id"), derefString(req.GroupField), derefString(req.OwnerMemberField), derefString(req.VisibilityField), derefString(req.MetadataField), firstNonEmpty(derefString(req.Status), "active"), metadata)
	if err != nil {
		writeError(w, r, http.StatusConflict, "RESOURCE_MAPPING_UPSERT_FAILED", "Failed to register ResourceMapping.", err.Error())
		return
	}
	row, err := queryOneMap(r.Context(), s.pool, `SELECT * FROM resource_mappings WHERE resource_type_id = $1`, stringFromMap(rt, "id"))
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load ResourceMapping.", err.Error())
		return
	}
	writeData(w, r, http.StatusCreated, row)
}

func (s *Server) loadResourceTypeByKey(ctx context.Context, key string) (map[string]any, error) {
	return queryOneMap(ctx, s.pool, `
		SELECT id, key, display_name, description, status, source, metadata, created_at, updated_at
		FROM resource_types
		WHERE key = $1
	`, key)
}

type userMutationRequest struct {
	Actor        authz.ActorContext `json:"actor"`
	AuditSpaceID string             `json:"audit_space_id"`
	ID           string             `json:"id"`
	Email        string             `json:"email"`
	Username     *string            `json:"username"`
	Phone        *string            `json:"phone"`
	PasswordHash *string            `json:"password_hash"`
	Status       *string            `json:"status"`
	Metadata     map[string]any     `json:"metadata"`
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var req userMutationRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		if strings.TrimSpace(req.Email) == "" {
			writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "email is required.", nil)
			return
		}
		if req.ID == "" {
			req.ID = newEntityID("user")
		}
		metadata, err := json.Marshal(nonNilMap(req.Metadata))
		if err != nil {
			writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "metadata must be JSON serializable.", err.Error())
			return
		}
		status := firstNonEmpty(derefString(req.Status), "active")
		_, err = s.pool.Exec(r.Context(), `
			INSERT INTO users (id, email, username, phone, password_hash, status, metadata)
			VALUES ($1, $2, NULLIF($3, ''), NULLIF($4, ''), NULLIF($5, ''), $6, $7::jsonb)
		`, req.ID, req.Email, derefString(req.Username), derefString(req.Phone), derefString(req.PasswordHash), status, metadata)
		if err != nil {
			writeError(w, r, http.StatusConflict, "USER_CREATE_FAILED", "Failed to create User.", err.Error())
			return
		}
		row, err := s.loadUser(r.Context(), req.ID)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load created User.", err.Error())
			return
		}
		s.recordMutationAudit(r.Context(), r, req.Actor, req.AuditSpaceID, "user.created", "user", req.ID, row)
		writeData(w, r, http.StatusCreated, row)
	case http.MethodGet:
		limit := limitFrom(r, 50)
		rows, err := queryMaps(r.Context(), s.pool, `
			SELECT id, email, username, phone, status, metadata, created_at, updated_at, deleted_at
			FROM users
			WHERE deleted_at IS NULL
			ORDER BY email
			LIMIT $1
		`, limit)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list Users.", err.Error())
			return
		}
		writeList(w, r, http.StatusOK, rows, limit)
	default:
		writeMethodNotAllowed(w, r)
	}
}

func (s *Server) handleUserSubroutes(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/users/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	userID := parts[0]
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			row, err := s.loadUser(r.Context(), userID)
			if errors.Is(err, pgx.ErrNoRows) {
				writeError(w, r, http.StatusNotFound, "USER_NOT_FOUND", "User was not found.", nil)
				return
			}
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load User.", err.Error())
				return
			}
			writeData(w, r, http.StatusOK, row)
		case http.MethodPatch:
			var req userMutationRequest
			if !decodeJSON(w, r, &req) {
				return
			}
			current, err := s.loadUser(r.Context(), userID)
			if errors.Is(err, pgx.ErrNoRows) {
				writeError(w, r, http.StatusNotFound, "USER_NOT_FOUND", "User was not found.", nil)
				return
			}
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load User.", err.Error())
				return
			}
			email := firstNonEmpty(req.Email, stringFromMap(current, "email"))
			status := firstNonEmpty(derefString(req.Status), stringFromMap(current, "status"), "active")
			metadata := mapFromAny(current["metadata"])
			if req.Metadata != nil {
				metadata = req.Metadata
			}
			metadataJSON, err := json.Marshal(nonNilMap(metadata))
			if err != nil {
				writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "metadata must be JSON serializable.", err.Error())
				return
			}
			username := nullableFromRequest(req.Username, stringFromMap(current, "username"))
			phone := nullableFromRequest(req.Phone, stringFromMap(current, "phone"))
			passwordHash := nullableFromRequest(req.PasswordHash, stringFromMap(current, "password_hash"))
			_, err = s.pool.Exec(r.Context(), `
				UPDATE users
				SET email = $2,
					username = NULLIF($3, ''),
					phone = NULLIF($4, ''),
					password_hash = NULLIF($5, ''),
					status = $6,
					metadata = $7::jsonb,
					updated_at = now()
				WHERE id = $1 AND deleted_at IS NULL
			`, userID, email, username, phone, passwordHash, status, metadataJSON)
			if err != nil {
				writeError(w, r, http.StatusConflict, "USER_UPDATE_FAILED", "Failed to update User.", err.Error())
				return
			}
			row, err := s.loadUser(r.Context(), userID)
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load updated User.", err.Error())
				return
			}
			s.recordMutationAudit(r.Context(), r, req.Actor, req.AuditSpaceID, "user.updated", "user", userID, row)
			writeData(w, r, http.StatusOK, row)
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
		var req userMutationRequest
		if r.Body != nil {
			_ = json.NewDecoder(r.Body).Decode(&req)
		}
		status := "disabled"
		action := "user.disabled"
		if parts[1] == "restore" {
			status = "active"
			action = "user.restored"
		}
		row, err := s.updateStatus(r.Context(), "users", userID, status)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to update User status.", err.Error())
			return
		}
		s.recordMutationAudit(r.Context(), r, req.Actor, req.AuditSpaceID, action, "user", userID, row)
		writeData(w, r, http.StatusOK, row)
		return
	}
	http.NotFound(w, r)
}

func (s *Server) loadUser(ctx context.Context, id string) (map[string]any, error) {
	return queryOneMap(ctx, s.pool, `
		SELECT id, email, username, phone, password_hash, status, metadata, created_at, updated_at, deleted_at
		FROM users
		WHERE id = $1 AND deleted_at IS NULL
	`, id)
}

func (s *Server) handleSpaces(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		s.handleSpaceCreate(w, r)
		return
	}
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, r)
		return
	}
	rows, err := queryMaps(r.Context(), s.pool, `SELECT id, name, slug, type, status, metadata, created_at, updated_at, deleted_at FROM spaces WHERE deleted_at IS NULL ORDER BY name`)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list spaces.", err.Error())
		return
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
			s.handleSingleByID(w, r, `SELECT id, name, slug, type, status, metadata, created_at, updated_at, deleted_at FROM spaces WHERE id = $1 AND deleted_at IS NULL`, spaceID, "SPACE_NOT_FOUND")
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
		_ = json.NewDecoder(r.Body).Decode(&req)
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
	case "member-role-grants":
		s.handleSpaceMemberRoles(w, r, spaceID, parts[2:])
	case "member-roles":
		s.handleSpaceMemberRoles(w, r, spaceID, parts[2:])
	case "resources":
		s.handleSpaceResources(w, r, spaceID, parts[2:])
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
	metadata, err := json.Marshal(nonNilMap(req.Metadata))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "metadata must be JSON serializable.", err.Error())
		return
	}
	_, err = s.pool.Exec(r.Context(), `
		INSERT INTO spaces (id, name, slug, type, status, metadata)
		VALUES ($1, $2, NULLIF($3, ''), $4, $5, $6::jsonb)
	`, req.ID, req.Name, derefString(req.Slug), firstNonEmpty(derefString(req.Type), "custom"), firstNonEmpty(derefString(req.Status), "active"), metadata)
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
	metadataJSON, err := json.Marshal(nonNilMap(metadata))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "metadata must be JSON serializable.", err.Error())
		return
	}
	_, err = s.pool.Exec(r.Context(), `
		UPDATE spaces
		SET name = $2,
			slug = NULLIF($3, ''),
			type = $4,
			status = $5,
			metadata = $6::jsonb,
			updated_at = now()
		WHERE id = $1 AND deleted_at IS NULL
	`, spaceID, name, nullableFromRequest(req.Slug, stringFromMap(current, "slug")), firstNonEmpty(derefString(req.Type), stringFromMap(current, "type"), "custom"), firstNonEmpty(derefString(req.Status), stringFromMap(current, "status"), "active"), metadataJSON)
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
	return queryOneMap(ctx, s.pool, `
		SELECT id, name, slug, type, status, metadata, created_at, updated_at, deleted_at
		FROM spaces
		WHERE id = $1 AND deleted_at IS NULL
	`, id)
}

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
			metadata, err := json.Marshal(nonNilMap(req.Metadata))
			if err != nil {
				writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "metadata must be JSON serializable.", err.Error())
				return
			}
			_, err = s.pool.Exec(r.Context(), `
				INSERT INTO groups (id, space_id, parent_group_id, name, display_name, path, depth, sort_order, status, metadata)
				VALUES ($1, $2, NULLIF($3, ''), $4, NULLIF($5, ''), $6, $7, $8, $9, $10::jsonb)
			`, req.ID, spaceID, parentID, name, derefString(req.DisplayName), req.Path, pathDepth(req.Path), intValue(req.SortOrder, 1000), firstNonEmpty(derefString(req.Status), "active"), metadata)
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
		_ = json.NewDecoder(r.Body).Decode(&req)
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
	metadataJSON, err := json.Marshal(nonNilMap(metadata))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "metadata must be JSON serializable.", err.Error())
		return
	}
	_, err = s.pool.Exec(r.Context(), `
		UPDATE groups
		SET name = $3,
			display_name = NULLIF($4, ''),
			sort_order = $5,
			status = $6,
			metadata = $7::jsonb,
			updated_at = now()
		WHERE id = $1 AND space_id = $2 AND deleted_at IS NULL
	`, groupID, spaceID, firstNonEmpty(req.Name, stringFromMap(current, "name")), nullableFromRequest(req.DisplayName, stringFromMap(current, "display_name")), intValue(req.SortOrder, intFromMap(current, "sort_order", 1000)), firstNonEmpty(derefString(req.Status), stringFromMap(current, "status"), "active"), metadataJSON)
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
	rows, err := queryMaps(r.Context(), s.pool, `
		SELECT id, space_id, parent_group_id, parent_group_id AS parent_id, name, display_name, path, depth, sort_order, status, metadata, created_at, updated_at, deleted_at
		FROM groups
		WHERE space_id = $1 AND deleted_at IS NULL
		ORDER BY path
		LIMIT $2
	`, spaceID, limit)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list Groups.", err.Error())
		return
	}
	writeList(w, r, http.StatusOK, rows, limit)
}

func (s *Server) loadGroupInSpace(ctx context.Context, spaceID, groupID string) (map[string]any, error) {
	return queryOneMap(ctx, s.pool, `
		SELECT id, space_id, parent_group_id, parent_group_id AS parent_id, name, display_name, path, depth, sort_order, status, metadata, created_at, updated_at, deleted_at
		FROM groups
		WHERE id = $1 AND space_id = $2 AND deleted_at IS NULL
	`, groupID, spaceID)
}

type memberMutationRequest struct {
	Actor       authz.ActorContext `json:"actor"`
	ID          string             `json:"id"`
	DisplayName string             `json:"display_name"`
	MemberType  *string            `json:"member_type"`
	Status      *string            `json:"status"`
	Metadata    map[string]any     `json:"metadata"`
}

func (s *Server) handleSpaceMembers(w http.ResponseWriter, r *http.Request, spaceID string, parts []string) {
	if len(parts) == 0 {
		switch r.Method {
		case http.MethodPost:
			var req memberMutationRequest
			if !decodeJSON(w, r, &req) {
				return
			}
			if strings.TrimSpace(req.DisplayName) == "" {
				writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "display_name is required.", nil)
				return
			}
			if req.ID == "" {
				req.ID = newEntityID("member")
			}
			metadata, err := json.Marshal(nonNilMap(req.Metadata))
			if err != nil {
				writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "metadata must be JSON serializable.", err.Error())
				return
			}
			_, err = s.pool.Exec(r.Context(), `
				INSERT INTO members (id, space_id, display_name, member_type, status, metadata)
				VALUES ($1, $2, $3, $4, $5, $6::jsonb)
			`, req.ID, spaceID, req.DisplayName, firstNonEmpty(derefString(req.MemberType), "human"), firstNonEmpty(derefString(req.Status), "active"), metadata)
			if err != nil {
				writeError(w, r, http.StatusConflict, "MEMBER_CREATE_FAILED", "Failed to create Member.", err.Error())
				return
			}
			row, err := s.loadMemberInSpace(r.Context(), spaceID, req.ID)
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load created Member.", err.Error())
				return
			}
			s.recordMutationAudit(r.Context(), r, req.Actor, spaceID, "member.created", "member", req.ID, row)
			writeData(w, r, http.StatusCreated, row)
		case http.MethodGet:
			limit := limitFrom(r, 50)
			rows, err := queryMaps(r.Context(), s.pool, `
				SELECT id, space_id, display_name, member_type, status, metadata, created_at, updated_at, deleted_at
				FROM members
				WHERE space_id = $1 AND deleted_at IS NULL
				ORDER BY display_name
				LIMIT $2
			`, spaceID, limit)
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list Members.", err.Error())
				return
			}
			writeList(w, r, http.StatusOK, rows, limit)
		default:
			writeMethodNotAllowed(w, r)
		}
		return
	}
	memberID := parts[0]
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			row, err := s.loadMemberInSpace(r.Context(), spaceID, memberID)
			if errors.Is(err, pgx.ErrNoRows) {
				writeError(w, r, http.StatusNotFound, "MEMBER_NOT_FOUND", "Member was not found.", nil)
				return
			}
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load Member.", err.Error())
				return
			}
			writeData(w, r, http.StatusOK, row)
		case http.MethodPatch:
			s.handleMemberUpdate(w, r, spaceID, memberID)
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
		var req memberMutationRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		row, err := s.updateScopedStatus(r.Context(), "members", memberID, spaceID, "disabled")
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to disable Member.", err.Error())
			return
		}
		s.recordMutationAudit(r.Context(), r, req.Actor, spaceID, "member.disabled", "member", memberID, row)
		writeData(w, r, http.StatusOK, row)
		return
	}
	http.NotFound(w, r)
}

func (s *Server) handleMemberUpdate(w http.ResponseWriter, r *http.Request, spaceID, memberID string) {
	var req memberMutationRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	current, err := s.loadMemberInSpace(r.Context(), spaceID, memberID)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, r, http.StatusNotFound, "MEMBER_NOT_FOUND", "Member was not found.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load Member.", err.Error())
		return
	}
	metadata := mapFromAny(current["metadata"])
	if req.Metadata != nil {
		metadata = req.Metadata
	}
	metadataJSON, err := json.Marshal(nonNilMap(metadata))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "metadata must be JSON serializable.", err.Error())
		return
	}
	_, err = s.pool.Exec(r.Context(), `
		UPDATE members
		SET display_name = $3,
			member_type = $4,
			status = $5,
			metadata = $6::jsonb,
			updated_at = now()
		WHERE id = $1 AND space_id = $2 AND deleted_at IS NULL
	`, memberID, spaceID, firstNonEmpty(req.DisplayName, stringFromMap(current, "display_name")), firstNonEmpty(derefString(req.MemberType), stringFromMap(current, "member_type"), "human"), firstNonEmpty(derefString(req.Status), stringFromMap(current, "status"), "active"), metadataJSON)
	if err != nil {
		writeError(w, r, http.StatusConflict, "MEMBER_UPDATE_FAILED", "Failed to update Member.", err.Error())
		return
	}
	row, err := s.loadMemberInSpace(r.Context(), spaceID, memberID)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load updated Member.", err.Error())
		return
	}
	s.recordMutationAudit(r.Context(), r, req.Actor, spaceID, "member.updated", "member", memberID, row)
	writeData(w, r, http.StatusOK, row)
}

func (s *Server) loadMemberInSpace(ctx context.Context, spaceID, memberID string) (map[string]any, error) {
	return queryOneMap(ctx, s.pool, `
		SELECT id, space_id, display_name, member_type, status, metadata, created_at, updated_at, deleted_at
		FROM members
		WHERE id = $1 AND space_id = $2 AND deleted_at IS NULL
	`, memberID, spaceID)
}

type userMemberMutationRequest struct {
	Actor            authz.ActorContext `json:"actor"`
	ID               string             `json:"id"`
	UserID           string             `json:"user_id"`
	MemberID         string             `json:"member_id"`
	RelationType     string             `json:"relation_type"`
	Status           *string            `json:"status"`
	IsPrimary        *bool              `json:"is_primary"`
	ExpiresAt        *time.Time         `json:"expires_at"`
	LinkedByMemberID *string            `json:"linked_by_member_id"`
	LinkedAt         *time.Time         `json:"linked_at"`
	RevokedReason    *string            `json:"revoked_reason"`
	Metadata         map[string]any     `json:"metadata"`
}

func (s *Server) handleSpaceUserMembers(w http.ResponseWriter, r *http.Request, spaceID string, parts []string) {
	if len(parts) == 0 {
		switch r.Method {
		case http.MethodPost:
			var req userMemberMutationRequest
			if !decodeJSON(w, r, &req) {
				return
			}
			if req.UserID == "" || req.MemberID == "" || req.RelationType == "" {
				writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "user_id, member_id, and relation_type are required.", nil)
				return
			}
			if req.ID == "" {
				req.ID = newEntityID("um")
			}
			if err := s.validateUserMemberRefs(r.Context(), spaceID, req.UserID, req.MemberID, derefString(req.LinkedByMemberID)); err != nil {
				writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "UserMember references are invalid.", err.Error())
				return
			}
			metadata, err := json.Marshal(nonNilMap(req.Metadata))
			if err != nil {
				writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "metadata must be JSON serializable.", err.Error())
				return
			}
			linkedAt := req.LinkedAt
			if linkedAt == nil {
				now := time.Now().UTC()
				linkedAt = &now
			}
			_, err = s.pool.Exec(r.Context(), `
				INSERT INTO user_members (id, user_id, member_id, space_id, relation_type, status, is_primary, expires_at, linked_by_member_id, linked_at, metadata)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULLIF($9, ''), $10, $11::jsonb)
			`, req.ID, req.UserID, req.MemberID, spaceID, req.RelationType, firstNonEmpty(derefString(req.Status), "active"), boolValue(req.IsPrimary, false), req.ExpiresAt, derefString(req.LinkedByMemberID), linkedAt, metadata)
			if err != nil {
				writeError(w, r, http.StatusConflict, "USER_MEMBER_CREATE_FAILED", "Failed to create UserMember.", err.Error())
				return
			}
			row, err := s.loadUserMemberInSpace(r.Context(), spaceID, req.ID)
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load created UserMember.", err.Error())
				return
			}
			s.recordMutationAudit(r.Context(), r, req.Actor, spaceID, "user_member.created", "user_member", req.ID, row)
			writeData(w, r, http.StatusCreated, row)
		case http.MethodGet:
			limit := limitFrom(r, 50)
			rows, err := queryMaps(r.Context(), s.pool, `
				SELECT um.id, um.user_id, u.email, um.member_id, m.display_name AS member_display_name,
					um.space_id, um.relation_type, um.status, um.is_primary, um.expires_at,
					um.linked_by_member_id, um.linked_at, um.revoked_at, um.revoked_reason,
					um.metadata, um.created_at, um.updated_at, um.deleted_at
				FROM user_members um
				JOIN users u ON u.id = um.user_id
				JOIN members m ON m.id = um.member_id
				WHERE um.space_id = $1 AND um.deleted_at IS NULL
				ORDER BY u.email, m.display_name
				LIMIT $2
			`, spaceID, limit)
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list UserMembers.", err.Error())
				return
			}
			writeList(w, r, http.StatusOK, rows, limit)
		default:
			writeMethodNotAllowed(w, r)
		}
		return
	}
	userMemberID := parts[0]
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			row, err := s.loadUserMemberInSpace(r.Context(), spaceID, userMemberID)
			if errors.Is(err, pgx.ErrNoRows) {
				writeError(w, r, http.StatusNotFound, "USER_MEMBER_NOT_FOUND", "UserMember was not found.", nil)
				return
			}
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load UserMember.", err.Error())
				return
			}
			writeData(w, r, http.StatusOK, row)
		case http.MethodPatch:
			s.handleUserMemberUpdate(w, r, spaceID, userMemberID)
		default:
			writeMethodNotAllowed(w, r)
		}
		return
	}
	if len(parts) == 2 && parts[1] == "revoke" {
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, r)
			return
		}
		var req userMemberMutationRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		_, err := s.pool.Exec(r.Context(), `
			UPDATE user_members
			SET status = 'revoked',
				revoked_at = now(),
				revoked_reason = NULLIF($3, ''),
				updated_at = now()
			WHERE id = $1 AND space_id = $2 AND deleted_at IS NULL
		`, userMemberID, spaceID, derefString(req.RevokedReason))
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to revoke UserMember.", err.Error())
			return
		}
		row, err := s.loadUserMemberInSpace(r.Context(), spaceID, userMemberID)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load revoked UserMember.", err.Error())
			return
		}
		s.recordMutationAudit(r.Context(), r, req.Actor, spaceID, "user_member.revoked", "user_member", userMemberID, row)
		writeData(w, r, http.StatusOK, row)
		return
	}
	http.NotFound(w, r)
}

func (s *Server) handleUserMemberUpdate(w http.ResponseWriter, r *http.Request, spaceID, userMemberID string) {
	var req userMemberMutationRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	current, err := s.loadUserMemberInSpace(r.Context(), spaceID, userMemberID)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, r, http.StatusNotFound, "USER_MEMBER_NOT_FOUND", "UserMember was not found.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load UserMember.", err.Error())
		return
	}
	userID := firstNonEmpty(req.UserID, stringFromMap(current, "user_id"))
	memberID := firstNonEmpty(req.MemberID, stringFromMap(current, "member_id"))
	linkedBy := nullableFromRequest(req.LinkedByMemberID, stringFromMap(current, "linked_by_member_id"))
	if err := s.validateUserMemberRefs(r.Context(), spaceID, userID, memberID, linkedBy); err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "UserMember references are invalid.", err.Error())
		return
	}
	metadata := mapFromAny(current["metadata"])
	if req.Metadata != nil {
		metadata = req.Metadata
	}
	metadataJSON, err := json.Marshal(nonNilMap(metadata))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "metadata must be JSON serializable.", err.Error())
		return
	}
	_, err = s.pool.Exec(r.Context(), `
		UPDATE user_members
		SET user_id = $3,
			member_id = $4,
			relation_type = $5,
			status = $6,
			is_primary = $7,
			expires_at = COALESCE($8, expires_at),
			linked_by_member_id = NULLIF($9, ''),
			linked_at = COALESCE($10, linked_at),
			metadata = $11::jsonb,
			updated_at = now()
		WHERE id = $1 AND space_id = $2 AND deleted_at IS NULL
	`, userMemberID, spaceID, userID, memberID, firstNonEmpty(req.RelationType, stringFromMap(current, "relation_type")), firstNonEmpty(derefString(req.Status), stringFromMap(current, "status"), "active"), boolValue(req.IsPrimary, boolFromMap(current, "is_primary", false)), req.ExpiresAt, linkedBy, req.LinkedAt, metadataJSON)
	if err != nil {
		writeError(w, r, http.StatusConflict, "USER_MEMBER_UPDATE_FAILED", "Failed to update UserMember.", err.Error())
		return
	}
	row, err := s.loadUserMemberInSpace(r.Context(), spaceID, userMemberID)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load updated UserMember.", err.Error())
		return
	}
	s.recordMutationAudit(r.Context(), r, req.Actor, spaceID, "user_member.updated", "user_member", userMemberID, row)
	writeData(w, r, http.StatusOK, row)
}

func (s *Server) loadUserMemberInSpace(ctx context.Context, spaceID, userMemberID string) (map[string]any, error) {
	return queryOneMap(ctx, s.pool, `
		SELECT um.id, um.user_id, u.email, um.member_id, m.display_name AS member_display_name,
			um.space_id, um.relation_type, um.status, um.is_primary, um.expires_at,
			um.linked_by_member_id, um.linked_at, um.revoked_at, um.revoked_reason,
			um.metadata, um.created_at, um.updated_at, um.deleted_at
		FROM user_members um
		JOIN users u ON u.id = um.user_id
		JOIN members m ON m.id = um.member_id
		WHERE um.id = $1 AND um.space_id = $2 AND um.deleted_at IS NULL
	`, userMemberID, spaceID)
}

func (s *Server) validateUserMemberRefs(ctx context.Context, spaceID, userID, memberID, linkedByMemberID string) error {
	var userExists bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE id = $1 AND deleted_at IS NULL)`, userID).Scan(&userExists); err != nil {
		return err
	}
	if !userExists {
		return fmt.Errorf("user %s does not exist", userID)
	}
	if err := s.validateMemberInSpace(ctx, spaceID, memberID); err != nil {
		return err
	}
	if linkedByMemberID != "" {
		if err := s.validateMemberInSpace(ctx, spaceID, linkedByMemberID); err != nil {
			return err
		}
	}
	return nil
}

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
			metadata, err := json.Marshal(nonNilMap(req.Metadata))
			if err != nil {
				writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "metadata must be JSON serializable.", err.Error())
				return
			}
			_, err = s.pool.Exec(r.Context(), `
				INSERT INTO roles (id, space_id, key, name, description, status, metadata)
				VALUES ($1, $2, $3, $4, NULLIF($5, ''), $6, $7::jsonb)
			`, req.ID, spaceID, req.Key, firstNonEmpty(req.Name, titleFromKey(req.Key)), derefString(req.Description), firstNonEmpty(derefString(req.Status), "active"), metadata)
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
			rows, err := queryMaps(r.Context(), s.pool, `
				SELECT id, space_id, key, name, description, status, metadata, created_at, updated_at, deleted_at
				FROM roles
				WHERE space_id = $1 AND deleted_at IS NULL
				ORDER BY key
				LIMIT $2
			`, spaceID, limit)
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list Roles.", err.Error())
				return
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
		_ = json.NewDecoder(r.Body).Decode(&req)
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
	metadataJSON, err := json.Marshal(nonNilMap(metadata))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "metadata must be JSON serializable.", err.Error())
		return
	}
	_, err = s.pool.Exec(r.Context(), `
		UPDATE roles
		SET name = $3,
			description = NULLIF($4, ''),
			status = $5,
			metadata = $6::jsonb,
			updated_at = now()
		WHERE id = $1 AND space_id = $2 AND deleted_at IS NULL
	`, roleID, spaceID, firstNonEmpty(req.Name, stringFromMap(current, "name")), nullableFromRequest(req.Description, stringFromMap(current, "description")), firstNonEmpty(derefString(req.Status), stringFromMap(current, "status"), "active"), metadataJSON)
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
	return queryOneMap(ctx, s.pool, `
		SELECT id, space_id, key, name, description, status, metadata, created_at, updated_at, deleted_at
		FROM roles
		WHERE id = $1 AND space_id = $2 AND deleted_at IS NULL
	`, roleID, spaceID)
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
			metadata, err := json.Marshal(nonNilMap(req.Metadata))
			if err != nil {
				writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "metadata must be JSON serializable.", err.Error())
				return
			}
			_, err = s.pool.Exec(r.Context(), `
				INSERT INTO member_roles (id, member_id, role_id, space_id, scope_anchor_group_id, status, metadata)
				VALUES ($1, $2, $3, $4, NULLIF($5, ''), $6, $7::jsonb)
			`, req.ID, req.MemberID, req.RoleID, spaceID, derefString(req.ScopeAnchorGroupID), firstNonEmpty(derefString(req.Status), "active"), metadata)
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
		_ = json.NewDecoder(r.Body).Decode(&req)
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
	rows, err := queryMaps(r.Context(), s.pool, `
		SELECT mr.id, mr.space_id, mr.member_id, m.display_name AS member_display_name,
			mr.role_id, ro.key AS role_key, ro.name AS role_name,
			mr.scope_anchor_group_id, g.path AS scope_anchor_path,
			mr.status, mr.metadata, mr.created_at, mr.updated_at, mr.deleted_at
		FROM member_roles mr
		JOIN members m ON m.id = mr.member_id
		JOIN roles ro ON ro.id = mr.role_id
		LEFT JOIN groups g ON g.id = mr.scope_anchor_group_id
		WHERE mr.space_id = $1 AND mr.deleted_at IS NULL
		ORDER BY m.display_name, ro.key
		LIMIT $2
	`, spaceID, limit)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list MemberRoles.", err.Error())
		return
	}
	writeList(w, r, http.StatusOK, rows, limit)
}

func (s *Server) loadMemberRoleInSpace(ctx context.Context, spaceID, memberRoleID string) (map[string]any, error) {
	return queryOneMap(ctx, s.pool, `
		SELECT mr.id, mr.space_id, mr.member_id, m.display_name AS member_display_name,
			mr.role_id, ro.key AS role_key, ro.name AS role_name,
			mr.scope_anchor_group_id, g.path AS scope_anchor_path,
			mr.status, mr.metadata, mr.created_at, mr.updated_at, mr.deleted_at
		FROM member_roles mr
		JOIN members m ON m.id = mr.member_id
		JOIN roles ro ON ro.id = mr.role_id
		LEFT JOIN groups g ON g.id = mr.scope_anchor_group_id
		WHERE mr.id = $1 AND mr.space_id = $2 AND mr.deleted_at IS NULL
	`, memberRoleID, spaceID)
}

func (s *Server) validateMemberRoleRefs(ctx context.Context, spaceID, memberID, roleID, anchorID string) error {
	if err := s.validateMemberInSpace(ctx, spaceID, memberID); err != nil {
		return err
	}
	var roleExists bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM roles WHERE id = $1 AND space_id = $2 AND deleted_at IS NULL)`, roleID, spaceID).Scan(&roleExists); err != nil {
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
			args := []any{spaceID, limit}
			where := []string{"res.space_id = $1", "res.deleted_at IS NULL"}
			if resourceType := r.URL.Query().Get("resource_type"); resourceType != "" {
				args = append(args, resourceType)
				where = append(where, fmt.Sprintf("res.resource_type = $%d", len(args)))
			}
			rows, err := queryMaps(r.Context(), s.pool, `
				SELECT res.id, res.resource_type, res.external_id, res.display_name, res.space_id, s.name AS space_name,
					res.group_id, g.path AS group_path, res.owner_member_id, m.display_name AS owner_member_display_name,
					res.visibility, res.metadata, res.status, res.created_at, res.updated_at, res.deleted_at
				FROM resources res
				JOIN spaces s ON s.id = res.space_id
				LEFT JOIN groups g ON g.id = res.group_id
				LEFT JOIN members m ON m.id = res.owner_member_id
				WHERE `+strings.Join(where, " AND ")+`
				ORDER BY res.resource_type, res.id
				LIMIT $2
			`, args...)
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list Resources.", err.Error())
				return
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
		_ = json.NewDecoder(r.Body).Decode(&req)
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
	metadataJSON, err := json.Marshal(nonNilMap(metadata))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "metadata must be JSON serializable.", err.Error())
		return
	}
	_, err = s.pool.Exec(r.Context(), `
		UPDATE resources
		SET external_id = NULLIF($3, ''),
			display_name = NULLIF($4, ''),
			group_id = NULLIF($5, ''),
			owner_member_id = NULLIF($6, ''),
			visibility = $7,
			status = $8,
			metadata = $9::jsonb,
			updated_at = now()
		WHERE id = $1 AND space_id = $2 AND deleted_at IS NULL
	`, resourceID, spaceID, nullableFromRequest(req.ExternalID, stringFromMap(current, "external_id")), nullableFromRequest(req.DisplayName, stringFromMap(current, "display_name")), groupID, ownerMemberID, firstNonEmpty(derefString(req.Visibility), stringFromMap(current, "visibility"), "private"), firstNonEmpty(derefString(req.Status), stringFromMap(current, "status"), "active"), metadataJSON)
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
	return queryOneMap(ctx, s.pool, `
		SELECT res.id, res.resource_type, res.external_id, res.display_name, res.space_id, s.name AS space_name,
			res.group_id, g.path AS group_path, res.owner_member_id, m.display_name AS owner_member_display_name,
			res.visibility, res.metadata, res.status, res.created_at, res.updated_at, res.deleted_at
		FROM resources res
		JOIN spaces s ON s.id = res.space_id
		LEFT JOIN groups g ON g.id = res.group_id
		LEFT JOIN members m ON m.id = res.owner_member_id
		WHERE res.id = $1 AND res.space_id = $2 AND res.deleted_at IS NULL
	`, resourceID, spaceID)
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
	groupID := derefString(req.GroupID)
	ownerMemberID := derefString(req.OwnerMemberID)
	if err := s.validateResourceRefs(r.Context(), spaceID, groupID, ownerMemberID); err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Resource references are invalid.", err.Error())
		return
	}
	metadata, err := json.Marshal(nonNilMap(req.Metadata))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "metadata must be JSON serializable.", err.Error())
		return
	}
	_, err = s.pool.Exec(r.Context(), `
		INSERT INTO resources (id, resource_type, external_id, display_name, space_id, group_id, owner_member_id, visibility, status, metadata)
		VALUES ($1, $2, NULLIF($3, ''), NULLIF($4, ''), $5, NULLIF($6, ''), NULLIF($7, ''), $8, $9, $10::jsonb)
	`, req.ID, req.ResourceType, derefString(req.ExternalID), derefString(req.DisplayName), spaceID, groupID, ownerMemberID, firstNonEmpty(derefString(req.Visibility), "private"), firstNonEmpty(derefString(req.Status), "active"), metadata)
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

func (s *Server) handleSpaceAuditLogs(w http.ResponseWriter, r *http.Request, spaceID string, parts []string) {
	if len(parts) == 0 {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, r)
			return
		}
		limit := limitFrom(r, 50)
		sqlText := `SELECT id, space_id, actor_user_id, actor_member_id, actor_user_member_id, action, resource_type, resource_id, decision, COALESCE(deny_code, '') AS deny_code, request_id, ip_address, user_agent, created_at FROM audit_logs`
		args := []any{spaceID}
		where := []string{"space_id = $1"}
		for _, filter := range []string{"actor_user_id", "actor_member_id", "actor_user_member_id", "resource_type", "resource_id", "decision", "deny_code", "request_id"} {
			if value := r.URL.Query().Get(filter); value != "" {
				args = append(args, value)
				where = append(where, fmt.Sprintf("%s = $%d", filter, len(args)))
			}
		}
		if from := r.URL.Query().Get("created_at_from"); from != "" {
			args = append(args, from)
			where = append(where, fmt.Sprintf("created_at >= $%d::timestamptz", len(args)))
		}
		if to := r.URL.Query().Get("created_at_to"); to != "" {
			args = append(args, to)
			where = append(where, fmt.Sprintf("created_at <= $%d::timestamptz", len(args)))
		}
		args = append(args, limit)
		sqlText += " WHERE " + strings.Join(where, " AND ") + fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d", len(args))
		rows, err := queryMaps(r.Context(), s.pool, sqlText, args...)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list AuditLogs.", err.Error())
			return
		}
		writeList(w, r, http.StatusOK, rows, limit)
		return
	}
	if len(parts) == 1 {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, r)
			return
		}
		row, err := queryOneMap(r.Context(), s.pool, `SELECT * FROM audit_logs WHERE id = $1 AND space_id = $2`, parts[0], spaceID)
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, r, http.StatusNotFound, "AUDIT_LOG_NOT_FOUND", "AuditLog was not found.", nil)
			return
		}
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load AuditLog.", err.Error())
			return
		}
		writeData(w, r, http.StatusOK, row)
		return
	}
	http.NotFound(w, r)
}

func (s *Server) handleGroupDetail(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/groups/")
	s.handleSingleByID(w, r, `SELECT id, space_id, parent_group_id, parent_group_id AS parent_id, name, display_name, path, depth, sort_order, status, metadata, created_at, updated_at, deleted_at FROM groups WHERE id = $1 AND deleted_at IS NULL`, id, "GROUP_NOT_FOUND")
}

func (s *Server) handleMemberDetail(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/members/")
	s.handleSingleByID(w, r, `SELECT id, space_id, display_name, member_type, status, metadata, created_at, updated_at, deleted_at FROM members WHERE id = $1 AND deleted_at IS NULL`, id, "MEMBER_NOT_FOUND")
}

func (s *Server) handleUserMemberDetail(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/user-members/")
	s.handleSingleByID(w, r, `
		SELECT um.id, um.user_id, u.email, um.member_id, m.display_name AS member_display_name,
			um.space_id, um.relation_type, um.status, um.is_primary, um.expires_at,
			um.linked_by_member_id, um.linked_at, um.revoked_at, um.revoked_reason,
			um.metadata, um.created_at, um.updated_at, um.deleted_at
		FROM user_members um
		JOIN users u ON u.id = um.user_id
		JOIN members m ON m.id = um.member_id
		WHERE um.id = $1 AND um.deleted_at IS NULL
	`, id, "USER_MEMBER_NOT_FOUND")
}

func (s *Server) handleRoleDetail(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/roles/")
	s.handleSingleByID(w, r, `SELECT id, space_id, key, name, description, status, metadata, created_at, updated_at, deleted_at FROM roles WHERE id = $1 AND deleted_at IS NULL`, id, "ROLE_NOT_FOUND")
}

func (s *Server) handlePermissions(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		s.handlePermissionCreate(w, r)
		return
	}
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, r)
		return
	}
	s.handleQueryList(w, r, `SELECT id, resource, action, scope, description, status, metadata, created_at, updated_at, deleted_at FROM permissions WHERE deleted_at IS NULL ORDER BY resource, action, scope`)
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
			s.handleSingleByID(w, r, `SELECT id, resource, action, scope, description, status, metadata, created_at, updated_at, deleted_at FROM permissions WHERE id = $1 AND deleted_at IS NULL`, id, "PERMISSION_NOT_FOUND")
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
		_ = json.NewDecoder(r.Body).Decode(&req)
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
	metadata, err := json.Marshal(nonNilMap(req.Metadata))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "metadata must be JSON serializable.", err.Error())
		return
	}
	_, err = s.pool.Exec(r.Context(), `
		INSERT INTO permissions (id, resource, action, scope, description, status, metadata)
		VALUES ($1, $2, $3, $4, NULLIF($5, ''), $6, $7::jsonb)
	`, req.ID, req.Resource, req.Action, req.Scope, derefString(req.Description), status, metadata)
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
	metadataJSON, err := json.Marshal(nonNilMap(metadata))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "metadata must be JSON serializable.", err.Error())
		return
	}
	_, err = s.pool.Exec(r.Context(), `
		UPDATE permissions
		SET resource = $2,
			action = $3,
			scope = $4,
			description = NULLIF($5, ''),
			status = $6,
			metadata = $7::jsonb,
			updated_at = now()
		WHERE id = $1 AND deleted_at IS NULL
	`, permissionID, resourceKey, actionKey, scope, nullableFromRequest(req.Description, stringFromMap(current, "description")), status, metadataJSON)
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
	return queryOneMap(ctx, s.pool, `
		SELECT id, resource, action, scope, description, status, metadata, created_at, updated_at, deleted_at
		FROM permissions
		WHERE id = $1 AND deleted_at IS NULL
	`, permissionID)
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
		metadata, err := json.Marshal(nonNilMap(req.Metadata))
		if err != nil {
			writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "metadata must be JSON serializable.", err.Error())
			return
		}
		_, err = s.pool.Exec(r.Context(), `
			INSERT INTO role_permissions (id, role_id, permission_id, metadata)
			VALUES ($1, $2, $3, $4::jsonb)
			ON CONFLICT (role_id, permission_id)
			DO UPDATE SET deleted_at = NULL, updated_at = now(), metadata = EXCLUDED.metadata
		`, req.ID, req.RoleID, req.PermissionID, metadata)
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
		rows, err := queryMaps(r.Context(), s.pool, `
			SELECT rp.id, rp.role_id, ro.space_id, ro.key AS role_key, rp.permission_id,
				p.resource, p.action, p.scope, rp.metadata, rp.created_at, rp.updated_at, rp.deleted_at
			FROM role_permissions rp
			JOIN roles ro ON ro.id = rp.role_id
			JOIN permissions p ON p.id = rp.permission_id
			WHERE rp.deleted_at IS NULL
			ORDER BY ro.space_id, ro.key, p.resource, p.action, p.scope
			LIMIT $1
		`, limit)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list RolePermissions.", err.Error())
			return
		}
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
		_ = json.NewDecoder(r.Body).Decode(&req)
		row, err := s.loadRolePermission(r.Context(), id)
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, r, http.StatusNotFound, "ROLE_PERMISSION_NOT_FOUND", "RolePermission was not found.", nil)
			return
		}
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load RolePermission.", err.Error())
			return
		}
		_, err = s.pool.Exec(r.Context(), `UPDATE role_permissions SET deleted_at = now(), updated_at = now() WHERE id = $1 AND deleted_at IS NULL`, id)
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
	return queryOneMap(ctx, s.pool, `
		SELECT rp.id, rp.role_id, ro.space_id, ro.key AS role_key, rp.permission_id,
			p.resource, p.action, p.scope, rp.metadata, rp.created_at, rp.updated_at, rp.deleted_at
		FROM role_permissions rp
		JOIN roles ro ON ro.id = rp.role_id
		JOIN permissions p ON p.id = rp.permission_id
		WHERE rp.id = $1 AND rp.deleted_at IS NULL
	`, id)
}

func (s *Server) loadRolePermissionByPair(ctx context.Context, roleID, permissionID string) (map[string]any, error) {
	return queryOneMap(ctx, s.pool, `
		SELECT rp.id, rp.role_id, ro.space_id, ro.key AS role_key, rp.permission_id,
			p.resource, p.action, p.scope, rp.metadata, rp.created_at, rp.updated_at, rp.deleted_at
		FROM role_permissions rp
		JOIN roles ro ON ro.id = rp.role_id
		JOIN permissions p ON p.id = rp.permission_id
		WHERE rp.role_id = $1 AND rp.permission_id = $2 AND rp.deleted_at IS NULL
	`, roleID, permissionID)
}

func (s *Server) roleSpaceID(ctx context.Context, roleID string) (string, error) {
	var spaceID string
	err := s.pool.QueryRow(ctx, `SELECT space_id FROM roles WHERE id = $1 AND deleted_at IS NULL`, roleID).Scan(&spaceID)
	return spaceID, err
}

func (s *Server) permissionExists(ctx context.Context, permissionID string) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM permissions WHERE id = $1 AND deleted_at IS NULL)`, permissionID).Scan(&exists)
	return exists, err
}

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
	args := []any{}
	where := []string{}
	if spaceID := r.URL.Query().Get("space_id"); spaceID != "" {
		args = append(args, spaceID)
		where = append(where, fmt.Sprintf("res.space_id = $%d", len(args)))
	}
	if resourceType := r.URL.Query().Get("resource_type"); resourceType != "" {
		args = append(args, resourceType)
		where = append(where, fmt.Sprintf("res.resource_type = $%d", len(args)))
	}
	sql := `
		SELECT res.id, res.resource_type, res.external_id, res.display_name, res.space_id, s.name AS space_name,
			res.group_id, g.path AS group_path, res.owner_member_id, m.display_name AS owner_member_display_name,
			res.visibility, res.metadata, res.status, res.created_at, res.updated_at, res.deleted_at
		FROM resources res
		JOIN spaces s ON s.id = res.space_id
		LEFT JOIN groups g ON g.id = res.group_id
		LEFT JOIN members m ON m.id = res.owner_member_id
	`
	if len(where) > 0 {
		sql += " WHERE " + strings.Join(where, " AND ")
	}
	sql += " ORDER BY res.resource_type, res.id"
	rows, err := queryMaps(r.Context(), s.pool, sql, args...)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list resources.", err.Error())
		return
	}
	writeList(w, r, http.StatusOK, rows, limitFrom(r, 50))
}

func (s *Server) handleResourceDetail(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/resources/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 2 {
		s.handleSingleByID(w, r, `
			SELECT res.id, res.resource_type, res.external_id, res.display_name, res.space_id, s.name AS space_name,
				res.group_id, g.path AS group_path, res.owner_member_id, m.display_name AS owner_member_display_name,
				res.visibility, res.metadata, res.status, res.created_at, res.updated_at, res.deleted_at
			FROM resources res
			JOIN spaces s ON s.id = res.space_id
			LEFT JOIN groups g ON g.id = res.group_id
			LEFT JOIN members m ON m.id = res.owner_member_id
			WHERE res.resource_type = $1 AND res.id = $2
		`, parts[0], "RESOURCE_NOT_FOUND", parts[1])
		return
	}
	http.NotFound(w, r)
}

func (s *Server) handleDataTables(w http.ResponseWriter, r *http.Request) {
	if !featureEnabled("DATA_CONSOLE_ENABLED") {
		writeError(w, r, http.StatusNotFound, "FEATURE_DISABLED", "Data Console API is disabled.", nil)
		return
	}
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, r)
		return
	}
	rows, err := queryMaps(r.Context(), s.pool, `
		SELECT rt.key AS resource_type, rt.display_name, rt.source,
			rm.storage_kind, rm.table_name, rm.id_field, rm.space_field, rm.group_field,
			rm.owner_member_field, rm.visibility_field, rm.metadata_field, rm.status, rm.metadata
		FROM resource_mappings rm
		JOIN resource_types rt ON rt.id = rm.resource_type_id
		ORDER BY rt.key
	`)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list data tables.", err.Error())
		return
	}
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
		args := []any{resourceType}
		where := []string{"res.resource_type = $1"}
		if spaceID := r.URL.Query().Get("space_id"); spaceID != "" {
			args = append(args, spaceID)
			where = append(where, fmt.Sprintf("res.space_id = $%d", len(args)))
		}
		sql := `
			SELECT res.id, res.resource_type, res.display_name, res.space_id, s.name AS space_name,
				res.group_id, g.path AS group_path, res.owner_member_id, m.display_name AS owner_member_display_name,
				res.visibility, res.metadata, res.status, res.created_at
			FROM resources res
			JOIN spaces s ON s.id = res.space_id
			LEFT JOIN groups g ON g.id = res.group_id
			LEFT JOIN members m ON m.id = res.owner_member_id
			WHERE ` + strings.Join(where, " AND ") + `
			ORDER BY res.id
		`
		rows, err := queryMaps(r.Context(), s.pool, sql, args...)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list data rows.", err.Error())
			return
		}
		writeList(w, r, http.StatusOK, rows, limitFrom(r, 50))
		return
	}
	if len(parts) == 2 && r.Method == http.MethodGet {
		s.handleSingleByID(w, r, `
			SELECT res.id, res.resource_type, res.display_name, res.space_id, s.name AS space_name,
				res.group_id, g.path AS group_path, res.owner_member_id, m.display_name AS owner_member_display_name,
				res.visibility, res.metadata, res.status, res.created_at
			FROM resources res
			JOIN spaces s ON s.id = res.space_id
			LEFT JOIN groups g ON g.id = res.group_id
			LEFT JOIN members m ON m.id = res.owner_member_id
			WHERE res.resource_type = $1 AND res.id = $2
		`, resourceType, "RESOURCE_NOT_FOUND", parts[1])
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

	metadataJSON, err := json.Marshal(nonNilMap(req.Metadata))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "metadata must be JSON serializable.", err.Error())
		return
	}
	_, err = s.pool.Exec(r.Context(), `
		INSERT INTO resources (id, resource_type, display_name, space_id, group_id, owner_member_id, visibility, metadata, status)
		VALUES ($1, $2, NULLIF($3, ''), $4, NULLIF($5, ''), NULLIF($6, ''), $7, $8::jsonb, $9)
	`, req.ID, resourceType, derefString(req.DisplayName), req.SpaceID, groupID, ownerMemberID, firstNonEmpty(derefString(req.Visibility), "private"), metadataJSON, firstNonEmpty(derefString(req.Status), "active"))
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
	metadataJSON, err := json.Marshal(nonNilMap(proposed.Resource.Metadata))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "metadata must be JSON serializable.", err.Error())
		return
	}
	_, err = s.pool.Exec(r.Context(), `
		UPDATE resources
		SET display_name = NULLIF($3, ''),
			group_id = NULLIF($4, ''),
			owner_member_id = NULLIF($5, ''),
			visibility = $6,
			metadata = $7::jsonb,
			status = $8,
			updated_at = now()
		WHERE resource_type = $1 AND id = $2
	`, resourceType, resourceID, proposed.Resource.DisplayName, proposed.Resource.GroupID, proposed.Resource.OwnerMemberID, firstNonEmpty(proposed.Resource.Visibility, "private"), metadataJSON, firstNonEmpty(proposed.Resource.Status, "active"))
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
	_, err = s.pool.Exec(r.Context(), `UPDATE resources SET status = 'deleted', updated_at = now() WHERE resource_type = $1 AND id = $2`, resourceType, resourceID)
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

func (s *Server) authorizeTarget(w http.ResponseWriter, r *http.Request, actor authz.ActorContext, resourceType, resourceID, action string, target authz.TargetSnapshot) (*authz.Decision, bool) {
	decision, err := authz.Check(r.Context(), s.authzStore, authz.CheckInput{
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
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Authorization check failed.", err.Error())
		return nil, false
	}
	if !decision.IsAllowed() {
		writeError(w, r, http.StatusForbidden, "AUTHORIZATION_DENIED", "The action is not allowed.", decision)
		return decision, false
	}
	return decision, true
}

func (s *Server) requireInternalResourceMapping(ctx context.Context, resourceType string) error {
	var storageKind, tableName string
	err := s.pool.QueryRow(ctx, `
		SELECT rm.storage_kind, COALESCE(rm.table_name, '')
		FROM resource_mappings rm
		JOIN resource_types rt ON rt.id = rm.resource_type_id
		WHERE rt.key = $1
	`, resourceType).Scan(&storageKind, &tableName)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrAPINotFound
	}
	if err != nil {
		return err
	}
	if storageKind != "internal_table" || tableName != "resources" {
		return ErrAPIUnsupportedMapping
	}
	return nil
}

var ErrAPINotFound = errors.New("api resource not found")
var ErrAPIUnsupportedMapping = errors.New("unsupported resource mapping")

func (s *Server) writeMappingError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrAPINotFound):
		writeError(w, r, http.StatusNotFound, "RESOURCE_TYPE_NOT_FOUND", "Resource type mapping was not found.", nil)
	case errors.Is(err, ErrAPIUnsupportedMapping):
		writeError(w, r, http.StatusBadRequest, "UNSUPPORTED_RESOURCE_MAPPING", "Data Console mutations currently support internal resources table mappings only.", nil)
	default:
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to validate resource mapping.", err.Error())
	}
}

func (s *Server) resourceExists(ctx context.Context, resourceType, resourceID string) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM resources WHERE resource_type = $1 AND id = $2)`, resourceType, resourceID).Scan(&exists)
	return exists, err
}

func (s *Server) validateResourceRefs(ctx context.Context, spaceID, groupID, ownerMemberID string) error {
	if groupID != "" {
		if _, err := s.loadGroupSnapshot(ctx, spaceID, groupID); err != nil {
			return err
		}
	}
	if ownerMemberID != "" {
		if err := s.validateMemberInSpace(ctx, spaceID, ownerMemberID); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) validateMemberInSpace(ctx context.Context, spaceID, memberID string) error {
	if memberID == "" {
		return nil
	}
	var exists bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM members WHERE id = $1 AND space_id = $2)`, memberID, spaceID).Scan(&exists)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("member %s is not in space %s", memberID, spaceID)
	}
	return nil
}

func (s *Server) proposedResourceTarget(ctx context.Context, resourceType, resourceID, spaceID, groupID, ownerMemberID, displayName, visibility, status string, metadata map[string]any) (authz.TargetSnapshot, error) {
	group, err := s.loadGroupSnapshot(ctx, spaceID, groupID)
	if err != nil {
		return authz.TargetSnapshot{}, err
	}
	return authz.TargetSnapshot{
		Resource: authz.ResourceSnapshot{
			ID:            resourceID,
			Type:          resourceType,
			SpaceID:       spaceID,
			GroupID:       groupID,
			OwnerMemberID: ownerMemberID,
			DisplayName:   displayName,
			Visibility:    visibility,
			Status:        status,
			Metadata:      nonNilMap(metadata),
		},
		Group: group,
	}, nil
}

func (s *Server) loadGroupSnapshot(ctx context.Context, spaceID, groupID string) (*authz.GroupSnapshot, error) {
	if groupID == "" {
		return nil, nil
	}
	var group authz.GroupSnapshot
	err := s.pool.QueryRow(ctx, `SELECT id, space_id, path, status FROM groups WHERE id = $1 AND space_id = $2`, groupID, spaceID).Scan(&group.ID, &group.SpaceID, &group.Path, &group.Status)
	if err != nil {
		return nil, err
	}
	return &group, nil
}

func (s *Server) loadResourceTarget(ctx context.Context, resourceType, resourceID string) (authz.TargetSnapshot, error) {
	var target authz.TargetSnapshot
	var groupID, ownerMemberID, displayName, visibility, status sql.NullString
	var metadataBytes []byte
	err := s.pool.QueryRow(ctx, `
		SELECT id, resource_type, space_id, group_id, owner_member_id, display_name, visibility, status, metadata
		FROM resources
		WHERE resource_type = $1 AND id = $2
	`, resourceType, resourceID).Scan(
		&target.Resource.ID,
		&target.Resource.Type,
		&target.Resource.SpaceID,
		&groupID,
		&ownerMemberID,
		&displayName,
		&visibility,
		&status,
		&metadataBytes,
	)
	if err != nil {
		return authz.TargetSnapshot{}, err
	}
	target.Resource.GroupID = nullStringValue(groupID)
	target.Resource.OwnerMemberID = nullStringValue(ownerMemberID)
	target.Resource.DisplayName = nullStringValue(displayName)
	target.Resource.Visibility = nullStringValue(visibility)
	target.Resource.Status = nullStringValue(status)
	if len(metadataBytes) > 0 {
		_ = json.Unmarshal(metadataBytes, &target.Resource.Metadata)
	}
	group, err := s.loadGroupSnapshot(ctx, target.Resource.SpaceID, target.Resource.GroupID)
	if err != nil {
		return authz.TargetSnapshot{}, err
	}
	target.Group = group
	return target, nil
}

func (s *Server) loadResourceRow(ctx context.Context, resourceType, resourceID string) (map[string]any, error) {
	return queryOneMap(ctx, s.pool, `
		SELECT res.id, res.resource_type, res.display_name, res.space_id, s.name AS space_name,
			res.group_id, g.path AS group_path, res.owner_member_id, m.display_name AS owner_member_display_name,
			res.visibility, res.metadata, res.status, res.created_at, res.updated_at
		FROM resources res
		JOIN spaces s ON s.id = res.space_id
		LEFT JOIN groups g ON g.id = res.group_id
		LEFT JOIN members m ON m.id = res.owner_member_id
		WHERE res.resource_type = $1 AND res.id = $2
	`, resourceType, resourceID)
}

func (s *Server) handlePluginManifestValidation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, r)
		return
	}
	var manifest plugins.Manifest
	if err := json.NewDecoder(r.Body).Decode(&manifest); err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Request body is invalid JSON.", err.Error())
		return
	}
	errors := plugins.ValidateManifestForCore(manifest, s.coreVersion)
	if errors == nil {
		errors = []string{}
	}
	writeData(w, r, http.StatusOK, map[string]any{
		"valid":  len(errors) == 0,
		"errors": errors,
	})
}

type pluginInstallRequest struct {
	Manifest plugins.Manifest `json:"manifest"`
	Source   string           `json:"source"`
}

func (s *Server) handlePluginInstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, r)
		return
	}
	var req pluginInstallRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Request body is invalid JSON.", err.Error())
		return
	}
	validationErrors := plugins.ValidateManifestForCore(req.Manifest, s.coreVersion)
	if len(validationErrors) > 0 {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Plugin manifest is invalid.", validationErrors)
		return
	}
	source := firstNonEmpty(req.Source, req.Manifest.Source, "local")
	status := firstNonEmpty(req.Manifest.Status, "installed")
	manifestJSON, err := json.Marshal(req.Manifest)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to encode plugin manifest.", err.Error())
		return
	}
	_, err = s.pool.Exec(r.Context(), `
		INSERT INTO plugins (id, key, name, description, version, source, status, manifest)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)
		ON CONFLICT (key) DO UPDATE SET
			name = EXCLUDED.name,
			description = EXCLUDED.description,
			version = EXCLUDED.version,
			source = EXCLUDED.source,
			status = EXCLUDED.status,
			manifest = EXCLUDED.manifest,
			updated_at = now()
	`, "plugin_"+safeIdentifier(req.Manifest.ID), req.Manifest.ID, req.Manifest.Name, req.Manifest.Description, req.Manifest.Version, source, status, manifestJSON)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to install plugin metadata.", err.Error())
		return
	}
	pluginID := "plugin_" + safeIdentifier(req.Manifest.ID)
	if err := s.installPluginManifestMetadata(r.Context(), pluginID, req.Manifest); err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to install plugin declarations.", err.Error())
		return
	}
	row, err := queryOneMap(r.Context(), s.pool, `SELECT id, key, name, description, version, source, status, manifest, created_at, updated_at FROM plugins WHERE key = $1`, req.Manifest.ID)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load installed plugin.", err.Error())
		return
	}
	writeData(w, r, http.StatusCreated, row)
}

func (s *Server) installPluginManifestMetadata(ctx context.Context, pluginID string, manifest plugins.Manifest) error {
	metadata, err := json.Marshal(map[string]any{"plugin": manifest.ID})
	if err != nil {
		return err
	}
	for _, resource := range manifest.Resources {
		resourceTypeID := "rt_" + safeIdentifier(manifest.ID+"_"+resource.Key)
		if _, err := s.pool.Exec(ctx, `
			INSERT INTO resource_types (id, key, display_name, description, status, source, metadata)
			VALUES ($1, $2, $3, '', 'active', $4, $5::jsonb)
			ON CONFLICT (key) DO UPDATE SET
				display_name = EXCLUDED.display_name,
				source = EXCLUDED.source,
				metadata = EXCLUDED.metadata,
				updated_at = now()
		`, resourceTypeID, resource.Key, resource.DisplayName, "plugin:"+manifest.ID, metadata); err != nil {
			return err
		}
		if _, err := s.pool.Exec(ctx, `
			INSERT INTO resource_mappings (
				id, resource_type_id, storage_kind, table_name, id_field, space_field,
				group_field, owner_member_field, visibility_field, metadata_field, status, metadata
			)
			VALUES ($1, $2, 'plugin_managed', NULL, 'id', 'space_id', 'group_id', 'owner_member_id', NULL, 'metadata', 'active', $3::jsonb)
			ON CONFLICT (resource_type_id) DO UPDATE SET
				storage_kind = EXCLUDED.storage_kind,
				table_name = EXCLUDED.table_name,
				id_field = EXCLUDED.id_field,
				space_field = EXCLUDED.space_field,
				group_field = EXCLUDED.group_field,
				owner_member_field = EXCLUDED.owner_member_field,
				visibility_field = EXCLUDED.visibility_field,
				metadata_field = EXCLUDED.metadata_field,
				status = EXCLUDED.status,
				metadata = EXCLUDED.metadata,
				updated_at = now()
		`, "rm_"+safeIdentifier(manifest.ID+"_"+resource.Key), resourceTypeID, metadata); err != nil {
			return err
		}
		for _, action := range resource.Actions {
			if _, err := s.pool.Exec(ctx, `
				INSERT INTO resource_actions (id, resource_type_id, key, display_name, description, risk_level, audit_default, metadata)
				VALUES ($1, $2, $3, $4, '', $5, true, $6::jsonb)
				ON CONFLICT (resource_type_id, key) DO UPDATE SET
					display_name = EXCLUDED.display_name,
					risk_level = EXCLUDED.risk_level,
					audit_default = EXCLUDED.audit_default,
					metadata = EXCLUDED.metadata,
					updated_at = now()
			`, "ra_"+safeIdentifier(manifest.ID+"_"+resource.Key+"_"+action.Key), resourceTypeID, action.Key, titleFromKey(action.Key), firstNonEmpty(action.RiskLevel, "normal"), metadata); err != nil {
				return err
			}
		}
	}
	for _, permission := range manifest.Permissions {
		for _, scope := range permission.Scopes {
			if _, err := s.pool.Exec(ctx, `
				INSERT INTO permissions (id, resource, action, scope)
				VALUES ($1, $2, $3, $4)
				ON CONFLICT (resource, action, scope) DO UPDATE SET
					resource = EXCLUDED.resource,
					action = EXCLUDED.action,
					scope = EXCLUDED.scope
			`, "perm_"+safeIdentifier(manifest.ID+"_"+permission.Resource+"_"+permission.Action+"_"+scope), permission.Resource, permission.Action, scope); err != nil {
				return err
			}
		}
	}
	for _, event := range manifest.AuditEvents {
		if _, err := s.pool.Exec(ctx, `
			INSERT INTO audit_event_types (id, key, plugin_id, display_name, description, risk_level, default_audit, metadata)
			VALUES ($1, $2, $3, $4, '', $5, true, $6::jsonb)
			ON CONFLICT (key) DO UPDATE SET
				plugin_id = EXCLUDED.plugin_id,
				display_name = EXCLUDED.display_name,
				risk_level = EXCLUDED.risk_level,
				default_audit = EXCLUDED.default_audit,
				metadata = EXCLUDED.metadata,
				updated_at = now()
		`, "aet_"+safeIdentifier(manifest.ID+"_"+event.Key), event.Key, pluginID, titleFromKey(event.Key), firstNonEmpty(event.RiskLevel, "normal"), metadata); err != nil {
			return err
		}
	}
	for i, menu := range manifest.AdminMenus {
		if _, err := s.pool.Exec(ctx, `
			INSERT INTO plugin_admin_menus (id, plugin_id, label, path, icon, required_permission, sort_order, metadata)
			VALUES ($1, $2, $3, $4, NULL, NULLIF($5, ''), $6, $7::jsonb)
			ON CONFLICT (id) DO UPDATE SET
				label = EXCLUDED.label,
				path = EXCLUDED.path,
				required_permission = EXCLUDED.required_permission,
				sort_order = EXCLUDED.sort_order,
				metadata = EXCLUDED.metadata,
				updated_at = now()
		`, "pam_"+safeIdentifier(manifest.ID+"_"+menu.Label), pluginID, menu.Label, menu.Path, menu.RequiredPermission, 1000+i, metadata); err != nil {
			return err
		}
	}
	for _, setting := range manifest.Settings {
		scope := firstNonEmpty(setting.Scope, "space")
		if _, err := s.pool.Exec(ctx, `
			INSERT INTO plugin_settings_definitions (id, plugin_id, key, value_type, default_value, description, scope, metadata)
			VALUES ($1, $2, $3, $4, 'null'::jsonb, $5, $6, $7::jsonb)
			ON CONFLICT (plugin_id, key, scope) DO UPDATE SET
				value_type = EXCLUDED.value_type,
				description = EXCLUDED.description,
				metadata = EXCLUDED.metadata,
				updated_at = now()
		`, "psd_"+safeIdentifier(manifest.ID+"_"+setting.Key+"_"+scope), pluginID, setting.Key, firstNonEmpty(setting.ValueType, "string"), setting.Description, scope, metadata); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) handlePlugins(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, r)
		return
	}
	rows, err := queryMaps(r.Context(), s.pool, `
		SELECT p.id, p.key, p.name, p.description, p.version, p.source, p.status,
			(SELECT count(*) FROM resource_types rt WHERE rt.source = 'plugin:' || p.key) AS resources_count,
			(SELECT count(*) FROM permissions perm WHERE perm.resource IN (
				SELECT rt.key FROM resource_types rt WHERE rt.source = 'plugin:' || p.key
			)) AS permissions_count,
			(SELECT count(*) FROM plugin_admin_menus pam WHERE pam.plugin_id = p.id) AS admin_menus_count,
			p.created_at, p.updated_at
		FROM plugins p
		ORDER BY p.name
	`)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list plugins.", err.Error())
		return
	}
	writeList(w, r, http.StatusOK, rows, limitFrom(r, 50))
}

func (s *Server) handlePluginSubroutes(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/plugins/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	pluginKey := parts[0]
	switch {
	case len(parts) == 1:
		s.handleSingleByID(w, r, `SELECT id, key, name, description, version, source, status, manifest, created_at, updated_at FROM plugins WHERE key = $1`, pluginKey, "PLUGIN_NOT_FOUND")
	case len(parts) == 2 && (parts[1] == "enable" || parts[1] == "disable" || parts[1] == "uninstall"):
		s.handlePluginLifecycle(w, r, pluginKey, parts[1])
	case len(parts) == 2 && parts[1] == "settings":
		s.handlePluginSettings(w, r, pluginKey)
	case len(parts) == 2 && parts[1] == "resources":
		s.handleQueryList(w, r, `SELECT id, key, display_name, description, status, source, metadata FROM resource_types WHERE source = 'plugin:' || $1 ORDER BY key`, pluginKey)
	case len(parts) == 2 && parts[1] == "permissions":
		s.handleQueryList(w, r, `
			SELECT p.id, p.resource, p.action, p.scope, p.created_at
			FROM permissions p
			WHERE p.resource IN (SELECT rt.key FROM resource_types rt WHERE rt.source = 'plugin:' || $1)
			ORDER BY p.resource, p.action, p.scope
		`, pluginKey)
	case len(parts) == 2 && parts[1] == "audit-events":
		s.handleQueryList(w, r, `
			SELECT aet.id, aet.key, aet.display_name, aet.description, aet.risk_level, aet.default_audit, aet.metadata
			FROM audit_event_types aet
			JOIN plugins p ON p.id = aet.plugin_id
			WHERE p.key = $1
			ORDER BY aet.key
		`, pluginKey)
	case len(parts) == 2 && parts[1] == "admin-menus":
		s.handleQueryList(w, r, `
			SELECT pam.id, pam.label, pam.path, pam.icon, pam.required_permission, pam.sort_order, pam.metadata
			FROM plugin_admin_menus pam
			JOIN plugins p ON p.id = pam.plugin_id
			WHERE p.key = $1
			ORDER BY pam.sort_order, pam.label
		`, pluginKey)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handlePluginLifecycle(w http.ResponseWriter, r *http.Request, pluginKey, action string) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, r)
		return
	}
	status := map[string]string{
		"enable":    "enabled",
		"disable":   "disabled",
		"uninstall": "uninstalled",
	}[action]
	tag, err := s.pool.Exec(r.Context(), `UPDATE plugins SET status = $2, updated_at = now() WHERE key = $1`, pluginKey, status)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to update plugin status.", err.Error())
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, r, http.StatusNotFound, "PLUGIN_NOT_FOUND", "Plugin was not found.", nil)
		return
	}
	row, err := queryOneMap(r.Context(), s.pool, `SELECT id, key, name, description, version, source, status, manifest, created_at, updated_at FROM plugins WHERE key = $1`, pluginKey)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load plugin.", err.Error())
		return
	}
	writeData(w, r, http.StatusOK, row)
}

type pluginSettingsUpdateRequest struct {
	SpaceID  string         `json:"space_id"`
	Settings map[string]any `json:"settings"`
}

func (s *Server) handlePluginSettings(w http.ResponseWriter, r *http.Request, pluginKey string) {
	switch r.Method {
	case http.MethodGet:
		settings, err := s.loadPluginSettings(r.Context(), pluginKey, r.URL.Query().Get("space_id"))
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, r, http.StatusNotFound, "PLUGIN_NOT_FOUND", "Plugin was not found.", nil)
			return
		}
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load plugin settings.", err.Error())
			return
		}
		writeList(w, r, http.StatusOK, settings, limitFrom(r, 50))
	case http.MethodPatch:
		var req pluginSettingsUpdateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Request body is invalid JSON.", err.Error())
			return
		}
		if req.Settings == nil {
			writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "settings is required.", nil)
			return
		}
		pluginID, err := s.loadPluginID(r.Context(), pluginKey)
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, r, http.StatusNotFound, "PLUGIN_NOT_FOUND", "Plugin was not found.", nil)
			return
		}
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load plugin.", err.Error())
			return
		}
		for key, value := range req.Settings {
			var exists bool
			err := s.pool.QueryRow(r.Context(), `SELECT EXISTS (SELECT 1 FROM plugin_settings_definitions WHERE plugin_id = $1 AND key = $2)`, pluginID, key).Scan(&exists)
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to validate plugin setting.", err.Error())
				return
			}
			if !exists {
				writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Unknown plugin setting.", map[string]string{"key": key})
				return
			}
			valueJSON, err := json.Marshal(value)
			if err != nil {
				writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Setting value is not JSON serializable.", map[string]string{"key": key})
				return
			}
			_, err = s.pool.Exec(r.Context(), `
				INSERT INTO plugin_settings_values (id, plugin_id, space_id, key, value)
				VALUES ($1, $2, $3, $4, $5::jsonb)
				ON CONFLICT (plugin_id, space_id, key) DO UPDATE SET
					value = EXCLUDED.value,
					updated_at = now()
			`, "psv_"+safeIdentifier(pluginID+"_"+req.SpaceID+"_"+key), pluginID, req.SpaceID, key, valueJSON)
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to update plugin setting.", err.Error())
				return
			}
		}
		settings, err := s.loadPluginSettings(r.Context(), pluginKey, req.SpaceID)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load plugin settings.", err.Error())
			return
		}
		writeList(w, r, http.StatusOK, settings, limitFrom(r, 50))
	default:
		writeMethodNotAllowed(w, r)
	}
}

func (s *Server) loadPluginSettings(ctx context.Context, pluginKey, spaceID string) ([]map[string]any, error) {
	if _, err := s.loadPluginID(ctx, pluginKey); err != nil {
		return nil, err
	}
	args := []any{pluginKey}
	join := `psv.plugin_id = p.id AND psv.key = psd.key AND psv.space_id = ''`
	if spaceID != "" {
		args = append(args, spaceID)
		join = `psv.plugin_id = p.id AND psv.key = psd.key AND psv.space_id = $2`
	}
	return queryMaps(ctx, s.pool, `
		SELECT psd.id, psd.key, psd.value_type, psd.default_value, COALESCE(psv.value, psd.default_value) AS value,
			psd.description, psd.scope, psd.metadata, psd.created_at, psd.updated_at
		FROM plugin_settings_definitions psd
		JOIN plugins p ON p.id = psd.plugin_id
		LEFT JOIN plugin_settings_values psv ON `+join+`
		WHERE p.key = $1
		ORDER BY psd.key
	`, args...)
}

func (s *Server) loadPluginID(ctx context.Context, pluginKey string) (string, error) {
	var pluginID string
	err := s.pool.QueryRow(ctx, `SELECT id FROM plugins WHERE key = $1`, pluginKey).Scan(&pluginID)
	return pluginID, err
}

type templateManifest struct {
	ID              string               `json:"id"`
	Name            string               `json:"name"`
	Version         string               `json:"version"`
	RequiresCore    string               `json:"requires_core"`
	RequiredPlugins []string             `json:"required_plugins"`
	Spaces          []templateSpace      `json:"spaces"`
	Groups          []templateGroup      `json:"groups"`
	Roles           []templateRole       `json:"roles"`
	Permissions     []templatePermission `json:"permissions"`
}

type templateSpace struct {
	Key  string `json:"key"`
	Name string `json:"name"`
}

type templateGroup struct {
	Key  string `json:"key"`
	Name string `json:"name"`
}

type templateRole struct {
	Key string `json:"key"`
}

type templatePermission struct {
	Role     string `json:"role"`
	Resource string `json:"resource"`
	Action   string `json:"action"`
	Scope    string `json:"scope"`
}

type templateInstallRequest struct {
	SpaceID                string `json:"space_id"`
	AllowMissingPlugins    bool   `json:"allow_missing_plugins"`
	InstalledByUserID      string `json:"installed_by_user_id"`
	InstalledByMemberID    string `json:"installed_by_member_id"`
	ActorUserID            string `json:"actor_user_id"`
	ActorMemberID          string `json:"actor_member_id"`
	ActorUserMemberID      string `json:"actor_user_member_id"`
	AllowExistingResources bool   `json:"allow_existing_resources"`
}

func (s *Server) handleTemplates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, r)
		return
	}
	writeList(w, r, http.StatusOK, templateCatalog(), limitFrom(r, 50))
}

func (s *Server) handleTemplateSubroutes(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/templates/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	tpl, ok := templateByID(parts[0])
	if !ok {
		writeError(w, r, http.StatusNotFound, "TEMPLATE_NOT_FOUND", "Template was not found.", nil)
		return
	}
	switch {
	case len(parts) == 1:
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, r)
			return
		}
		writeData(w, r, http.StatusOK, tpl)
	case len(parts) == 2 && parts[1] == "preview-install":
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, r)
			return
		}
		if err := s.validateTemplateCoreVersion(tpl); err != nil {
			writeError(w, r, http.StatusBadRequest, "INCOMPATIBLE_TEMPLATE", "Template is not compatible with this Core version.", err.Error())
			return
		}
		missing, err := s.missingTemplatePlugins(r.Context(), tpl)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to validate template plugins.", err.Error())
			return
		}
		writeData(w, r, http.StatusOK, templatePreview(tpl, missing))
	case len(parts) == 2 && parts[1] == "install":
		s.handleTemplateInstall(w, r, tpl)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleTemplateInstall(w http.ResponseWriter, r *http.Request, tpl templateManifest) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, r)
		return
	}
	var req templateInstallRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Request body is invalid JSON.", err.Error())
		return
	}
	if err := s.validateTemplateCoreVersion(tpl); err != nil {
		writeError(w, r, http.StatusBadRequest, "INCOMPATIBLE_TEMPLATE", "Template is not compatible with this Core version.", err.Error())
		return
	}
	missing, err := s.missingTemplatePlugins(r.Context(), tpl)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to validate template plugins.", err.Error())
		return
	}
	if len(missing) > 0 && !req.AllowMissingPlugins {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Template requires plugins that are not enabled.", map[string]any{"missing_plugins": missing})
		return
	}
	applied, err := s.applyTemplateDefaults(r.Context(), tpl, req)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Failed to apply template defaults.", err.Error())
		return
	}
	snapshot, err := json.Marshal(tpl)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to encode template manifest.", err.Error())
		return
	}
	installationID := "ti_" + safeIdentifier(tpl.ID+"_"+strconv.FormatInt(time.Now().UTC().UnixNano(), 10))
	installedByUserID := firstNonEmpty(req.InstalledByUserID, req.ActorUserID)
	installedByMemberID := firstNonEmpty(req.InstalledByMemberID, req.ActorMemberID)
	_, err = s.pool.Exec(r.Context(), `
		INSERT INTO template_installations (
			id, template_id, template_version, space_id, status, manifest_snapshot, installed_by_user_id, installed_by_member_id
		)
		VALUES ($1, $2, $3, NULLIF($4, ''), 'installed', $5::jsonb, NULLIF($6, ''), NULLIF($7, ''))
	`, installationID, tpl.ID, tpl.Version, req.SpaceID, snapshot, installedByUserID, installedByMemberID)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to record template installation.", err.Error())
		return
	}
	if err := s.writeTemplateInstallAudit(r.Context(), tpl, req, installationID, applied, missing); err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to write template install audit log.", err.Error())
		return
	}
	writeData(w, r, http.StatusCreated, map[string]any{
		"installation_id": installationID,
		"status":          "installed",
		"template":        tpl,
		"preview":         templatePreview(tpl, missing),
		"applied":         applied,
	})
}

func (s *Server) validateTemplateCoreVersion(tpl templateManifest) error {
	if !plugins.VersionSatisfies(s.coreVersion, tpl.RequiresCore) {
		return fmt.Errorf("requires_core %q is not satisfied by Core %q", tpl.RequiresCore, s.coreVersion)
	}
	return nil
}

func (s *Server) applyTemplateDefaults(ctx context.Context, tpl templateManifest, req templateInstallRequest) (map[string]any, error) {
	applied := map[string]any{
		"spaces":           []string{},
		"groups":           []string{},
		"roles":            []string{},
		"permissions":      []string{},
		"role_permissions": []string{},
	}
	targetSpaceID := req.SpaceID
	if targetSpaceID == "" && len(tpl.Spaces) > 0 {
		targetSpaceID = "space_" + safeIdentifier(tpl.ID+"_"+tpl.Spaces[0].Key)
	}
	if req.SpaceID != "" {
		var exists bool
		if err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM spaces WHERE id = $1)`, req.SpaceID).Scan(&exists); err != nil {
			return nil, err
		}
		if !exists {
			return nil, fmt.Errorf("space %s was not found", req.SpaceID)
		}
		applied["spaces"] = append(applied["spaces"].([]string), req.SpaceID)
	} else {
		for _, space := range tpl.Spaces {
			spaceID := "space_" + safeIdentifier(tpl.ID+"_"+space.Key)
			if _, err := s.pool.Exec(ctx, `
				INSERT INTO spaces (id, name, status)
				VALUES ($1, $2, 'active')
				ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, status = EXCLUDED.status, updated_at = now()
			`, spaceID, firstNonEmpty(space.Name, titleFromKey(space.Key))); err != nil {
				return nil, err
			}
			applied["spaces"] = append(applied["spaces"].([]string), spaceID)
			if targetSpaceID == "" {
				targetSpaceID = spaceID
			}
		}
	}
	if targetSpaceID == "" {
		return nil, fmt.Errorf("space_id is required for templates that do not create a Space")
	}
	for _, group := range tpl.Groups {
		groupID := "group_" + safeIdentifier(targetSpaceID+"_"+group.Key)
		if _, err := s.pool.Exec(ctx, `
			INSERT INTO groups (id, space_id, parent_group_id, display_name, path, status)
			VALUES ($1, $2, NULL, $3, $4, 'active')
			ON CONFLICT (space_id, path) DO UPDATE SET display_name = EXCLUDED.display_name, status = EXCLUDED.status, updated_at = now()
		`, groupID, targetSpaceID, firstNonEmpty(group.Name, titleFromKey(group.Key)), group.Key); err != nil {
			return nil, err
		}
		applied["groups"] = append(applied["groups"].([]string), groupID)
	}
	roleIDs := map[string]string{}
	for _, role := range tpl.Roles {
		roleID := "role_" + safeIdentifier(targetSpaceID+"_"+role.Key)
		if _, err := s.pool.Exec(ctx, `
			INSERT INTO roles (id, space_id, key)
			VALUES ($1, $2, $3)
			ON CONFLICT (space_id, key) DO UPDATE SET key = EXCLUDED.key, updated_at = now()
		`, roleID, targetSpaceID, role.Key); err != nil {
			return nil, err
		}
		roleIDs[role.Key] = roleID
		applied["roles"] = append(applied["roles"].([]string), roleID)
	}
	for _, permission := range tpl.Permissions {
		roleID := roleIDs[permission.Role]
		if roleID == "" {
			return nil, fmt.Errorf("template permission references unknown role %q", permission.Role)
		}
		permissionID := "perm_" + safeIdentifier(permission.Resource+"_"+permission.Action+"_"+permission.Scope)
		if _, err := s.pool.Exec(ctx, `
			INSERT INTO permissions (id, resource, action, scope)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (resource, action, scope) DO UPDATE SET
				resource = EXCLUDED.resource,
				action = EXCLUDED.action,
				scope = EXCLUDED.scope
		`, permissionID, permission.Resource, permission.Action, permission.Scope); err != nil {
			return nil, err
		}
		rolePermissionID := "rp_" + safeIdentifier(roleID+"_"+permissionID)
		if _, err := s.pool.Exec(ctx, `
			INSERT INTO role_permissions (id, role_id, permission_id)
			VALUES ($1, $2, $3)
			ON CONFLICT (role_id, permission_id) DO UPDATE SET updated_at = now()
		`, rolePermissionID, roleID, permissionID); err != nil {
			return nil, err
		}
		applied["permissions"] = append(applied["permissions"].([]string), permissionID)
		applied["role_permissions"] = append(applied["role_permissions"].([]string), rolePermissionID)
	}
	return applied, nil
}

func (s *Server) writeTemplateInstallAudit(ctx context.Context, tpl templateManifest, req templateInstallRequest, installationID string, applied map[string]any, missing []string) error {
	actorUserID := firstNonEmpty(req.ActorUserID, req.InstalledByUserID)
	actorMemberID := firstNonEmpty(req.ActorMemberID, req.InstalledByMemberID)
	actorUserMemberID := req.ActorUserMemberID
	spaceID := req.SpaceID
	if spaceID == "" {
		spaces, _ := applied["spaces"].([]string)
		if len(spaces) > 0 {
			spaceID = spaces[0]
		}
	}
	if actorUserMemberID == "" && actorUserID != "" && actorMemberID != "" {
		_ = s.pool.QueryRow(ctx, `
			SELECT id
			FROM user_members
			WHERE user_id = $1 AND member_id = $2 AND space_id = $3
				AND status = 'active'
				AND (expires_at IS NULL OR expires_at > now())
			ORDER BY is_primary DESC, created_at DESC
			LIMIT 1
		`, actorUserID, actorMemberID, spaceID).Scan(&actorUserMemberID)
	}
	if actorUserID == "" || actorMemberID == "" || actorUserMemberID == "" || spaceID == "" {
		return fmt.Errorf("actor_user_id, actor_member_id, actor_user_member_id, and space_id are required for template install audit")
	}
	trace := map[string]any{
		"trace_version":   "1.0",
		"decision":        "allow",
		"reason":          "template installed",
		"template":        tpl,
		"applied":         applied,
		"missing_plugins": missing,
		"request": map[string]any{
			"space_id":        req.SpaceID,
			"installation_id": installationID,
		},
	}
	traceJSON, err := json.Marshal(trace)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO audit_logs (
			id, space_id, actor_user_id, actor_member_id, actor_user_member_id,
			action, resource_type, resource_id, decision, trace, request_id
		)
		VALUES ($1, $2, $3, $4, $5, 'template.install', 'template', $6, 'allow', $7::jsonb, $8)
	`, "audit_"+safeIdentifier(installationID), spaceID, actorUserID, actorMemberID, actorUserMemberID, tpl.ID, traceJSON, installationID)
	return err
}

func (s *Server) missingTemplatePlugins(ctx context.Context, tpl templateManifest) ([]string, error) {
	missing := []string{}
	for _, key := range tpl.RequiredPlugins {
		var status string
		err := s.pool.QueryRow(ctx, `SELECT status FROM plugins WHERE key = $1`, key).Scan(&status)
		if errors.Is(err, pgx.ErrNoRows) {
			missing = append(missing, key)
			continue
		}
		if err != nil {
			return nil, err
		}
		if status != "enabled" && status != "installed" {
			missing = append(missing, key)
		}
	}
	return missing, nil
}

func templatePreview(tpl templateManifest, missingPlugins []string) map[string]any {
	return map[string]any{
		"template_id":     tpl.ID,
		"missing_plugins": missingPlugins,
		"changes": map[string]any{
			"spaces":      tpl.Spaces,
			"groups":      tpl.Groups,
			"roles":       tpl.Roles,
			"permissions": tpl.Permissions,
		},
	}
}

func templateCatalog() []templateManifest {
	return []templateManifest{
		{
			ID:           "blank",
			Name:         "Blank",
			Version:      "1.0.0",
			RequiresCore: ">=1.0.0 <2.0.0",
		},
		{
			ID:              "internal-admin",
			Name:            "Internal Admin",
			Version:         "1.0.0",
			RequiresCore:    ">=1.0.0 <2.0.0",
			RequiredPlugins: []string{"plystra.api_keys", "plystra.webhooks"},
			Spaces:          []templateSpace{{Key: "default", Name: "Default Workspace"}},
			Groups: []templateGroup{
				{Key: "operations", Name: "Operations"},
				{Key: "finance", Name: "Finance"},
			},
			Roles: []templateRole{{Key: "space_owner"}, {Key: "auditor"}, {Key: "operator"}},
			Permissions: []templatePermission{
				{Role: "space_owner", Resource: "api_key", Action: "read", Scope: "space"},
				{Role: "space_owner", Resource: "webhook_endpoint", Action: "read", Scope: "space"},
			},
		},
		{
			ID:              "community-lite",
			Name:            "Community Lite",
			Version:         "1.0.0",
			RequiresCore:    ">=1.0.0 <2.0.0",
			RequiredPlugins: []string{"plystra.moderation"},
			Spaces:          []templateSpace{{Key: "community", Name: "Community"}},
			Groups: []templateGroup{
				{Key: "general", Name: "General"},
				{Key: "moderation", Name: "Moderation"},
			},
			Roles: []templateRole{{Key: "moderator"}, {Key: "member"}},
			Permissions: []templatePermission{
				{Role: "moderator", Resource: "report", Action: "resolve", Scope: "group_tree"},
			},
		},
	}
}

func templateByID(id string) (templateManifest, bool) {
	for _, tpl := range templateCatalog() {
		if tpl.ID == id {
			return tpl, true
		}
	}
	return templateManifest{}, false
}

func (s *Server) handleQueryList(w http.ResponseWriter, r *http.Request, sql string, args ...any) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, r)
		return
	}
	rows, err := queryMaps(r.Context(), s.pool, sql, args...)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Query failed.", err.Error())
		return
	}
	writeList(w, r, http.StatusOK, rows, limitFrom(r, 50))
}

func (s *Server) handleSingleByID(w http.ResponseWriter, r *http.Request, sql, id, notFoundCode string, extraArgs ...any) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, r)
		return
	}
	args := append([]any{id}, extraArgs...)
	row, err := queryOneMap(r.Context(), s.pool, sql, args...)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, r, http.StatusNotFound, notFoundCode, "Resource was not found.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Query failed.", err.Error())
		return
	}
	writeData(w, r, http.StatusOK, row)
}

type contextKey string

const requestIDKey contextKey = "request_id"

func requestMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		origin := allowedCORSOrigin(r)
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
		}
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Request-ID, X-Plystra-Admin-Token, X-Plystra-Metrics-Token")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
		requestID := r.Header.Get(requestIDHeader())
		if requestID == "" {
			requestID = newRequestID()
		}
		w.Header().Set(requestIDHeader(), requestID)
		ctxReq := r.WithContext(context.WithValue(r.Context(), requestIDKey, requestID))
		defer func() {
			if recovered := recover(); recovered != nil {
				if !recorder.wrote {
					writeError(recorder, ctxReq, http.StatusInternalServerError, "INTERNAL_ERROR", "Request handling failed.", safePanicDetails(recovered))
				}
				logHTTPRequest(ctxReq, recorder.Header(), recorder.status, recorder.bytes, time.Since(start), "INTERNAL_ERROR")
				return
			}
			logHTTPRequest(ctxReq, recorder.Header(), recorder.status, recorder.bytes, time.Since(start), w.Header().Get("X-Plystra-Error-Code"))
		}()
		if r.Method == http.MethodOptions {
			recorder.WriteHeader(http.StatusNoContent)
			return
		}
		if !publicRoute(ctxReq) {
			token := adminToken()
			if token == "" {
				writeError(recorder, ctxReq, http.StatusServiceUnavailable, "ADMIN_TOKEN_NOT_CONFIGURED", "Admin token is not configured.", nil)
				return
			}
			if !adminAuthorized(ctxReq) {
				writeError(recorder, ctxReq, http.StatusUnauthorized, "ADMIN_TOKEN_REQUIRED", "A valid admin token is required.", nil)
				return
			}
		}
		next.ServeHTTP(recorder, ctxReq)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
	wrote  bool
}

func (r *statusRecorder) WriteHeader(status int) {
	if r.wrote {
		return
	}
	r.status = status
	r.wrote = true
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Write(data []byte) (int, error) {
	if !r.wrote {
		r.WriteHeader(r.status)
	}
	n, err := r.ResponseWriter.Write(data)
	r.bytes += n
	return n, err
}

func requestIDHeader() string {
	if value := os.Getenv("REQUEST_ID_HEADER"); value != "" {
		return value
	}
	return "X-Request-ID"
}

func allowedCORSOrigin(r *http.Request) string {
	configured := os.Getenv("CORS_ALLOWED_ORIGINS")
	if configured == "" {
		return "*"
	}
	origin := r.Header.Get("Origin")
	for _, allowed := range strings.Split(configured, ",") {
		allowed = strings.TrimSpace(allowed)
		if allowed == "*" {
			return "*"
		}
		if origin != "" && allowed == origin {
			return origin
		}
	}
	return ""
}

func publicRoute(r *http.Request) bool {
	if r.Method == http.MethodOptions {
		return true
	}
	path := r.URL.Path
	if r.Method == http.MethodGet {
		switch path {
		case "/api/v1/health", "/api/v1/ready", "/api/v1/version",
			"/api/v1/system/health", "/api/v1/system/ready", "/api/v1/system/version",
			"/system/health", "/system/ready", "/system/version",
			"/metrics":
			return true
		}
	}
	if r.Method == http.MethodPost {
		switch path {
		case "/api/v1/auth/login", "/api/v1/auth/refresh", "/api/v1/auth/logout":
			return true
		case "/api/v1/actor/switch-member":
			return true
		}
	}
	return r.Method == http.MethodGet && path == "/api/v1/actor/context"
}

func adminAuthorized(r *http.Request) bool {
	configured := adminToken()
	if configured == "" {
		return false
	}
	for _, provided := range []string{
		strings.TrimSpace(r.Header.Get("X-Plystra-Admin-Token")),
		strings.TrimSpace(r.Header.Get("X-Admin-Token")),
		bearerToken(r),
	} {
		if constantTimeStringEqual(provided, configured) {
			return true
		}
	}
	return false
}

func metricsAuthorized(r *http.Request) bool {
	configured := firstEnv("METRICS_TOKEN", "PLYSTRA_METRICS_TOKEN")
	if configured != "" {
		for _, provided := range []string{
			strings.TrimSpace(r.Header.Get("X-Plystra-Metrics-Token")),
			strings.TrimSpace(r.Header.Get("X-Metrics-Token")),
			bearerToken(r),
		} {
			if constantTimeStringEqual(provided, configured) {
				return true
			}
		}
		return false
	}
	return adminAuthorized(r)
}

func adminToken() string {
	return strings.TrimSpace(firstEnv("PLYSTRA_ADMIN_TOKEN", "ADMIN_TOKEN"))
}

func constantTimeStringEqual(left, right string) bool {
	if left == "" || right == "" || len(left) != len(right) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func featureEnabled(key string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "on", "enabled":
		return true
	default:
		return false
	}
}

func logHTTPRequest(r *http.Request, headers http.Header, status, bytes int, latency time.Duration, errorCode string) {
	remoteIP := remoteIPFrom(r)
	if strings.EqualFold(os.Getenv("LOG_FORMAT"), "text") {
		fmt.Fprintf(os.Stdout, "timestamp=%s level=info request_id=%s method=%s path=%s status=%d latency_ms=%d remote_ip=%s user_agent=%q error_code=%s\n",
			time.Now().UTC().Format(time.RFC3339), requestIDFrom(r), r.Method, r.URL.Path, status, latency.Milliseconds(), remoteIP, r.UserAgent(), errorCode)
		return
	}
	entry := map[string]any{
		"timestamp":   time.Now().UTC().Format(time.RFC3339Nano),
		"level":       "info",
		"request_id":  requestIDFrom(r),
		"method":      r.Method,
		"path":        r.URL.Path,
		"status":      status,
		"status_code": status,
		"latency_ms":  latency.Milliseconds(),
		"remote_ip":   remoteIP,
		"user_agent":  r.UserAgent(),
		"bytes":       bytes,
	}
	if errorCode != "" {
		entry["error_code"] = errorCode
	}
	if traceID := headers.Get("X-Plystra-Trace-ID"); traceID != "" {
		entry["trace_id"] = traceID
	}
	if auditLogID := headers.Get("X-Plystra-Audit-Log-ID"); auditLogID != "" {
		entry["audit_log_id"] = auditLogID
	}
	_ = json.NewEncoder(os.Stdout).Encode(entry)
}

func remoteIPFrom(r *http.Request) string {
	if configured := os.Getenv("TRUSTED_PROXIES"); strings.TrimSpace(configured) != "" {
		if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); forwarded != "" {
			parts := strings.Split(forwarded, ",")
			if len(parts) > 0 {
				return strings.TrimSpace(parts[0])
			}
		}
		if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" {
			return realIP
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func safePanicDetails(recovered any) any {
	if strings.EqualFold(firstEnv("SERVER_MODE", "PLYSTRA_ENV"), "production") {
		return nil
	}
	return fmt.Sprint(recovered)
}

func firstEnv(keys ...string) string {
	for _, key := range keys {
		if value := os.Getenv(key); value != "" {
			return value
		}
	}
	return ""
}

func requestIDFrom(r *http.Request) string {
	if value, ok := r.Context().Value(requestIDKey).(string); ok {
		return value
	}
	return newRequestID()
}

func writeData(w http.ResponseWriter, r *http.Request, status int, data any) {
	requestID := requestIDFrom(r)
	writeJSON(w, status, map[string]any{
		"data":       data,
		"request_id": requestID,
		"meta":       map[string]any{"request_id": requestID},
	})
}

func writeList(w http.ResponseWriter, r *http.Request, status int, data any, limit int) {
	requestID := requestIDFrom(r)
	writeJSON(w, status, map[string]any{
		"data": data,
		"pagination": map[string]any{
			"limit":    limit,
			"cursor":   nil,
			"has_more": false,
		},
		"request_id": requestID,
		"meta":       map[string]any{"request_id": requestID},
	})
}

func writeError(w http.ResponseWriter, r *http.Request, status int, code, message string, details any) {
	requestID := requestIDFrom(r)
	w.Header().Set("X-Plystra-Error-Code", code)
	errPayload := map[string]any{
		"code":       code,
		"message":    message,
		"details":    details,
		"request_id": requestID,
	}
	if decision, ok := authzDecisionFromDetails(details); ok {
		if decision.DenyCode != nil {
			errPayload["deny_code"] = string(*decision.DenyCode)
		}
		if decision.TraceID != "" {
			errPayload["trace_id"] = decision.TraceID
		}
		if decision.Audit.ID != "" {
			errPayload["audit_log_id"] = decision.Audit.ID
		}
		w.Header().Set("X-Plystra-Trace-ID", decision.TraceID)
		if decision.Audit.ID != "" {
			w.Header().Set("X-Plystra-Audit-Log-ID", decision.Audit.ID)
		}
	}
	writeJSON(w, status, map[string]any{
		"error":      errPayload,
		"request_id": requestID,
		"meta":       map[string]any{"request_id": requestID},
	})
}

func authzDecisionFromDetails(details any) (*authz.Decision, bool) {
	switch typed := details.(type) {
	case *authz.Decision:
		if typed == nil {
			return nil, false
		}
		return typed, true
	case authz.Decision:
		return &typed, true
	default:
		return nil, false
	}
}

func writeMethodNotAllowed(w http.ResponseWriter, r *http.Request) {
	writeError(w, r, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "HTTP method is not allowed for this endpoint.", nil)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func queryOneMap(ctx context.Context, pool *pgxpool.Pool, sql string, args ...any) (map[string]any, error) {
	rows, err := queryMaps(ctx, pool, sql, args...)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, pgx.ErrNoRows
	}
	return rows[0], nil
}

func queryMaps(ctx context.Context, pool *pgxpool.Pool, sql string, args ...any) ([]map[string]any, error) {
	rows, err := pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	fields := rows.FieldDescriptions()
	var out []map[string]any
	for rows.Next() {
		values, err := rows.Values()
		if err != nil {
			return nil, err
		}
		row := map[string]any{}
		for i, field := range fields {
			row[string(field.Name)] = normalizeValue(values[i])
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func normalizeValue(value any) any {
	switch typed := value.(type) {
	case []byte:
		var decoded any
		if json.Unmarshal(typed, &decoded) == nil {
			return decoded
		}
		return string(typed)
	case time.Time:
		return typed.UTC().Format(time.RFC3339)
	default:
		return value
	}
}

func limitFrom(r *http.Request, fallback int) int {
	if raw := r.URL.Query().Get("limit"); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err == nil && limit > 0 && limit <= 200 {
			return limit
		}
	}
	return fallback
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func derefString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func nullStringValue(value sql.NullString) string {
	if !value.Valid {
		return ""
	}
	return value.String
}

func nonNilMap(value map[string]any) map[string]any {
	if value == nil {
		return map[string]any{}
	}
	return value
}

func decodeJSON(w http.ResponseWriter, r *http.Request, out any) bool {
	if err := json.NewDecoder(r.Body).Decode(out); err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Request body is invalid JSON.", err.Error())
		return false
	}
	return true
}

func (s *Server) updateStatus(ctx context.Context, table, id, status string) (map[string]any, error) {
	if !allowedStatusTable(table) {
		return nil, fmt.Errorf("unsupported status table %s", table)
	}
	rows, err := queryMaps(ctx, s.pool, fmt.Sprintf(`
		UPDATE %s
		SET status = $2, updated_at = now()
		WHERE id = $1 AND deleted_at IS NULL
		RETURNING *
	`, table), id, status)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, pgx.ErrNoRows
	}
	return rows[0], nil
}

func (s *Server) updateScopedStatus(ctx context.Context, table, id, spaceID, status string) (map[string]any, error) {
	if !allowedStatusTable(table) {
		return nil, fmt.Errorf("unsupported status table %s", table)
	}
	rows, err := queryMaps(ctx, s.pool, fmt.Sprintf(`
		UPDATE %s
		SET status = $3, updated_at = now()
		WHERE id = $1 AND space_id = $2 AND deleted_at IS NULL
		RETURNING *
	`, table), id, spaceID, status)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, pgx.ErrNoRows
	}
	return rows[0], nil
}

func allowedStatusTable(table string) bool {
	switch table {
	case "users", "spaces", "groups", "members", "user_members", "roles", "permissions", "member_roles", "resources":
		return true
	default:
		return false
	}
}

func (s *Server) recordMutationAudit(ctx context.Context, r *http.Request, actor authz.ActorContext, spaceID, action, resourceType, resourceID string, details any) {
	if spaceID == "" {
		return
	}
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
	traceJSON, err := json.Marshal(trace)
	if err != nil {
		return
	}
	_, _ = s.pool.Exec(ctx, `
		INSERT INTO audit_logs (id, space_id, actor_user_id, actor_member_id, actor_user_member_id,
			action, resource_type, resource_id, decision, deny_code, trace, request_id, ip_address, user_agent)
		VALUES ($1, $2, NULLIF($3, ''), NULLIF($4, ''), NULLIF($5, ''),
			$6, $7, $8, 'allow', NULL, $9::jsonb, $10, NULLIF($11, ''), NULLIF($12, ''))
	`, newEntityID("audit"), spaceID, actor.UserID, actor.MemberID, actor.UserMemberID,
		action, resourceType, resourceID, traceJSON, requestIDFrom(r), remoteIPFrom(r), r.UserAgent())
}

func stringFromMap(values map[string]any, key string) string {
	value, ok := values[key]
	if !ok || value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	default:
		return fmt.Sprint(typed)
	}
}

func mapFromAny(value any) map[string]any {
	if value == nil {
		return map[string]any{}
	}
	if typed, ok := value.(map[string]any); ok {
		return typed
	}
	return map[string]any{}
}

func nullableFromRequest(value *string, current string) string {
	if value == nil {
		return current
	}
	return *value
}

func intValue(value *int, fallback int) int {
	if value == nil {
		return fallback
	}
	return *value
}

func intFromMap(values map[string]any, key string, fallback int) int {
	value, ok := values[key]
	if !ok || value == nil {
		return fallback
	}
	switch typed := value.(type) {
	case int:
		return typed
	case int32:
		return int(typed)
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	default:
		parsed, err := strconv.Atoi(fmt.Sprint(typed))
		if err != nil {
			return fallback
		}
		return parsed
	}
}

func boolValue(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}
	return *value
}

func boolFromMap(values map[string]any, key string, fallback bool) bool {
	value, ok := values[key]
	if !ok || value == nil {
		return fallback
	}
	if typed, ok := value.(bool); ok {
		return typed
	}
	parsed, err := strconv.ParseBool(fmt.Sprint(value))
	if err != nil {
		return fallback
	}
	return parsed
}

func pathDepth(path string) int {
	path = strings.Trim(path, ".")
	if path == "" {
		return 0
	}
	return strings.Count(path, ".")
}

func lastPathSegment(path string) string {
	path = strings.Trim(path, ".")
	if path == "" {
		return ""
	}
	parts := strings.Split(path, ".")
	return parts[len(parts)-1]
}

func newEntityID(prefix string) string {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return safeIdentifier(prefix) + "_" + strconv.FormatInt(time.Now().UTC().UnixNano(), 10)
	}
	return safeIdentifier(prefix) + "_" + hex.EncodeToString(buf[:])
}

func safeIdentifier(value string) string {
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + ('a' - 'A'))
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return strings.Trim(b.String(), "_")
}

func titleFromKey(value string) string {
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == '_' || r == '.' || r == '-'
	})
	for i, part := range parts {
		if part == "" {
			continue
		}
		parts[i] = strings.ToUpper(part[:1]) + part[1:]
	}
	return strings.Join(parts, " ")
}

func newRequestID() string {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return fmt.Sprintf("req_%d", time.Now().UTC().UnixNano())
	}
	return "req_" + hex.EncodeToString(buf[:])
}
