package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
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

	entsql "entgo.io/ent/dialect/sql"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	coreent "github.com/plystra/plystra/ent"
	entauditeventtype "github.com/plystra/plystra/ent/auditeventtype"
	"github.com/plystra/plystra/ent/auditlog"
	entgroup "github.com/plystra/plystra/ent/group"
	entmember "github.com/plystra/plystra/ent/member"
	entmemberrole "github.com/plystra/plystra/ent/memberrole"
	entpermission "github.com/plystra/plystra/ent/permission"
	entplugin "github.com/plystra/plystra/ent/plugin"
	entpluginadminmenu "github.com/plystra/plystra/ent/pluginadminmenu"
	entpluginsettingsdefinition "github.com/plystra/plystra/ent/pluginsettingsdefinition"
	entpluginsettingsvalue "github.com/plystra/plystra/ent/pluginsettingsvalue"
	entresource "github.com/plystra/plystra/ent/resource"
	entresourceaction "github.com/plystra/plystra/ent/resourceaction"
	entresourcemapping "github.com/plystra/plystra/ent/resourcemapping"
	entresourcetype "github.com/plystra/plystra/ent/resourcetype"
	entrole "github.com/plystra/plystra/ent/role"
	entrolepermission "github.com/plystra/plystra/ent/rolepermission"
	entspace "github.com/plystra/plystra/ent/space"
	entuser "github.com/plystra/plystra/ent/user"
	entusermember "github.com/plystra/plystra/ent/usermember"
	"github.com/plystra/plystra/internal/authz"
	"github.com/plystra/plystra/internal/plugins"
)

type Server struct {
	pool        *pgxpool.Pool
	ent         *coreent.Client
	authzStore  authz.Store
	coreVersion string
}

type entClientProvider interface {
	Client() *coreent.Client
}

func NewServer(pool *pgxpool.Pool, authzStore authz.Store, coreVersion string) *Server {
	var entClient *coreent.Client
	if provider, ok := authzStore.(entClientProvider); ok {
		entClient = provider.Client()
	}
	return &Server{
		pool:        pool,
		ent:         entClient,
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
	var auditLogs int
	var authzDenies int
	if s.ent == nil {
		writeError(w, r, http.StatusServiceUnavailable, "NOT_READY", "Ent client is not configured.", nil)
		return
	}
	var err error
	auditLogs, err = s.ent.AuditLog.Query().Count(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to read audit metrics.", err.Error())
		return
	}
	authzDenies, err = s.ent.AuditLog.Query().Where(auditlog.Decision("deny")).Count(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to read audit metrics.", err.Error())
		return
	}
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
	// schema_migrations is migration metadata, not a Core business entity.
	// Keep this tiny control-plane read outside Ent so readiness can validate migrations.
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
	// See latestSchemaVersion: schema_migrations intentionally remains migration metadata.
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
	if s.ent == nil {
		writeError(w, r, http.StatusServiceUnavailable, "NOT_READY", "Ent client is not configured.", nil)
		return
	}
	counts := map[string]int{}
	var err error
	if counts["spaces"], err = s.ent.Space.Query().Count(ctx); err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load overview counts.", err.Error())
		return
	}
	if counts["users"], err = s.ent.User.Query().Count(ctx); err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load overview counts.", err.Error())
		return
	}
	if counts["members"], err = s.ent.Member.Query().Count(ctx); err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load overview counts.", err.Error())
		return
	}
	if counts["user_member_bindings"], err = s.ent.UserMember.Query().Count(ctx); err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load overview counts.", err.Error())
		return
	}
	if counts["groups"], err = s.ent.Group.Query().Count(ctx); err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load overview counts.", err.Error())
		return
	}
	if counts["roles"], err = s.ent.Role.Query().Count(ctx); err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load overview counts.", err.Error())
		return
	}
	if counts["permissions"], err = s.ent.Permission.Query().Count(ctx); err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load overview counts.", err.Error())
		return
	}
	if counts["resource_types"], err = s.ent.ResourceType.Query().Count(ctx); err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load overview counts.", err.Error())
		return
	}
	if counts["resources"], err = s.ent.Resource.Query().Count(ctx); err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load overview counts.", err.Error())
		return
	}
	if counts["audit_logs"], err = s.ent.AuditLog.Query().Count(ctx); err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load overview counts.", err.Error())
		return
	}

	logs, err := s.ent.AuditLog.Query().Order(auditlog.ByCreatedAt(entsql.OrderDesc())).Limit(10).All(ctx)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load recent audit logs.", err.Error())
		return
	}
	recent := make([]map[string]any, 0, len(logs))
	for _, log := range logs {
		recent = append(recent, map[string]any{
			"id":              log.ID,
			"created_at":      formatTime(log.CreatedAt),
			"decision":        log.Decision,
			"deny_code":       derefString(log.DenyCode),
			"actor_user_id":   derefString(log.ActorUserID),
			"actor_member_id": derefString(log.ActorMemberID),
			"resource_type":   log.ResourceType,
			"resource_id":     log.ResourceID,
			"action":          log.Action,
		})
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
	if s.ent == nil {
		writeError(w, r, http.StatusServiceUnavailable, "NOT_READY", "Ent client is not configured.", nil)
		return
	}
	limit := limitFrom(r, 50)
	q := s.ent.AuditLog.Query()
	for _, filter := range []string{"space_id", "actor_user_id", "actor_member_id", "actor_user_member_id", "resource_type", "resource_id", "decision", "deny_code", "request_id"} {
		if value := r.URL.Query().Get(filter); value != "" {
			switch filter {
			case "space_id":
				q = q.Where(auditlog.SpaceID(value))
			case "actor_user_id":
				q = q.Where(auditlog.ActorUserID(value))
			case "actor_member_id":
				q = q.Where(auditlog.ActorMemberID(value))
			case "actor_user_member_id":
				q = q.Where(auditlog.ActorUserMemberID(value))
			case "resource_type":
				q = q.Where(auditlog.ResourceType(value))
			case "resource_id":
				q = q.Where(auditlog.ResourceID(value))
			case "decision":
				q = q.Where(auditlog.Decision(value))
			case "deny_code":
				q = q.Where(auditlog.DenyCode(value))
			case "request_id":
				q = q.Where(auditlog.RequestID(value))
			}
		}
	}
	if from := r.URL.Query().Get("created_at_from"); from != "" {
		parsed, err := time.Parse(time.RFC3339, from)
		if err != nil {
			writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "created_at_from must be RFC3339.", err.Error())
			return
		}
		q = q.Where(auditlog.CreatedAtGTE(parsed))
	}
	if to := r.URL.Query().Get("created_at_to"); to != "" {
		parsed, err := time.Parse(time.RFC3339, to)
		if err != nil {
			writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "created_at_to must be RFC3339.", err.Error())
			return
		}
		q = q.Where(auditlog.CreatedAtLTE(parsed))
	}
	logs, err := q.Order(auditlog.ByCreatedAt(entsql.OrderDesc())).Limit(limit).All(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list audit logs.", err.Error())
		return
	}
	rows := make([]map[string]any, 0, len(logs))
	for _, log := range logs {
		rows = append(rows, auditLogListItem(log))
	}
	writeList(w, r, http.StatusOK, rows, limit)
}

func (s *Server) handleAuditLogDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, r)
		return
	}
	if s.ent == nil {
		writeError(w, r, http.StatusServiceUnavailable, "NOT_READY", "Ent client is not configured.", nil)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/audit/logs/")
	if id == r.URL.Path {
		id = strings.TrimPrefix(r.URL.Path, "/api/v1/audit-logs/")
	}
	log, err := s.ent.AuditLog.Query().Where(auditlog.ID(id)).Only(r.Context())
	if coreent.IsNotFound(err) {
		writeError(w, r, http.StatusNotFound, "AUDIT_LOG_NOT_FOUND", "Resource was not found.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load audit log.", err.Error())
		return
	}
	writeData(w, r, http.StatusOK, auditLogDetail(log))
}

func auditLogListItem(log *coreent.AuditLog) map[string]any {
	return map[string]any{
		"id":                   log.ID,
		"space_id":             log.SpaceID,
		"actor_user_id":        derefString(log.ActorUserID),
		"actor_member_id":      derefString(log.ActorMemberID),
		"actor_user_member_id": derefString(log.ActorUserMemberID),
		"action":               log.Action,
		"resource_type":        log.ResourceType,
		"resource_id":          log.ResourceID,
		"decision":             log.Decision,
		"deny_code":            derefString(log.DenyCode),
		"request_id":           derefString(log.RequestID),
		"ip_address":           derefString(log.IPAddress),
		"user_agent":           derefString(log.UserAgent),
		"created_at":           log.CreatedAt.UTC().Format(time.RFC3339),
	}
}

func auditLogDetail(log *coreent.AuditLog) map[string]any {
	row := auditLogListItem(log)
	row["trace"] = nonNilMap(log.Trace)
	return row
}

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
		client, ok := s.requireEnt(w, r)
		if !ok {
			return
		}
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
		status := firstNonEmpty(derefString(req.Status), "active")
		_, err := client.User.Create().
			SetID(req.ID).
			SetEmail(req.Email).
			SetNillableUsername(optionalString(derefString(req.Username))).
			SetNillablePhone(optionalString(derefString(req.Phone))).
			SetNillablePasswordHash(optionalString(derefString(req.PasswordHash))).
			SetStatus(status).
			SetMetadata(nonNilMap(req.Metadata)).
			Save(r.Context())
		if err != nil {
			writeError(w, r, http.StatusConflict, "USER_CREATE_FAILED", "Failed to create User.", err.Error())
			return
		}
		row, err := s.loadUser(r.Context(), req.ID)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load created User.", err.Error())
			return
		}
		response := userResponse(row)
		s.recordMutationAudit(r.Context(), r, req.Actor, req.AuditSpaceID, "user.created", "user", req.ID, response)
		writeData(w, r, http.StatusCreated, response)
	case http.MethodGet:
		limit := limitFrom(r, 50)
		client, ok := s.requireEnt(w, r)
		if !ok {
			return
		}
		users, err := client.User.Query().
			Where(entuser.DeletedAtIsNil()).
			Order(entuser.ByEmail()).
			Limit(limit).
			All(r.Context())
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list Users.", err.Error())
			return
		}
		rows := make([]map[string]any, 0, len(users))
		for _, user := range users {
			rows = append(rows, userResponse(userMap(user)))
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
			writeData(w, r, http.StatusOK, userResponse(row))
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
			username := nullableFromRequest(req.Username, stringFromMap(current, "username"))
			phone := nullableFromRequest(req.Phone, stringFromMap(current, "phone"))
			passwordHash := nullableFromRequest(req.PasswordHash, stringFromMap(current, "password_hash"))
			client, ok := s.requireEnt(w, r)
			if !ok {
				return
			}
			update := client.User.UpdateOneID(userID).
				SetEmail(email).
				SetStatus(status).
				SetMetadata(nonNilMap(metadata))
			if username == "" {
				update.ClearUsername()
			} else {
				update.SetUsername(username)
			}
			if phone == "" {
				update.ClearPhone()
			} else {
				update.SetPhone(phone)
			}
			if passwordHash == "" {
				update.ClearPasswordHash()
			} else {
				update.SetPasswordHash(passwordHash)
			}
			err = update.Exec(r.Context())
			if err != nil {
				writeError(w, r, http.StatusConflict, "USER_UPDATE_FAILED", "Failed to update User.", err.Error())
				return
			}
			row, err := s.loadUser(r.Context(), userID)
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load updated User.", err.Error())
				return
			}
			response := userResponse(row)
			s.recordMutationAudit(r.Context(), r, req.Actor, req.AuditSpaceID, "user.updated", "user", userID, response)
			writeData(w, r, http.StatusOK, response)
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
		response := userResponse(row)
		s.recordMutationAudit(r.Context(), r, req.Actor, req.AuditSpaceID, action, "user", userID, response)
		writeData(w, r, http.StatusOK, response)
		return
	}
	http.NotFound(w, r)
}

func (s *Server) loadUser(ctx context.Context, id string) (map[string]any, error) {
	if s.ent == nil {
		return nil, errors.New("ent client is not configured")
	}
	row, err := s.ent.User.Query().Where(entuser.ID(id), entuser.DeletedAtIsNil()).Only(ctx)
	if coreent.IsNotFound(err) {
		return nil, pgx.ErrNoRows
	}
	if err != nil {
		return nil, err
	}
	return userMap(row), nil
}

func userResponse(row map[string]any) map[string]any {
	if row == nil {
		return nil
	}
	response := make(map[string]any, len(row))
	for key, value := range row {
		if key == "password_hash" {
			continue
		}
		response[key] = value
	}
	return response
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
			client, ok := s.requireEnt(w, r)
			if !ok {
				return
			}
			_, err := client.Member.Create().
				SetID(req.ID).
				SetSpaceID(spaceID).
				SetDisplayName(req.DisplayName).
				SetMemberType(firstNonEmpty(derefString(req.MemberType), "human")).
				SetStatus(firstNonEmpty(derefString(req.Status), "active")).
				SetMetadata(nonNilMap(req.Metadata)).
				Save(r.Context())
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
			client, ok := s.requireEnt(w, r)
			if !ok {
				return
			}
			members, err := client.Member.Query().
				Where(entmember.SpaceID(spaceID), entmember.DeletedAtIsNil()).
				Order(entmember.ByDisplayName()).
				Limit(limit).
				All(r.Context())
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list Members.", err.Error())
				return
			}
			rows := make([]map[string]any, 0, len(members))
			for _, member := range members {
				rows = append(rows, memberMap(member))
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
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	err = client.Member.UpdateOneID(memberID).
		SetDisplayName(firstNonEmpty(req.DisplayName, stringFromMap(current, "display_name"))).
		SetMemberType(firstNonEmpty(derefString(req.MemberType), stringFromMap(current, "member_type"), "human")).
		SetStatus(firstNonEmpty(derefString(req.Status), stringFromMap(current, "status"), "active")).
		SetMetadata(nonNilMap(metadata)).
		Exec(r.Context())
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
	if s.ent == nil {
		return nil, errors.New("ent client is not configured")
	}
	row, err := s.ent.Member.Query().Where(entmember.ID(memberID), entmember.SpaceID(spaceID), entmember.DeletedAtIsNil()).Only(ctx)
	if coreent.IsNotFound(err) {
		return nil, pgx.ErrNoRows
	}
	if err != nil {
		return nil, err
	}
	return memberMap(row), nil
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
			linkedAt := req.LinkedAt
			if linkedAt == nil {
				now := time.Now().UTC()
				linkedAt = &now
			}
			client, ok := s.requireEnt(w, r)
			if !ok {
				return
			}
			_, err := client.UserMember.Create().
				SetID(req.ID).
				SetUserID(req.UserID).
				SetMemberID(req.MemberID).
				SetSpaceID(spaceID).
				SetRelationType(req.RelationType).
				SetStatus(firstNonEmpty(derefString(req.Status), "active")).
				SetIsPrimary(boolValue(req.IsPrimary, false)).
				SetNillableExpiresAt(req.ExpiresAt).
				SetNillableLinkedByMemberID(optionalString(derefString(req.LinkedByMemberID))).
				SetNillableLinkedAt(linkedAt).
				SetMetadata(nonNilMap(req.Metadata)).
				Save(r.Context())
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
			client, ok := s.requireEnt(w, r)
			if !ok {
				return
			}
			userMembers, err := client.UserMember.Query().
				Where(entusermember.SpaceID(spaceID), entusermember.DeletedAtIsNil()).
				Limit(limit).
				All(r.Context())
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list UserMembers.", err.Error())
				return
			}
			rows := make([]map[string]any, 0, len(userMembers))
			for _, userMember := range userMembers {
				row, err := s.userMemberMapWithRefs(r.Context(), userMember)
				if err != nil {
					writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list UserMembers.", err.Error())
					return
				}
				rows = append(rows, row)
			}
			sort.SliceStable(rows, func(i, j int) bool {
				leftEmail, _ := rows[i]["email"].(string)
				rightEmail, _ := rows[j]["email"].(string)
				if leftEmail != rightEmail {
					return leftEmail < rightEmail
				}
				leftMember, _ := rows[i]["member_display_name"].(string)
				rightMember, _ := rows[j]["member_display_name"].(string)
				return leftMember < rightMember
			})
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
		client, ok := s.requireEnt(w, r)
		if !ok {
			return
		}
		update := client.UserMember.UpdateOneID(userMemberID).
			SetStatus("revoked").
			SetRevokedAt(time.Now().UTC())
		if reason := derefString(req.RevokedReason); reason != "" {
			update.SetRevokedReason(reason)
		} else {
			update.ClearRevokedReason()
		}
		err := update.Exec(r.Context())
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
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	update := client.UserMember.UpdateOneID(userMemberID).
		SetUserID(userID).
		SetMemberID(memberID).
		SetRelationType(firstNonEmpty(req.RelationType, stringFromMap(current, "relation_type"))).
		SetStatus(firstNonEmpty(derefString(req.Status), stringFromMap(current, "status"), "active")).
		SetIsPrimary(boolValue(req.IsPrimary, boolFromMap(current, "is_primary", false))).
		SetMetadata(nonNilMap(metadata))
	if req.ExpiresAt != nil {
		update.SetExpiresAt(*req.ExpiresAt)
	}
	if linkedBy == "" {
		update.ClearLinkedByMemberID()
	} else {
		update.SetLinkedByMemberID(linkedBy)
	}
	if req.LinkedAt != nil {
		update.SetLinkedAt(*req.LinkedAt)
	}
	err = update.Exec(r.Context())
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
	if s.ent == nil {
		return nil, errors.New("ent client is not configured")
	}
	row, err := s.ent.UserMember.Query().Where(entusermember.ID(userMemberID), entusermember.SpaceID(spaceID), entusermember.DeletedAtIsNil()).Only(ctx)
	if coreent.IsNotFound(err) {
		return nil, pgx.ErrNoRows
	}
	if err != nil {
		return nil, err
	}
	return s.userMemberMapWithRefs(ctx, row)
}

func (s *Server) validateUserMemberRefs(ctx context.Context, spaceID, userID, memberID, linkedByMemberID string) error {
	if s.ent == nil {
		return errors.New("ent client is not configured")
	}
	userExists, err := s.ent.User.Query().Where(entuser.ID(userID), entuser.DeletedAtIsNil()).Exist(ctx)
	if err != nil {
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

func (s *Server) userMemberMapWithRefs(ctx context.Context, row *coreent.UserMember) (map[string]any, error) {
	userRecord, err := s.ent.User.Query().Where(entuser.ID(row.UserID), entuser.DeletedAtIsNil()).Only(ctx)
	if coreent.IsNotFound(err) {
		return userMemberMap(row, "", ""), nil
	}
	if err != nil {
		return nil, err
	}
	memberRecord, err := s.ent.Member.Query().Where(entmember.ID(row.MemberID), entmember.DeletedAtIsNil()).Only(ctx)
	if coreent.IsNotFound(err) {
		return userMemberMap(row, userRecord.Email, ""), nil
	}
	if err != nil {
		return nil, err
	}
	return userMemberMap(row, userRecord.Email, memberRecord.DisplayName), nil
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
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	memberRoles, err := client.MemberRole.Query().
		Where(entmemberrole.SpaceID(spaceID), entmemberrole.DeletedAtIsNil()).
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

func (s *Server) handleSpaceAuditLogs(w http.ResponseWriter, r *http.Request, spaceID string, parts []string) {
	if len(parts) == 0 {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, r)
			return
		}
		limit := limitFrom(r, 50)
		if s.ent == nil {
			writeError(w, r, http.StatusServiceUnavailable, "NOT_READY", "Ent client is not configured.", nil)
			return
		}
		q := s.ent.AuditLog.Query().Where(auditlog.SpaceID(spaceID))
		for _, filter := range []string{"actor_user_id", "actor_member_id", "actor_user_member_id", "resource_type", "resource_id", "decision", "deny_code", "request_id"} {
			if value := r.URL.Query().Get(filter); value != "" {
				switch filter {
				case "actor_user_id":
					q = q.Where(auditlog.ActorUserID(value))
				case "actor_member_id":
					q = q.Where(auditlog.ActorMemberID(value))
				case "actor_user_member_id":
					q = q.Where(auditlog.ActorUserMemberID(value))
				case "resource_type":
					q = q.Where(auditlog.ResourceType(value))
				case "resource_id":
					q = q.Where(auditlog.ResourceID(value))
				case "decision":
					q = q.Where(auditlog.Decision(value))
				case "deny_code":
					q = q.Where(auditlog.DenyCode(value))
				case "request_id":
					q = q.Where(auditlog.RequestID(value))
				}
			}
		}
		if from := r.URL.Query().Get("created_at_from"); from != "" {
			parsed, err := time.Parse(time.RFC3339, from)
			if err != nil {
				writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "created_at_from must be RFC3339.", err.Error())
				return
			}
			q = q.Where(auditlog.CreatedAtGTE(parsed))
		}
		if to := r.URL.Query().Get("created_at_to"); to != "" {
			parsed, err := time.Parse(time.RFC3339, to)
			if err != nil {
				writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "created_at_to must be RFC3339.", err.Error())
				return
			}
			q = q.Where(auditlog.CreatedAtLTE(parsed))
		}
		logs, err := q.Order(auditlog.ByCreatedAt(entsql.OrderDesc())).Limit(limit).All(r.Context())
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list AuditLogs.", err.Error())
			return
		}
		rows := make([]map[string]any, 0, len(logs))
		for _, log := range logs {
			rows = append(rows, auditLogListItem(log))
		}
		writeList(w, r, http.StatusOK, rows, limit)
		return
	}
	if len(parts) == 1 {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, r)
			return
		}
		if s.ent == nil {
			writeError(w, r, http.StatusServiceUnavailable, "NOT_READY", "Ent client is not configured.", nil)
			return
		}
		log, err := s.ent.AuditLog.Query().Where(auditlog.ID(parts[0]), auditlog.SpaceID(spaceID)).Only(r.Context())
		if coreent.IsNotFound(err) {
			writeError(w, r, http.StatusNotFound, "AUDIT_LOG_NOT_FOUND", "AuditLog was not found.", nil)
			return
		}
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load AuditLog.", err.Error())
			return
		}
		writeData(w, r, http.StatusOK, auditLogDetail(log))
		return
	}
	http.NotFound(w, r)
}

func (s *Server) handleGroupDetail(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/groups/")
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, r)
		return
	}
	if s.ent == nil {
		writeError(w, r, http.StatusServiceUnavailable, "NOT_READY", "Ent client is not configured.", nil)
		return
	}
	row, err := s.ent.Group.Query().Where(entgroup.ID(id), entgroup.DeletedAtIsNil()).Only(r.Context())
	if coreent.IsNotFound(err) {
		writeError(w, r, http.StatusNotFound, "GROUP_NOT_FOUND", "Group was not found.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load Group.", err.Error())
		return
	}
	writeData(w, r, http.StatusOK, groupMap(row))
}

func (s *Server) handleMemberDetail(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/members/")
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, r)
		return
	}
	if s.ent == nil {
		writeError(w, r, http.StatusServiceUnavailable, "NOT_READY", "Ent client is not configured.", nil)
		return
	}
	row, err := s.ent.Member.Query().Where(entmember.ID(id), entmember.DeletedAtIsNil()).Only(r.Context())
	if coreent.IsNotFound(err) {
		writeError(w, r, http.StatusNotFound, "MEMBER_NOT_FOUND", "Member was not found.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load Member.", err.Error())
		return
	}
	writeData(w, r, http.StatusOK, memberMap(row))
}

func (s *Server) handleUserMemberDetail(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/user-members/")
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, r)
		return
	}
	if s.ent == nil {
		writeError(w, r, http.StatusServiceUnavailable, "NOT_READY", "Ent client is not configured.", nil)
		return
	}
	row, err := s.ent.UserMember.Query().Where(entusermember.ID(id), entusermember.DeletedAtIsNil()).Only(r.Context())
	if coreent.IsNotFound(err) {
		writeError(w, r, http.StatusNotFound, "USER_MEMBER_NOT_FOUND", "UserMember was not found.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load UserMember.", err.Error())
		return
	}
	out, err := s.userMemberMapWithRefs(r.Context(), row)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load UserMember.", err.Error())
		return
	}
	writeData(w, r, http.StatusOK, out)
}

func (s *Server) handleRoleDetail(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/roles/")
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, r)
		return
	}
	if s.ent == nil {
		writeError(w, r, http.StatusServiceUnavailable, "NOT_READY", "Ent client is not configured.", nil)
		return
	}
	row, err := s.ent.Role.Query().Where(entrole.ID(id), entrole.DeletedAtIsNil()).Only(r.Context())
	if coreent.IsNotFound(err) {
		writeError(w, r, http.StatusNotFound, "ROLE_NOT_FOUND", "Role was not found.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load Role.", err.Error())
		return
	}
	writeData(w, r, http.StatusOK, roleMap(row))
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
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	permissions, err := client.Permission.Query().
		Where(entpermission.DeletedAtIsNil()).
		Order(entpermission.ByResource(), entpermission.ByAction(), entpermission.ByScope()).
		All(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list Permissions.", err.Error())
		return
	}
	rows := make([]map[string]any, 0, len(permissions))
	for _, permission := range permissions {
		rows = append(rows, permissionMap(permission))
	}
	writeList(w, r, http.StatusOK, rows, limitFrom(r, 50))
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
			row, err := s.loadPermission(r.Context(), id)
			if errors.Is(err, pgx.ErrNoRows) {
				writeError(w, r, http.StatusNotFound, "PERMISSION_NOT_FOUND", "Permission was not found.", nil)
				return
			}
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load Permission.", err.Error())
				return
			}
			writeData(w, r, http.StatusOK, row)
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
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	_, err := client.Permission.Create().
		SetID(req.ID).
		SetResource(req.Resource).
		SetAction(req.Action).
		SetScope(req.Scope).
		SetNillableDescription(optionalString(derefString(req.Description))).
		SetStatus(status).
		SetMetadata(nonNilMap(req.Metadata)).
		Save(r.Context())
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
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	description := nullableFromRequest(req.Description, stringFromMap(current, "description"))
	update := client.Permission.UpdateOneID(permissionID).
		SetResource(resourceKey).
		SetAction(actionKey).
		SetScope(scope).
		SetStatus(status).
		SetMetadata(nonNilMap(metadata))
	if description == "" {
		update.ClearDescription()
	} else {
		update.SetDescription(description)
	}
	err = update.Exec(r.Context())
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
	if s.ent == nil {
		return nil, errors.New("ent client is not configured")
	}
	row, err := s.ent.Permission.Query().Where(entpermission.ID(permissionID), entpermission.DeletedAtIsNil()).Only(ctx)
	if coreent.IsNotFound(err) {
		return nil, pgx.ErrNoRows
	}
	if err != nil {
		return nil, err
	}
	return permissionMap(row), nil
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
		client, ok := s.requireEnt(w, r)
		if !ok {
			return
		}
		existing, err := client.RolePermission.Query().Where(entrolepermission.RoleID(req.RoleID), entrolepermission.PermissionID(req.PermissionID)).Only(r.Context())
		if coreent.IsNotFound(err) {
			_, err = client.RolePermission.Create().
				SetID(req.ID).
				SetRoleID(req.RoleID).
				SetPermissionID(req.PermissionID).
				SetMetadata(nonNilMap(req.Metadata)).
				Save(r.Context())
		} else if err == nil {
			err = client.RolePermission.UpdateOneID(existing.ID).
				ClearDeletedAt().
				SetMetadata(nonNilMap(req.Metadata)).
				Exec(r.Context())
		}
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
		client, ok := s.requireEnt(w, r)
		if !ok {
			return
		}
		rolePermissions, err := client.RolePermission.Query().
			Where(entrolepermission.DeletedAtIsNil()).
			Limit(limit).
			All(r.Context())
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list RolePermissions.", err.Error())
			return
		}
		rows := make([]map[string]any, 0, len(rolePermissions))
		for _, rolePermission := range rolePermissions {
			row, err := s.rolePermissionMapWithRefs(r.Context(), rolePermission)
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list RolePermissions.", err.Error())
				return
			}
			rows = append(rows, row)
		}
		sort.SliceStable(rows, func(i, j int) bool {
			for _, key := range []string{"space_id", "role_key", "resource", "action", "scope"} {
				left, _ := rows[i][key].(string)
				right, _ := rows[j][key].(string)
				if left != right {
					return left < right
				}
			}
			return false
		})
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
		client, ok := s.requireEnt(w, r)
		if !ok {
			return
		}
		err = client.RolePermission.UpdateOneID(id).SetDeletedAt(time.Now().UTC()).Exec(r.Context())
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
	if s.ent == nil {
		return nil, errors.New("ent client is not configured")
	}
	row, err := s.ent.RolePermission.Query().Where(entrolepermission.ID(id), entrolepermission.DeletedAtIsNil()).Only(ctx)
	if coreent.IsNotFound(err) {
		return nil, pgx.ErrNoRows
	}
	if err != nil {
		return nil, err
	}
	return s.rolePermissionMapWithRefs(ctx, row)
}

func (s *Server) loadRolePermissionByPair(ctx context.Context, roleID, permissionID string) (map[string]any, error) {
	if s.ent == nil {
		return nil, errors.New("ent client is not configured")
	}
	row, err := s.ent.RolePermission.Query().Where(entrolepermission.RoleID(roleID), entrolepermission.PermissionID(permissionID), entrolepermission.DeletedAtIsNil()).Only(ctx)
	if coreent.IsNotFound(err) {
		return nil, pgx.ErrNoRows
	}
	if err != nil {
		return nil, err
	}
	return s.rolePermissionMapWithRefs(ctx, row)
}

func (s *Server) roleSpaceID(ctx context.Context, roleID string) (string, error) {
	if s.ent == nil {
		return "", errors.New("ent client is not configured")
	}
	role, err := s.ent.Role.Query().Where(entrole.ID(roleID), entrole.DeletedAtIsNil()).Only(ctx)
	if coreent.IsNotFound(err) {
		return "", pgx.ErrNoRows
	}
	if err != nil {
		return "", err
	}
	return role.SpaceID, nil
}

func (s *Server) permissionExists(ctx context.Context, permissionID string) (bool, error) {
	if s.ent == nil {
		return false, errors.New("ent client is not configured")
	}
	return s.ent.Permission.Query().Where(entpermission.ID(permissionID), entpermission.DeletedAtIsNil()).Exist(ctx)
}

func (s *Server) rolePermissionMapWithRefs(ctx context.Context, row *coreent.RolePermission) (map[string]any, error) {
	roleRecord, err := s.ent.Role.Query().Where(entrole.ID(row.RoleID), entrole.DeletedAtIsNil()).Only(ctx)
	if err != nil {
		if coreent.IsNotFound(err) {
			roleRecord = &coreent.Role{}
		} else {
			return nil, err
		}
	}
	permissionRecord, err := s.ent.Permission.Query().Where(entpermission.ID(row.PermissionID), entpermission.DeletedAtIsNil()).Only(ctx)
	if err != nil {
		if coreent.IsNotFound(err) {
			permissionRecord = &coreent.Permission{}
		} else {
			return nil, err
		}
	}
	return rolePermissionMap(row, roleRecord.SpaceID, roleRecord.Key, permissionRecord), nil
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
	rt, err := s.loadResourceTypeEntityByKey(ctx, resourceType)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrAPINotFound
		}
		return err
	}
	mapping, err := s.ent.ResourceMapping.Query().Where(entresourcemapping.ResourceTypeID(rt.ID)).Only(ctx)
	if coreent.IsNotFound(err) {
		return ErrAPINotFound
	}
	if err != nil {
		return err
	}
	if mapping.StorageKind != "internal_table" || derefString(mapping.TableName) != "resources" {
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
	if s.ent == nil {
		return false, errors.New("ent client is not configured")
	}
	return s.ent.Resource.Query().Where(entresource.ResourceType(resourceType), entresource.ID(resourceID), entresource.DeletedAtIsNil()).Exist(ctx)
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
	if s.ent == nil {
		return errors.New("ent client is not configured")
	}
	exists, err := s.ent.Member.Query().Where(entmember.ID(memberID), entmember.SpaceID(spaceID), entmember.DeletedAtIsNil()).Exist(ctx)
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
	return &authz.GroupSnapshot{
		ID:      row.ID,
		SpaceID: row.SpaceID,
		Path:    row.Path,
		Status:  row.Status,
	}, nil
}

func (s *Server) loadResourceTarget(ctx context.Context, resourceType, resourceID string) (authz.TargetSnapshot, error) {
	if s.ent == nil {
		return authz.TargetSnapshot{}, errors.New("ent client is not configured")
	}
	row, err := s.ent.Resource.Query().Where(entresource.ResourceType(resourceType), entresource.ID(resourceID), entresource.DeletedAtIsNil()).Only(ctx)
	if coreent.IsNotFound(err) {
		return authz.TargetSnapshot{}, pgx.ErrNoRows
	}
	if err != nil {
		return authz.TargetSnapshot{}, err
	}
	target := authz.TargetSnapshot{
		Resource: authz.ResourceSnapshot{
			ID:            row.ID,
			Type:          row.ResourceType,
			SpaceID:       row.SpaceID,
			GroupID:       derefString(row.GroupID),
			OwnerMemberID: derefString(row.OwnerMemberID),
			DisplayName:   derefString(row.DisplayName),
			Visibility:    row.Visibility,
			Status:        row.Status,
			Metadata:      nonNilMap(row.Metadata),
		},
	}
	group, err := s.loadGroupSnapshot(ctx, target.Resource.SpaceID, target.Resource.GroupID)
	if err != nil {
		return authz.TargetSnapshot{}, err
	}
	target.Group = group
	return target, nil
}

func (s *Server) loadResourceRow(ctx context.Context, resourceType, resourceID string) (map[string]any, error) {
	if s.ent == nil {
		return nil, errors.New("ent client is not configured")
	}
	row, err := s.ent.Resource.Query().Where(entresource.ResourceType(resourceType), entresource.ID(resourceID)).Only(ctx)
	if coreent.IsNotFound(err) {
		return nil, pgx.ErrNoRows
	}
	if err != nil {
		return nil, err
	}
	return s.resourceMapWithRefs(ctx, row)
}

func (s *Server) resourceMapWithRefs(ctx context.Context, row *coreent.Resource) (map[string]any, error) {
	spaceName := ""
	if row.SpaceID != "" {
		spaceRecord, err := s.ent.Space.Query().Where(entspace.ID(row.SpaceID), entspace.DeletedAtIsNil()).Only(ctx)
		if err != nil && !coreent.IsNotFound(err) {
			return nil, err
		}
		if spaceRecord != nil {
			spaceName = spaceRecord.Name
		}
	}
	groupPath := ""
	if groupID := derefString(row.GroupID); groupID != "" {
		groupRecord, err := s.ent.Group.Query().Where(entgroup.ID(groupID), entgroup.DeletedAtIsNil()).Only(ctx)
		if err != nil && !coreent.IsNotFound(err) {
			return nil, err
		}
		if groupRecord != nil {
			groupPath = groupRecord.Path
		}
	}
	ownerMemberDisplayName := ""
	if memberID := derefString(row.OwnerMemberID); memberID != "" {
		memberRecord, err := s.ent.Member.Query().Where(entmember.ID(memberID), entmember.DeletedAtIsNil()).Only(ctx)
		if err != nil && !coreent.IsNotFound(err) {
			return nil, err
		}
		if memberRecord != nil {
			ownerMemberDisplayName = memberRecord.DisplayName
		}
	}
	return resourceMap(row, spaceName, groupPath, ownerMemberDisplayName), nil
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

func pluginManifestMap(manifest plugins.Manifest) (map[string]any, error) {
	raw, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
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
	manifestMap, err := pluginManifestMap(req.Manifest)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to encode plugin manifest.", err.Error())
		return
	}
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	pluginID := "plugin_" + safeIdentifier(req.Manifest.ID)
	existing, err := client.Plugin.Query().Where(entplugin.Key(req.Manifest.ID)).Only(r.Context())
	if coreent.IsNotFound(err) {
		_, err = client.Plugin.Create().
			SetID(pluginID).
			SetKey(req.Manifest.ID).
			SetName(req.Manifest.Name).
			SetNillableDescription(optionalString(req.Manifest.Description)).
			SetVersion(req.Manifest.Version).
			SetSource(source).
			SetStatus(status).
			SetManifest(manifestMap).
			Save(r.Context())
	} else if err == nil {
		update := client.Plugin.UpdateOneID(existing.ID).
			SetName(req.Manifest.Name).
			SetVersion(req.Manifest.Version).
			SetSource(source).
			SetStatus(status).
			SetManifest(manifestMap)
		if req.Manifest.Description == "" {
			update.ClearDescription()
		} else {
			update.SetDescription(req.Manifest.Description)
		}
		err = update.Exec(r.Context())
		pluginID = existing.ID
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to install plugin metadata.", err.Error())
		return
	}
	if err := s.installPluginManifestMetadata(r.Context(), pluginID, req.Manifest); err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to install plugin declarations.", err.Error())
		return
	}
	row, err := s.loadPluginByKey(r.Context(), req.Manifest.ID)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load installed plugin.", err.Error())
		return
	}
	writeData(w, r, http.StatusCreated, row)
}

func (s *Server) installPluginManifestMetadata(ctx context.Context, pluginID string, manifest plugins.Manifest) error {
	if s.ent == nil {
		return errors.New("ent client is not configured")
	}
	metadata := map[string]any{"plugin": manifest.ID}
	for _, resource := range manifest.Resources {
		resourceTypeID := "rt_" + safeIdentifier(manifest.ID+"_"+resource.Key)
		existingRT, err := s.ent.ResourceType.Query().Where(entresourcetype.Key(resource.Key)).Only(ctx)
		if coreent.IsNotFound(err) {
			_, err = s.ent.ResourceType.Create().
				SetID(resourceTypeID).
				SetKey(resource.Key).
				SetDisplayName(resource.DisplayName).
				SetStatus("active").
				SetSource("plugin:" + manifest.ID).
				SetMetadata(metadata).
				Save(ctx)
		} else if err == nil {
			err = s.ent.ResourceType.UpdateOneID(existingRT.ID).
				SetDisplayName(resource.DisplayName).
				SetSource("plugin:" + manifest.ID).
				SetMetadata(metadata).
				Exec(ctx)
			resourceTypeID = existingRT.ID
		}
		if err != nil {
			return err
		}
		existingMapping, err := s.ent.ResourceMapping.Query().Where(entresourcemapping.ResourceTypeID(resourceTypeID)).Only(ctx)
		if coreent.IsNotFound(err) {
			_, err = s.ent.ResourceMapping.Create().
				SetID("rm_" + safeIdentifier(manifest.ID+"_"+resource.Key)).
				SetResourceTypeID(resourceTypeID).
				SetStorageKind("plugin_managed").
				SetIDField("id").
				SetSpaceField("space_id").
				SetGroupField("group_id").
				SetOwnerMemberField("owner_member_id").
				SetMetadataField("metadata").
				SetStatus("active").
				SetMetadata(metadata).
				Save(ctx)
		} else if err == nil {
			err = s.ent.ResourceMapping.UpdateOneID(existingMapping.ID).
				SetStorageKind("plugin_managed").
				ClearTableName().
				SetIDField("id").
				SetSpaceField("space_id").
				SetGroupField("group_id").
				SetOwnerMemberField("owner_member_id").
				ClearVisibilityField().
				SetMetadataField("metadata").
				SetStatus("active").
				SetMetadata(metadata).
				Exec(ctx)
		}
		if err != nil {
			return err
		}
		for _, action := range resource.Actions {
			existingAction, err := s.ent.ResourceAction.Query().Where(entresourceaction.ResourceTypeID(resourceTypeID), entresourceaction.Key(action.Key)).Only(ctx)
			if coreent.IsNotFound(err) {
				_, err = s.ent.ResourceAction.Create().
					SetID("ra_" + safeIdentifier(manifest.ID+"_"+resource.Key+"_"+action.Key)).
					SetResourceTypeID(resourceTypeID).
					SetKey(action.Key).
					SetDisplayName(titleFromKey(action.Key)).
					SetRiskLevel(firstNonEmpty(action.RiskLevel, "normal")).
					SetAuditDefault(true).
					SetMetadata(metadata).
					Save(ctx)
			} else if err == nil {
				err = s.ent.ResourceAction.UpdateOneID(existingAction.ID).
					SetDisplayName(titleFromKey(action.Key)).
					SetRiskLevel(firstNonEmpty(action.RiskLevel, "normal")).
					SetAuditDefault(true).
					SetMetadata(metadata).
					Exec(ctx)
			}
			if err != nil {
				return err
			}
		}
	}
	for _, permission := range manifest.Permissions {
		for _, scope := range permission.Scopes {
			existingPermission, err := s.ent.Permission.Query().Where(entpermission.Resource(permission.Resource), entpermission.Action(permission.Action), entpermission.Scope(scope)).Only(ctx)
			if coreent.IsNotFound(err) {
				_, err = s.ent.Permission.Create().
					SetID("perm_" + safeIdentifier(manifest.ID+"_"+permission.Resource+"_"+permission.Action+"_"+scope)).
					SetResource(permission.Resource).
					SetAction(permission.Action).
					SetScope(scope).
					Save(ctx)
			} else if err == nil {
				err = s.ent.Permission.UpdateOneID(existingPermission.ID).
					SetResource(permission.Resource).
					SetAction(permission.Action).
					SetScope(scope).
					Exec(ctx)
			}
			if err != nil {
				return err
			}
		}
	}
	for _, event := range manifest.AuditEvents {
		existingEvent, err := s.ent.AuditEventType.Query().Where(entauditeventtype.Key(event.Key)).Only(ctx)
		if coreent.IsNotFound(err) {
			_, err = s.ent.AuditEventType.Create().
				SetID("aet_" + safeIdentifier(manifest.ID+"_"+event.Key)).
				SetKey(event.Key).
				SetPluginID(pluginID).
				SetDisplayName(titleFromKey(event.Key)).
				SetRiskLevel(firstNonEmpty(event.RiskLevel, "normal")).
				SetDefaultAudit(true).
				SetMetadata(metadata).
				Save(ctx)
		} else if err == nil {
			err = s.ent.AuditEventType.UpdateOneID(existingEvent.ID).
				SetPluginID(pluginID).
				SetDisplayName(titleFromKey(event.Key)).
				SetRiskLevel(firstNonEmpty(event.RiskLevel, "normal")).
				SetDefaultAudit(true).
				SetMetadata(metadata).
				Exec(ctx)
		}
		if err != nil {
			return err
		}
	}
	for i, menu := range manifest.AdminMenus {
		menuID := "pam_" + safeIdentifier(manifest.ID+"_"+menu.Label)
		existingMenu, err := s.ent.PluginAdminMenu.Query().Where(entpluginadminmenu.ID(menuID)).Only(ctx)
		if coreent.IsNotFound(err) {
			_, err = s.ent.PluginAdminMenu.Create().
				SetID(menuID).
				SetPluginID(pluginID).
				SetLabel(menu.Label).
				SetPath(menu.Path).
				SetNillableRequiredPermission(optionalString(menu.RequiredPermission)).
				SetSortOrder(1000 + i).
				SetMetadata(metadata).
				Save(ctx)
		} else if err == nil {
			update := s.ent.PluginAdminMenu.UpdateOneID(existingMenu.ID).
				SetLabel(menu.Label).
				SetPath(menu.Path).
				SetSortOrder(1000 + i).
				SetMetadata(metadata)
			if menu.RequiredPermission == "" {
				update.ClearRequiredPermission()
			} else {
				update.SetRequiredPermission(menu.RequiredPermission)
			}
			err = update.Exec(ctx)
		}
		if err != nil {
			return err
		}
	}
	for _, setting := range manifest.Settings {
		scope := firstNonEmpty(setting.Scope, "space")
		existingSetting, err := s.ent.PluginSettingsDefinition.Query().Where(entpluginsettingsdefinition.PluginID(pluginID), entpluginsettingsdefinition.Key(setting.Key), entpluginsettingsdefinition.Scope(scope)).Only(ctx)
		if coreent.IsNotFound(err) {
			_, err = s.ent.PluginSettingsDefinition.Create().
				SetID("psd_" + safeIdentifier(manifest.ID+"_"+setting.Key+"_"+scope)).
				SetPluginID(pluginID).
				SetKey(setting.Key).
				SetValueType(firstNonEmpty(setting.ValueType, "string")).
				SetDefaultValue(map[string]any{}).
				SetNillableDescription(optionalString(setting.Description)).
				SetScope(scope).
				SetMetadata(metadata).
				Save(ctx)
		} else if err == nil {
			update := s.ent.PluginSettingsDefinition.UpdateOneID(existingSetting.ID).
				SetValueType(firstNonEmpty(setting.ValueType, "string")).
				SetMetadata(metadata)
			if setting.Description == "" {
				update.ClearDescription()
			} else {
				update.SetDescription(setting.Description)
			}
			err = update.Exec(ctx)
		}
		if err != nil {
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
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	pluginRows, err := client.Plugin.Query().Order(entplugin.ByName()).All(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list plugins.", err.Error())
		return
	}
	rows := make([]map[string]any, 0, len(pluginRows))
	for _, pluginRow := range pluginRows {
		row := pluginMap(pluginRow)
		resourceTypes, err := client.ResourceType.Query().Where(entresourcetype.Source("plugin:" + pluginRow.Key)).All(r.Context())
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list plugins.", err.Error())
			return
		}
		resourceKeys := make([]string, 0, len(resourceTypes))
		for _, resourceType := range resourceTypes {
			resourceKeys = append(resourceKeys, resourceType.Key)
		}
		row["resources_count"] = len(resourceTypes)
		if len(resourceKeys) > 0 {
			count, err := client.Permission.Query().Where(entpermission.ResourceIn(resourceKeys...)).Count(r.Context())
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list plugins.", err.Error())
				return
			}
			row["permissions_count"] = count
		} else {
			row["permissions_count"] = 0
		}
		count, err := client.PluginAdminMenu.Query().Where(entpluginadminmenu.PluginID(pluginRow.ID)).Count(r.Context())
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list plugins.", err.Error())
			return
		}
		row["admin_menus_count"] = count
		rows = append(rows, row)
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
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, r)
			return
		}
		row, err := s.loadPluginByKey(r.Context(), pluginKey)
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, r, http.StatusNotFound, "PLUGIN_NOT_FOUND", "Plugin was not found.", nil)
			return
		}
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load plugin.", err.Error())
			return
		}
		writeData(w, r, http.StatusOK, row)
	case len(parts) == 2 && (parts[1] == "enable" || parts[1] == "disable" || parts[1] == "uninstall"):
		s.handlePluginLifecycle(w, r, pluginKey, parts[1])
	case len(parts) == 2 && parts[1] == "settings":
		s.handlePluginSettings(w, r, pluginKey)
	case len(parts) == 2 && parts[1] == "resources":
		s.handlePluginResources(w, r, pluginKey)
	case len(parts) == 2 && parts[1] == "permissions":
		s.handlePluginPermissions(w, r, pluginKey)
	case len(parts) == 2 && parts[1] == "audit-events":
		s.handlePluginAuditEvents(w, r, pluginKey)
	case len(parts) == 2 && parts[1] == "admin-menus":
		s.handlePluginAdminMenus(w, r, pluginKey)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) loadPluginByKey(ctx context.Context, key string) (map[string]any, error) {
	if s.ent == nil {
		return nil, errors.New("ent client is not configured")
	}
	row, err := s.ent.Plugin.Query().Where(entplugin.Key(key)).Only(ctx)
	if coreent.IsNotFound(err) {
		return nil, pgx.ErrNoRows
	}
	if err != nil {
		return nil, err
	}
	return pluginMap(row), nil
}

func (s *Server) handlePluginResources(w http.ResponseWriter, r *http.Request, pluginKey string) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, r)
		return
	}
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	rows, err := client.ResourceType.Query().
		Where(entresourcetype.Source("plugin:" + pluginKey)).
		Order(entresourcetype.ByKey()).
		All(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list plugin resources.", err.Error())
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, resourceTypeMap(row))
	}
	writeList(w, r, http.StatusOK, out, limitFrom(r, 50))
}

func (s *Server) handlePluginPermissions(w http.ResponseWriter, r *http.Request, pluginKey string) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, r)
		return
	}
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	resourceTypes, err := client.ResourceType.Query().Where(entresourcetype.Source("plugin:" + pluginKey)).All(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list plugin permissions.", err.Error())
		return
	}
	keys := make([]string, 0, len(resourceTypes))
	for _, resourceType := range resourceTypes {
		keys = append(keys, resourceType.Key)
	}
	if len(keys) == 0 {
		writeList(w, r, http.StatusOK, []map[string]any{}, limitFrom(r, 50))
		return
	}
	permissions, err := client.Permission.Query().
		Where(entpermission.ResourceIn(keys...)).
		Order(entpermission.ByResource(), entpermission.ByAction(), entpermission.ByScope()).
		All(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list plugin permissions.", err.Error())
		return
	}
	out := make([]map[string]any, 0, len(permissions))
	for _, permission := range permissions {
		out = append(out, permissionMap(permission))
	}
	writeList(w, r, http.StatusOK, out, limitFrom(r, 50))
}

func (s *Server) handlePluginAuditEvents(w http.ResponseWriter, r *http.Request, pluginKey string) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, r)
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
	rows, err := s.ent.AuditEventType.Query().
		Where(entauditeventtype.PluginID(pluginID)).
		Order(entauditeventtype.ByKey()).
		All(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list plugin audit events.", err.Error())
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, auditEventTypeMap(row))
	}
	writeList(w, r, http.StatusOK, out, limitFrom(r, 50))
}

func (s *Server) handlePluginAdminMenus(w http.ResponseWriter, r *http.Request, pluginKey string) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, r)
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
	rows, err := s.ent.PluginAdminMenu.Query().
		Where(entpluginadminmenu.PluginID(pluginID)).
		Order(entpluginadminmenu.BySortOrder(), entpluginadminmenu.ByLabel()).
		All(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list plugin admin menus.", err.Error())
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, pluginAdminMenuMap(row))
	}
	writeList(w, r, http.StatusOK, out, limitFrom(r, 50))
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
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	pluginRow, err := client.Plugin.Query().Where(entplugin.Key(pluginKey)).Only(r.Context())
	if coreent.IsNotFound(err) {
		writeError(w, r, http.StatusNotFound, "PLUGIN_NOT_FOUND", "Plugin was not found.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load plugin.", err.Error())
		return
	}
	err = client.Plugin.UpdateOneID(pluginRow.ID).SetStatus(status).Exec(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to update plugin status.", err.Error())
		return
	}
	row, err := s.loadPluginByKey(r.Context(), pluginKey)
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
			client, ok := s.requireEnt(w, r)
			if !ok {
				return
			}
			exists, err := client.PluginSettingsDefinition.Query().Where(entpluginsettingsdefinition.PluginID(pluginID), entpluginsettingsdefinition.Key(key)).Exist(r.Context())
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to validate plugin setting.", err.Error())
				return
			}
			if !exists {
				writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Unknown plugin setting.", map[string]string{"key": key})
				return
			}
			valueMap := pluginSettingValueMap(value)
			existing, err := client.PluginSettingsValue.Query().Where(entpluginsettingsvalue.PluginID(pluginID), entpluginsettingsvalue.SpaceID(req.SpaceID), entpluginsettingsvalue.Key(key)).Only(r.Context())
			if coreent.IsNotFound(err) {
				_, err = client.PluginSettingsValue.Create().
					SetID("psv_" + safeIdentifier(pluginID+"_"+req.SpaceID+"_"+key)).
					SetPluginID(pluginID).
					SetSpaceID(req.SpaceID).
					SetKey(key).
					SetValue(valueMap).
					Save(r.Context())
			} else if err == nil {
				err = client.PluginSettingsValue.UpdateOneID(existing.ID).SetValue(valueMap).Exec(r.Context())
			}
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
	pluginID, err := s.loadPluginID(ctx, pluginKey)
	if err != nil {
		return nil, err
	}
	definitions, err := s.ent.PluginSettingsDefinition.Query().
		Where(entpluginsettingsdefinition.PluginID(pluginID)).
		Order(entpluginsettingsdefinition.ByKey()).
		All(ctx)
	if err != nil {
		return nil, err
	}
	rows := make([]map[string]any, 0, len(definitions))
	for _, definition := range definitions {
		value := definition.DefaultValue
		settingValue, err := s.ent.PluginSettingsValue.Query().
			Where(entpluginsettingsvalue.PluginID(pluginID), entpluginsettingsvalue.Key(definition.Key), entpluginsettingsvalue.SpaceID(spaceID)).
			Only(ctx)
		if err != nil && !coreent.IsNotFound(err) {
			return nil, err
		}
		if settingValue != nil {
			value = settingValue.Value
		}
		rows = append(rows, pluginSettingsDefinitionMap(definition, value))
	}
	return rows, nil
}

func (s *Server) loadPluginID(ctx context.Context, pluginKey string) (string, error) {
	if s.ent == nil {
		return "", errors.New("ent client is not configured")
	}
	pluginRow, err := s.ent.Plugin.Query().Where(entplugin.Key(pluginKey)).Only(ctx)
	if coreent.IsNotFound(err) {
		return "", pgx.ErrNoRows
	}
	if err != nil {
		return "", err
	}
	return pluginRow.ID, nil
}

func pluginSettingValueMap(value any) map[string]any {
	if value == nil {
		return map[string]any{}
	}
	if typed, ok := value.(map[string]any); ok {
		return typed
	}
	return map[string]any{"value": value}
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
	snapshot, err := templateManifestMap(tpl)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to encode template manifest.", err.Error())
		return
	}
	installationID := "ti_" + safeIdentifier(tpl.ID+"_"+strconv.FormatInt(time.Now().UTC().UnixNano(), 10))
	installedByUserID := firstNonEmpty(req.InstalledByUserID, req.ActorUserID)
	installedByMemberID := firstNonEmpty(req.InstalledByMemberID, req.ActorMemberID)
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	_, err = client.TemplateInstallation.Create().
		SetID(installationID).
		SetTemplateID(tpl.ID).
		SetTemplateVersion(tpl.Version).
		SetNillableSpaceID(optionalString(req.SpaceID)).
		SetStatus("installed").
		SetManifestSnapshot(snapshot).
		SetNillableInstalledByUserID(optionalString(installedByUserID)).
		SetNillableInstalledByMemberID(optionalString(installedByMemberID)).
		Save(r.Context())
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

func templateManifestMap(tpl templateManifest) (map[string]any, error) {
	raw, err := json.Marshal(tpl)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
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
	if s.ent == nil {
		return nil, errors.New("ent client is not configured")
	}
	if req.SpaceID != "" {
		exists, err := s.ent.Space.Query().Where(entspace.ID(req.SpaceID), entspace.DeletedAtIsNil()).Exist(ctx)
		if err != nil {
			return nil, err
		}
		if !exists {
			return nil, fmt.Errorf("space %s was not found", req.SpaceID)
		}
		applied["spaces"] = append(applied["spaces"].([]string), req.SpaceID)
	} else {
		for _, space := range tpl.Spaces {
			spaceID := "space_" + safeIdentifier(tpl.ID+"_"+space.Key)
			name := firstNonEmpty(space.Name, titleFromKey(space.Key))
			existing, err := s.ent.Space.Query().Where(entspace.ID(spaceID)).Only(ctx)
			if coreent.IsNotFound(err) {
				_, err = s.ent.Space.Create().SetID(spaceID).SetName(name).SetStatus("active").Save(ctx)
			} else if err == nil {
				err = s.ent.Space.UpdateOneID(existing.ID).SetName(name).SetStatus("active").Exec(ctx)
			}
			if err != nil {
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
		name := firstNonEmpty(group.Name, titleFromKey(group.Key))
		existing, err := s.ent.Group.Query().Where(entgroup.SpaceID(targetSpaceID), entgroup.Path(group.Key)).Only(ctx)
		if coreent.IsNotFound(err) {
			_, err = s.ent.Group.Create().
				SetID(groupID).
				SetSpaceID(targetSpaceID).
				SetName(name).
				SetDisplayName(name).
				SetPath(group.Key).
				SetDepth(pathDepth(group.Key)).
				SetStatus("active").
				Save(ctx)
		} else if err == nil {
			err = s.ent.Group.UpdateOneID(existing.ID).
				SetName(name).
				SetDisplayName(name).
				SetStatus("active").
				Exec(ctx)
			groupID = existing.ID
		}
		if err != nil {
			return nil, err
		}
		applied["groups"] = append(applied["groups"].([]string), groupID)
	}
	roleIDs := map[string]string{}
	for _, role := range tpl.Roles {
		roleID := "role_" + safeIdentifier(targetSpaceID+"_"+role.Key)
		existing, err := s.ent.Role.Query().Where(entrole.SpaceID(targetSpaceID), entrole.Key(role.Key)).Only(ctx)
		if coreent.IsNotFound(err) {
			_, err = s.ent.Role.Create().
				SetID(roleID).
				SetSpaceID(targetSpaceID).
				SetKey(role.Key).
				SetName(titleFromKey(role.Key)).
				Save(ctx)
		} else if err == nil {
			err = s.ent.Role.UpdateOneID(existing.ID).SetKey(role.Key).Exec(ctx)
			roleID = existing.ID
		}
		if err != nil {
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
		existingPermission, err := s.ent.Permission.Query().Where(entpermission.Resource(permission.Resource), entpermission.Action(permission.Action), entpermission.Scope(permission.Scope)).Only(ctx)
		if coreent.IsNotFound(err) {
			_, err = s.ent.Permission.Create().
				SetID(permissionID).
				SetResource(permission.Resource).
				SetAction(permission.Action).
				SetScope(permission.Scope).
				Save(ctx)
		} else if err == nil {
			permissionID = existingPermission.ID
			err = s.ent.Permission.UpdateOneID(existingPermission.ID).
				SetResource(permission.Resource).
				SetAction(permission.Action).
				SetScope(permission.Scope).
				Exec(ctx)
		}
		if err != nil {
			return nil, err
		}
		rolePermissionID := "rp_" + safeIdentifier(roleID+"_"+permissionID)
		existingRolePermission, err := s.ent.RolePermission.Query().Where(entrolepermission.RoleID(roleID), entrolepermission.PermissionID(permissionID)).Only(ctx)
		if coreent.IsNotFound(err) {
			_, err = s.ent.RolePermission.Create().
				SetID(rolePermissionID).
				SetRoleID(roleID).
				SetPermissionID(permissionID).
				Save(ctx)
		} else if err == nil {
			rolePermissionID = existingRolePermission.ID
			err = s.ent.RolePermission.UpdateOneID(existingRolePermission.ID).ClearDeletedAt().Exec(ctx)
		}
		if err != nil {
			return nil, err
		}
		applied["permissions"] = append(applied["permissions"].([]string), permissionID)
		applied["role_permissions"] = append(applied["role_permissions"].([]string), rolePermissionID)
	}
	return applied, nil
}

func (s *Server) writeTemplateInstallAudit(ctx context.Context, tpl templateManifest, req templateInstallRequest, installationID string, applied map[string]any, missing []string) error {
	if s.ent == nil {
		return errors.New("ent client is not configured")
	}
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
		userMembers, err := s.ent.UserMember.Query().
			Where(
				entusermember.UserID(actorUserID),
				entusermember.MemberID(actorMemberID),
				entusermember.SpaceID(spaceID),
				entusermember.Status("active"),
				entusermember.DeletedAtIsNil(),
				entusermember.Or(entusermember.ExpiresAtIsNil(), entusermember.ExpiresAtGT(time.Now().UTC())),
			).
			All(ctx)
		if err == nil && len(userMembers) > 0 {
			sort.SliceStable(userMembers, func(i, j int) bool {
				if userMembers[i].IsPrimary != userMembers[j].IsPrimary {
					return userMembers[i].IsPrimary
				}
				return userMembers[i].CreatedAt.After(userMembers[j].CreatedAt)
			})
			actorUserMemberID = userMembers[0].ID
		}
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
	if s.ent == nil {
		return errors.New("ent client is not configured")
	}
	_, err := s.ent.AuditLog.Create().
		SetID("audit_" + safeIdentifier(installationID)).
		SetSpaceID(spaceID).
		SetActorUserID(actorUserID).
		SetActorMemberID(actorMemberID).
		SetActorUserMemberID(actorUserMemberID).
		SetAction("template.install").
		SetResourceType("template").
		SetResourceID(tpl.ID).
		SetDecision("allow").
		SetTrace(trace).
		SetRequestID(installationID).
		Save(ctx)
	return err
}

func (s *Server) missingTemplatePlugins(ctx context.Context, tpl templateManifest) ([]string, error) {
	if s.ent == nil {
		return nil, errors.New("ent client is not configured")
	}
	missing := []string{}
	for _, key := range tpl.RequiredPlugins {
		pluginRow, err := s.ent.Plugin.Query().Where(entplugin.Key(key)).Only(ctx)
		if coreent.IsNotFound(err) {
			missing = append(missing, key)
			continue
		}
		if err != nil {
			return nil, err
		}
		if pluginRow.Status != "enabled" && pluginRow.Status != "installed" {
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
	if s.ent == nil {
		return nil, errors.New("ent client is not configured")
	}
	switch table {
	case "users":
		if err := s.ent.User.UpdateOneID(id).SetStatus(status).Exec(ctx); err != nil {
			return nil, err
		}
		return s.loadUser(ctx, id)
	case "spaces":
		if err := s.ent.Space.UpdateOneID(id).SetStatus(status).Exec(ctx); err != nil {
			return nil, err
		}
		return s.loadSpace(ctx, id)
	case "permissions":
		if err := s.ent.Permission.UpdateOneID(id).SetStatus(status).Exec(ctx); err != nil {
			return nil, err
		}
		return s.loadPermission(ctx, id)
	default:
		return nil, fmt.Errorf("unsupported unscoped status table %s", table)
	}
}

func (s *Server) updateScopedStatus(ctx context.Context, table, id, spaceID, status string) (map[string]any, error) {
	if !allowedStatusTable(table) {
		return nil, fmt.Errorf("unsupported status table %s", table)
	}
	if s.ent == nil {
		return nil, errors.New("ent client is not configured")
	}
	switch table {
	case "groups":
		if err := s.ent.Group.UpdateOneID(id).SetStatus(status).Exec(ctx); err != nil {
			return nil, err
		}
		return s.loadGroupInSpace(ctx, spaceID, id)
	case "members":
		if err := s.ent.Member.UpdateOneID(id).SetStatus(status).Exec(ctx); err != nil {
			return nil, err
		}
		return s.loadMemberInSpace(ctx, spaceID, id)
	case "roles":
		if err := s.ent.Role.UpdateOneID(id).SetStatus(status).Exec(ctx); err != nil {
			return nil, err
		}
		return s.loadRoleInSpace(ctx, spaceID, id)
	case "member_roles":
		if err := s.ent.MemberRole.UpdateOneID(id).SetStatus(status).Exec(ctx); err != nil {
			return nil, err
		}
		return s.loadMemberRoleInSpace(ctx, spaceID, id)
	case "resources":
		if err := s.ent.Resource.UpdateOneID(id).SetStatus(status).Exec(ctx); err != nil {
			return nil, err
		}
		return s.loadResourceInSpace(ctx, spaceID, id)
	default:
		return nil, fmt.Errorf("unsupported scoped status table %s", table)
	}
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
	if s.ent == nil {
		return
	}
	_, _ = s.ent.AuditLog.Create().
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
