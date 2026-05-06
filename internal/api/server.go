package api

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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
	authzStore  *store.PostgresStore
	coreVersion string
}

func NewServer(pool *pgxpool.Pool, coreVersion string) *Server {
	return &Server{
		pool:        pool,
		authzStore:  store.NewPostgresStore(pool),
		coreVersion: coreVersion,
	}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/system/health", s.handleHealth)
	mux.HandleFunc("/api/v1/system/ready", s.handleReady)
	mux.HandleFunc("/api/v1/system/version", s.handleVersion)
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
	mux.HandleFunc("/api/v1/spaces", s.handleSpaces)
	mux.HandleFunc("/api/v1/spaces/", s.handleSpaceSubroutes)
	mux.HandleFunc("/api/v1/groups/", s.handleGroupDetail)
	mux.HandleFunc("/api/v1/members/", s.handleMemberDetail)
	mux.HandleFunc("/api/v1/user-members/", s.handleUserMemberDetail)
	mux.HandleFunc("/api/v1/permissions", s.handlePermissions)
	mux.HandleFunc("/api/v1/permissions/", s.handlePermissionDetail)
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
	writeData(w, r, http.StatusOK, map[string]any{"status": "ready"})
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, r)
		return
	}
	writeData(w, r, http.StatusOK, map[string]any{
		"core_version":              s.coreVersion,
		"api_version":               "v1",
		"plugin_api_version":        "1.0",
		"resource_registry_version": "1.0",
		"build_time":                time.Now().UTC().Format(time.RFC3339),
	})
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
	if input.RequestID == "" {
		input.RequestID = requestIDFrom(r)
	}
	input.Explain = explain || req.Explain

	decision, err := authz.Check(r.Context(), s.authzStore, input)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Authorization check failed.", err.Error())
		return
	}
	if input.Explain {
		writeData(w, r, http.StatusOK, decision)
		return
	}
	writeData(w, r, http.StatusOK, map[string]any{
		"allow":     decision.IsAllowed(),
		"decision":  decision.Decision,
		"deny_code": decision.DenyCode,
		"reason":    decision.Reason,
		"audit":     decision.Audit,
	})
}

func (s *Server) handleAuditLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, r)
		return
	}
	limit := limitFrom(r, 50)
	sql := `SELECT id, space_id, actor_user_id, actor_member_id, actor_user_member_id, action, resource_type, resource_id, decision, COALESCE(deny_code, '') AS deny_code, request_id, created_at FROM audit_logs`
	args := []any{}
	where := []string{}
	for _, filter := range []string{"space_id", "actor_user_id", "actor_member_id", "resource_type", "resource_id", "decision", "deny_code"} {
		if value := r.URL.Query().Get(filter); value != "" {
			args = append(args, value)
			where = append(where, fmt.Sprintf("%s = $%d", filter, len(args)))
		}
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

func (s *Server) handleSpaces(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, r)
		return
	}
	rows, err := queryMaps(r.Context(), s.pool, `SELECT id, name, status, created_at FROM spaces ORDER BY name`)
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
		s.handleSingleByID(w, r, `SELECT id, name, status, created_at FROM spaces WHERE id = $1`, spaceID, "SPACE_NOT_FOUND")
		return
	}
	switch parts[1] {
	case "groups":
		s.handleQueryList(w, r, `SELECT id, space_id, parent_group_id, display_name, path, status, created_at FROM groups WHERE space_id = $1 ORDER BY path`, spaceID)
	case "members":
		s.handleQueryList(w, r, `SELECT id, space_id, display_name, status, created_at FROM members WHERE space_id = $1 ORDER BY display_name`, spaceID)
	case "user-members":
		s.handleQueryList(w, r, `
			SELECT um.id, um.user_id, u.email, um.member_id, m.display_name AS member_display_name, um.space_id, um.relation_type, um.status, um.is_primary, um.expires_at, um.created_at
			FROM user_members um
			JOIN users u ON u.id = um.user_id
			JOIN members m ON m.id = um.member_id
			WHERE um.space_id = $1
			ORDER BY u.email, m.display_name
		`, spaceID)
	case "roles":
		s.handleQueryList(w, r, `SELECT id, space_id, key, created_at FROM roles WHERE space_id = $1 ORDER BY key`, spaceID)
	case "member-role-grants":
		s.handleQueryList(w, r, `
			SELECT mr.id, mr.space_id, mr.member_id, m.display_name AS member_display_name, mr.role_id, r.key AS role_key,
				mr.scope_anchor_group_id, g.path AS scope_anchor_path, mr.created_at
			FROM member_roles mr
			JOIN members m ON m.id = mr.member_id
			JOIN roles r ON r.id = mr.role_id
			LEFT JOIN groups g ON g.id = mr.scope_anchor_group_id
			WHERE mr.space_id = $1
			ORDER BY m.display_name, r.key
		`, spaceID)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleGroupDetail(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/groups/")
	s.handleSingleByID(w, r, `SELECT id, space_id, parent_group_id, display_name, path, status, created_at FROM groups WHERE id = $1`, id, "GROUP_NOT_FOUND")
}

func (s *Server) handleMemberDetail(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/members/")
	s.handleSingleByID(w, r, `SELECT id, space_id, display_name, status, created_at FROM members WHERE id = $1`, id, "MEMBER_NOT_FOUND")
}

func (s *Server) handleUserMemberDetail(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/user-members/")
	s.handleSingleByID(w, r, `
		SELECT um.id, um.user_id, u.email, um.member_id, m.display_name AS member_display_name, um.space_id, um.relation_type, um.status, um.is_primary, um.expires_at, um.created_at
		FROM user_members um
		JOIN users u ON u.id = um.user_id
		JOIN members m ON m.id = um.member_id
		WHERE um.id = $1
	`, id, "USER_MEMBER_NOT_FOUND")
}

func (s *Server) handleRoleDetail(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/roles/")
	s.handleSingleByID(w, r, `SELECT id, space_id, key, created_at FROM roles WHERE id = $1`, id, "ROLE_NOT_FOUND")
}

func (s *Server) handlePermissions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, r)
		return
	}
	s.handleQueryList(w, r, `SELECT id, resource, action, scope, created_at FROM permissions ORDER BY resource, action, scope`)
}

func (s *Server) handlePermissionDetail(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/permissions/")
	s.handleSingleByID(w, r, `SELECT id, resource, action, scope, created_at FROM permissions WHERE id = $1`, id, "PERMISSION_NOT_FOUND")
}

func (s *Server) handleResources(w http.ResponseWriter, r *http.Request) {
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
		SELECT res.id, res.resource_type, res.display_name, res.space_id, s.name AS space_name,
			res.group_id, g.path AS group_path, res.owner_member_id, m.display_name AS owner_member_display_name,
			res.visibility, res.metadata, res.status, res.created_at
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
			SELECT res.id, res.resource_type, res.display_name, res.space_id, s.name AS space_name,
				res.group_id, g.path AS group_path, res.owner_member_id, m.display_name AS owner_member_display_name,
				res.visibility, res.metadata, res.status, res.created_at
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
		IP:           r.RemoteAddr,
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
	errors := plugins.ValidateManifest(manifest)
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
	validationErrors := plugins.ValidateManifest(req.Manifest)
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
	row, err := queryOneMap(r.Context(), s.pool, `SELECT id, key, name, description, version, source, status, manifest, created_at, updated_at FROM plugins WHERE key = $1`, req.Manifest.ID)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load installed plugin.", err.Error())
		return
	}
	writeData(w, r, http.StatusCreated, row)
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
	missing, err := s.missingTemplatePlugins(r.Context(), tpl)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to validate template plugins.", err.Error())
		return
	}
	if len(missing) > 0 && !req.AllowMissingPlugins {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Template requires plugins that are not enabled.", map[string]any{"missing_plugins": missing})
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
	writeData(w, r, http.StatusCreated, map[string]any{
		"installation_id": installationID,
		"status":          "installed",
		"template":        tpl,
		"preview":         templatePreview(tpl, missing),
	})
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
			Version:      "0.1.0",
			RequiresCore: ">=0.8.0 <0.9.0",
		},
		{
			ID:              "internal-admin",
			Name:            "Internal Admin",
			Version:         "0.1.0",
			RequiresCore:    ">=0.8.0 <0.9.0",
			RequiredPlugins: []string{"plystra.api_keys", "plystra.webhooks"},
			Spaces:          []templateSpace{{Key: "default", Name: "Default Workspace"}},
			Groups: []templateGroup{
				{Key: "operations", Name: "Operations"},
				{Key: "finance", Name: "Finance"},
			},
			Roles: []templateRole{{Key: "space_owner"}, {Key: "auditor"}, {Key: "operator"}},
			Permissions: []templatePermission{
				{Role: "space_owner", Resource: "*", Action: "*", Scope: "space"},
			},
		},
		{
			ID:              "community-lite",
			Name:            "Community Lite",
			Version:         "0.1.0",
			RequiresCore:    ">=0.8.0 <0.9.0",
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
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Request-ID")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = newRequestID()
		}
		w.Header().Set("X-Request-ID", requestID)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey, requestID)))
	})
}

func requestIDFrom(r *http.Request) string {
	if value, ok := r.Context().Value(requestIDKey).(string); ok {
		return value
	}
	return newRequestID()
}

func writeData(w http.ResponseWriter, r *http.Request, status int, data any) {
	writeJSON(w, status, map[string]any{
		"data": data,
		"meta": map[string]any{"request_id": requestIDFrom(r)},
	})
}

func writeList(w http.ResponseWriter, r *http.Request, status int, data any, limit int) {
	writeJSON(w, status, map[string]any{
		"data": data,
		"pagination": map[string]any{
			"limit":    limit,
			"cursor":   nil,
			"has_more": false,
		},
		"meta": map[string]any{"request_id": requestIDFrom(r)},
	})
}

func writeError(w http.ResponseWriter, r *http.Request, status int, code, message string, details any) {
	writeJSON(w, status, map[string]any{
		"error": map[string]any{
			"code":       code,
			"message":    message,
			"details":    details,
			"request_id": requestIDFrom(r),
		},
	})
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

func newRequestID() string {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return fmt.Sprintf("req_%d", time.Now().UTC().UnixNano())
	}
	return "req_" + hex.EncodeToString(buf[:])
}
