package api

import (
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	coreent "github.com/plystra/plystra/ent"
	"github.com/plystra/plystra/internal/authz"
)

type Server struct {
	pool        *pgxpool.Pool
	ent         *coreent.Client
	authzStore  authz.Store
	coreVersion string
	authLimiter *loginAttemptLimiter
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
		authLimiter: newLoginAttemptLimiterFromEnv(),
	}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/health", s.handleHealth)
	mux.HandleFunc("/api/v1/ready", s.handleReady)
	mux.HandleFunc("/api/v1/version", s.handleVersion)
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/api/v1/console/overview", s.handleOverview)
	mux.HandleFunc("/api/v1/auth/register", s.handleAuthRegister)
	mux.HandleFunc("/api/v1/auth/login", s.handleAuthLogin)
	mux.HandleFunc("/api/v1/auth/logout", s.handleAuthLogout)
	mux.HandleFunc("/api/v1/auth/refresh", s.handleAuthRefresh)
	mux.HandleFunc("/api/v1/actor/context", s.handleActorContext)
	mux.HandleFunc("/api/v1/actor/switch-member", s.handleActorSwitchMember)
	mux.HandleFunc("/api/v1/admin/me", s.handleAdminMe)
	mux.HandleFunc("/api/v1/admin/grants", s.handleAdminGrants)
	mux.HandleFunc("/api/v1/admin/grants/", s.handleAdminGrantSubroutes)
	mux.HandleFunc("/api/v1/api-keys", s.handleAPIKeys)
	mux.HandleFunc("/api/v1/api-keys/", s.handleAPIKeySubroutes)
	mux.HandleFunc("/api/v1/authz/check", s.handleAuthzCheck)
	mux.HandleFunc("/api/v1/authz/explain", s.handleAuthzExplain)
	mux.HandleFunc("/api/v1/audit/logs", s.handleAuditLogs)
	mux.HandleFunc("/api/v1/audit/logs/", s.handleAuditLogDetail)
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
	return s.requestMiddleware(mux)
}
