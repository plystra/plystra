package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"time"

	oapi "github.com/swaggest/openapi-go"
	"github.com/swaggest/openapi-go/openapi3"
	"gopkg.in/yaml.v3"

	"github.com/plystra/plystra/internal/plugins"
	"github.com/plystra/plystra/internal/templates"
)

const OpenAPIVersion = "0.0.1"

type openAPIRoute struct {
	Method      string
	Path        string
	Tag         string
	ID          string
	Summary     string
	Description string
	Params      any
	Body        any
	Response    any
	ContentType string
	Status      int
	Security    openAPISecurity
}

type openAPISecurity int

const (
	openAPIPublic openAPISecurity = iota
	openAPISession
	openAPIAdmin
	openAPIMetrics
)

type openAPITagGroup struct {
	Name string   `json:"name" yaml:"name"`
	Tags []string `json:"tags" yaml:"tags"`
}

type openAPIEnvelope[T any] struct {
	Data      T      `json:"data"`
	RequestID string `json:"request_id" example:"req_01hzyj6b6q8"`
}

type openAPIListEnvelope[T any] struct {
	Data       []T               `json:"data"`
	Pagination openAPIPagination `json:"pagination"`
	RequestID  string            `json:"request_id" example:"req_01hzyj6b6q8"`
}

type openAPIPagination struct {
	Limit   int     `json:"limit" example:"50"`
	Cursor  *string `json:"cursor"`
	HasMore bool    `json:"has_more" example:"false"`
}

type openAPIErrorEnvelope struct {
	Error     openAPIError `json:"error"`
	RequestID string       `json:"request_id" example:"req_01hzyj6b6q8"`
}

type openAPIError struct {
	Code       string `json:"code" example:"VALIDATION_FAILED"`
	Message    string `json:"message" example:"Request body is invalid JSON."`
	Details    any    `json:"details,omitempty"`
	RequestID  string `json:"request_id" example:"req_01hzyj6b6q8"`
	DenyCode   string `json:"deny_code,omitempty" example:"SCOPE_OUT_OF_BOUNDS"`
	TraceID    string `json:"trace_id,omitempty" example:"trace_01hzyj6b6q8"`
	AuditLogID string `json:"audit_log_id,omitempty" example:"audit_01hzyj6b6q8"`
}

type openAPIHealth struct {
	Status string `json:"status" example:"ok"`
}

type openAPIReady struct {
	Status                string         `json:"status" example:"ready"`
	SchemaVersion         string         `json:"schema_version" example:"017"`
	ExpectedSchemaVersion string         `json:"expected_schema_version" example:"017"`
	TraceVersion          string         `json:"trace_version" example:"1.0"`
	SystemCapabilities    map[string]any `json:"system_capabilities"`
	Plugins               map[string]any `json:"plugins"`
}

type openAPIVersionResponse struct {
	Version string `json:"version" example:"0.0.1"`
}

type openAPILoginResponse struct {
	AccessToken      string             `json:"access_token"`
	RefreshToken     string             `json:"refresh_token"`
	TokenType        string             `json:"token_type" example:"Bearer"`
	ExpiresAt        string             `json:"expires_at" format:"date-time"`
	RefreshExpiresAt string             `json:"refresh_expires_at" format:"date-time"`
	User             openAPIUserSession `json:"user"`
	Actor            map[string]any     `json:"actor"`
	AvailableMembers []map[string]any   `json:"available_members"`
}

type openAPIRefreshResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type" example:"Bearer"`
	ExpiresAt        string `json:"expires_at" format:"date-time"`
	RefreshExpiresAt string `json:"refresh_expires_at" format:"date-time"`
}

type openAPIRegisterResponse struct {
	AccessToken                  string             `json:"access_token"`
	RefreshToken                 string             `json:"refresh_token"`
	TokenType                    string             `json:"token_type" example:"Bearer"`
	ExpiresAt                    string             `json:"expires_at" format:"date-time"`
	RefreshExpiresAt             string             `json:"refresh_expires_at" format:"date-time"`
	User                         openAPIUserSession `json:"user"`
	Actor                        map[string]any     `json:"actor"`
	AvailableMembers             []map[string]any   `json:"available_members"`
	BootstrapSuperAdmin          bool               `json:"bootstrap_super_admin"`
	BootstrapAdminGrantID        string             `json:"bootstrap_admin_grant_id,omitempty"`
	SpaceAdminGrantID            string             `json:"space_admin_grant_id"`
	RegistrationMode             string             `json:"registration_mode" example:"ordinary"`
	UserOnly                     bool               `json:"user_only"`
	RegistrationRequiresApproval bool               `json:"registration_requires_approval"`
}

type openAPIUserSession struct {
	ID     string `json:"id" example:"user_alice"`
	Email  string `json:"email" example:"alice@example.com"`
	Status string `json:"status" example:"active"`
}

type openAPILogoutResponse struct {
	LoggedOut bool `json:"logged_out" example:"true"`
}

type openAPIActorContextResponse struct {
	Actor            map[string]any   `json:"actor"`
	AvailableMembers []map[string]any `json:"available_members"`
}

type openAPIAdminMeResponse struct {
	CredentialType string                 `json:"credential_type" example:"session"`
	SessionID      string                 `json:"session_id,omitempty"`
	UserID         string                 `json:"user_id,omitempty"`
	ActiveSpace    string                 `json:"active_space,omitempty"`
	ActiveMember   string                 `json:"active_member,omitempty"`
	Grants         []openAPIAdminGrant    `json:"grants"`
	Capabilities   map[string]bool        `json:"capabilities"`
	APIKey         *openAPIAPIKey         `json:"api_key,omitempty"`
	Extra          map[string]interface{} `json:"-"`
}

type openAPIAdminGrant struct {
	ID                string         `json:"id"`
	UserID            string         `json:"user_id"`
	MemberID          string         `json:"member_id,omitempty"`
	SpaceID           string         `json:"space_id,omitempty"`
	GroupID           string         `json:"group_id,omitempty"`
	Level             string         `json:"level" example:"space_admin"`
	PermissionKey     string         `json:"permission_key" example:"spaces:manage"`
	Status            string         `json:"status" example:"active"`
	GrantedByUserID   string         `json:"granted_by_user_id,omitempty"`
	GrantedByMemberID string         `json:"granted_by_member_id,omitempty"`
	ExpiresAt         *time.Time     `json:"expires_at,omitempty"`
	RevokedAt         *time.Time     `json:"revoked_at,omitempty"`
	RevokedReason     string         `json:"revoked_reason,omitempty"`
	Metadata          map[string]any `json:"metadata"`
	CreatedAt         string         `json:"created_at" format:"date-time"`
	UpdatedAt         string         `json:"updated_at" format:"date-time"`
	DeletedAt         *time.Time     `json:"deleted_at,omitempty"`
}

type openAPIAPIKey struct {
	ID                string         `json:"id"`
	Name              string         `json:"name"`
	KeyPrefix         string         `json:"key_prefix"`
	Key               string         `json:"key,omitempty" description:"Only returned once by POST /api/v1/api-keys."`
	Level             string         `json:"level" example:"space"`
	SpaceID           string         `json:"space_id,omitempty"`
	GroupID           string         `json:"group_id,omitempty"`
	PermissionKeys    []string       `json:"permission_keys"`
	Status            string         `json:"status" example:"active"`
	ExpiresAt         *time.Time     `json:"expires_at,omitempty"`
	LastUsedAt        *time.Time     `json:"last_used_at,omitempty"`
	CreatedByUserID   string         `json:"created_by_user_id,omitempty"`
	CreatedByMemberID string         `json:"created_by_member_id,omitempty"`
	RevokedAt         *time.Time     `json:"revoked_at,omitempty"`
	RevokedByUserID   string         `json:"revoked_by_user_id,omitempty"`
	RevokedReason     string         `json:"revoked_reason,omitempty"`
	Metadata          map[string]any `json:"metadata"`
	CreatedAt         string         `json:"created_at" format:"date-time"`
	UpdatedAt         string         `json:"updated_at" format:"date-time"`
	DeletedAt         *time.Time     `json:"deleted_at,omitempty"`
}

type openAPIAuthzCheckResponse struct {
	Allow      bool           `json:"allow"`
	Decision   string         `json:"decision" example:"allow"`
	DenyCode   *string        `json:"deny_code"`
	Reason     string         `json:"reason"`
	TraceID    string         `json:"trace_id"`
	AuditLogID string         `json:"audit_log_id"`
	Audit      map[string]any `json:"audit"`
}

type openAPIUser struct {
	ID                string         `json:"id"`
	Email             string         `json:"email"`
	Username          string         `json:"username,omitempty"`
	Phone             string         `json:"phone,omitempty"`
	Status            string         `json:"status"`
	Metadata          map[string]any `json:"metadata"`
	PasswordChangedAt *time.Time     `json:"password_changed_at,omitempty"`
	LastLoginAt       *time.Time     `json:"last_login_at,omitempty"`
	CreatedAt         string         `json:"created_at" format:"date-time"`
	UpdatedAt         string         `json:"updated_at" format:"date-time"`
	DeletedAt         *time.Time     `json:"deleted_at,omitempty"`
}

type openAPISpace struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Slug      string         `json:"slug,omitempty"`
	Type      string         `json:"type"`
	Status    string         `json:"status"`
	Metadata  map[string]any `json:"metadata"`
	CreatedAt string         `json:"created_at" format:"date-time"`
	UpdatedAt string         `json:"updated_at" format:"date-time"`
	DeletedAt *time.Time     `json:"deleted_at,omitempty"`
}

type openAPIGroup struct {
	ID            string         `json:"id"`
	SpaceID       string         `json:"space_id"`
	ParentGroupID string         `json:"parent_group_id,omitempty"`
	ParentID      string         `json:"parent_id,omitempty"`
	Name          string         `json:"name"`
	DisplayName   string         `json:"display_name,omitempty"`
	Path          string         `json:"path"`
	Depth         int            `json:"depth"`
	SortOrder     int            `json:"sort_order"`
	Status        string         `json:"status"`
	Metadata      map[string]any `json:"metadata"`
	CreatedAt     string         `json:"created_at" format:"date-time"`
	UpdatedAt     string         `json:"updated_at" format:"date-time"`
	DeletedAt     *time.Time     `json:"deleted_at,omitempty"`
}

type openAPIMember struct {
	ID          string         `json:"id"`
	SpaceID     string         `json:"space_id"`
	DisplayName string         `json:"display_name"`
	MemberType  string         `json:"member_type"`
	Status      string         `json:"status"`
	Metadata    map[string]any `json:"metadata"`
	CreatedAt   string         `json:"created_at" format:"date-time"`
	UpdatedAt   string         `json:"updated_at" format:"date-time"`
	DeletedAt   *time.Time     `json:"deleted_at,omitempty"`
}

type openAPIUserMember struct {
	ID                string         `json:"id"`
	UserID            string         `json:"user_id"`
	Email             string         `json:"email,omitempty"`
	MemberID          string         `json:"member_id"`
	MemberDisplayName string         `json:"member_display_name,omitempty"`
	SpaceID           string         `json:"space_id"`
	RelationType      string         `json:"relation_type"`
	Status            string         `json:"status"`
	IsPrimary         bool           `json:"is_primary"`
	ExpiresAt         *time.Time     `json:"expires_at,omitempty"`
	LinkedByMemberID  string         `json:"linked_by_member_id,omitempty"`
	LinkedAt          *time.Time     `json:"linked_at,omitempty"`
	RevokedAt         *time.Time     `json:"revoked_at,omitempty"`
	RevokedReason     string         `json:"revoked_reason,omitempty"`
	Metadata          map[string]any `json:"metadata"`
	CreatedAt         string         `json:"created_at" format:"date-time"`
	UpdatedAt         string         `json:"updated_at" format:"date-time"`
	DeletedAt         *time.Time     `json:"deleted_at,omitempty"`
}

type openAPIRole struct {
	ID          string         `json:"id"`
	SpaceID     string         `json:"space_id"`
	Key         string         `json:"key"`
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Status      string         `json:"status"`
	Metadata    map[string]any `json:"metadata"`
	CreatedAt   string         `json:"created_at" format:"date-time"`
	UpdatedAt   string         `json:"updated_at" format:"date-time"`
	DeletedAt   *time.Time     `json:"deleted_at,omitempty"`
}

type openAPIMemberRole struct {
	ID                 string         `json:"id"`
	SpaceID            string         `json:"space_id"`
	MemberID           string         `json:"member_id"`
	MemberDisplayName  string         `json:"member_display_name,omitempty"`
	RoleID             string         `json:"role_id"`
	RoleKey            string         `json:"role_key,omitempty"`
	RoleName           string         `json:"role_name,omitempty"`
	ScopeAnchorGroupID string         `json:"scope_anchor_group_id,omitempty"`
	ScopeAnchorPath    string         `json:"scope_anchor_path,omitempty"`
	Status             string         `json:"status"`
	Metadata           map[string]any `json:"metadata"`
	CreatedAt          string         `json:"created_at" format:"date-time"`
	UpdatedAt          string         `json:"updated_at" format:"date-time"`
	DeletedAt          *time.Time     `json:"deleted_at,omitempty"`
}

type openAPIPermission struct {
	ID          string         `json:"id"`
	Resource    string         `json:"resource"`
	Action      string         `json:"action"`
	Scope       string         `json:"scope"`
	Description string         `json:"description,omitempty"`
	Status      string         `json:"status"`
	Metadata    map[string]any `json:"metadata"`
	CreatedAt   string         `json:"created_at" format:"date-time"`
	UpdatedAt   string         `json:"updated_at" format:"date-time"`
	DeletedAt   *time.Time     `json:"deleted_at,omitempty"`
}

type openAPIRolePermission struct {
	ID           string         `json:"id"`
	RoleID       string         `json:"role_id"`
	SpaceID      string         `json:"space_id,omitempty"`
	RoleKey      string         `json:"role_key,omitempty"`
	PermissionID string         `json:"permission_id"`
	Resource     string         `json:"resource,omitempty"`
	Action       string         `json:"action,omitempty"`
	Scope        string         `json:"scope,omitempty"`
	Metadata     map[string]any `json:"metadata"`
	CreatedAt    string         `json:"created_at" format:"date-time"`
	UpdatedAt    string         `json:"updated_at" format:"date-time"`
	DeletedAt    *time.Time     `json:"deleted_at,omitempty"`
}

type openAPIAppDataPermissionSummary struct {
	ID       string `json:"id"`
	Resource string `json:"resource"`
	Action   string `json:"action"`
	Scope    string `json:"scope"`
	Status   string `json:"status"`
}

type openAPIAppDataModel struct {
	ID          string                            `json:"id"`
	SpaceID     string                            `json:"space_id"`
	Key         string                            `json:"key"`
	DisplayName string                            `json:"display_name"`
	Description string                            `json:"description,omitempty"`
	Source      string                            `json:"source"`
	Status      string                            `json:"status"`
	Schema      map[string]any                    `json:"schema"`
	Metadata    map[string]any                    `json:"metadata"`
	Permissions []openAPIAppDataPermissionSummary `json:"permissions"`
	CreatedAt   string                            `json:"created_at" format:"date-time"`
	UpdatedAt   string                            `json:"updated_at" format:"date-time"`
	DeletedAt   *time.Time                        `json:"deleted_at,omitempty"`
}

type openAPIAppDataRecord struct {
	ID            string         `json:"id"`
	SpaceID       string         `json:"space_id"`
	ModelID       string         `json:"model_id"`
	ModelKey      string         `json:"model_key"`
	GroupID       string         `json:"group_id,omitempty"`
	OwnerMemberID string         `json:"owner_member_id,omitempty"`
	DisplayName   string         `json:"display_name,omitempty"`
	Visibility    string         `json:"visibility"`
	Status        string         `json:"status"`
	Data          map[string]any `json:"data"`
	Metadata      map[string]any `json:"metadata"`
	CreatedAt     string         `json:"created_at" format:"date-time"`
	UpdatedAt     string         `json:"updated_at" format:"date-time"`
	DeletedAt     *time.Time     `json:"deleted_at,omitempty"`
}

type openAPIAppDataRecordResponse struct {
	Record        openAPIAppDataRecord      `json:"record"`
	Authorization openAPIAuthzCheckResponse `json:"authorization"`
}

type openAPIAppDataRecordBatchResult struct {
	OperationIndex int                       `json:"operation_index"`
	Operation      string                    `json:"operation"`
	ModelKey       string                    `json:"model_key"`
	Record         openAPIAppDataRecord      `json:"record"`
	Authorization  openAPIAuthzCheckResponse `json:"authorization"`
}

type openAPIAppDataRecordBatchResponse struct {
	OperationCount int                               `json:"operation_count"`
	Results        []openAPIAppDataRecordBatchResult `json:"results"`
}

type openAPIAppDataRevision struct {
	ID                string         `json:"id"`
	RecordID          string         `json:"record_id"`
	SpaceID           string         `json:"space_id"`
	ModelID           string         `json:"model_id"`
	ModelKey          string         `json:"model_key"`
	Revision          int            `json:"revision"`
	Operation         string         `json:"operation"`
	ActorUserID       string         `json:"actor_user_id,omitempty"`
	ActorMemberID     string         `json:"actor_member_id,omitempty"`
	ActorUserMemberID string         `json:"actor_user_member_id,omitempty"`
	Data              map[string]any `json:"data"`
	Metadata          map[string]any `json:"metadata"`
	CreatedAt         string         `json:"created_at" format:"date-time"`
}

type openAPIResourceType struct {
	ID          string         `json:"id"`
	Key         string         `json:"key"`
	DisplayName string         `json:"display_name"`
	Description string         `json:"description,omitempty"`
	Status      string         `json:"status"`
	Source      string         `json:"source"`
	Metadata    map[string]any `json:"metadata"`
	CreatedAt   string         `json:"created_at" format:"date-time"`
	UpdatedAt   string         `json:"updated_at" format:"date-time"`
}

type openAPIResourceAction struct {
	ID           string         `json:"id"`
	Key          string         `json:"key"`
	DisplayName  string         `json:"display_name"`
	Description  string         `json:"description,omitempty"`
	RiskLevel    string         `json:"risk_level"`
	AuditDefault bool           `json:"audit_default"`
	Metadata     map[string]any `json:"metadata"`
}

type openAPIResourceMapping struct {
	ID               string         `json:"id"`
	ResourceTypeID   string         `json:"resource_type_id"`
	ResourceType     string         `json:"resource_type,omitempty"`
	DisplayName      string         `json:"display_name,omitempty"`
	Source           string         `json:"source,omitempty"`
	StorageKind      string         `json:"storage_kind"`
	TableName        string         `json:"table_name,omitempty"`
	IDField          string         `json:"id_field"`
	SpaceField       string         `json:"space_field"`
	GroupField       string         `json:"group_field,omitempty"`
	OwnerMemberField string         `json:"owner_member_field,omitempty"`
	VisibilityField  string         `json:"visibility_field,omitempty"`
	MetadataField    string         `json:"metadata_field,omitempty"`
	Status           string         `json:"status"`
	Metadata         map[string]any `json:"metadata"`
	CreatedAt        string         `json:"created_at" format:"date-time"`
	UpdatedAt        string         `json:"updated_at" format:"date-time"`
}

type openAPIResource struct {
	ID                     string         `json:"id"`
	ResourceType           string         `json:"resource_type"`
	ExternalID             string         `json:"external_id,omitempty"`
	DisplayName            string         `json:"display_name,omitempty"`
	SpaceID                string         `json:"space_id"`
	SpaceName              string         `json:"space_name,omitempty"`
	GroupID                string         `json:"group_id,omitempty"`
	GroupPath              string         `json:"group_path,omitempty"`
	OwnerMemberID          string         `json:"owner_member_id,omitempty"`
	OwnerMemberDisplayName string         `json:"owner_member_display_name,omitempty"`
	Visibility             string         `json:"visibility"`
	Metadata               map[string]any `json:"metadata"`
	Status                 string         `json:"status"`
	CreatedAt              string         `json:"created_at" format:"date-time"`
	UpdatedAt              string         `json:"updated_at" format:"date-time"`
	DeletedAt              *time.Time     `json:"deleted_at,omitempty"`
}

type openAPIAuditLog struct {
	ID                string         `json:"id"`
	SpaceID           string         `json:"space_id"`
	ActorUserID       string         `json:"actor_user_id,omitempty"`
	ActorMemberID     string         `json:"actor_member_id,omitempty"`
	ActorUserMemberID string         `json:"actor_user_member_id,omitempty"`
	Action            string         `json:"action"`
	ResourceType      string         `json:"resource_type"`
	ResourceID        string         `json:"resource_id"`
	Decision          string         `json:"decision"`
	DenyCode          string         `json:"deny_code,omitempty"`
	RequestID         string         `json:"request_id,omitempty"`
	IPAddress         string         `json:"ip_address,omitempty"`
	UserAgent         string         `json:"user_agent,omitempty"`
	Trace             map[string]any `json:"trace,omitempty"`
	CreatedAt         string         `json:"created_at" format:"date-time"`
}

type openAPIPlugin struct {
	ID               string         `json:"id"`
	Key              string         `json:"key"`
	Name             string         `json:"name"`
	Description      string         `json:"description,omitempty"`
	Version          string         `json:"version"`
	Source           string         `json:"source"`
	Status           string         `json:"status"`
	Manifest         map[string]any `json:"manifest"`
	ResourcesCount   int            `json:"resources_count,omitempty"`
	PermissionsCount int            `json:"permissions_count,omitempty"`
	AdminMenusCount  int            `json:"admin_menus_count,omitempty"`
	CreatedAt        string         `json:"created_at" format:"date-time"`
	UpdatedAt        string         `json:"updated_at" format:"date-time"`
}

type openAPIAuditEventType struct {
	ID           string         `json:"id"`
	Key          string         `json:"key"`
	PluginID     string         `json:"plugin_id,omitempty"`
	DisplayName  string         `json:"display_name"`
	Description  string         `json:"description,omitempty"`
	RiskLevel    string         `json:"risk_level"`
	DefaultAudit bool           `json:"default_audit"`
	Metadata     map[string]any `json:"metadata"`
	CreatedAt    string         `json:"created_at" format:"date-time"`
	UpdatedAt    string         `json:"updated_at" format:"date-time"`
}

type openAPIPluginAdminMenu struct {
	ID                 string         `json:"id"`
	PluginID           string         `json:"plugin_id"`
	Label              string         `json:"label"`
	Path               string         `json:"path"`
	Icon               string         `json:"icon,omitempty"`
	RequiredPermission string         `json:"required_permission,omitempty"`
	SortOrder          int            `json:"sort_order"`
	Metadata           map[string]any `json:"metadata"`
	CreatedAt          string         `json:"created_at" format:"date-time"`
	UpdatedAt          string         `json:"updated_at" format:"date-time"`
}

type openAPIPluginSetting struct {
	ID           string         `json:"id"`
	Key          string         `json:"key"`
	ValueType    string         `json:"value_type"`
	DefaultValue map[string]any `json:"default_value,omitempty"`
	Value        map[string]any `json:"value"`
	Description  string         `json:"description,omitempty"`
	Scope        string         `json:"scope"`
	Metadata     map[string]any `json:"metadata"`
	CreatedAt    string         `json:"created_at" format:"date-time"`
	UpdatedAt    string         `json:"updated_at" format:"date-time"`
}

type openAPIOverviewResponse struct {
	Counts          map[string]int    `json:"counts"`
	RecentAuditLogs []openAPIAuditLog `json:"recent_audit_logs"`
}

type openAPIPluginValidationResponse struct {
	Valid  bool     `json:"valid"`
	Errors []string `json:"errors"`
}

type openAPITemplateInstallResponse struct {
	InstallationID string             `json:"installation_id"`
	Status         string             `json:"status"`
	Template       templates.Manifest `json:"template"`
	Preview        map[string]any     `json:"preview"`
	Applied        map[string]any     `json:"applied"`
}

type openAPIDataRowMutationResponse struct {
	Row           openAPIResource           `json:"row"`
	Authorization openAPIAuthzCheckResponse `json:"authorization"`
}

type openAPILimitQuery struct {
	Limit int `query:"limit" minimum:"1" maximum:"200" description:"Maximum number of rows to return."`
}

type openAPIResourceListQuery struct {
	SpaceID      string `query:"space_id" description:"Filter resources by Space ID."`
	ResourceType string `query:"resource_type" description:"Filter resources by resource type."`
	Limit        int    `query:"limit" minimum:"1" maximum:"200"`
}

type openAPIAuditLogQuery struct {
	SpaceID           string `query:"space_id"`
	ActorUserID       string `query:"actor_user_id"`
	ActorMemberID     string `query:"actor_member_id"`
	ActorUserMemberID string `query:"actor_user_member_id"`
	ResourceType      string `query:"resource_type"`
	ResourceID        string `query:"resource_id"`
	Decision          string `query:"decision"`
	DenyCode          string `query:"deny_code"`
	RequestID         string `query:"request_id"`
	CreatedAtFrom     string `query:"created_at_from" format:"date-time"`
	CreatedAtTo       string `query:"created_at_to" format:"date-time"`
	Limit             int    `query:"limit" minimum:"1" maximum:"200"`
}

type openAPIPluginSettingsQuery struct {
	SpaceID string `query:"space_id" description:"Space-specific settings scope."`
}

func GenerateOpenAPI(version string) (*openapi3.Spec, error) {
	if version == "" {
		version = OpenAPIVersion
	}
	reflector := openapi3.NewReflector()
	spec := reflector.SpecEns()
	spec.SetTitle("Plystra Core API")
	spec.SetVersion(version)
	spec.SetDescription("Self-hosted Plystra Core API. Stable surfaces cover identity, authorization, resource registry, audit, admin control-plane, and scoped API keys; plugin, template, and Data Console routes are preview metadata surfaces.")
	spec.WithServers(openapi3.Server{URL: "http://localhost:8080"})
	spec.SetHTTPBearerTokenSecurity("BearerAuth", "opaque Plystra access token", "Use the access_token returned by POST /api/v1/auth/login or POST /api/v1/auth/refresh.")
	spec.SetAPIKeySecurity("ApiKeyAuth", "X-Plystra-API-Key", oapi.InHeader, "Scoped API key for server-to-server Core calls.")
	spec.SetAPIKeySecurity("MetricsTokenAuth", "X-Plystra-Metrics-Token", oapi.InHeader, "Dedicated metrics token when METRICS_TOKEN or PLYSTRA_METRICS_TOKEN is configured.")
	spec.WithTags(openAPITags()...)
	spec.WithMapOfAnythingItem("x-tagGroups", []openAPITagGroup{
		{Name: "Platform", Tags: []string{"System", "Console"}},
		{Name: "Authentication", Tags: []string{"Auth", "Actor"}},
		{Name: "Administration", Tags: []string{"Admin", "API Keys"}},
		{Name: "Authorization", Tags: []string{"Authorization", "Permissions", "Roles"}},
		{Name: "Identity", Tags: []string{"Users", "Spaces", "Groups", "Members", "User Members"}},
		{Name: "Resources", Tags: []string{"Resource Types", "Resources", "App Data", "Data Console"}},
		{Name: "Audit", Tags: []string{"Audit"}},
		{Name: "Extensions", Tags: []string{"Plugins", "Templates"}},
	})
	for _, route := range openAPIRoutes() {
		oc, err := reflector.NewOperationContext(route.Method, route.Path)
		if err != nil {
			return nil, err
		}
		oc.SetID(route.ID)
		oc.SetSummary(route.Summary)
		if route.Description != "" {
			oc.SetDescription(route.Description)
		}
		oc.SetTags(route.Tag)
		for _, securityName := range openAPISecurityNames(route.Security) {
			oc.AddSecurity(securityName)
		}
		if route.Params != nil {
			oc.AddReqStructure(route.Params)
		}
		if route.Body != nil {
			oc.AddReqStructure(route.Body, jsonRequestBody())
		}
		status := route.Status
		if status == 0 {
			status = http.StatusOK
		}
		if route.Response != nil {
			oc.AddRespStructure(route.Response, contentType(route.ContentType), httpStatus(status))
		}
		oc.AddRespStructure(new(openAPIErrorEnvelope), jsonContent(), defaultErrorResponse())
		if err := reflector.AddOperation(oc); err != nil {
			return nil, err
		}
	}
	return spec, nil
}

func WriteOpenAPIFiles(dir, version string) error {
	spec, err := GenerateOpenAPI(version)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	rawJSON, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		return err
	}
	rawJSON = append(rawJSON, '\n')
	if err := os.WriteFile(filepath.Join(dir, "plystra.v0.0.1.json"), rawJSON, 0o644); err != nil {
		return err
	}
	var decoded any
	if err := json.Unmarshal(rawJSON, &decoded); err != nil {
		return err
	}
	rawYAML, err := yaml.Marshal(decoded)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "plystra.v0.0.1.yaml"), rawYAML, 0o644)
}

func jsonContent() oapi.ContentOption {
	return oapi.WithContentType("application/json")
}

func jsonRequestBody() oapi.ContentOption {
	return func(cu *oapi.ContentUnit) {
		cu.ContentType = "application/json"
		cu.Customize = func(cor oapi.ContentOrReference) {
			if requestBody, ok := cor.(*openapi3.RequestBodyOrRef); ok {
				requestBody.RequestBodyEns().WithRequired(true)
			}
		}
	}
}

func contentType(value string) oapi.ContentOption {
	if value == "" {
		value = "application/json"
	}
	return oapi.WithContentType(value)
}

func httpStatus(status int) oapi.ContentOption {
	return func(cu *oapi.ContentUnit) {
		cu.HTTPStatus = status
	}
}

func defaultErrorResponse() oapi.ContentOption {
	return func(cu *oapi.ContentUnit) {
		cu.IsDefault = true
		cu.Description = "Error response."
	}
}

func openAPISecurityNames(security openAPISecurity) []string {
	switch security {
	case openAPISession:
		return []string{"BearerAuth"}
	case openAPIAdmin:
		return []string{"BearerAuth", "ApiKeyAuth"}
	case openAPIMetrics:
		return []string{"MetricsTokenAuth", "BearerAuth", "ApiKeyAuth"}
	default:
		return nil
	}
}

func openAPITags() []openapi3.Tag {
	tags := []struct {
		name        string
		description string
	}{
		{"System", "Health, readiness, version, and metrics endpoints."},
		{"Console", "Admin Console overview endpoints."},
		{"Auth", "User session login, refresh, and logout."},
		{"Actor", "Session actor context and member switching."},
		{"Admin", "Instance, space, and group admin grants."},
		{"API Keys", "Scoped API keys for server-to-server Core access."},
		{"Authorization", "Authorization check and explain endpoints."},
		{"Users", "User identity records."},
		{"Spaces", "Workspace and tenant boundaries."},
		{"Groups", "Hierarchical groups inside a Space."},
		{"Members", "Delegatable Member identities inside a Space."},
		{"User Members", "Explicit User-to-Member bindings."},
		{"Roles", "Roles and scoped MemberRole grants."},
		{"Permissions", "Permission definitions and role-permission bindings."},
		{"Resource Types", "Resource registry declarations, actions, and mappings."},
		{"Resources", "Protected resource records."},
		{"App Data", "Generic space-scoped business data models and records governed by Plystra authorization."},
		{"Data Console", "Feature-flagged preview data API; disabled by default."},
		{"Audit", "Append-only audit log query endpoints."},
		{"Plugins", "Preview plugin metadata, lifecycle flags, settings, and generated metadata; not a stable plugin runtime."},
		{"Templates", "Preview template catalog and install-flow metadata; not a stable template ecosystem."},
	}
	out := make([]openapi3.Tag, 0, len(tags))
	for _, tag := range tags {
		out = append(out, *new(openapi3.Tag).WithName(tag.name).WithDescription(tag.description))
	}
	return out
}

func openAPIRoutes() []openAPIRoute {
	return []openAPIRoute{
		{Method: http.MethodGet, Path: "/api/v1/health", Tag: "System", ID: "getHealth", Summary: "Get health status", Response: new(openAPIEnvelope[openAPIHealth]), Security: openAPIPublic},
		{Method: http.MethodGet, Path: "/api/v1/ready", Tag: "System", ID: "getReadiness", Summary: "Get readiness status", Response: new(openAPIEnvelope[openAPIReady]), Security: openAPIPublic},
		{Method: http.MethodGet, Path: "/api/v1/version", Tag: "System", ID: "getVersion", Summary: "Get Core version", Response: new(openAPIEnvelope[openAPIVersionResponse]), Security: openAPIPublic},
		{Method: http.MethodGet, Path: "/metrics", Tag: "System", ID: "getMetrics", Summary: "Get Prometheus metrics", Response: new(string), ContentType: "text/plain", Security: openAPIMetrics},
		{Method: http.MethodGet, Path: "/api/v1/console/overview", Tag: "Console", ID: "getConsoleOverview", Summary: "Get admin console overview", Response: new(openAPIEnvelope[openAPIOverviewResponse]), Security: openAPIAdmin},

		{Method: http.MethodPost, Path: "/api/v1/auth/register", Tag: "Auth", ID: "register", Summary: "Register a user", Description: "Registration is disabled by default. Token-protected ordinary registration creates a user, default Member, UserMember binding, Space admin grant, and session inside the deployment-level Simple Mode default Space. First-super-admin bootstrap requires PLYSTRA_BOOTSTRAP_REGISTRATION_ENABLED plus PLYSTRA_BOOTSTRAP_REGISTRATION_TOKEN. Public user-only registration with PLYSTRA_AUTH_PUBLIC_USER_REGISTRATION_ENABLED creates only a User and does not create a Member, UserMember binding, admin grant, or session.", Body: new(authRegisterRequest), Response: new(openAPIEnvelope[openAPIRegisterResponse]), Status: http.StatusCreated, Security: openAPIPublic},
		{Method: http.MethodPost, Path: "/api/v1/auth/login", Tag: "Auth", ID: "login", Summary: "Create a user session", Body: new(authLoginRequest), Response: new(openAPIEnvelope[openAPILoginResponse]), Security: openAPIPublic},
		{Method: http.MethodPost, Path: "/api/v1/auth/refresh", Tag: "Auth", ID: "refreshSession", Summary: "Rotate access and refresh tokens", Body: new(authRefreshRequest), Response: new(openAPIEnvelope[openAPIRefreshResponse]), Security: openAPIPublic},
		{Method: http.MethodPost, Path: "/api/v1/auth/logout", Tag: "Auth", ID: "logout", Summary: "Revoke a session token", Body: new(authLogoutRequest), Response: new(openAPIEnvelope[openAPILogoutResponse]), Security: openAPIPublic},
		{Method: http.MethodGet, Path: "/api/v1/actor/context", Tag: "Actor", ID: "getActorContext", Summary: "Get current actor context", Response: new(openAPIEnvelope[openAPIActorContextResponse]), Security: openAPISession},
		{Method: http.MethodPost, Path: "/api/v1/actor/switch-member", Tag: "Actor", ID: "switchMember", Summary: "Switch active Member for a session", Body: new(switchMemberRequest), Response: new(openAPIEnvelope[openAPIActorContextResponse]), Security: openAPISession},

		{Method: http.MethodGet, Path: "/api/v1/admin/me", Tag: "Admin", ID: "getAdminMe", Summary: "Inspect current admin principal", Response: new(openAPIEnvelope[openAPIAdminMeResponse]), Security: openAPIAdmin},
		{Method: http.MethodGet, Path: "/api/v1/admin/grants", Tag: "Admin", ID: "listAdminGrants", Summary: "List admin grants", Params: new(openAPILimitQuery), Response: new(openAPIListEnvelope[openAPIAdminGrant]), Security: openAPIAdmin},
		{Method: http.MethodPost, Path: "/api/v1/admin/grants", Tag: "Admin", ID: "createAdminGrant", Summary: "Create an admin grant", Body: new(adminGrantMutationRequest), Response: new(openAPIEnvelope[openAPIAdminGrant]), Status: http.StatusCreated, Security: openAPIAdmin},
		{Method: http.MethodGet, Path: "/api/v1/admin/grants/{admin_grant_id}", Tag: "Admin", ID: "getAdminGrant", Summary: "Get an admin grant", Params: new(struct {
			AdminGrantID string `path:"admin_grant_id"`
		}), Response: new(openAPIEnvelope[openAPIAdminGrant]), Security: openAPIAdmin},
		{Method: http.MethodPost, Path: "/api/v1/admin/grants/{admin_grant_id}/revoke", Tag: "Admin", ID: "revokeAdminGrant", Summary: "Revoke an admin grant", Params: new(struct {
			AdminGrantID string `path:"admin_grant_id"`
		}), Body: new(adminGrantMutationRequest), Response: new(openAPIEnvelope[openAPIAdminGrant]), Security: openAPIAdmin},

		{Method: http.MethodGet, Path: "/api/v1/api-keys", Tag: "API Keys", ID: "listAPIKeys", Summary: "List API keys", Params: new(openAPILimitQuery), Response: new(openAPIListEnvelope[openAPIAPIKey]), Security: openAPIAdmin},
		{Method: http.MethodPost, Path: "/api/v1/api-keys", Tag: "API Keys", ID: "createAPIKey", Summary: "Create a scoped API key", Body: new(apiKeyMutationRequest), Response: new(openAPIEnvelope[openAPIAPIKey]), Status: http.StatusCreated, Security: openAPIAdmin},
		{Method: http.MethodGet, Path: "/api/v1/api-keys/{api_key_id}", Tag: "API Keys", ID: "getAPIKey", Summary: "Get an API key", Params: new(struct {
			APIKeyID string `path:"api_key_id"`
		}), Response: new(openAPIEnvelope[openAPIAPIKey]), Security: openAPIAdmin},
		{Method: http.MethodPost, Path: "/api/v1/api-keys/{api_key_id}/revoke", Tag: "API Keys", ID: "revokeAPIKey", Summary: "Revoke an API key", Params: new(struct {
			APIKeyID string `path:"api_key_id"`
		}), Body: new(apiKeyMutationRequest), Response: new(openAPIEnvelope[openAPIAPIKey]), Security: openAPIAdmin},

		{Method: http.MethodPost, Path: "/api/v1/authz/check", Tag: "Authorization", ID: "checkAuthorization", Summary: "Run authorization check", Body: new(authzRequest), Response: new(openAPIEnvelope[openAPIAuthzCheckResponse]), Security: openAPIAdmin},
		{Method: http.MethodPost, Path: "/api/v1/authz/explain", Tag: "Authorization", ID: "explainAuthorization", Summary: "Run authorization explain trace", Body: new(authzRequest), Response: new(openAPIEnvelope[map[string]any]), Security: openAPIAdmin},

		{Method: http.MethodGet, Path: "/api/v1/users", Tag: "Users", ID: "listUsers", Summary: "List users", Params: new(openAPILimitQuery), Response: new(openAPIListEnvelope[openAPIUser]), Security: openAPIAdmin},
		{Method: http.MethodPost, Path: "/api/v1/users", Tag: "Users", ID: "createUser", Summary: "Create a user", Body: new(userMutationRequest), Response: new(openAPIEnvelope[openAPIUser]), Status: http.StatusCreated, Security: openAPIAdmin},
		{Method: http.MethodGet, Path: "/api/v1/users/{user_id}", Tag: "Users", ID: "getUser", Summary: "Get a user", Params: new(struct {
			UserID string `path:"user_id"`
		}), Response: new(openAPIEnvelope[openAPIUser]), Security: openAPIAdmin},
		{Method: http.MethodPatch, Path: "/api/v1/users/{user_id}", Tag: "Users", ID: "updateUser", Summary: "Update a user", Params: new(struct {
			UserID string `path:"user_id"`
		}), Body: new(userMutationRequest), Response: new(openAPIEnvelope[openAPIUser]), Security: openAPIAdmin},
		{Method: http.MethodPost, Path: "/api/v1/users/{user_id}/disable", Tag: "Users", ID: "disableUser", Summary: "Disable a user", Params: new(struct {
			UserID string `path:"user_id"`
		}), Body: new(userMutationRequest), Response: new(openAPIEnvelope[openAPIUser]), Security: openAPIAdmin},
		{Method: http.MethodPost, Path: "/api/v1/users/{user_id}/restore", Tag: "Users", ID: "restoreUser", Summary: "Restore a user", Params: new(struct {
			UserID string `path:"user_id"`
		}), Body: new(userMutationRequest), Response: new(openAPIEnvelope[openAPIUser]), Security: openAPIAdmin},

		{Method: http.MethodGet, Path: "/api/v1/spaces", Tag: "Spaces", ID: "listSpaces", Summary: "List spaces", Params: new(openAPILimitQuery), Response: new(openAPIListEnvelope[openAPISpace]), Security: openAPIAdmin},
		{Method: http.MethodPost, Path: "/api/v1/spaces", Tag: "Spaces", ID: "createSpace", Summary: "Create a space", Body: new(spaceMutationRequest), Response: new(openAPIEnvelope[openAPISpace]), Status: http.StatusCreated, Security: openAPIAdmin},
		{Method: http.MethodGet, Path: "/api/v1/spaces/{space_id}", Tag: "Spaces", ID: "getSpace", Summary: "Get a space", Params: new(struct {
			SpaceID string `path:"space_id"`
		}), Response: new(openAPIEnvelope[openAPISpace]), Security: openAPIAdmin},
		{Method: http.MethodPatch, Path: "/api/v1/spaces/{space_id}", Tag: "Spaces", ID: "updateSpace", Summary: "Update a space", Params: new(struct {
			SpaceID string `path:"space_id"`
		}), Body: new(spaceMutationRequest), Response: new(openAPIEnvelope[openAPISpace]), Security: openAPIAdmin},
		{Method: http.MethodPost, Path: "/api/v1/spaces/{space_id}/disable", Tag: "Spaces", ID: "disableSpace", Summary: "Disable a space", Params: new(struct {
			SpaceID string `path:"space_id"`
		}), Body: new(spaceMutationRequest), Response: new(openAPIEnvelope[openAPISpace]), Security: openAPIAdmin},
		{Method: http.MethodPost, Path: "/api/v1/spaces/{space_id}/restore", Tag: "Spaces", ID: "restoreSpace", Summary: "Restore a space", Params: new(struct {
			SpaceID string `path:"space_id"`
		}), Body: new(spaceMutationRequest), Response: new(openAPIEnvelope[openAPISpace]), Security: openAPIAdmin},

		{Method: http.MethodGet, Path: "/api/v1/groups/{group_id}", Tag: "Groups", ID: "getGroupByID", Summary: "Get a group by ID", Params: new(struct {
			GroupID string `path:"group_id"`
		}), Response: new(openAPIEnvelope[openAPIGroup]), Security: openAPIAdmin},
		{Method: http.MethodGet, Path: "/api/v1/spaces/{space_id}/groups", Tag: "Groups", ID: "listGroups", Summary: "List groups in a space", Params: new(struct {
			SpaceID string `path:"space_id"`
			Limit   int    `query:"limit" minimum:"1" maximum:"200"`
		}), Response: new(openAPIListEnvelope[openAPIGroup]), Security: openAPIAdmin},
		{Method: http.MethodPost, Path: "/api/v1/spaces/{space_id}/groups", Tag: "Groups", ID: "createGroup", Summary: "Create a group", Params: new(struct {
			SpaceID string `path:"space_id"`
		}), Body: new(groupMutationRequest), Response: new(openAPIEnvelope[openAPIGroup]), Status: http.StatusCreated, Security: openAPIAdmin},
		{Method: http.MethodGet, Path: "/api/v1/spaces/{space_id}/groups/tree", Tag: "Groups", ID: "getGroupTree", Summary: "List groups as a tree", Params: new(struct {
			SpaceID string `path:"space_id"`
		}), Response: new(openAPIListEnvelope[openAPIGroup]), Security: openAPIAdmin},
		{Method: http.MethodGet, Path: "/api/v1/spaces/{space_id}/groups/{group_id}", Tag: "Groups", ID: "getGroup", Summary: "Get a group in a space", Params: new(struct {
			SpaceID string `path:"space_id"`
			GroupID string `path:"group_id"`
		}), Response: new(openAPIEnvelope[openAPIGroup]), Security: openAPIAdmin},
		{Method: http.MethodPatch, Path: "/api/v1/spaces/{space_id}/groups/{group_id}", Tag: "Groups", ID: "updateGroup", Summary: "Update a group", Params: new(struct {
			SpaceID string `path:"space_id"`
			GroupID string `path:"group_id"`
		}), Body: new(groupMutationRequest), Response: new(openAPIEnvelope[openAPIGroup]), Security: openAPIAdmin},
		{Method: http.MethodPost, Path: "/api/v1/spaces/{space_id}/groups/{group_id}/disable", Tag: "Groups", ID: "disableGroup", Summary: "Disable a group", Params: new(struct {
			SpaceID string `path:"space_id"`
			GroupID string `path:"group_id"`
		}), Body: new(groupMutationRequest), Response: new(openAPIEnvelope[openAPIGroup]), Security: openAPIAdmin},

		{Method: http.MethodGet, Path: "/api/v1/members/{member_id}", Tag: "Members", ID: "getMemberByID", Summary: "Get a member by ID", Params: new(struct {
			MemberID string `path:"member_id"`
		}), Response: new(openAPIEnvelope[openAPIMember]), Security: openAPIAdmin},
		{Method: http.MethodGet, Path: "/api/v1/spaces/{space_id}/members", Tag: "Members", ID: "listMembers", Summary: "List members in a space", Params: new(struct {
			SpaceID string `path:"space_id"`
			Limit   int    `query:"limit" minimum:"1" maximum:"200"`
		}), Response: new(openAPIListEnvelope[openAPIMember]), Security: openAPIAdmin},
		{Method: http.MethodPost, Path: "/api/v1/spaces/{space_id}/members", Tag: "Members", ID: "createMember", Summary: "Create a member", Params: new(struct {
			SpaceID string `path:"space_id"`
		}), Body: new(memberMutationRequest), Response: new(openAPIEnvelope[openAPIMember]), Status: http.StatusCreated, Security: openAPIAdmin},
		{Method: http.MethodGet, Path: "/api/v1/spaces/{space_id}/members/{member_id}", Tag: "Members", ID: "getMember", Summary: "Get a member in a space", Params: new(struct {
			SpaceID  string `path:"space_id"`
			MemberID string `path:"member_id"`
		}), Response: new(openAPIEnvelope[openAPIMember]), Security: openAPIAdmin},
		{Method: http.MethodPatch, Path: "/api/v1/spaces/{space_id}/members/{member_id}", Tag: "Members", ID: "updateMember", Summary: "Update a member", Params: new(struct {
			SpaceID  string `path:"space_id"`
			MemberID string `path:"member_id"`
		}), Body: new(memberMutationRequest), Response: new(openAPIEnvelope[openAPIMember]), Security: openAPIAdmin},
		{Method: http.MethodPost, Path: "/api/v1/spaces/{space_id}/members/{member_id}/disable", Tag: "Members", ID: "disableMember", Summary: "Disable a member", Params: new(struct {
			SpaceID  string `path:"space_id"`
			MemberID string `path:"member_id"`
		}), Body: new(memberMutationRequest), Response: new(openAPIEnvelope[openAPIMember]), Security: openAPIAdmin},

		{Method: http.MethodGet, Path: "/api/v1/user-members/{user_member_id}", Tag: "User Members", ID: "getUserMemberByID", Summary: "Get a user-member binding by ID", Params: new(struct {
			UserMemberID string `path:"user_member_id"`
		}), Response: new(openAPIEnvelope[openAPIUserMember]), Security: openAPIAdmin},
		{Method: http.MethodGet, Path: "/api/v1/spaces/{space_id}/user-members", Tag: "User Members", ID: "listUserMembers", Summary: "List user-member bindings", Params: new(struct {
			SpaceID string `path:"space_id"`
			Limit   int    `query:"limit" minimum:"1" maximum:"200"`
		}), Response: new(openAPIListEnvelope[openAPIUserMember]), Security: openAPIAdmin},
		{Method: http.MethodPost, Path: "/api/v1/spaces/{space_id}/user-members", Tag: "User Members", ID: "createUserMember", Summary: "Create a user-member binding", Params: new(struct {
			SpaceID string `path:"space_id"`
		}), Body: new(userMemberMutationRequest), Response: new(openAPIEnvelope[openAPIUserMember]), Status: http.StatusCreated, Security: openAPIAdmin},
		{Method: http.MethodGet, Path: "/api/v1/spaces/{space_id}/user-members/{user_member_id}", Tag: "User Members", ID: "getUserMember", Summary: "Get a user-member binding in a space", Params: new(struct {
			SpaceID      string `path:"space_id"`
			UserMemberID string `path:"user_member_id"`
		}), Response: new(openAPIEnvelope[openAPIUserMember]), Security: openAPIAdmin},
		{Method: http.MethodPatch, Path: "/api/v1/spaces/{space_id}/user-members/{user_member_id}", Tag: "User Members", ID: "updateUserMember", Summary: "Update a user-member binding", Params: new(struct {
			SpaceID      string `path:"space_id"`
			UserMemberID string `path:"user_member_id"`
		}), Body: new(userMemberMutationRequest), Response: new(openAPIEnvelope[openAPIUserMember]), Security: openAPIAdmin},
		{Method: http.MethodPost, Path: "/api/v1/spaces/{space_id}/user-members/{user_member_id}/revoke", Tag: "User Members", ID: "revokeUserMember", Summary: "Revoke a user-member binding", Params: new(struct {
			SpaceID      string `path:"space_id"`
			UserMemberID string `path:"user_member_id"`
		}), Body: new(userMemberMutationRequest), Response: new(openAPIEnvelope[openAPIUserMember]), Security: openAPIAdmin},

		{Method: http.MethodGet, Path: "/api/v1/roles/{role_id}", Tag: "Roles", ID: "getRoleByID", Summary: "Get a role by ID", Params: new(struct {
			RoleID string `path:"role_id"`
		}), Response: new(openAPIEnvelope[openAPIRole]), Security: openAPIAdmin},
		{Method: http.MethodGet, Path: "/api/v1/spaces/{space_id}/roles", Tag: "Roles", ID: "listRoles", Summary: "List roles in a space", Params: new(struct {
			SpaceID string `path:"space_id"`
			Limit   int    `query:"limit" minimum:"1" maximum:"200"`
		}), Response: new(openAPIListEnvelope[openAPIRole]), Security: openAPIAdmin},
		{Method: http.MethodPost, Path: "/api/v1/spaces/{space_id}/roles", Tag: "Roles", ID: "createRole", Summary: "Create a role", Params: new(struct {
			SpaceID string `path:"space_id"`
		}), Body: new(roleMutationRequest), Response: new(openAPIEnvelope[openAPIRole]), Status: http.StatusCreated, Security: openAPIAdmin},
		{Method: http.MethodGet, Path: "/api/v1/spaces/{space_id}/roles/{role_id}", Tag: "Roles", ID: "getRole", Summary: "Get a role in a space", Params: new(struct {
			SpaceID string `path:"space_id"`
			RoleID  string `path:"role_id"`
		}), Response: new(openAPIEnvelope[openAPIRole]), Security: openAPIAdmin},
		{Method: http.MethodPatch, Path: "/api/v1/spaces/{space_id}/roles/{role_id}", Tag: "Roles", ID: "updateRole", Summary: "Update a role", Params: new(struct {
			SpaceID string `path:"space_id"`
			RoleID  string `path:"role_id"`
		}), Body: new(roleMutationRequest), Response: new(openAPIEnvelope[openAPIRole]), Security: openAPIAdmin},
		{Method: http.MethodPost, Path: "/api/v1/spaces/{space_id}/roles/{role_id}/disable", Tag: "Roles", ID: "disableRole", Summary: "Disable a role", Params: new(struct {
			SpaceID string `path:"space_id"`
			RoleID  string `path:"role_id"`
		}), Body: new(roleMutationRequest), Response: new(openAPIEnvelope[openAPIRole]), Security: openAPIAdmin},

		{Method: http.MethodGet, Path: "/api/v1/spaces/{space_id}/member-roles", Tag: "Roles", ID: "listMemberRoles", Summary: "List member role grants", Params: new(struct {
			SpaceID  string `path:"space_id"`
			Limit    int    `query:"limit" minimum:"1" maximum:"200"`
			MemberID string `query:"member_id"`
			RoleID   string `query:"role_id"`
			Status   string `query:"status"`
		}), Response: new(openAPIListEnvelope[openAPIMemberRole]), Security: openAPIAdmin},
		{Method: http.MethodPost, Path: "/api/v1/spaces/{space_id}/member-roles", Tag: "Roles", ID: "createMemberRole", Summary: "Create a member role grant", Params: new(struct {
			SpaceID string `path:"space_id"`
		}), Body: new(memberRoleMutationRequest), Response: new(openAPIEnvelope[openAPIMemberRole]), Status: http.StatusCreated, Security: openAPIAdmin},
		{Method: http.MethodGet, Path: "/api/v1/spaces/{space_id}/member-roles/{member_role_id}", Tag: "Roles", ID: "getMemberRole", Summary: "Get a member role grant", Params: new(struct {
			SpaceID      string `path:"space_id"`
			MemberRoleID string `path:"member_role_id"`
		}), Response: new(openAPIEnvelope[openAPIMemberRole]), Security: openAPIAdmin},
		{Method: http.MethodPost, Path: "/api/v1/spaces/{space_id}/member-roles/{member_role_id}/revoke", Tag: "Roles", ID: "revokeMemberRole", Summary: "Revoke a member role grant", Params: new(struct {
			SpaceID      string `path:"space_id"`
			MemberRoleID string `path:"member_role_id"`
		}), Body: new(memberRoleMutationRequest), Response: new(openAPIEnvelope[openAPIMemberRole]), Security: openAPIAdmin},

		{Method: http.MethodGet, Path: "/api/v1/permissions", Tag: "Permissions", ID: "listPermissions", Summary: "List permissions", Params: new(openAPILimitQuery), Response: new(openAPIListEnvelope[openAPIPermission]), Security: openAPIAdmin},
		{Method: http.MethodPost, Path: "/api/v1/permissions", Tag: "Permissions", ID: "createPermission", Summary: "Create a permission", Body: new(permissionMutationRequest), Response: new(openAPIEnvelope[openAPIPermission]), Status: http.StatusCreated, Security: openAPIAdmin},
		{Method: http.MethodGet, Path: "/api/v1/permissions/{permission_id}", Tag: "Permissions", ID: "getPermission", Summary: "Get a permission", Params: new(struct {
			PermissionID string `path:"permission_id"`
		}), Response: new(openAPIEnvelope[openAPIPermission]), Security: openAPIAdmin},
		{Method: http.MethodPatch, Path: "/api/v1/permissions/{permission_id}", Tag: "Permissions", ID: "updatePermission", Summary: "Update a permission", Params: new(struct {
			PermissionID string `path:"permission_id"`
		}), Body: new(permissionMutationRequest), Response: new(openAPIEnvelope[openAPIPermission]), Security: openAPIAdmin},
		{Method: http.MethodPost, Path: "/api/v1/permissions/{permission_id}/disable", Tag: "Permissions", ID: "disablePermission", Summary: "Disable a permission", Params: new(struct {
			PermissionID string `path:"permission_id"`
		}), Body: new(permissionMutationRequest), Response: new(openAPIEnvelope[openAPIPermission]), Security: openAPIAdmin},
		{Method: http.MethodGet, Path: "/api/v1/role-permissions", Tag: "Permissions", ID: "listRolePermissions", Summary: "List role-permission bindings", Params: new(openAPILimitQuery), Response: new(openAPIListEnvelope[openAPIRolePermission]), Security: openAPIAdmin},
		{Method: http.MethodPost, Path: "/api/v1/role-permissions", Tag: "Permissions", ID: "createRolePermission", Summary: "Create a role-permission binding", Body: new(rolePermissionMutationRequest), Response: new(openAPIEnvelope[openAPIRolePermission]), Status: http.StatusCreated, Security: openAPIAdmin},
		{Method: http.MethodGet, Path: "/api/v1/role-permissions/{role_permission_id}", Tag: "Permissions", ID: "getRolePermission", Summary: "Get a role-permission binding", Params: new(struct {
			RolePermissionID string `path:"role_permission_id"`
		}), Response: new(openAPIEnvelope[openAPIRolePermission]), Security: openAPIAdmin},
		{Method: http.MethodDelete, Path: "/api/v1/role-permissions/{role_permission_id}", Tag: "Permissions", ID: "deleteRolePermission", Summary: "Revoke a role-permission binding", Params: new(struct {
			RolePermissionID string `path:"role_permission_id"`
		}), Body: new(rolePermissionMutationRequest), Response: new(openAPIEnvelope[openAPIRolePermission]), Security: openAPIAdmin},
		{Method: http.MethodGet, Path: "/api/v1/spaces/{space_id}/role-permissions", Tag: "Permissions", ID: "listSpaceRolePermissions", Summary: "List role-permission bindings in a space", Params: new(struct {
			SpaceID string `path:"space_id"`
			Limit   int    `query:"limit" minimum:"1" maximum:"200"`
		}), Response: new(openAPIListEnvelope[openAPIRolePermission]), Security: openAPIAdmin},
		{Method: http.MethodPost, Path: "/api/v1/spaces/{space_id}/role-permissions", Tag: "Permissions", ID: "createSpaceRolePermission", Summary: "Create a role-permission binding in a space", Params: new(struct {
			SpaceID string `path:"space_id"`
		}), Body: new(rolePermissionMutationRequest), Response: new(openAPIEnvelope[openAPIRolePermission]), Status: http.StatusCreated, Security: openAPIAdmin},
		{Method: http.MethodGet, Path: "/api/v1/spaces/{space_id}/role-permissions/{role_permission_id}", Tag: "Permissions", ID: "getSpaceRolePermission", Summary: "Get a role-permission binding in a space", Params: new(struct {
			SpaceID          string `path:"space_id"`
			RolePermissionID string `path:"role_permission_id"`
		}), Response: new(openAPIEnvelope[openAPIRolePermission]), Security: openAPIAdmin},
		{Method: http.MethodDelete, Path: "/api/v1/spaces/{space_id}/role-permissions/{role_permission_id}", Tag: "Permissions", ID: "deleteSpaceRolePermission", Summary: "Revoke a role-permission binding in a space", Params: new(struct {
			SpaceID          string `path:"space_id"`
			RolePermissionID string `path:"role_permission_id"`
		}), Body: new(rolePermissionMutationRequest), Response: new(openAPIEnvelope[openAPIRolePermission]), Security: openAPIAdmin},

		{Method: http.MethodGet, Path: "/api/v1/resource-types", Tag: "Resource Types", ID: "listResourceTypes", Summary: "List resource types", Params: new(openAPILimitQuery), Response: new(openAPIListEnvelope[openAPIResourceType]), Security: openAPIAdmin},
		{Method: http.MethodPost, Path: "/api/v1/resource-types", Tag: "Resource Types", ID: "upsertResourceType", Summary: "Register or update a resource type", Body: new(resourceTypeMutationRequest), Response: new(openAPIEnvelope[openAPIResourceType]), Status: http.StatusCreated, Security: openAPIAdmin},
		{Method: http.MethodGet, Path: "/api/v1/resource-types/{resource_type}", Tag: "Resource Types", ID: "getResourceType", Summary: "Get a resource type", Params: new(struct {
			ResourceType string `path:"resource_type"`
		}), Response: new(openAPIEnvelope[openAPIResourceType]), Security: openAPIAdmin},
		{Method: http.MethodGet, Path: "/api/v1/resource-types/{resource_type}/actions", Tag: "Resource Types", ID: "listResourceActions", Summary: "List resource actions", Params: new(struct {
			ResourceType string `path:"resource_type"`
		}), Response: new(openAPIListEnvelope[openAPIResourceAction]), Security: openAPIAdmin},
		{Method: http.MethodPost, Path: "/api/v1/resource-types/{resource_type}/actions", Tag: "Resource Types", ID: "upsertResourceAction", Summary: "Register or update a resource action", Params: new(struct {
			ResourceType string `path:"resource_type"`
		}), Body: new(resourceActionMutationRequest), Response: new(openAPIEnvelope[openAPIResourceAction]), Status: http.StatusCreated, Security: openAPIAdmin},
		{Method: http.MethodGet, Path: "/api/v1/resource-types/{resource_type}/mapping", Tag: "Resource Types", ID: "getResourceMapping", Summary: "Get resource mapping", Params: new(struct {
			ResourceType string `path:"resource_type"`
		}), Response: new(openAPIEnvelope[openAPIResourceMapping]), Security: openAPIAdmin},
		{Method: http.MethodPost, Path: "/api/v1/resource-types/{resource_type}/mapping", Tag: "Resource Types", ID: "upsertResourceMapping", Summary: "Register or update resource mapping", Params: new(struct {
			ResourceType string `path:"resource_type"`
		}), Body: new(resourceMappingMutationRequest), Response: new(openAPIEnvelope[openAPIResourceMapping]), Status: http.StatusCreated, Security: openAPIAdmin},

		{Method: http.MethodGet, Path: "/api/v1/resources", Tag: "Resources", ID: "listResources", Summary: "List resources", Params: new(openAPIResourceListQuery), Response: new(openAPIListEnvelope[openAPIResource]), Security: openAPIAdmin},
		{Method: http.MethodPost, Path: "/api/v1/resources", Tag: "Resources", ID: "createResource", Summary: "Create a resource", Body: new(resourceMutationRequest), Response: new(openAPIEnvelope[openAPIResource]), Status: http.StatusCreated, Security: openAPIAdmin},
		{Method: http.MethodGet, Path: "/api/v1/resources/{resource_type}/{resource_id}", Tag: "Resources", ID: "getResourceByTypeAndID", Summary: "Get a resource by type and ID", Params: new(struct {
			ResourceType string `path:"resource_type"`
			ResourceID   string `path:"resource_id"`
		}), Response: new(openAPIEnvelope[openAPIResource]), Security: openAPIAdmin},
		{Method: http.MethodGet, Path: "/api/v1/spaces/{space_id}/resources", Tag: "Resources", ID: "listSpaceResources", Summary: "List resources in a space", Params: new(struct {
			SpaceID      string `path:"space_id"`
			ResourceType string `query:"resource_type"`
			Limit        int    `query:"limit" minimum:"1" maximum:"200"`
		}), Response: new(openAPIListEnvelope[openAPIResource]), Security: openAPIAdmin},
		{Method: http.MethodPost, Path: "/api/v1/spaces/{space_id}/resources", Tag: "Resources", ID: "createSpaceResource", Summary: "Create a resource in a space", Params: new(struct {
			SpaceID string `path:"space_id"`
		}), Body: new(resourceMutationRequest), Response: new(openAPIEnvelope[openAPIResource]), Status: http.StatusCreated, Security: openAPIAdmin},
		{Method: http.MethodGet, Path: "/api/v1/spaces/{space_id}/resources/{resource_id}", Tag: "Resources", ID: "getSpaceResource", Summary: "Get a resource in a space", Params: new(struct {
			SpaceID    string `path:"space_id"`
			ResourceID string `path:"resource_id"`
		}), Response: new(openAPIEnvelope[openAPIResource]), Security: openAPIAdmin},
		{Method: http.MethodPatch, Path: "/api/v1/spaces/{space_id}/resources/{resource_id}", Tag: "Resources", ID: "updateSpaceResource", Summary: "Update a resource in a space", Params: new(struct {
			SpaceID    string `path:"space_id"`
			ResourceID string `path:"resource_id"`
		}), Body: new(resourceMutationRequest), Response: new(openAPIEnvelope[openAPIResource]), Security: openAPIAdmin},
		{Method: http.MethodPost, Path: "/api/v1/spaces/{space_id}/resources/{resource_id}/archive", Tag: "Resources", ID: "archiveSpaceResource", Summary: "Archive a resource", Params: new(struct {
			SpaceID    string `path:"space_id"`
			ResourceID string `path:"resource_id"`
		}), Body: new(resourceMutationRequest), Response: new(openAPIEnvelope[openAPIResource]), Security: openAPIAdmin},

		{Method: http.MethodGet, Path: "/api/v1/spaces/{space_id}/data", Tag: "App Data", ID: "getAppDataSpaceInfo", Summary: "Get app data endpoints for a space", Params: new(struct {
			SpaceID string `path:"space_id"`
		}), Response: new(openAPIEnvelope[map[string]any]), Security: openAPIAdmin},
		{Method: http.MethodGet, Path: "/api/v1/spaces/{space_id}/data/models", Tag: "App Data", ID: "listAppDataModels", Summary: "List app data models", Params: new(struct {
			SpaceID string `path:"space_id"`
			Status  string `query:"status"`
			Limit   int    `query:"limit" minimum:"1" maximum:"200"`
		}), Response: new(openAPIListEnvelope[openAPIAppDataModel]), Security: openAPIAdmin},
		{Method: http.MethodPost, Path: "/api/v1/spaces/{space_id}/data/models", Tag: "App Data", ID: "createAppDataModel", Summary: "Create an app data model", Params: new(struct {
			SpaceID string `path:"space_id"`
		}), Body: new(appDataModelMutationRequest), Response: new(openAPIEnvelope[openAPIAppDataModel]), Status: http.StatusCreated, Security: openAPIAdmin},
		{Method: http.MethodGet, Path: "/api/v1/spaces/{space_id}/data/models/{model_key}", Tag: "App Data", ID: "getAppDataModel", Summary: "Get an app data model", Params: new(struct {
			SpaceID  string `path:"space_id"`
			ModelKey string `path:"model_key"`
		}), Response: new(openAPIEnvelope[openAPIAppDataModel]), Security: openAPIAdmin},
		{Method: http.MethodPatch, Path: "/api/v1/spaces/{space_id}/data/models/{model_key}", Tag: "App Data", ID: "updateAppDataModel", Summary: "Update an app data model", Params: new(struct {
			SpaceID  string `path:"space_id"`
			ModelKey string `path:"model_key"`
		}), Body: new(appDataModelMutationRequest), Response: new(openAPIEnvelope[openAPIAppDataModel]), Security: openAPIAdmin},
		{Method: http.MethodPost, Path: "/api/v1/spaces/{space_id}/data/records/batch", Tag: "App Data", ID: "batchAppDataRecords", Summary: "Apply app data record operations transactionally", Description: "Creates, updates, archives, or soft-deletes up to 25 App Data records across models in the same Space. All record mutations, revisions, and mutation audit rows commit atomically or roll back together.", Params: new(struct {
			SpaceID string `path:"space_id"`
		}), Body: new(appDataRecordBatchRequest), Response: new(openAPIEnvelope[openAPIAppDataRecordBatchResponse]), Security: openAPISession},
		{Method: http.MethodGet, Path: "/api/v1/spaces/{space_id}/data/models/{model_key}/records", Tag: "App Data", ID: "listAppDataRecords", Summary: "List app data records", Params: new(struct {
			SpaceID       string `path:"space_id"`
			ModelKey      string `path:"model_key"`
			Status        string `query:"status"`
			GroupID       string `query:"group_id"`
			OwnerMemberID string `query:"owner_member_id"`
			Visibility    string `query:"visibility"`
			Search        string `query:"search" maxLength:"128"`
			Sort          string `query:"sort" enum:"id,created_at,updated_at,status,visibility"`
			Order         string `query:"order" enum:"asc,desc"`
			Cursor        string `query:"cursor"`
			Limit         int    `query:"limit" minimum:"1" maximum:"200"`
		}), Response: new(openAPIListEnvelope[openAPIAppDataRecord]), Security: openAPISession},
		{Method: http.MethodPost, Path: "/api/v1/spaces/{space_id}/data/models/{model_key}/records", Tag: "App Data", ID: "createAppDataRecord", Summary: "Create an app data record", Params: new(struct {
			SpaceID  string `path:"space_id"`
			ModelKey string `path:"model_key"`
		}), Body: new(appDataRecordMutationRequest), Response: new(openAPIEnvelope[openAPIAppDataRecordResponse]), Status: http.StatusCreated, Security: openAPISession},
		{Method: http.MethodGet, Path: "/api/v1/spaces/{space_id}/data/models/{model_key}/records/{record_id}", Tag: "App Data", ID: "getAppDataRecord", Summary: "Get an app data record", Params: new(struct {
			SpaceID  string `path:"space_id"`
			ModelKey string `path:"model_key"`
			RecordID string `path:"record_id"`
		}), Response: new(openAPIEnvelope[openAPIAppDataRecordResponse]), Security: openAPISession},
		{Method: http.MethodPatch, Path: "/api/v1/spaces/{space_id}/data/models/{model_key}/records/{record_id}", Tag: "App Data", ID: "updateAppDataRecord", Summary: "Update an app data record", Params: new(struct {
			SpaceID  string `path:"space_id"`
			ModelKey string `path:"model_key"`
			RecordID string `path:"record_id"`
		}), Body: new(appDataRecordMutationRequest), Response: new(openAPIEnvelope[openAPIAppDataRecordResponse]), Security: openAPISession},
		{Method: http.MethodDelete, Path: "/api/v1/spaces/{space_id}/data/models/{model_key}/records/{record_id}", Tag: "App Data", ID: "deleteAppDataRecord", Summary: "Soft-delete an app data record", Params: new(struct {
			SpaceID  string `path:"space_id"`
			ModelKey string `path:"model_key"`
			RecordID string `path:"record_id"`
		}), Body: new(appDataRecordMutationRequest), Response: new(openAPIEnvelope[openAPIAppDataRecordResponse]), Security: openAPISession},
		{Method: http.MethodPost, Path: "/api/v1/spaces/{space_id}/data/models/{model_key}/records/{record_id}/archive", Tag: "App Data", ID: "archiveAppDataRecord", Summary: "Archive an app data record", Params: new(struct {
			SpaceID  string `path:"space_id"`
			ModelKey string `path:"model_key"`
			RecordID string `path:"record_id"`
		}), Body: new(appDataRecordMutationRequest), Response: new(openAPIEnvelope[openAPIAppDataRecordResponse]), Security: openAPISession},
		{Method: http.MethodGet, Path: "/api/v1/spaces/{space_id}/data/models/{model_key}/records/{record_id}/revisions", Tag: "App Data", ID: "listAppDataRecordRevisions", Summary: "List app data record revisions", Params: new(struct {
			SpaceID  string `path:"space_id"`
			ModelKey string `path:"model_key"`
			RecordID string `path:"record_id"`
			Limit    int    `query:"limit" minimum:"1" maximum:"200"`
		}), Response: new(openAPIListEnvelope[openAPIAppDataRevision]), Security: openAPISession},
		{Method: http.MethodGet, Path: "/api/v1/app-data/{model_key}/{record_id}", Tag: "App Data", ID: "lookupAppDataRecord", Summary: "Lookup an app data record by model key and ID", Params: new(struct {
			ModelKey string `path:"model_key"`
			RecordID string `path:"record_id"`
		}), Response: new(openAPIEnvelope[openAPIAppDataRecordResponse]), Security: openAPISession},

		{Method: http.MethodGet, Path: "/api/v1/data/tables", Tag: "Data Console", ID: "listDataTables", Summary: "List data-console tables", Params: new(openAPILimitQuery), Response: new(openAPIListEnvelope[openAPIResourceMapping]), Security: openAPIAdmin},
		{Method: http.MethodGet, Path: "/api/v1/data/rows/{resource_type}", Tag: "Data Console", ID: "listDataRows", Summary: "List data rows for a resource type", Params: new(struct {
			ResourceType string `path:"resource_type"`
			SpaceID      string `query:"space_id"`
			Limit        int    `query:"limit" minimum:"1" maximum:"200"`
		}), Response: new(openAPIListEnvelope[openAPIResource]), Security: openAPIAdmin},
		{Method: http.MethodPost, Path: "/api/v1/data/rows/{resource_type}", Tag: "Data Console", ID: "createDataRow", Summary: "Create a data row", Params: new(struct {
			ResourceType string `path:"resource_type"`
		}), Body: new(dataRowMutationRequest), Response: new(openAPIEnvelope[openAPIDataRowMutationResponse]), Status: http.StatusCreated, Security: openAPIAdmin},
		{Method: http.MethodGet, Path: "/api/v1/data/rows/{resource_type}/{resource_id}", Tag: "Data Console", ID: "getDataRow", Summary: "Get a data row", Params: new(struct {
			ResourceType string `path:"resource_type"`
			ResourceID   string `path:"resource_id"`
		}), Response: new(openAPIEnvelope[openAPIResource]), Security: openAPIAdmin},
		{Method: http.MethodPatch, Path: "/api/v1/data/rows/{resource_type}/{resource_id}", Tag: "Data Console", ID: "updateDataRow", Summary: "Update a data row", Params: new(struct {
			ResourceType string `path:"resource_type"`
			ResourceID   string `path:"resource_id"`
		}), Body: new(dataRowMutationRequest), Response: new(openAPIEnvelope[openAPIDataRowMutationResponse]), Security: openAPIAdmin},
		{Method: http.MethodDelete, Path: "/api/v1/data/rows/{resource_type}/{resource_id}", Tag: "Data Console", ID: "deleteDataRow", Summary: "Soft-delete a data row", Params: new(struct {
			ResourceType string `path:"resource_type"`
			ResourceID   string `path:"resource_id"`
		}), Body: new(dataRowMutationRequest), Response: new(openAPIEnvelope[openAPIDataRowMutationResponse]), Security: openAPIAdmin},

		{Method: http.MethodGet, Path: "/api/v1/audit/logs", Tag: "Audit", ID: "listAuditLogs", Summary: "List audit logs", Params: new(openAPIAuditLogQuery), Response: new(openAPIListEnvelope[openAPIAuditLog]), Security: openAPIAdmin},
		{Method: http.MethodGet, Path: "/api/v1/audit/logs/{audit_log_id}", Tag: "Audit", ID: "getAuditLog", Summary: "Get audit log detail", Params: new(struct {
			AuditLogID string `path:"audit_log_id"`
		}), Response: new(openAPIEnvelope[openAPIAuditLog]), Security: openAPIAdmin},
		{Method: http.MethodGet, Path: "/api/v1/spaces/{space_id}/audit-logs", Tag: "Audit", ID: "listSpaceAuditLogs", Summary: "List audit logs in a space", Params: new(struct {
			SpaceID string `path:"space_id"`
			Limit   int    `query:"limit" minimum:"1" maximum:"200"`
		}), Response: new(openAPIListEnvelope[openAPIAuditLog]), Security: openAPIAdmin},
		{Method: http.MethodGet, Path: "/api/v1/spaces/{space_id}/audit-logs/{audit_log_id}", Tag: "Audit", ID: "getSpaceAuditLog", Summary: "Get audit log detail in a space", Params: new(struct {
			SpaceID    string `path:"space_id"`
			AuditLogID string `path:"audit_log_id"`
		}), Response: new(openAPIEnvelope[openAPIAuditLog]), Security: openAPIAdmin},

		{Method: http.MethodPost, Path: "/api/v1/plugins/validate-manifest", Tag: "Plugins", ID: "validatePluginManifest", Summary: "Validate plugin manifest", Body: new(plugins.Manifest), Response: new(openAPIEnvelope[openAPIPluginValidationResponse]), Security: openAPIAdmin},
		{Method: http.MethodPost, Path: "/api/v1/plugins/install", Tag: "Plugins", ID: "installPlugin", Summary: "Install plugin metadata", Body: new(pluginInstallRequest), Response: new(openAPIEnvelope[openAPIPlugin]), Status: http.StatusCreated, Security: openAPIAdmin},
		{Method: http.MethodGet, Path: "/api/v1/plugins", Tag: "Plugins", ID: "listPlugins", Summary: "List plugins", Params: new(openAPILimitQuery), Response: new(openAPIListEnvelope[openAPIPlugin]), Security: openAPIAdmin},
		{Method: http.MethodGet, Path: "/api/v1/plugins/{plugin_key}", Tag: "Plugins", ID: "getPlugin", Summary: "Get plugin metadata", Params: new(struct {
			PluginKey string `path:"plugin_key"`
		}), Response: new(openAPIEnvelope[openAPIPlugin]), Security: openAPIAdmin},
		{Method: http.MethodPost, Path: "/api/v1/plugins/{plugin_key}/enable", Tag: "Plugins", ID: "enablePlugin", Summary: "Enable plugin", Params: new(struct {
			PluginKey string `path:"plugin_key"`
		}), Response: new(openAPIEnvelope[openAPIPlugin]), Security: openAPIAdmin},
		{Method: http.MethodPost, Path: "/api/v1/plugins/{plugin_key}/disable", Tag: "Plugins", ID: "disablePlugin", Summary: "Disable plugin", Params: new(struct {
			PluginKey string `path:"plugin_key"`
		}), Response: new(openAPIEnvelope[openAPIPlugin]), Security: openAPIAdmin},
		{Method: http.MethodPost, Path: "/api/v1/plugins/{plugin_key}/uninstall", Tag: "Plugins", ID: "uninstallPlugin", Summary: "Uninstall plugin", Params: new(struct {
			PluginKey string `path:"plugin_key"`
		}), Response: new(openAPIEnvelope[openAPIPlugin]), Security: openAPIAdmin},
		{Method: http.MethodGet, Path: "/api/v1/plugins/{plugin_key}/settings", Tag: "Plugins", ID: "listPluginSettings", Summary: "List plugin settings", Params: new(struct {
			PluginKey string `path:"plugin_key"`
			SpaceID   string `query:"space_id"`
		}), Response: new(openAPIListEnvelope[openAPIPluginSetting]), Security: openAPIAdmin},
		{Method: http.MethodPatch, Path: "/api/v1/plugins/{plugin_key}/settings", Tag: "Plugins", ID: "updatePluginSettings", Summary: "Update plugin settings", Params: new(struct {
			PluginKey string `path:"plugin_key"`
		}), Body: new(pluginSettingsUpdateRequest), Response: new(openAPIListEnvelope[openAPIPluginSetting]), Security: openAPIAdmin},
		{Method: http.MethodGet, Path: "/api/v1/plugins/{plugin_key}/resources", Tag: "Plugins", ID: "listPluginResources", Summary: "List plugin resource types", Params: new(struct {
			PluginKey string `path:"plugin_key"`
		}), Response: new(openAPIListEnvelope[openAPIResourceType]), Security: openAPIAdmin},
		{Method: http.MethodGet, Path: "/api/v1/plugins/{plugin_key}/permissions", Tag: "Plugins", ID: "listPluginPermissions", Summary: "List plugin permissions", Params: new(struct {
			PluginKey string `path:"plugin_key"`
		}), Response: new(openAPIListEnvelope[openAPIPermission]), Security: openAPIAdmin},
		{Method: http.MethodGet, Path: "/api/v1/plugins/{plugin_key}/audit-events", Tag: "Plugins", ID: "listPluginAuditEvents", Summary: "List plugin audit events", Params: new(struct {
			PluginKey string `path:"plugin_key"`
		}), Response: new(openAPIListEnvelope[openAPIAuditEventType]), Security: openAPIAdmin},
		{Method: http.MethodGet, Path: "/api/v1/plugins/{plugin_key}/admin-menus", Tag: "Plugins", ID: "listPluginAdminMenus", Summary: "List plugin admin menus", Params: new(struct {
			PluginKey string `path:"plugin_key"`
		}), Response: new(openAPIListEnvelope[openAPIPluginAdminMenu]), Security: openAPIAdmin},

		{Method: http.MethodGet, Path: "/api/v1/templates", Tag: "Templates", ID: "listTemplates", Summary: "List templates", Params: new(openAPILimitQuery), Response: new(openAPIListEnvelope[templates.Manifest]), Security: openAPIAdmin},
		{Method: http.MethodGet, Path: "/api/v1/templates/{template_id}", Tag: "Templates", ID: "getTemplate", Summary: "Get template", Params: new(struct {
			TemplateID string `path:"template_id"`
		}), Response: new(openAPIEnvelope[templates.Manifest]), Security: openAPIAdmin},
		{Method: http.MethodPost, Path: "/api/v1/templates/{template_id}/preview-install", Tag: "Templates", ID: "previewTemplateInstall", Summary: "Preview template installation", Params: new(struct {
			TemplateID string `path:"template_id"`
		}), Body: new(templateInstallRequest), Response: new(openAPIEnvelope[map[string]any]), Security: openAPIAdmin},
		{Method: http.MethodPost, Path: "/api/v1/templates/{template_id}/install", Tag: "Templates", ID: "installTemplate", Summary: "Install template", Params: new(struct {
			TemplateID string `path:"template_id"`
		}), Body: new(templateInstallRequest), Response: new(openAPIEnvelope[openAPITemplateInstallResponse]), Status: http.StatusCreated, Security: openAPIAdmin},
	}
}
