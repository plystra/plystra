package capability

const (
	PathDescribe = "/contract/v1/capability/describe"
	PathPrepare  = "/contract/v1/capability/prepare"
	PathStart    = "/contract/v1/capability/start"
	PathHealth   = "/contract/v1/capability/health"
	PathStop     = "/contract/v1/capability/stop"

	PathAuditRecord            = "/contract/v1/audit/record"
	PathAuditQuery             = "/contract/v1/audit/query"
	PathIdentityResolveActor   = "/contract/v1/identity/resolve-actor"
	PathIdentityValidate       = "/contract/v1/identity/validate-user-member"
	PathResourceRegistration   = "/contract/v1/resource/registration"
	PathResourceRegisterType   = "/contract/v1/resource/register-type"
	PathResourceRegisterAction = "/contract/v1/resource/register-action"
	PathAuthorizationCheck     = "/contract/v1/authorization/check"
	PathAuthorizationExplain   = "/contract/v1/authorization/explain"
	PathAdminAuthorize         = "/contract/v1/admin/authorize"
)
