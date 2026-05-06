package authz

type DenyCode string

const (
	DenyActorUserInactive     DenyCode = "ACTOR_USER_INACTIVE"
	DenyActorMemberInactive   DenyCode = "ACTOR_MEMBER_INACTIVE"
	DenyUserMemberRevoked     DenyCode = "USER_MEMBER_REVOKED"
	DenyUserMemberExpired     DenyCode = "USER_MEMBER_EXPIRED"
	DenySpaceInactive         DenyCode = "SPACE_INACTIVE"
	DenyCrossSpaceViolation   DenyCode = "CROSS_SPACE_VIOLATION"
	DenyNoMatchingPermission  DenyCode = "NO_MATCHING_PERMISSION"
	DenyScopeAnchorMissing    DenyCode = "SCOPE_ANCHOR_MISSING"
	DenyTargetGroupMissing    DenyCode = "TARGET_GROUP_MISSING"
	DenyScopeOutOfBounds      DenyCode = "SCOPE_OUT_OF_BOUNDS"
	DenyGlobalScopeDisabled   DenyCode = "GLOBAL_SCOPE_DISABLED"
	DenyInvalidResourceType   DenyCode = "INVALID_RESOURCE_TYPE"
	DenyInvalidResourceAction DenyCode = "INVALID_RESOURCE_ACTION"
)

func denyCodePtr(code DenyCode) *DenyCode {
	return &code
}
