package authz

import (
	"context"
	"time"

	contractauthz "github.com/plystra/plystra/internal/kernel/contracts/authz"
)

const (
	StatusActive = contractauthz.StatusActive

	DecisionAllow = contractauthz.DecisionAllow
	DecisionDeny  = contractauthz.DecisionDeny
)

var ErrNotFound = contractauthz.ErrNotFound
var ErrResourceTypeNotFound = contractauthz.ErrResourceTypeNotFound
var ErrResourceActionNotFound = contractauthz.ErrResourceActionNotFound

type Scope = contractauthz.Scope

const (
	ScopeSelf      = contractauthz.ScopeSelf
	ScopeGroup     = contractauthz.ScopeGroup
	ScopeGroupTree = contractauthz.ScopeGroupTree
	ScopeSpace     = contractauthz.ScopeSpace
	ScopeGlobal    = contractauthz.ScopeGlobal
)

type DenyCode = contractauthz.DenyCode

const (
	DenyActorUserInactive     = contractauthz.DenyActorUserInactive
	DenyActorMemberInactive   = contractauthz.DenyActorMemberInactive
	DenyUserMemberRevoked     = contractauthz.DenyUserMemberRevoked
	DenyUserMemberExpired     = contractauthz.DenyUserMemberExpired
	DenySpaceInactive         = contractauthz.DenySpaceInactive
	DenyCrossSpaceViolation   = contractauthz.DenyCrossSpaceViolation
	DenyNoMatchingPermission  = contractauthz.DenyNoMatchingPermission
	DenyScopeAnchorMissing    = contractauthz.DenyScopeAnchorMissing
	DenyTargetGroupMissing    = contractauthz.DenyTargetGroupMissing
	DenyScopeOutOfBounds      = contractauthz.DenyScopeOutOfBounds
	DenyGlobalScopeDisabled   = contractauthz.DenyGlobalScopeDisabled
	DenyInvalidResourceType   = contractauthz.DenyInvalidResourceType
	DenyInvalidResourceAction = contractauthz.DenyInvalidResourceAction
)

type (
	CheckInput                 = contractauthz.CheckInput
	ActorContext               = contractauthz.ActorContext
	CandidateQuery             = contractauthz.CandidateQuery
	Store                      = contractauthz.Store
	AuthorizationContextLoader = contractauthz.AuthorizationContextLoader
	AuthorizationContext       = contractauthz.AuthorizationContext
	ActorSnapshot              = contractauthz.ActorSnapshot
	UserSnapshot               = contractauthz.UserSnapshot
	MemberSnapshot             = contractauthz.MemberSnapshot
	UserMemberSnapshot         = contractauthz.UserMemberSnapshot
	SpaceSnapshot              = contractauthz.SpaceSnapshot
	TargetSnapshot             = contractauthz.TargetSnapshot
	ResourceSnapshot           = contractauthz.ResourceSnapshot
	GroupSnapshot              = contractauthz.GroupSnapshot
	RoleSnapshot               = contractauthz.RoleSnapshot
	PermissionSnapshot         = contractauthz.PermissionSnapshot
	PermissionCandidate        = contractauthz.PermissionCandidate
	GrantContext               = contractauthz.GrantContext
	ScopeCheck                 = contractauthz.ScopeCheck
	AuditContext               = contractauthz.AuditContext
	ResourceRegistrySnapshot   = contractauthz.ResourceRegistrySnapshot
	ResourceTypeSnapshot       = contractauthz.ResourceTypeSnapshot
	ResourceActionSnapshot     = contractauthz.ResourceActionSnapshot
	ResourceMappingSnapshot    = contractauthz.ResourceMappingSnapshot
	RequestMetadata            = contractauthz.RequestMetadata
	Decision                   = contractauthz.Decision
	Engine                     = engine
)

func NewEngine(store Store) *Engine {
	return newEngine(store)
}

func NewEngineWithClock(store Store, now func() time.Time) *Engine {
	return newEngineWithClock(store, now)
}

func Check(ctx context.Context, store Store, input CheckInput) (*Decision, error) {
	return check(ctx, store, input)
}

func Explain(ctx context.Context, store Store, input CheckInput) (*Decision, error) {
	return explain(ctx, store, input)
}

func ResolveScope(scope Scope, actor ActorSnapshot, target TargetSnapshot, anchor *GroupSnapshot) ScopeCheck {
	return resolveScope(scope, actor, target, anchor)
}

func BuildInlineAuthorizationContext(ctx context.Context, store Store, input CheckInput) (AuthorizationContext, error) {
	return buildInlineAuthorizationContext(ctx, store, input)
}

func ValidateInlineContextInput(input CheckInput) error {
	return validateInlineContextInput(input)
}
