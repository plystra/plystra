package authz

import (
	"context"
	"time"

	systemauthz "github.com/plystra/system-authz"
)

const (
	StatusActive = systemauthz.StatusActive

	DecisionAllow = systemauthz.DecisionAllow
	DecisionDeny  = systemauthz.DecisionDeny
)

var ErrNotFound = systemauthz.ErrNotFound
var ErrResourceTypeNotFound = systemauthz.ErrResourceTypeNotFound
var ErrResourceActionNotFound = systemauthz.ErrResourceActionNotFound

type Scope = systemauthz.Scope

const (
	ScopeSelf      = systemauthz.ScopeSelf
	ScopeGroup     = systemauthz.ScopeGroup
	ScopeGroupTree = systemauthz.ScopeGroupTree
	ScopeSpace     = systemauthz.ScopeSpace
	ScopeGlobal    = systemauthz.ScopeGlobal
)

type DenyCode = systemauthz.DenyCode

const (
	DenyActorUserInactive     = systemauthz.DenyActorUserInactive
	DenyActorMemberInactive   = systemauthz.DenyActorMemberInactive
	DenyUserMemberRevoked     = systemauthz.DenyUserMemberRevoked
	DenyUserMemberExpired     = systemauthz.DenyUserMemberExpired
	DenySpaceInactive         = systemauthz.DenySpaceInactive
	DenyCrossSpaceViolation   = systemauthz.DenyCrossSpaceViolation
	DenyNoMatchingPermission  = systemauthz.DenyNoMatchingPermission
	DenyScopeAnchorMissing    = systemauthz.DenyScopeAnchorMissing
	DenyTargetGroupMissing    = systemauthz.DenyTargetGroupMissing
	DenyScopeOutOfBounds      = systemauthz.DenyScopeOutOfBounds
	DenyGlobalScopeDisabled   = systemauthz.DenyGlobalScopeDisabled
	DenyInvalidResourceType   = systemauthz.DenyInvalidResourceType
	DenyInvalidResourceAction = systemauthz.DenyInvalidResourceAction
)

type (
	CheckInput                 = systemauthz.CheckInput
	ActorContext               = systemauthz.ActorContext
	CandidateQuery             = systemauthz.CandidateQuery
	Store                      = systemauthz.Store
	AuthorizationContextLoader = systemauthz.AuthorizationContextLoader
	AuthorizationContext       = systemauthz.AuthorizationContext
	ActorSnapshot              = systemauthz.ActorSnapshot
	UserSnapshot               = systemauthz.UserSnapshot
	MemberSnapshot             = systemauthz.MemberSnapshot
	UserMemberSnapshot         = systemauthz.UserMemberSnapshot
	SpaceSnapshot              = systemauthz.SpaceSnapshot
	TargetSnapshot             = systemauthz.TargetSnapshot
	ResourceSnapshot           = systemauthz.ResourceSnapshot
	GroupSnapshot              = systemauthz.GroupSnapshot
	RoleSnapshot               = systemauthz.RoleSnapshot
	PermissionSnapshot         = systemauthz.PermissionSnapshot
	PermissionCandidate        = systemauthz.PermissionCandidate
	GrantContext               = systemauthz.GrantContext
	ScopeCheck                 = systemauthz.ScopeCheck
	AuditContext               = systemauthz.AuditContext
	ResourceRegistrySnapshot   = systemauthz.ResourceRegistrySnapshot
	ResourceTypeSnapshot       = systemauthz.ResourceTypeSnapshot
	ResourceActionSnapshot     = systemauthz.ResourceActionSnapshot
	ResourceMappingSnapshot    = systemauthz.ResourceMappingSnapshot
	RequestMetadata            = systemauthz.RequestMetadata
	Decision                   = systemauthz.Decision
	Engine                     = systemauthz.Engine
)

func NewEngine(store Store) *Engine {
	return systemauthz.NewEngine(store)
}

func NewEngineWithClock(store Store, now func() time.Time) *Engine {
	return systemauthz.NewEngineWithClock(store, now)
}

func Check(ctx context.Context, store Store, input CheckInput) (*Decision, error) {
	return systemauthz.Check(ctx, store, input)
}

func Explain(ctx context.Context, store Store, input CheckInput) (*Decision, error) {
	return systemauthz.Explain(ctx, store, input)
}

func ResolveScope(scope Scope, actor ActorSnapshot, target TargetSnapshot, anchor *GroupSnapshot) ScopeCheck {
	return systemauthz.ResolveScope(scope, actor, target, anchor)
}

func BuildInlineAuthorizationContext(ctx context.Context, store Store, input CheckInput) (AuthorizationContext, error) {
	return systemauthz.BuildInlineAuthorizationContext(ctx, store, input)
}

func ValidateInlineContextInput(input CheckInput) error {
	return systemauthz.ValidateInlineContextInput(input)
}
