package authz

import (
	"context"
	"fmt"
	"time"
)

type Engine struct {
	store Store
	now   func() time.Time
}

func NewEngine(store Store) *Engine {
	return NewEngineWithClock(store, func() time.Time {
		return time.Now().UTC()
	})
}

func NewEngineWithClock(store Store, now func() time.Time) *Engine {
	return &Engine{
		store: store,
		now:   now,
	}
}

func (e *Engine) Check(ctx context.Context, input CheckInput) (*Decision, error) {
	if e == nil || e.store == nil {
		return nil, fmt.Errorf("authz engine requires a store")
	}
	if err := input.Validate(); err != nil {
		return nil, err
	}

	actor, err := e.store.LoadActor(ctx, ActorContext{
		UserID:       input.ActorUserID,
		MemberID:     input.ActorMemberID,
		UserMemberID: input.ActorUserMemberID,
		SpaceID:      input.SpaceID,
	})
	if err != nil {
		return nil, fmt.Errorf("load actor context: %w", err)
	}

	target, err := e.store.LoadTarget(ctx, input.ResourceType, input.ResourceID)
	if err != nil {
		return nil, fmt.Errorf("load target resource: %w", err)
	}

	candidates, err := e.store.LoadPermissionCandidates(ctx, CandidateQuery{
		MemberID:     input.ActorMemberID,
		ResourceType: input.ResourceType,
		Action:       input.Action,
	})
	if err != nil {
		return nil, fmt.Errorf("load permission candidates: %w", err)
	}

	for i := range candidates {
		candidates[i].ScopeCheck = ResolveScope(candidates[i].Permission.Scope, actor, target, candidates[i].ScopeAnchor)
	}

	decision := Decision{
		Actor:             actor,
		Space:             actor.Space,
		Target:            target,
		MatchedCandidates: candidates,
		Audit: AuditContext{
			ActorUserID:       input.ActorUserID,
			ActorMemberID:     input.ActorMemberID,
			ActorUserMemberID: input.ActorUserMemberID,
			SpaceID:           input.SpaceID,
			Action:            input.ResourceType + "." + input.Action,
			ResourceType:      input.ResourceType,
			ResourceID:        input.ResourceID,
		},
	}
	if actor.User.Status != StatusActive {
		return e.finish(ctx, decision, DecisionDeny, denyCodePtr(DenyActorUserInactive), "actor User is not active")
	}
	if actor.Member.Status != StatusActive {
		return e.finish(ctx, decision, DecisionDeny, denyCodePtr(DenyActorMemberInactive), "actor Member is not active")
	}
	if decision.Space.Status != StatusActive {
		return e.finish(ctx, decision, DecisionDeny, denyCodePtr(DenySpaceInactive), "active Space is not active")
	}
	if actor.UserMember.Status != StatusActive {
		return e.finish(ctx, decision, DecisionDeny, denyCodePtr(DenyUserMemberRevoked), "UserMember binding is not active")
	}
	if actor.UserMember.ExpiresAt != nil && actor.UserMember.ExpiresAt.Before(e.now()) {
		return e.finish(ctx, decision, DecisionDeny, denyCodePtr(DenyUserMemberExpired), "UserMember binding has expired")
	}
	if violatesSameSpace(input, actor, target, candidates) {
		return e.finish(ctx, decision, DecisionDeny, denyCodePtr(DenyCrossSpaceViolation), "actor context, grants, and target resource must belong to the same Space")
	}
	if len(candidates) == 0 {
		return e.finish(ctx, decision, DecisionDeny, denyCodePtr(DenyNoMatchingPermission), "no permission grant matched the requested resource and action")
	}

	for _, candidate := range candidates {
		if candidate.ScopeCheck.Covered {
			return e.finish(ctx, decision, DecisionAllow, nil, "at least one matching permission grant covers the target resource")
		}
	}

	code := firstScopeDeny(candidates)
	return e.finish(ctx, decision, DecisionDeny, denyCodePtr(code), "matching permission grants do not cover the target resource scope")
}

func (e *Engine) finish(ctx context.Context, decision Decision, result string, denyCode *DenyCode, reason string) (*Decision, error) {
	decision.Decision = result
	decision.DenyCode = denyCode
	decision.Reason = reason
	decision.Audit.Decision = result
	decision.Audit.DenyCode = denyCode

	if err := e.store.WriteAuditLog(ctx, decision); err != nil {
		return nil, fmt.Errorf("write audit log: %w", err)
	}

	return &decision, nil
}

func violatesSameSpace(input CheckInput, actor ActorSnapshot, target TargetSnapshot, candidates []PermissionCandidate) bool {
	if actor.User.ID != input.ActorUserID ||
		actor.Member.ID != input.ActorMemberID ||
		actor.UserMember.ID != input.ActorUserMemberID ||
		actor.Space.ID != input.SpaceID ||
		actor.UserMember.UserID != actor.User.ID ||
		actor.UserMember.MemberID != actor.Member.ID ||
		actor.UserMember.SpaceID != input.SpaceID ||
		actor.Member.SpaceID != input.SpaceID ||
		target.Resource.SpaceID != input.SpaceID {
		return true
	}

	if target.Group != nil && target.Group.SpaceID != input.SpaceID {
		return true
	}

	for _, candidate := range candidates {
		if candidate.Role.SpaceID != input.SpaceID || candidate.MemberRoleSpaceID != input.SpaceID {
			return true
		}
		if candidate.ScopeAnchor != nil && candidate.ScopeAnchor.SpaceID != input.SpaceID {
			return true
		}
	}

	return false
}

func firstScopeDeny(candidates []PermissionCandidate) DenyCode {
	for _, candidate := range candidates {
		if candidate.ScopeCheck.DenyCode != nil {
			return *candidate.ScopeCheck.DenyCode
		}
	}

	return DenyScopeOutOfBounds
}
