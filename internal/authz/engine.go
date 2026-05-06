package authz

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
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
	actorContext := input.NormalizedActor()

	loaded, err := e.loadAuthorizationContext(ctx, input)
	if err != nil {
		return nil, err
	}
	actor := loaded.Actor
	registry := loaded.ResourceRegistry
	registryErr := loaded.RegistryErr

	decision := Decision{
		TraceVersion:     "1.0",
		TraceID:          traceIDFromRequest(input.RequestID, e.now()),
		Actor:            actor,
		Space:            actor.Space,
		ResourceRegistry: registry,
		Request: RequestMetadata{
			RequestID: input.RequestID,
			IP:        input.IP,
			UserAgent: input.UserAgent,
		},
		Audit: AuditContext{
			ActorUserID:       actorContext.UserID,
			ActorMemberID:     actorContext.MemberID,
			ActorUserMemberID: actorContext.UserMemberID,
			SpaceID:           actorContext.SpaceID,
			Action:            input.ResourceType + "." + input.Action,
			ResourceType:      input.ResourceType,
			ResourceID:        input.ResourceID,
			RequestID:         input.RequestID,
		},
	}
	if registryErr == ErrResourceTypeNotFound {
		if code, reason, denied := validateActorState(actor, e.now()); denied {
			return e.finish(ctx, decision, DecisionDeny, denyCodePtr(code), reason)
		}
		return e.finish(ctx, decision, DecisionDeny, denyCodePtr(DenyInvalidResourceType), "resource type is not registered")
	}
	if registryErr == ErrResourceActionNotFound {
		if code, reason, denied := validateActorState(actor, e.now()); denied {
			return e.finish(ctx, decision, DecisionDeny, denyCodePtr(code), reason)
		}
		return e.finish(ctx, decision, DecisionDeny, denyCodePtr(DenyInvalidResourceAction), "resource action is not registered for the resource type")
	}

	target := loaded.Target
	candidates := loaded.PermissionGrants

	for i := range candidates {
		candidates[i].ScopeCheck = ResolveScope(candidates[i].Permission.Scope, actor, target, candidates[i].ScopeAnchor)
	}
	decision.Target = target
	decision.MatchedCandidates = candidates

	if code, reason, denied := validateActorState(actor, e.now()); denied {
		return e.finish(ctx, decision, DecisionDeny, denyCodePtr(code), reason)
	}
	if violatesSameSpace(actorContext, actor, target, candidates) {
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
	if decision.TraceVersion == "" {
		decision.TraceVersion = "1.0"
	}
	if decision.TraceID == "" {
		decision.TraceID = traceIDFromRequest(decision.Request.RequestID, e.now())
	}
	if decision.Audit.ID == "" {
		decision.Audit.ID = auditIDFromTraceID(decision.TraceID)
	}
	decision.Audit.Decision = result
	decision.Audit.DenyCode = denyCode

	if err := e.store.WriteAuditLog(ctx, decision); err != nil {
		return nil, fmt.Errorf("write audit log: %w", err)
	}

	return &decision, nil
}

func (e *Engine) loadAuthorizationContext(ctx context.Context, input CheckInput) (AuthorizationContext, error) {
	if loader, ok := e.store.(AuthorizationContextLoader); ok {
		loaded, err := loader.LoadAuthorizationContext(ctx, input)
		if err != nil {
			return AuthorizationContext{}, fmt.Errorf("load authorization context: %w", err)
		}
		return loaded, nil
	}

	actorContext := input.NormalizedActor()
	actor, err := e.store.LoadActor(ctx, actorContext)
	if err != nil {
		return AuthorizationContext{}, fmt.Errorf("load actor context: %w", err)
	}

	registry, err := e.store.LoadResourceRegistration(ctx, input.ResourceType, input.Action)
	if err != nil && err != ErrResourceTypeNotFound && err != ErrResourceActionNotFound {
		return AuthorizationContext{}, fmt.Errorf("load resource registry metadata: %w", err)
	}
	if err == ErrResourceTypeNotFound || err == ErrResourceActionNotFound {
		return AuthorizationContext{
			Actor:            actor,
			ResourceRegistry: registry,
			RegistryErr:      err,
		}, nil
	}

	target, err := e.loadTarget(ctx, input)
	if err != nil {
		return AuthorizationContext{}, err
	}

	candidates, err := e.store.LoadPermissionCandidates(ctx, CandidateQuery{
		MemberID:     actorContext.MemberID,
		ResourceType: input.ResourceType,
		Action:       input.Action,
	})
	if err != nil {
		return AuthorizationContext{}, fmt.Errorf("load permission candidates: %w", err)
	}

	return AuthorizationContext{
		Actor:              actor,
		ResourceRegistry:   registry,
		Target:             target,
		PermissionGrants:   candidates,
		PermissionFiltered: true,
	}, nil
}

func (e *Engine) loadTarget(ctx context.Context, input CheckInput) (TargetSnapshot, error) {
	if input.Target != nil {
		target := *input.Target
		if target.Resource.ID == "" {
			target.Resource.ID = input.ResourceID
		}
		if target.Resource.Type == "" {
			target.Resource.Type = input.ResourceType
		}
		return target, nil
	}

	target, err := e.store.LoadTarget(ctx, input.ResourceType, input.ResourceID)
	if err != nil {
		return TargetSnapshot{}, fmt.Errorf("load target resource: %w", err)
	}
	return target, nil
}

func validateActorState(actor ActorSnapshot, now time.Time) (DenyCode, string, bool) {
	if actor.User.Status != StatusActive {
		return DenyActorUserInactive, "actor User is not active", true
	}
	if actor.Member.Status != StatusActive {
		return DenyActorMemberInactive, "actor Member is not active", true
	}
	if actor.Space.Status != StatusActive {
		return DenySpaceInactive, "active Space is not active", true
	}
	if actor.UserMember.Status != StatusActive {
		return DenyUserMemberRevoked, "UserMember binding is not active", true
	}
	if actor.UserMember.ExpiresAt != nil && actor.UserMember.ExpiresAt.Before(now) {
		return DenyUserMemberExpired, "UserMember binding has expired", true
	}
	return "", "", false
}

func violatesSameSpace(input ActorContext, actor ActorSnapshot, target TargetSnapshot, candidates []PermissionCandidate) bool {
	if actor.User.ID != input.UserID ||
		actor.Member.ID != input.MemberID ||
		actor.UserMember.ID != input.UserMemberID ||
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

func traceIDFromRequest(requestID string, now time.Time) string {
	return randomID("trc", now)
}

func auditIDFromTraceID(traceID string) string {
	if traceID == "" {
		return ""
	}
	return "audit_" + strings.TrimPrefix(traceID, "trc_")
}

func randomID(prefix string, now time.Time) string {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err == nil {
		return prefix + "_" + hex.EncodeToString(buf[:])
	}
	return prefix + "_" + strconv.FormatInt(now.UTC().UnixNano(), 36)
}
