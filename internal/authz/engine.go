package authz

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	contractauthz "github.com/plystra/contracts/authz"
)

type engine struct {
	store contractauthz.Store
	now   func() time.Time
}

func newEngine(store contractauthz.Store) *engine {
	return NewEngineWithClock(store, func() time.Time {
		return time.Now().UTC()
	})
}

func newEngineWithClock(store contractauthz.Store, now func() time.Time) *engine {
	return &engine{store: store, now: now}
}

func check(ctx context.Context, store contractauthz.Store, input contractauthz.CheckInput) (*contractauthz.Decision, error) {
	return newEngine(store).Check(ctx, input)
}

func explain(ctx context.Context, store contractauthz.Store, input contractauthz.CheckInput) (*contractauthz.Decision, error) {
	return check(ctx, store, input)
}

func (e *engine) Check(ctx context.Context, input contractauthz.CheckInput) (*contractauthz.Decision, error) {
	if e == nil || e.store == nil {
		return nil, fmt.Errorf("authz engine requires a store")
	}
	input = input.Normalized()
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
	registryErr := loaded.RegistryError
	if loaded.RegistryErr != nil {
		registryErr = loaded.RegistryErr.Error()
	}

	decision := contractauthz.Decision{
		TraceVersion:     "1.0",
		TraceID:          traceIDFromRequest(input.RequestID, e.now()),
		Actor:            actor,
		Space:            actor.Space,
		ResourceRegistry: registry,
		Request: contractauthz.RequestMetadata{
			RequestID: input.RequestID,
			IP:        input.IP,
			UserAgent: input.UserAgent,
		},
		Audit: contractauthz.AuditContext{
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
	if registryErr == contractauthz.ErrResourceTypeNotFound.Error() {
		if code, reason, denied := validateActorState(actor, e.now()); denied {
			return e.finish(ctx, decision, contractauthz.DecisionDeny, denyCodePtr(code), reason)
		}
		return e.finish(ctx, decision, contractauthz.DecisionDeny, denyCodePtr(contractauthz.DenyInvalidResourceType), "resource type is not registered")
	}
	if registryErr == contractauthz.ErrResourceActionNotFound.Error() {
		if code, reason, denied := validateActorState(actor, e.now()); denied {
			return e.finish(ctx, decision, contractauthz.DecisionDeny, denyCodePtr(code), reason)
		}
		return e.finish(ctx, decision, contractauthz.DecisionDeny, denyCodePtr(contractauthz.DenyInvalidResourceAction), "resource action is not registered for the resource type")
	}

	target := loaded.Target
	candidates := loaded.PermissionGrants
	for i := range candidates {
		candidates[i].ScopeCheck = resolveScope(candidates[i].Permission.Scope, actor, target, candidates[i].ScopeAnchor)
	}
	decision.Target = target
	decision.MatchedCandidates = candidates

	if code, reason, denied := validateActorState(actor, e.now()); denied {
		return e.finish(ctx, decision, contractauthz.DecisionDeny, denyCodePtr(code), reason)
	}
	if violatesSameSpace(actorContext, actor, target, candidates) {
		return e.finish(ctx, decision, contractauthz.DecisionDeny, denyCodePtr(contractauthz.DenyCrossSpaceViolation), "actor context, grants, and target resource must belong to the same Space")
	}
	if len(candidates) == 0 {
		return e.finish(ctx, decision, contractauthz.DecisionDeny, denyCodePtr(contractauthz.DenyNoMatchingPermission), "no permission grant matched the requested resource and action")
	}
	for _, candidate := range candidates {
		if candidate.ScopeCheck.Covered {
			return e.finish(ctx, decision, contractauthz.DecisionAllow, nil, "at least one matching permission grant covers the target resource")
		}
	}
	code := firstScopeDeny(candidates)
	return e.finish(ctx, decision, contractauthz.DecisionDeny, denyCodePtr(code), "matching permission grants do not cover the target resource scope")
}

func (e *engine) finish(ctx context.Context, decision contractauthz.Decision, result string, denyCode *contractauthz.DenyCode, reason string) (*contractauthz.Decision, error) {
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

func (e *engine) loadAuthorizationContext(ctx context.Context, input contractauthz.CheckInput) (contractauthz.AuthorizationContext, error) {
	if input.PreloadedContext != nil {
		return *input.PreloadedContext, nil
	}
	if input.InlineContext {
		loaded, err := buildInlineAuthorizationContext(ctx, e.store, input)
		if err != nil {
			return contractauthz.AuthorizationContext{}, fmt.Errorf("load inline authorization context: %w", err)
		}
		return loaded, nil
	}
	if loader, ok := e.store.(contractauthz.AuthorizationContextLoader); ok {
		loaded, err := loader.LoadAuthorizationContext(ctx, input)
		if err != nil {
			return contractauthz.AuthorizationContext{}, fmt.Errorf("load authorization context: %w", err)
		}
		return loaded, nil
	}

	actorContext := input.NormalizedActor()
	actor, err := e.store.LoadActor(ctx, actorContext)
	if err != nil {
		return contractauthz.AuthorizationContext{}, fmt.Errorf("load actor context: %w", err)
	}
	registry, err := e.store.LoadResourceRegistration(ctx, input.ResourceType, input.Action)
	if err != nil && err != contractauthz.ErrResourceTypeNotFound && err != contractauthz.ErrResourceActionNotFound {
		return contractauthz.AuthorizationContext{}, fmt.Errorf("load resource registry metadata: %w", err)
	}
	if err == contractauthz.ErrResourceTypeNotFound || err == contractauthz.ErrResourceActionNotFound {
		return contractauthz.AuthorizationContext{Actor: actor, ResourceRegistry: registry, RegistryErr: err, RegistryError: err.Error()}, nil
	}
	target, err := e.loadTarget(ctx, input)
	if err != nil {
		return contractauthz.AuthorizationContext{}, err
	}
	candidates, err := e.store.LoadPermissionCandidates(ctx, contractauthz.CandidateQuery{
		MemberID:     actorContext.MemberID,
		ResourceType: input.ResourceType,
		Action:       input.Action,
	})
	if err != nil {
		return contractauthz.AuthorizationContext{}, fmt.Errorf("load permission candidates: %w", err)
	}
	return contractauthz.AuthorizationContext{
		Actor:              actor,
		ResourceRegistry:   registry,
		Target:             target,
		PermissionGrants:   candidates,
		PermissionFiltered: true,
	}, nil
}

func (e *engine) loadTarget(ctx context.Context, input contractauthz.CheckInput) (contractauthz.TargetSnapshot, error) {
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
		return contractauthz.TargetSnapshot{}, fmt.Errorf("load target resource: %w", err)
	}
	return target, nil
}

func validateActorState(actor contractauthz.ActorSnapshot, now time.Time) (contractauthz.DenyCode, string, bool) {
	if actor.User.Status != contractauthz.StatusActive {
		return contractauthz.DenyActorUserInactive, "actor User is not active", true
	}
	if actor.Member.Status != contractauthz.StatusActive {
		return contractauthz.DenyActorMemberInactive, "actor Member is not active", true
	}
	if actor.Space.Status != contractauthz.StatusActive {
		return contractauthz.DenySpaceInactive, "active Space is not active", true
	}
	if actor.UserMember.Status != contractauthz.StatusActive {
		return contractauthz.DenyUserMemberRevoked, "UserMember binding is not active", true
	}
	if actor.UserMember.ExpiresAt != nil && actor.UserMember.ExpiresAt.Before(now) {
		return contractauthz.DenyUserMemberExpired, "UserMember binding has expired", true
	}
	return "", "", false
}

func violatesSameSpace(input contractauthz.ActorContext, actor contractauthz.ActorSnapshot, target contractauthz.TargetSnapshot, candidates []contractauthz.PermissionCandidate) bool {
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

func firstScopeDeny(candidates []contractauthz.PermissionCandidate) contractauthz.DenyCode {
	for _, candidate := range candidates {
		if candidate.ScopeCheck.DenyCode != nil {
			return *candidate.ScopeCheck.DenyCode
		}
	}
	return contractauthz.DenyScopeOutOfBounds
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
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%s_%d", prefix, now.UnixNano())
	}
	return prefix + "_" + hex.EncodeToString(b[:])
}

func denyCodePtr(code contractauthz.DenyCode) *contractauthz.DenyCode {
	return &code
}
