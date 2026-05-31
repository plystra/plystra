package api

import (
	"context"
	"net/http"
	"strings"

	"github.com/plystra/plystra/internal/authz"
)

type authzRequest struct {
	Actor        authz.ActorContext   `json:"actor"`
	ResourceType string               `json:"resource_type"`
	ResourceID   string               `json:"resource_id"`
	Resource     authzResourceContext `json:"resource"`
	Grants       []authz.GrantContext `json:"grants"`
	Action       string               `json:"action"`
	Explain      bool                 `json:"explain"`
}

type authzResourceContext struct {
	Type          string         `json:"type"`
	ID            string         `json:"id"`
	ExternalID    string         `json:"external_id"`
	SpaceID       string         `json:"space_id"`
	GroupID       string         `json:"group_id"`
	GroupPath     string         `json:"group_path"`
	OwnerMemberID string         `json:"owner_member_id"`
	DisplayName   string         `json:"display_name"`
	Visibility    string         `json:"visibility"`
	Status        string         `json:"status"`
	Metadata      map[string]any `json:"metadata"`
}

func (req authzRequest) CheckInput() authz.CheckInput {
	resourceType := req.ResourceType
	if resourceType == "" {
		resourceType = req.Resource.Type
	}
	resourceID := req.ResourceID
	if resourceID == "" {
		resourceID = firstNonEmpty(req.Resource.ID, req.Resource.ExternalID)
	}
	var target *authz.TargetSnapshot
	if req.Resource.hasInlineContext() {
		target = &authz.TargetSnapshot{
			Resource: authz.ResourceSnapshot{
				ID:            req.Resource.ID,
				ExternalID:    req.Resource.ExternalID,
				Type:          req.Resource.Type,
				SpaceID:       req.Resource.SpaceID,
				GroupID:       req.Resource.GroupID,
				GroupPath:     req.Resource.GroupPath,
				OwnerMemberID: req.Resource.OwnerMemberID,
				DisplayName:   req.Resource.DisplayName,
				Visibility:    req.Resource.Visibility,
				Status:        req.Resource.Status,
				Metadata:      req.Resource.Metadata,
			},
		}
	}
	return authz.CheckInput{
		Actor:        req.Actor,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Target:       target,
		InlineGrants: req.Grants,
		Action:       req.Action,
		Explain:      req.Explain,
	}
}

func (res authzResourceContext) hasInlineContext() bool {
	return res.SpaceID != "" ||
		res.ExternalID != "" ||
		res.GroupID != "" ||
		res.GroupPath != "" ||
		res.OwnerMemberID != "" ||
		res.DisplayName != "" ||
		res.Visibility != "" ||
		res.Status != "" ||
		len(res.Metadata) > 0
}

func (req authzRequest) usesInlineContext() bool {
	return req.Resource.hasInlineContext() || len(req.Grants) > 0 || actorUsesInlineMetadata(req.Actor)
}

func (req authzRequest) requiresPureInlineContext() bool {
	return len(req.Grants) > 0 || actorUsesInlineMetadata(req.Actor)
}

func actorUsesInlineMetadata(actor authz.ActorContext) bool {
	return actor.UserEmail != "" ||
		actor.UserStatus != "" ||
		actor.MemberName != "" ||
		actor.MemberStatus != "" ||
		actor.BindingStatus != "" ||
		actor.RelationType != "" ||
		actor.SpaceName != "" ||
		actor.SpaceStatus != ""
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
	if !decodeJSON(w, r, &req) {
		return
	}
	input := req.CheckInput()
	input.Actor = input.Actor.Normalized()
	input.RequestID = requestIDFrom(r)
	input.IP = remoteIPFrom(r)
	input.UserAgent = r.UserAgent()
	input.Explain = explain || req.Explain
	if principal, ok := adminPrincipalFrom(r); ok {
		if req.usesInlineContext() {
			if principal.CredentialType != "api_key" {
				writeError(w, r, http.StatusForbidden, "INLINE_CONTEXT_REQUIRES_API_KEY", "Inline actor, resource, or grant context requires a server-side API key.", nil)
				return
			}
			input.InlineContext = req.requiresPureInlineContext()
		}
		if actorContextEmpty(input.Actor) {
			if principal.CredentialType != "session" {
				writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "actor is required when using an API key.", nil)
				return
			}
			actor, _, err := s.actorForSession(r.Context(), principal.Session)
			if err != nil {
				writeError(w, r, http.StatusForbidden, "ACTIVE_MEMBER_REQUIRED", "Session has no active Member binding.", nil)
				return
			}
			input.Actor = authz.ActorContext{
				UserID:       stringMapValue(actor, "user_id"),
				SpaceID:      stringMapValue(actor, "space_id"),
				MemberID:     stringMapValue(actor, "member_id"),
				UserMemberID: stringMapValue(actor, "user_member_id"),
			}
		} else if principal.CredentialType == "session" {
			actor, err := s.actorBindingForUser(r.Context(), principal.Session.UserID, input.Actor.MemberID, input.Actor.UserMemberID)
			if err != nil {
				writeError(w, r, http.StatusForbidden, "ACTIVE_MEMBER_REQUIRED", "Requested actor is not active for this User.", nil)
				return
			}
			if input.Actor.SpaceID != "" && input.Actor.SpaceID != stringMapValue(actor, "space_id") {
				writeError(w, r, http.StatusForbidden, "ACTIVE_MEMBER_REQUIRED", "Requested actor does not belong to that Space.", nil)
				return
			}
			input.Actor = authz.ActorContext{
				UserID:       stringMapValue(actor, "user_id"),
				SpaceID:      stringMapValue(actor, "space_id"),
				MemberID:     stringMapValue(actor, "member_id"),
				UserMemberID: stringMapValue(actor, "user_member_id"),
			}
		}
		input = input.Normalized()
		if input.InlineContext {
			if err := authz.ValidateInlineContextInput(input); err != nil {
				writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Inline authorization context is invalid.", err.Error())
				return
			}
			for _, scope := range inlineContextScopeRequirements(input) {
				allowed, err := s.adminPrincipalAllows(r.Context(), principal, scope)
				if err != nil {
					writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to evaluate inline authz scope.", err.Error())
					return
				}
				if !allowed {
					writeError(w, r, http.StatusForbidden, "ADMIN_PERMISSION_REQUIRED", "The current credential cannot run authz checks for this inline context scope.", map[string]any{"permission": "authz:check"})
					return
				}
			}
		}
		scope := adminRequirement{
			PermissionKey: "authz:check",
			SpaceID:       firstNonEmpty(input.SpaceID, input.Actor.SpaceID, inlineTargetSpaceID(input.Target)),
			EntityKind:    "resource",
			EntityID:      input.ResourceID,
		}
		resolvedScope, err := s.resolveAdminRequirementScope(r.Context(), scope)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to resolve authz scope.", err.Error())
			return
		}
		if !adminPrincipalHasInstanceReach(principal, "authz:check") && resolvedScope.SpaceID == "" && resolvedScope.GroupID == "" {
			writeError(w, r, http.StatusForbidden, "ADMIN_PERMISSION_REQUIRED", "Scoped credentials must provide or resolve a Space or Group for authz checks.", map[string]any{"permission": "authz:check"})
			return
		}
		allowed, err := s.adminPrincipalAllows(r.Context(), principal, resolvedScope)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to evaluate authz scope.", err.Error())
			return
		}
		if !allowed {
			writeError(w, r, http.StatusForbidden, "ADMIN_PERMISSION_REQUIRED", "The current credential cannot run authz checks for this scope.", map[string]any{"permission": "authz:check"})
			return
		}
	}

	decision, err := authz.Check(r.Context(), s.authzStore, input)
	if s.kernel != nil {
		decision, err = s.authzViaKernel(r, input)
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Authorization check failed.", err.Error())
		return
	}
	w.Header().Set("X-Plystra-Trace-ID", decision.TraceID)
	if decision.Audit.ID != "" {
		w.Header().Set("X-Plystra-Audit-Log-ID", decision.Audit.ID)
	}
	if input.Explain {
		writeData(w, r, http.StatusOK, decision)
		return
	}
	writeData(w, r, http.StatusOK, map[string]any{
		"allow":        decision.IsAllowed(),
		"decision":     decision.Decision,
		"deny_code":    decision.DenyCode,
		"reason":       decision.Reason,
		"trace_id":     decision.TraceID,
		"audit_log_id": decision.Audit.ID,
		"audit":        decision.Audit,
	})
}

func (s *Server) authzViaKernel(r *http.Request, input authz.CheckInput) (*authz.Decision, error) {
	input = input.Normalized()
	loaded, err := s.preloadAuthorizationContext(r.Context(), input)
	if err != nil {
		return nil, err
	}
	input.PreloadedContext = &loaded
	service, ok := s.kernel.AuthorizationService()
	if !ok {
		return nil, authz.ErrNotFound
	}
	if input.Explain {
		return service.Explain(r.Context(), input)
	}
	return service.Check(r.Context(), input)
}

func (s *Server) preloadAuthorizationContext(ctx context.Context, input authz.CheckInput) (authz.AuthorizationContext, error) {
	if input.InlineContext {
		return authz.BuildInlineAuthorizationContext(ctx, s.authzStore, input)
	}
	if loader, ok := s.authzStore.(authz.AuthorizationContextLoader); ok {
		return loader.LoadAuthorizationContext(ctx, input)
	}
	actorContext := input.NormalizedActor()
	actor, err := s.authzStore.LoadActor(ctx, actorContext)
	if err != nil {
		return authz.AuthorizationContext{}, err
	}
	registry, registryErr := s.authzStore.LoadResourceRegistration(ctx, input.ResourceType, input.Action)
	if registryErr != nil {
		return authz.AuthorizationContext{Actor: actor, ResourceRegistry: registry, RegistryErr: registryErr, RegistryError: registryErr.Error()}, nil
	}
	target, err := s.authzStore.LoadTarget(ctx, input.ResourceType, input.ResourceID)
	if err != nil {
		return authz.AuthorizationContext{}, err
	}
	candidates, err := s.authzStore.LoadPermissionCandidates(ctx, authz.CandidateQuery{MemberID: actorContext.MemberID, ResourceType: input.ResourceType, Action: input.Action})
	if err != nil {
		return authz.AuthorizationContext{}, err
	}
	return authz.AuthorizationContext{Actor: actor, ResourceRegistry: registry, Target: target, PermissionGrants: candidates, PermissionFiltered: true}, nil
}

func actorContextEmpty(actor authz.ActorContext) bool {
	actor = actor.Normalized()
	return actor.UserID == "" && actor.SpaceID == "" && actor.MemberID == "" && actor.UserMemberID == ""
}

func inlineTargetSpaceID(target *authz.TargetSnapshot) string {
	if target == nil {
		return ""
	}
	return strings.TrimSpace(target.Resource.SpaceID)
}

func inlineContextScopeRequirements(input authz.CheckInput) []adminRequirement {
	input = input.Normalized()
	requirements := make([]adminRequirement, 0, 2+len(input.InlineGrants))
	seen := map[string]struct{}{}
	add := func(spaceID, groupID string) {
		spaceID = strings.TrimSpace(spaceID)
		groupID = strings.TrimSpace(groupID)
		if spaceID == "" && groupID == "" {
			return
		}
		key := spaceID + "\x00" + groupID
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		requirements = append(requirements, adminRequirement{
			PermissionKey: "authz:check",
			SpaceID:       spaceID,
			GroupID:       groupID,
		})
	}

	add(input.Actor.SpaceID, "")
	if input.Target != nil {
		add(input.Target.Resource.SpaceID, input.Target.Resource.GroupID)
	}
	for _, grant := range input.InlineGrants {
		add(firstNonEmpty(grant.SpaceID, input.Actor.SpaceID), grant.ScopeAnchorGroupID)
	}

	return requirements
}
