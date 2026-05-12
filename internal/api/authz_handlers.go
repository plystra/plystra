package api

import (
	"encoding/json"
	"net/http"

	"github.com/plystra/plystra/internal/authz"
)

type authzRequest struct {
	Actor        authz.ActorContext `json:"actor"`
	ResourceType string             `json:"resource_type"`
	ResourceID   string             `json:"resource_id"`
	Resource     struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	} `json:"resource"`
	Action  string `json:"action"`
	Explain bool   `json:"explain"`
}

func (req authzRequest) CheckInput() authz.CheckInput {
	resourceType := req.ResourceType
	if resourceType == "" {
		resourceType = req.Resource.Type
	}
	resourceID := req.ResourceID
	if resourceID == "" {
		resourceID = req.Resource.ID
	}
	return authz.CheckInput{
		Actor:        req.Actor,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Action:       req.Action,
		Explain:      req.Explain,
	}
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
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Request body is invalid JSON.", err.Error())
		return
	}
	input := req.CheckInput()
	input.RequestID = requestIDFrom(r)
	input.IP = remoteIPFrom(r)
	input.UserAgent = r.UserAgent()
	input.Explain = explain || req.Explain
	if principal, ok := adminPrincipalFrom(r); ok {
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
		}
		scope := adminRequirement{
			PermissionKey: "authz:check",
			SpaceID:       firstNonEmpty(input.SpaceID, input.Actor.SpaceID),
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

func actorContextEmpty(actor authz.ActorContext) bool {
	return actor.UserID == "" && actor.SpaceID == "" && actor.MemberID == "" && actor.UserMemberID == ""
}
