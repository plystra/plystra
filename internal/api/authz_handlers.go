package api

import (
	"encoding/json"
	"net/http"

	"github.com/plystra/plystra/internal/authz"
)

type authzRequest struct {
	Actor             authz.ActorContext `json:"actor"`
	ActorUserID       string             `json:"actor_user_id"`
	ActorMemberID     string             `json:"actor_member_id"`
	ActorUserMemberID string             `json:"actor_user_member_id"`
	SpaceID           string             `json:"space_id"`
	ResourceType      string             `json:"resource_type"`
	ResourceID        string             `json:"resource_id"`
	Resource          struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	} `json:"resource"`
	Action    string `json:"action"`
	Explain   bool   `json:"explain"`
	RequestID string `json:"request_id"`
	IP        string `json:"ip"`
	UserAgent string `json:"user_agent"`
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
		Actor:             req.Actor,
		ActorUserID:       req.ActorUserID,
		ActorMemberID:     req.ActorMemberID,
		ActorUserMemberID: req.ActorUserMemberID,
		SpaceID:           req.SpaceID,
		ResourceType:      resourceType,
		ResourceID:        resourceID,
		Action:            req.Action,
		Explain:           req.Explain,
		RequestID:         req.RequestID,
		IP:                req.IP,
		UserAgent:         req.UserAgent,
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Request body is invalid JSON.", err.Error())
		return
	}
	input := req.CheckInput()
	input.RequestID = requestIDFrom(r)
	input.IP = remoteIPFrom(r)
	input.UserAgent = r.UserAgent()
	input.Explain = explain || req.Explain

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
