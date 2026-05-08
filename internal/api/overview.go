package api

import (
	"net/http"

	entsql "entgo.io/ent/dialect/sql"

	"github.com/plystra/plystra/ent/auditlog"
)

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, r)
		return
	}
	ctx := r.Context()
	if s.ent == nil {
		writeError(w, r, http.StatusServiceUnavailable, "NOT_READY", "Ent client is not configured.", nil)
		return
	}
	counts := map[string]int{}
	var err error
	if counts["spaces"], err = s.ent.Space.Query().Count(ctx); err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load overview counts.", err.Error())
		return
	}
	if counts["users"], err = s.ent.User.Query().Count(ctx); err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load overview counts.", err.Error())
		return
	}
	if counts["members"], err = s.ent.Member.Query().Count(ctx); err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load overview counts.", err.Error())
		return
	}
	if counts["user_member_bindings"], err = s.ent.UserMember.Query().Count(ctx); err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load overview counts.", err.Error())
		return
	}
	if counts["groups"], err = s.ent.Group.Query().Count(ctx); err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load overview counts.", err.Error())
		return
	}
	if counts["roles"], err = s.ent.Role.Query().Count(ctx); err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load overview counts.", err.Error())
		return
	}
	if counts["permissions"], err = s.ent.Permission.Query().Count(ctx); err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load overview counts.", err.Error())
		return
	}
	if counts["resource_types"], err = s.ent.ResourceType.Query().Count(ctx); err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load overview counts.", err.Error())
		return
	}
	if counts["resources"], err = s.ent.Resource.Query().Count(ctx); err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load overview counts.", err.Error())
		return
	}
	if counts["audit_logs"], err = s.ent.AuditLog.Query().Count(ctx); err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load overview counts.", err.Error())
		return
	}

	logs, err := s.ent.AuditLog.Query().Order(auditlog.ByCreatedAt(entsql.OrderDesc())).Limit(10).All(ctx)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load recent audit logs.", err.Error())
		return
	}
	recent := make([]map[string]any, 0, len(logs))
	for _, log := range logs {
		recent = append(recent, map[string]any{
			"id":              log.ID,
			"created_at":      formatTime(log.CreatedAt),
			"decision":        log.Decision,
			"deny_code":       derefString(log.DenyCode),
			"actor_user_id":   derefString(log.ActorUserID),
			"actor_member_id": derefString(log.ActorMemberID),
			"resource_type":   log.ResourceType,
			"resource_id":     log.ResourceID,
			"action":          log.Action,
		})
	}

	writeData(w, r, http.StatusOK, map[string]any{
		"counts":            counts,
		"recent_audit_logs": recent,
	})
}
