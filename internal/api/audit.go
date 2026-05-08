package api

import (
	"net/http"
	"strings"
	"time"

	entsql "entgo.io/ent/dialect/sql"
	coreent "github.com/plystra/plystra/ent"

	"github.com/plystra/plystra/ent/auditlog"
)

func (s *Server) handleAuditLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, r)
		return
	}
	if s.ent == nil {
		writeError(w, r, http.StatusServiceUnavailable, "NOT_READY", "Ent client is not configured.", nil)
		return
	}
	limit := limitFrom(r, 50)
	q := s.ent.AuditLog.Query()
	for _, filter := range []string{"space_id", "actor_user_id", "actor_member_id", "actor_user_member_id", "resource_type", "resource_id", "decision", "deny_code", "request_id"} {
		if value := r.URL.Query().Get(filter); value != "" {
			switch filter {
			case "space_id":
				q = q.Where(auditlog.SpaceID(value))
			case "actor_user_id":
				q = q.Where(auditlog.ActorUserID(value))
			case "actor_member_id":
				q = q.Where(auditlog.ActorMemberID(value))
			case "actor_user_member_id":
				q = q.Where(auditlog.ActorUserMemberID(value))
			case "resource_type":
				q = q.Where(auditlog.ResourceType(value))
			case "resource_id":
				q = q.Where(auditlog.ResourceID(value))
			case "decision":
				q = q.Where(auditlog.Decision(value))
			case "deny_code":
				q = q.Where(auditlog.DenyCode(value))
			case "request_id":
				q = q.Where(auditlog.RequestID(value))
			}
		}
	}
	if from := r.URL.Query().Get("created_at_from"); from != "" {
		parsed, err := time.Parse(time.RFC3339, from)
		if err != nil {
			writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "created_at_from must be RFC3339.", err.Error())
			return
		}
		q = q.Where(auditlog.CreatedAtGTE(parsed))
	}
	if to := r.URL.Query().Get("created_at_to"); to != "" {
		parsed, err := time.Parse(time.RFC3339, to)
		if err != nil {
			writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "created_at_to must be RFC3339.", err.Error())
			return
		}
		q = q.Where(auditlog.CreatedAtLTE(parsed))
	}
	logs, err := q.Order(auditlog.ByCreatedAt(entsql.OrderDesc())).Limit(limit).All(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list audit logs.", err.Error())
		return
	}
	rows := make([]map[string]any, 0, len(logs))
	for _, log := range logs {
		rows = append(rows, auditLogListItem(log))
	}
	writeList(w, r, http.StatusOK, rows, limit)
}

func (s *Server) handleAuditLogDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, r)
		return
	}
	if s.ent == nil {
		writeError(w, r, http.StatusServiceUnavailable, "NOT_READY", "Ent client is not configured.", nil)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/audit/logs/")
	if id == r.URL.Path {
		id = strings.TrimPrefix(r.URL.Path, "/api/v1/audit-logs/")
	}
	log, err := s.ent.AuditLog.Query().Where(auditlog.ID(id)).Only(r.Context())
	if coreent.IsNotFound(err) {
		writeError(w, r, http.StatusNotFound, "AUDIT_LOG_NOT_FOUND", "Resource was not found.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load audit log.", err.Error())
		return
	}
	writeData(w, r, http.StatusOK, auditLogDetail(log))
}

func auditLogListItem(log *coreent.AuditLog) map[string]any {
	return map[string]any{
		"id":                   log.ID,
		"space_id":             log.SpaceID,
		"actor_user_id":        derefString(log.ActorUserID),
		"actor_member_id":      derefString(log.ActorMemberID),
		"actor_user_member_id": derefString(log.ActorUserMemberID),
		"action":               log.Action,
		"resource_type":        log.ResourceType,
		"resource_id":          log.ResourceID,
		"decision":             log.Decision,
		"deny_code":            derefString(log.DenyCode),
		"request_id":           derefString(log.RequestID),
		"ip_address":           derefString(log.IPAddress),
		"user_agent":           derefString(log.UserAgent),
		"created_at":           log.CreatedAt.UTC().Format(time.RFC3339),
	}
}

func auditLogDetail(log *coreent.AuditLog) map[string]any {
	row := auditLogListItem(log)
	row["trace"] = nonNilMap(log.Trace)
	return row
}
