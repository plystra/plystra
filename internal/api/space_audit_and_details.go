package api

import (
	"net/http"
	"strings"
	"time"

	entsql "entgo.io/ent/dialect/sql"
	entgroup "github.com/plystra/plystra/ent/group"
	entrole "github.com/plystra/plystra/ent/role"

	coreent "github.com/plystra/plystra/ent"
	"github.com/plystra/plystra/ent/auditlog"
	entmember "github.com/plystra/plystra/ent/member"
	entusermember "github.com/plystra/plystra/ent/usermember"
)

func (s *Server) handleSpaceAuditLogs(w http.ResponseWriter, r *http.Request, spaceID string, parts []string) {
	if len(parts) == 0 {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, r)
			return
		}
		limit := limitFrom(r, 50)
		if s.ent == nil {
			writeError(w, r, http.StatusServiceUnavailable, "NOT_READY", "Ent client is not configured.", nil)
			return
		}
		q := s.ent.AuditLog.Query().Where(auditlog.SpaceID(spaceID))
		for _, filter := range []string{"actor_user_id", "actor_member_id", "actor_user_member_id", "resource_type", "resource_id", "decision", "deny_code", "request_id"} {
			if value := r.URL.Query().Get(filter); value != "" {
				switch filter {
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
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list AuditLogs.", err.Error())
			return
		}
		rows := make([]map[string]any, 0, len(logs))
		for _, log := range logs {
			rows = append(rows, auditLogListItem(log))
		}
		writeList(w, r, http.StatusOK, rows, limit)
		return
	}
	if len(parts) == 1 {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, r)
			return
		}
		if s.ent == nil {
			writeError(w, r, http.StatusServiceUnavailable, "NOT_READY", "Ent client is not configured.", nil)
			return
		}
		log, err := s.ent.AuditLog.Query().Where(auditlog.ID(parts[0]), auditlog.SpaceID(spaceID)).Only(r.Context())
		if coreent.IsNotFound(err) {
			writeError(w, r, http.StatusNotFound, "AUDIT_LOG_NOT_FOUND", "AuditLog was not found.", nil)
			return
		}
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load AuditLog.", err.Error())
			return
		}
		writeData(w, r, http.StatusOK, auditLogDetail(log))
		return
	}
	http.NotFound(w, r)
}

func (s *Server) handleGroupDetail(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/groups/")
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, r)
		return
	}
	if s.ent == nil {
		writeError(w, r, http.StatusServiceUnavailable, "NOT_READY", "Ent client is not configured.", nil)
		return
	}
	row, err := s.ent.Group.Query().Where(entgroup.ID(id), entgroup.DeletedAtIsNil()).Only(r.Context())
	if coreent.IsNotFound(err) {
		writeError(w, r, http.StatusNotFound, "GROUP_NOT_FOUND", "Group was not found.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load Group.", err.Error())
		return
	}
	writeData(w, r, http.StatusOK, groupMap(row))
}

func (s *Server) handleMemberDetail(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/members/")
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, r)
		return
	}
	if s.ent == nil {
		writeError(w, r, http.StatusServiceUnavailable, "NOT_READY", "Ent client is not configured.", nil)
		return
	}
	row, err := s.ent.Member.Query().Where(entmember.ID(id), entmember.DeletedAtIsNil()).Only(r.Context())
	if coreent.IsNotFound(err) {
		writeError(w, r, http.StatusNotFound, "MEMBER_NOT_FOUND", "Member was not found.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load Member.", err.Error())
		return
	}
	writeData(w, r, http.StatusOK, memberMap(row))
}

func (s *Server) handleUserMemberDetail(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/user-members/")
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, r)
		return
	}
	if s.ent == nil {
		writeError(w, r, http.StatusServiceUnavailable, "NOT_READY", "Ent client is not configured.", nil)
		return
	}
	row, err := s.ent.UserMember.Query().Where(entusermember.ID(id), entusermember.DeletedAtIsNil()).Only(r.Context())
	if coreent.IsNotFound(err) {
		writeError(w, r, http.StatusNotFound, "USER_MEMBER_NOT_FOUND", "UserMember was not found.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load UserMember.", err.Error())
		return
	}
	out, err := s.userMemberMapWithRefs(r.Context(), row)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load UserMember.", err.Error())
		return
	}
	writeData(w, r, http.StatusOK, out)
}

func (s *Server) handleRoleDetail(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/roles/")
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, r)
		return
	}
	if s.ent == nil {
		writeError(w, r, http.StatusServiceUnavailable, "NOT_READY", "Ent client is not configured.", nil)
		return
	}
	row, err := s.ent.Role.Query().Where(entrole.ID(id), entrole.DeletedAtIsNil()).Only(r.Context())
	if coreent.IsNotFound(err) {
		writeError(w, r, http.StatusNotFound, "ROLE_NOT_FOUND", "Role was not found.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load Role.", err.Error())
		return
	}
	writeData(w, r, http.StatusOK, roleMap(row))
}
