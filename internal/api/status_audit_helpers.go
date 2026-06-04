package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/plystra/core/internal/authz"
)

func (s *Server) updateStatus(ctx context.Context, table, id, status string) (map[string]any, error) {
	if !allowedStatusTable(table) {
		return nil, fmt.Errorf("unsupported status table %s", table)
	}
	if s.ent == nil {
		return nil, errors.New("ent client is not configured")
	}
	switch table {
	case "users":
		if err := s.ent.User.UpdateOneID(id).SetStatus(status).Exec(ctx); err != nil {
			return nil, err
		}
		return s.loadUser(ctx, id)
	case "spaces":
		if err := s.ent.Space.UpdateOneID(id).SetStatus(status).Exec(ctx); err != nil {
			return nil, err
		}
		return s.loadSpace(ctx, id)
	case "permissions":
		if err := s.ent.Permission.UpdateOneID(id).SetStatus(status).Exec(ctx); err != nil {
			return nil, err
		}
		return s.loadPermission(ctx, id)
	default:
		return nil, fmt.Errorf("unsupported unscoped status table %s", table)
	}
}

func (s *Server) updateScopedStatus(ctx context.Context, table, id, spaceID, status string) (map[string]any, error) {
	if !allowedStatusTable(table) {
		return nil, fmt.Errorf("unsupported status table %s", table)
	}
	if s.ent == nil {
		return nil, errors.New("ent client is not configured")
	}
	switch table {
	case "groups":
		if err := s.ent.Group.UpdateOneID(id).SetStatus(status).Exec(ctx); err != nil {
			return nil, err
		}
		return s.loadGroupInSpace(ctx, spaceID, id)
	case "members":
		if err := s.ent.Member.UpdateOneID(id).SetStatus(status).Exec(ctx); err != nil {
			return nil, err
		}
		return s.loadMemberInSpace(ctx, spaceID, id)
	case "roles":
		if err := s.ent.Role.UpdateOneID(id).SetStatus(status).Exec(ctx); err != nil {
			return nil, err
		}
		return s.loadRoleInSpace(ctx, spaceID, id)
	case "member_roles":
		if err := s.ent.MemberRole.UpdateOneID(id).SetStatus(status).Exec(ctx); err != nil {
			return nil, err
		}
		return s.loadMemberRoleInSpace(ctx, spaceID, id)
	case "resources":
		if err := s.ent.Resource.UpdateOneID(id).SetStatus(status).Exec(ctx); err != nil {
			return nil, err
		}
		return s.loadResourceInSpace(ctx, spaceID, id)
	default:
		return nil, fmt.Errorf("unsupported scoped status table %s", table)
	}
}

func allowedStatusTable(table string) bool {
	switch table {
	case "users", "spaces", "groups", "members", "user_members", "roles", "permissions", "member_roles", "resources":
		return true
	default:
		return false
	}
}

func (s *Server) recordMutationAudit(ctx context.Context, r *http.Request, actor authz.ActorContext, spaceID, action, resourceType, resourceID string, details any) {
	if spaceID == "" {
		return
	}
	actor = auditActorFromRequest(r, actor, spaceID)
	trace := map[string]any{
		"trace_version": traceVersion(),
		"decision":      authz.DecisionAllow,
		"reason":        "Core management API mutation was accepted",
		"request_id":    requestIDFrom(r),
		"actor": map[string]any{
			"user_id":        actor.UserID,
			"member_id":      actor.MemberID,
			"user_member_id": actor.UserMemberID,
			"space_id":       firstNonEmpty(actor.SpaceID, spaceID),
		},
		"target": map[string]any{
			"resource_type": resourceType,
			"resource_id":   resourceID,
		},
		"details":    details,
		"created_at": time.Now().UTC().Format(time.RFC3339),
	}
	if s.ent == nil {
		return
	}
	_, _ = s.ent.AuditLog.Create().
		SetID(newEntityID("audit")).
		SetSpaceID(spaceID).
		SetNillableActorUserID(optionalString(actor.UserID)).
		SetNillableActorMemberID(optionalString(actor.MemberID)).
		SetNillableActorUserMemberID(optionalString(actor.UserMemberID)).
		SetAction(action).
		SetResourceType(resourceType).
		SetResourceID(resourceID).
		SetDecision(string(authz.DecisionAllow)).
		SetTrace(trace).
		SetNillableRequestID(optionalString(requestIDFrom(r))).
		SetNillableIPAddress(optionalString(remoteIPFrom(r))).
		SetNillableUserAgent(optionalString(r.UserAgent())).
		Save(ctx)
}

func auditActorFromRequest(r *http.Request, fallback authz.ActorContext, spaceID string) authz.ActorContext {
	if principal, ok := adminPrincipalFrom(r); ok {
		switch principal.CredentialType {
		case "session":
			return authz.ActorContext{
				UserID:       principal.Session.UserID,
				MemberID:     principal.Session.ActiveMemberID,
				UserMemberID: principal.Session.ActiveUserMemberID,
				SpaceID:      firstNonEmpty(principal.Session.ActiveSpaceID, spaceID),
			}
		case "api_key":
			if principal.APIKey != nil {
				return authz.ActorContext{
					UserID:  derefString(principal.APIKey.CreatedByUserID),
					SpaceID: firstNonEmpty(derefString(principal.APIKey.SpaceID), spaceID),
				}
			}
		}
	}
	if fallback.SpaceID == "" {
		fallback.SpaceID = spaceID
	}
	return fallback
}

func stringFromMap(values map[string]any, key string) string {
	value, ok := values[key]
	if !ok || value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	default:
		return fmt.Sprint(typed)
	}
}

func mapFromAny(value any) map[string]any {
	if value == nil {
		return map[string]any{}
	}
	if typed, ok := value.(map[string]any); ok {
		return typed
	}
	return map[string]any{}
}

func nullableFromRequest(value *string, current string) string {
	if value == nil {
		return current
	}
	return *value
}

func intValue(value *int, fallback int) int {
	if value == nil {
		return fallback
	}
	return *value
}

func intFromMap(values map[string]any, key string, fallback int) int {
	value, ok := values[key]
	if !ok || value == nil {
		return fallback
	}
	switch typed := value.(type) {
	case int:
		return typed
	case int32:
		return int(typed)
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	default:
		parsed, err := strconv.Atoi(fmt.Sprint(typed))
		if err != nil {
			return fallback
		}
		return parsed
	}
}

func boolValue(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}
	return *value
}

func boolFromMap(values map[string]any, key string, fallback bool) bool {
	value, ok := values[key]
	if !ok || value == nil {
		return fallback
	}
	if typed, ok := value.(bool); ok {
		return typed
	}
	parsed, err := strconv.ParseBool(fmt.Sprint(value))
	if err != nil {
		return fallback
	}
	return parsed
}

func pathDepth(path string) int {
	path = strings.Trim(path, ".")
	if path == "" {
		return 0
	}
	return strings.Count(path, ".")
}

func lastPathSegment(path string) string {
	path = strings.Trim(path, ".")
	if path == "" {
		return ""
	}
	parts := strings.Split(path, ".")
	return parts[len(parts)-1]
}

func newEntityID(prefix string) string {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return safeIdentifier(prefix) + "_" + strconv.FormatInt(time.Now().UTC().UnixNano(), 10)
	}
	return safeIdentifier(prefix) + "_" + hex.EncodeToString(buf[:])
}

func safeIdentifier(value string) string {
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + ('a' - 'A'))
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return strings.Trim(b.String(), "_")
}

func titleFromKey(value string) string {
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == '_' || r == '.' || r == '-'
	})
	for i, part := range parts {
		if part == "" {
			continue
		}
		parts[i] = strings.ToUpper(part[:1]) + part[1:]
	}
	return strings.Join(parts, " ")
}

func newRequestID() string {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return fmt.Sprintf("req_%d", time.Now().UTC().UnixNano())
	}
	return "req_" + hex.EncodeToString(buf[:])
}
