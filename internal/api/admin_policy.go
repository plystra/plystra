package api

import (
	"context"
	"errors"
	"strings"
	"time"

	coreent "github.com/plystra/core/ent"
	entadmingrant "github.com/plystra/core/ent/admingrant"
	"github.com/plystra/core/ent/appdatarecord"
	entauditlog "github.com/plystra/core/ent/auditlog"
	entgroup "github.com/plystra/core/ent/group"
	entmember "github.com/plystra/core/ent/member"
	entresource "github.com/plystra/core/ent/resource"
	entrole "github.com/plystra/core/ent/role"
	entusermember "github.com/plystra/core/ent/usermember"
	contractadmin "github.com/plystra/core/internal/kernel/contracts/admin"
)

var errAdminEntNotConfigured = errors.New("ent client is not configured")

const (
	adminLevelInstanceSuper = "instance_super_admin"
	adminLevelInstance      = "instance_admin"
	adminLevelSpace         = "space_admin"
	adminLevelGroup         = "group_admin"
)

type adminRequirement struct {
	PermissionKey string
	SpaceID       string
	GroupID       string
	EntityKind    string
	EntityID      string
}

type adminPrincipal struct {
	CredentialType string
	Session        sessionRecord
	APIKey         *coreent.ApiKey
	Grants         []*coreent.AdminGrant
}

func adminRequirementFor(method, path, querySpaceID string) adminRequirement {
	mutating := method == "POST" || method == "PATCH" || method == "DELETE"
	readOrManage := "read"
	if mutating {
		readOrManage = "manage"
	}
	parts := pathParts(path)

	if path == "/api/v1/console/overview" {
		return adminRequirement{PermissionKey: "instance:read"}
	}
	if path == "/api/v1/capabilities" {
		return adminRequirement{PermissionKey: "instance:read"}
	}
	if path == "/api/v1/capability-grants" {
		return adminRequirement{PermissionKey: "capabilities:invoke", SpaceID: querySpaceID}
	}
	if path == "/api/v1/grants/introspect" || path == "/api/v1/capability-outcomes" {
		return adminRequirement{PermissionKey: "capabilities:manage", SpaceID: querySpaceID}
	}
	if path == "/api/v1/authz/check" || path == "/api/v1/authz/explain" {
		return adminRequirement{PermissionKey: "authz:check"}
	}
	if path == "/metrics" {
		return adminRequirement{PermissionKey: "metrics:read"}
	}
	if strings.HasPrefix(path, "/api/v1/admin/grants") {
		req := adminRequirement{PermissionKey: "admin_grants:manage"}
		if method == "GET" {
			req.PermissionKey = "admin_grants:read"
		}
		if path != "/api/v1/admin/grants" {
			grantID := strings.TrimPrefix(path, "/api/v1/admin/grants/")
			grantID = strings.TrimSuffix(grantID, "/revoke")
			if grantID != "" {
				req.EntityKind = "admin_grant"
				req.EntityID = grantID
			}
		}
		return req
	}
	if strings.HasPrefix(path, "/api/v1/api-keys") {
		switch method {
		case "GET":
			return adminRequirement{PermissionKey: "api_keys:read"}
		case "POST":
			if strings.HasSuffix(path, "/revoke") {
				return adminRequirement{PermissionKey: "api_keys:revoke"}
			}
			return adminRequirement{PermissionKey: "api_keys:create"}
		default:
			return adminRequirement{PermissionKey: "api_keys:manage"}
		}
	}
	if path == "/api/v1/admin/me" {
		return adminRequirement{PermissionKey: "instance:read"}
	}
	if path == "/api/v1/audit/logs" || strings.HasPrefix(path, "/api/v1/audit/logs/") {
		req := adminRequirement{PermissionKey: "audit:read", SpaceID: querySpaceID}
		if strings.HasPrefix(path, "/api/v1/audit/logs/") {
			req.EntityKind = "audit_log"
			req.EntityID = strings.TrimPrefix(path, "/api/v1/audit/logs/")
		}
		return req
	}
	if strings.HasPrefix(path, "/api/v1/users") {
		return adminRequirement{PermissionKey: "users:" + readOrManage}
	}
	if path == "/api/v1/spaces" {
		return adminRequirement{PermissionKey: "spaces:" + readOrManage}
	}
	if len(parts) >= 3 && parts[0] == "api" && parts[1] == "v1" && parts[2] == "spaces" && len(parts) >= 4 {
		return spaceRouteRequirement(method, parts, readOrManage)
	}
	if strings.HasPrefix(path, "/api/v1/groups/") {
		return adminRequirement{PermissionKey: "groups:read", EntityKind: "group", EntityID: strings.TrimPrefix(path, "/api/v1/groups/")}
	}
	if strings.HasPrefix(path, "/api/v1/members/") {
		return adminRequirement{PermissionKey: "members:read", EntityKind: "member", EntityID: strings.TrimPrefix(path, "/api/v1/members/")}
	}
	if strings.HasPrefix(path, "/api/v1/user-members/") {
		return adminRequirement{PermissionKey: "user_members:read", EntityKind: "user_member", EntityID: strings.TrimPrefix(path, "/api/v1/user-members/")}
	}
	if strings.HasPrefix(path, "/api/v1/roles/") {
		return adminRequirement{PermissionKey: "roles:read", EntityKind: "role", EntityID: strings.TrimPrefix(path, "/api/v1/roles/")}
	}
	if strings.HasPrefix(path, "/api/v1/permissions") || strings.HasPrefix(path, "/api/v1/role-permissions") {
		return adminRequirement{PermissionKey: "permissions:" + readOrManage}
	}
	if strings.HasPrefix(path, "/api/v1/resource-types") {
		return adminRequirement{PermissionKey: "registry:" + readOrManage}
	}
	if path == "/api/v1/resources" {
		return adminRequirement{PermissionKey: "resources:" + readOrManage, SpaceID: querySpaceID}
	}
	if strings.HasPrefix(path, "/api/v1/resources/") {
		resourcePath := strings.TrimPrefix(path, "/api/v1/resources/")
		resourceParts := pathParts(resourcePath)
		resourceID := resourcePath
		if len(resourceParts) >= 2 {
			resourceID = resourceParts[len(resourceParts)-1]
		}
		return adminRequirement{PermissionKey: "resources:" + readOrManage, EntityKind: "resource", EntityID: resourceID}
	}
	if strings.HasPrefix(path, "/api/v1/data/") {
		return adminRequirement{PermissionKey: "data:" + readOrManage}
	}
	if strings.HasPrefix(path, "/api/v1/plugins") || strings.HasPrefix(path, "/api/v1/app-modules") {
		return adminRequirement{PermissionKey: "plugins:" + readOrManage}
	}
	if strings.HasPrefix(path, "/api/v1/templates") {
		return adminRequirement{PermissionKey: "templates:" + readOrManage}
	}
	return adminRequirement{PermissionKey: "instance:" + readOrManage}
}

func spaceRouteRequirement(method string, parts []string, readOrManage string) adminRequirement {
	spaceID := parts[3]
	if len(parts) == 4 {
		return adminRequirement{PermissionKey: "spaces:" + readOrManage, SpaceID: spaceID}
	}
	if len(parts) == 5 && (parts[4] == "disable" || parts[4] == "restore") {
		return adminRequirement{PermissionKey: "spaces:manage", SpaceID: spaceID}
	}
	segment := parts[4]
	switch segment {
	case "groups":
		req := adminRequirement{PermissionKey: "groups:" + readOrManage, SpaceID: spaceID}
		if len(parts) >= 6 && parts[5] != "tree" {
			req.GroupID = parts[5]
		}
		return req
	case "members":
		return adminRequirement{PermissionKey: "members:" + readOrManage, SpaceID: spaceID}
	case "user-members":
		return adminRequirement{PermissionKey: "user_members:" + readOrManage, SpaceID: spaceID}
	case "roles", "role-permissions", "member-roles", "member-role-grants":
		return adminRequirement{PermissionKey: "roles:" + readOrManage, SpaceID: spaceID}
	case "resources":
		req := adminRequirement{PermissionKey: "resources:" + readOrManage, SpaceID: spaceID}
		if len(parts) >= 6 && method != "POST" {
			req.EntityKind = "resource"
			req.EntityID = parts[5]
		}
		return req
	case "data":
		req := adminRequirement{PermissionKey: "data:" + readOrManage, SpaceID: spaceID}
		if len(parts) >= 8 && parts[4] == "data" && parts[5] == "models" && parts[7] == "records" {
			if len(parts) >= 9 && method != "POST" {
				req.EntityKind = "app_data_record"
				req.EntityID = parts[8]
			}
		}
		return req
	case "audit-logs":
		req := adminRequirement{PermissionKey: "audit:read", SpaceID: spaceID}
		if len(parts) >= 6 {
			req.EntityKind = "audit_log"
			req.EntityID = parts[5]
		}
		return req
	default:
		return adminRequirement{PermissionKey: "spaces:" + readOrManage, SpaceID: spaceID}
	}
}

func pathParts(path string) []string {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "/")
}

func (s *Server) loadActiveAdminGrants(ctx context.Context, userID string) ([]*coreent.AdminGrant, error) {
	if s.ent == nil {
		return nil, errAdminEntNotConfigured
	}
	now := time.Now().UTC()
	return s.ent.AdminGrant.Query().
		Where(
			entadmingrant.UserID(userID),
			entadmingrant.Status("active"),
			entadmingrant.DeletedAtIsNil(),
			entadmingrant.RevokedAtIsNil(),
			entadmingrant.Or(entadmingrant.ExpiresAtIsNil(), entadmingrant.ExpiresAtGT(now)),
		).
		All(ctx)
}

func (s *Server) adminSessionAllowed(ctx context.Context, session sessionRecord, requirement adminRequirement) (adminPrincipal, bool, error) {
	grants, err := s.loadActiveAdminGrants(ctx, session.UserID)
	if err != nil {
		return adminPrincipal{}, false, err
	}
	principal := adminPrincipal{CredentialType: "session", Session: session, Grants: grants}
	allowed, err := s.adminPrincipalAllows(ctx, principal, requirement)
	return principal, allowed, err
}

func (s *Server) adminPrincipalAllows(ctx context.Context, principal adminPrincipal, requirement adminRequirement) (bool, error) {
	resolved, err := s.resolveAdminRequirementScope(ctx, requirement)
	if err != nil {
		return false, err
	}
	if principal.CredentialType == "api_key" {
		return s.apiKeyAllows(ctx, principal.APIKey, resolved)
	}
	for _, grant := range principal.Grants {
		if allowed, err := s.adminGrantAllows(ctx, grant, resolved); err != nil {
			return false, err
		} else if allowed {
			return true, nil
		}
	}
	return false, nil
}

func (s *Server) adminGrantAllows(ctx context.Context, grant *coreent.AdminGrant, requirement adminRequirement) (bool, error) {
	if grant == nil {
		return false, nil
	}
	if grant.Level == adminLevelInstanceSuper {
		return true, nil
	}
	if !adminPermissionMatches(grant.PermissionKey, requirement.PermissionKey) {
		return false, nil
	}
	switch grant.Level {
	case adminLevelInstance:
		return true, nil
	case adminLevelSpace:
		if requirement.SpaceID == "" && requirement.GroupID == "" && adminPermissionMayResolveInHandler(requirement.PermissionKey) {
			return true, nil
		}
		grantSpaceID := derefString(grant.SpaceID)
		return grantSpaceID != "" && requirement.SpaceID != "" && grantSpaceID == requirement.SpaceID, nil
	case adminLevelGroup:
		if requirement.SpaceID == "" && requirement.GroupID == "" && adminPermissionMayResolveInHandler(requirement.PermissionKey) {
			return true, nil
		}
		grantGroupID := derefString(grant.GroupID)
		if grantGroupID == "" || requirement.GroupID == "" {
			return false, nil
		}
		return s.groupGrantCovers(ctx, grantGroupID, requirement.GroupID)
	default:
		return false, nil
	}
}

func adminPermissionMatches(grantKey, requiredKey string) bool {
	return contractadmin.PermissionMatches(grantKey, requiredKey)
}

func validAdminPermissionKey(key string) bool {
	return contractadmin.ValidPermissionKey(key)
}

func adminPermissionTokenValid(value string) bool {
	if value == "" {
		return false
	}
	if strings.Contains(value, "*") {
		return value == "*"
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '_' || r == '-':
		case r == '*':
		default:
			return false
		}
	}
	return true
}

func adminPermissionMayResolveInHandler(permissionKey string) bool {
	return strings.HasPrefix(permissionKey, "api_keys:") ||
		strings.HasPrefix(permissionKey, "admin_grants:") ||
		strings.HasPrefix(permissionKey, "capabilities:") ||
		permissionKey == "authz:check"
}

func (s *Server) resolveAdminRequirementScope(ctx context.Context, req adminRequirement) (adminRequirement, error) {
	if s.ent == nil || req.EntityKind == "" || req.EntityID == "" {
		return req, nil
	}
	switch req.EntityKind {
	case "group":
		row, err := s.ent.Group.Query().Where(entgroup.ID(req.EntityID), entgroup.DeletedAtIsNil()).Only(ctx)
		if coreent.IsNotFound(err) {
			return req, nil
		}
		if err != nil {
			return req, err
		}
		req.SpaceID = row.SpaceID
		req.GroupID = row.ID
	case "member":
		row, err := s.ent.Member.Query().Where(entmember.ID(req.EntityID), entmember.DeletedAtIsNil()).Only(ctx)
		if coreent.IsNotFound(err) {
			return req, nil
		}
		if err != nil {
			return req, err
		}
		req.SpaceID = row.SpaceID
	case "user_member":
		row, err := s.ent.UserMember.Query().Where(entusermember.ID(req.EntityID), entusermember.DeletedAtIsNil()).Only(ctx)
		if coreent.IsNotFound(err) {
			return req, nil
		}
		if err != nil {
			return req, err
		}
		req.SpaceID = row.SpaceID
	case "role":
		row, err := s.ent.Role.Query().Where(entrole.ID(req.EntityID), entrole.DeletedAtIsNil()).Only(ctx)
		if coreent.IsNotFound(err) {
			return req, nil
		}
		if err != nil {
			return req, err
		}
		req.SpaceID = row.SpaceID
	case "resource":
		row, err := s.ent.Resource.Query().Where(entresource.ID(req.EntityID), entresource.DeletedAtIsNil()).Only(ctx)
		if coreent.IsNotFound(err) {
			return req, nil
		}
		if err != nil {
			return req, err
		}
		req.SpaceID = row.SpaceID
		req.GroupID = derefString(row.GroupID)
	case "app_data_record":
		row, err := s.ent.AppDataRecord.Query().Where(appdatarecord.ID(req.EntityID), appdatarecord.DeletedAtIsNil()).Only(ctx)
		if coreent.IsNotFound(err) {
			return req, nil
		}
		if err != nil {
			return req, err
		}
		req.SpaceID = row.SpaceID
		req.GroupID = derefString(row.GroupID)
	case "audit_log":
		row, err := s.ent.AuditLog.Query().Where(entauditlog.ID(req.EntityID)).Only(ctx)
		if coreent.IsNotFound(err) {
			return req, nil
		}
		if err != nil {
			return req, err
		}
		req.SpaceID = row.SpaceID
	case "admin_grant":
		row, err := s.ent.AdminGrant.Query().Where(entadmingrant.ID(req.EntityID), entadmingrant.DeletedAtIsNil()).Only(ctx)
		if coreent.IsNotFound(err) {
			return req, nil
		}
		if err != nil {
			return req, err
		}
		req.SpaceID = derefString(row.SpaceID)
		req.GroupID = derefString(row.GroupID)
	}
	return req, nil
}

func (s *Server) groupGrantCovers(ctx context.Context, grantGroupID, targetGroupID string) (bool, error) {
	if grantGroupID == targetGroupID {
		return true, nil
	}
	if s.ent == nil {
		return false, errAdminEntNotConfigured
	}
	grantGroup, err := s.ent.Group.Query().Where(entgroup.ID(grantGroupID), entgroup.DeletedAtIsNil()).Only(ctx)
	if coreent.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	targetGroup, err := s.ent.Group.Query().Where(entgroup.ID(targetGroupID), entgroup.DeletedAtIsNil()).Only(ctx)
	if coreent.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return grantGroup.SpaceID == targetGroup.SpaceID &&
		(targetGroup.Path == grantGroup.Path || strings.HasPrefix(targetGroup.Path, grantGroup.Path+".")), nil
}

func adminPrincipalHasInstanceReach(principal adminPrincipal, permissionKey string) bool {
	if principal.CredentialType == "api_key" {
		return principal.APIKey != nil &&
			principal.APIKey.Level == "instance" &&
			apiKeyPermissionMatches(principal.APIKey.PermissionKeys, permissionKey)
	}
	for _, grant := range principal.Grants {
		if grant.Level == adminLevelInstanceSuper {
			return true
		}
		if grant.Level == adminLevelInstance && adminPermissionMatches(grant.PermissionKey, permissionKey) {
			return true
		}
	}
	return false
}

func adminPrincipalIsSuper(principal adminPrincipal) bool {
	if principal.CredentialType != "session" {
		return false
	}
	for _, grant := range principal.Grants {
		if grant.Level == adminLevelInstanceSuper {
			return true
		}
	}
	return false
}

func (s *Server) principalCanDelegatePermission(ctx context.Context, principal adminPrincipal, permissionKey, spaceID, groupID string) (bool, error) {
	if adminPrincipalIsSuper(principal) {
		return true, nil
	}
	return s.adminPrincipalAllows(ctx, principal, adminRequirement{
		PermissionKey: permissionKey,
		SpaceID:       spaceID,
		GroupID:       groupID,
	})
}

func (s *Server) principalCanDelegatePermissions(ctx context.Context, principal adminPrincipal, permissionKeys []string, spaceID, groupID string) (bool, string, error) {
	for _, permissionKey := range permissionKeys {
		allowed, err := s.principalCanDelegatePermission(ctx, principal, permissionKey, spaceID, groupID)
		if err != nil {
			return false, permissionKey, err
		}
		if !allowed {
			return false, permissionKey, nil
		}
	}
	return true, "", nil
}
