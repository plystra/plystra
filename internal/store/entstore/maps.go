package entstore

import (
	coreent "github.com/plystra/core/ent"
	"github.com/plystra/core/internal/authz"
)

func mapResourceType(rt *coreent.ResourceType) authz.ResourceTypeSnapshot {
	return authz.ResourceTypeSnapshot{
		ID:          rt.ID,
		Key:         rt.Key,
		DisplayName: rt.DisplayName,
		Description: derefString(rt.Description),
		Status:      rt.Status,
		Source:      rt.Source,
		Metadata:    nonNilMap(rt.Metadata),
	}
}

func mapResourceAction(ra *coreent.ResourceAction) authz.ResourceActionSnapshot {
	return authz.ResourceActionSnapshot{
		ID:             ra.ID,
		ResourceTypeID: ra.ResourceTypeID,
		Key:            ra.Key,
		DisplayName:    ra.DisplayName,
		Description:    derefString(ra.Description),
		RiskLevel:      ra.RiskLevel,
		AuditDefault:   ra.AuditDefault,
		Metadata:       nonNilMap(ra.Metadata),
	}
}

func mapResourceMapping(rm *coreent.ResourceMapping) authz.ResourceMappingSnapshot {
	return authz.ResourceMappingSnapshot{
		ID:               rm.ID,
		ResourceTypeID:   rm.ResourceTypeID,
		StorageKind:      rm.StorageKind,
		TableName:        derefString(rm.TableName),
		IDField:          rm.IDField,
		SpaceField:       rm.SpaceField,
		GroupField:       derefString(rm.GroupField),
		OwnerMemberField: derefString(rm.OwnerMemberField),
		VisibilityField:  derefString(rm.VisibilityField),
		MetadataField:    derefString(rm.MetadataField),
		Status:           rm.Status,
		Metadata:         nonNilMap(rm.Metadata),
	}
}

func mapResource(res *coreent.Resource) authz.ResourceSnapshot {
	return authz.ResourceSnapshot{
		ID:            res.ID,
		Type:          res.ResourceType,
		SpaceID:       res.SpaceID,
		GroupID:       derefString(res.GroupID),
		OwnerMemberID: derefString(res.OwnerMemberID),
		DisplayName:   derefString(res.DisplayName),
		Visibility:    res.Visibility,
		Status:        res.Status,
		Metadata:      nonNilMap(res.Metadata),
	}
}

func mapRoles(roles []*coreent.Role) map[string]authz.RoleSnapshot {
	out := make(map[string]authz.RoleSnapshot, len(roles))
	for _, role := range roles {
		out[role.ID] = authz.RoleSnapshot{
			ID:      role.ID,
			Key:     role.Key,
			SpaceID: role.SpaceID,
		}
	}
	return out
}

func mapPermissions(perms []*coreent.Permission) map[string]authz.PermissionSnapshot {
	out := make(map[string]authz.PermissionSnapshot, len(perms))
	for _, perm := range perms {
		out[perm.ID] = authz.PermissionSnapshot{
			ID:       perm.ID,
			Resource: perm.Resource,
			Action:   perm.Action,
			Scope:    authz.Scope(perm.Scope),
		}
	}
	return out
}

func mapMemberRoles(grants []*coreent.MemberRole) map[string][]*coreent.MemberRole {
	out := make(map[string][]*coreent.MemberRole)
	for _, grant := range grants {
		out[grant.RoleID] = append(out[grant.RoleID], grant)
	}
	return out
}

func uniqueStringsFrom[T any](values []T, pick func(T) string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, value := range values {
		item := pick(value)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}
