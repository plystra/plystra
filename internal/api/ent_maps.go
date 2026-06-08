package api

import (
	"time"

	coreent "github.com/plystra/core/ent"
)

func formatTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339)
}

func optionalTime(value *time.Time) any {
	if value == nil {
		return nil
	}
	return value.UTC().Format(time.RFC3339)
}

func userMap(row *coreent.User) map[string]any {
	return map[string]any{
		"id":                  row.ID,
		"email":               row.Email,
		"username":            derefString(row.Username),
		"phone":               derefString(row.Phone),
		"status":              row.Status,
		"metadata":            nonNilMap(row.Metadata),
		"password_changed_at": optionalTime(row.PasswordChangedAt),
		"last_login_at":       optionalTime(row.LastLoginAt),
		"created_at":          formatTime(row.CreatedAt),
		"updated_at":          formatTime(row.UpdatedAt),
		"deleted_at":          optionalTime(row.DeletedAt),
	}
}

func userPersistenceMap(row *coreent.User) map[string]any {
	out := userMap(row)
	out["password_hash"] = derefString(row.PasswordHash)
	return out
}

func adminGrantMap(row *coreent.AdminGrant) map[string]any {
	return map[string]any{
		"id":                   row.ID,
		"user_id":              row.UserID,
		"member_id":            derefString(row.MemberID),
		"space_id":             derefString(row.SpaceID),
		"group_id":             derefString(row.GroupID),
		"level":                row.Level,
		"permission_key":       row.PermissionKey,
		"status":               row.Status,
		"granted_by_user_id":   derefString(row.GrantedByUserID),
		"granted_by_member_id": derefString(row.GrantedByMemberID),
		"expires_at":           optionalTime(row.ExpiresAt),
		"revoked_at":           optionalTime(row.RevokedAt),
		"revoked_reason":       derefString(row.RevokedReason),
		"metadata":             nonNilMap(row.Metadata),
		"created_at":           formatTime(row.CreatedAt),
		"updated_at":           formatTime(row.UpdatedAt),
		"deleted_at":           optionalTime(row.DeletedAt),
	}
}

func apiKeyMap(row *coreent.ApiKey) map[string]any {
	return map[string]any{
		"id":                         row.ID,
		"name":                       row.Name,
		"key_prefix":                 row.KeyPrefix,
		"level":                      row.Level,
		"space_id":                   derefString(row.SpaceID),
		"group_id":                   derefString(row.GroupID),
		"permission_keys":            row.PermissionKeys,
		"status":                     row.Status,
		"provider_runtime_plugin_id": derefString(row.ProviderRuntimePluginID),
		"expires_at":                 optionalTime(row.ExpiresAt),
		"last_used_at":               optionalTime(row.LastUsedAt),
		"created_by_user_id":         derefString(row.CreatedByUserID),
		"created_by_member_id":       derefString(row.CreatedByMemberID),
		"revoked_at":                 optionalTime(row.RevokedAt),
		"revoked_by_user_id":         derefString(row.RevokedByUserID),
		"revoked_reason":             derefString(row.RevokedReason),
		"metadata":                   nonNilMap(row.Metadata),
		"created_at":                 formatTime(row.CreatedAt),
		"updated_at":                 formatTime(row.UpdatedAt),
		"deleted_at":                 optionalTime(row.DeletedAt),
	}
}

func spaceMap(row *coreent.Space) map[string]any {
	return map[string]any{
		"id":         row.ID,
		"name":       row.Name,
		"slug":       derefString(row.Slug),
		"type":       row.Type,
		"status":     row.Status,
		"metadata":   nonNilMap(row.Metadata),
		"created_at": formatTime(row.CreatedAt),
		"updated_at": formatTime(row.UpdatedAt),
		"deleted_at": optionalTime(row.DeletedAt),
	}
}

func groupMap(row *coreent.Group) map[string]any {
	parentID := derefString(row.ParentGroupID)
	return map[string]any{
		"id":              row.ID,
		"space_id":        row.SpaceID,
		"parent_group_id": parentID,
		"parent_id":       parentID,
		"name":            row.Name,
		"display_name":    derefString(row.DisplayName),
		"path":            row.Path,
		"depth":           row.Depth,
		"sort_order":      row.SortOrder,
		"status":          row.Status,
		"metadata":        nonNilMap(row.Metadata),
		"created_at":      formatTime(row.CreatedAt),
		"updated_at":      formatTime(row.UpdatedAt),
		"deleted_at":      optionalTime(row.DeletedAt),
	}
}

func memberMap(row *coreent.Member) map[string]any {
	return map[string]any{
		"id":           row.ID,
		"space_id":     row.SpaceID,
		"display_name": row.DisplayName,
		"member_type":  row.MemberType,
		"status":       row.Status,
		"metadata":     nonNilMap(row.Metadata),
		"created_at":   formatTime(row.CreatedAt),
		"updated_at":   formatTime(row.UpdatedAt),
		"deleted_at":   optionalTime(row.DeletedAt),
	}
}

func userMemberMap(row *coreent.UserMember, email, memberDisplayName string) map[string]any {
	return map[string]any{
		"id":                  row.ID,
		"user_id":             row.UserID,
		"email":               email,
		"member_id":           row.MemberID,
		"member_display_name": memberDisplayName,
		"space_id":            row.SpaceID,
		"relation_type":       row.RelationType,
		"status":              row.Status,
		"is_primary":          row.IsPrimary,
		"expires_at":          optionalTime(row.ExpiresAt),
		"linked_by_member_id": derefString(row.LinkedByMemberID),
		"linked_at":           optionalTime(row.LinkedAt),
		"revoked_at":          optionalTime(row.RevokedAt),
		"revoked_reason":      derefString(row.RevokedReason),
		"metadata":            nonNilMap(row.Metadata),
		"created_at":          formatTime(row.CreatedAt),
		"updated_at":          formatTime(row.UpdatedAt),
		"deleted_at":          optionalTime(row.DeletedAt),
	}
}

func roleMap(row *coreent.Role) map[string]any {
	return map[string]any{
		"id":          row.ID,
		"space_id":    row.SpaceID,
		"key":         row.Key,
		"name":        row.Name,
		"description": derefString(row.Description),
		"status":      row.Status,
		"metadata":    nonNilMap(row.Metadata),
		"created_at":  formatTime(row.CreatedAt),
		"updated_at":  formatTime(row.UpdatedAt),
		"deleted_at":  optionalTime(row.DeletedAt),
	}
}

func memberRoleMap(row *coreent.MemberRole, memberDisplayName, roleKey, roleName, anchorPath string) map[string]any {
	return map[string]any{
		"id":                    row.ID,
		"space_id":              row.SpaceID,
		"member_id":             row.MemberID,
		"member_display_name":   memberDisplayName,
		"role_id":               row.RoleID,
		"role_key":              roleKey,
		"role_name":             roleName,
		"scope_anchor_group_id": derefString(row.ScopeAnchorGroupID),
		"scope_anchor_path":     anchorPath,
		"status":                row.Status,
		"metadata":              nonNilMap(row.Metadata),
		"created_at":            formatTime(row.CreatedAt),
		"updated_at":            formatTime(row.UpdatedAt),
		"deleted_at":            optionalTime(row.DeletedAt),
	}
}

func permissionMap(row *coreent.Permission) map[string]any {
	return map[string]any{
		"id":          row.ID,
		"resource":    row.Resource,
		"action":      row.Action,
		"scope":       row.Scope,
		"description": derefString(row.Description),
		"status":      row.Status,
		"metadata":    nonNilMap(row.Metadata),
		"created_at":  formatTime(row.CreatedAt),
		"updated_at":  formatTime(row.UpdatedAt),
		"deleted_at":  optionalTime(row.DeletedAt),
	}
}

func rolePermissionMap(row *coreent.RolePermission, roleSpaceID, roleKey string, permission *coreent.Permission) map[string]any {
	return map[string]any{
		"id":            row.ID,
		"role_id":       row.RoleID,
		"space_id":      roleSpaceID,
		"role_key":      roleKey,
		"permission_id": row.PermissionID,
		"resource":      permission.Resource,
		"action":        permission.Action,
		"scope":         permission.Scope,
		"metadata":      nonNilMap(row.Metadata),
		"created_at":    formatTime(row.CreatedAt),
		"updated_at":    formatTime(row.UpdatedAt),
		"deleted_at":    optionalTime(row.DeletedAt),
	}
}

func resourceMap(row *coreent.Resource, spaceName, groupPath, ownerMemberDisplayName string) map[string]any {
	return map[string]any{
		"id":                        row.ID,
		"resource_type":             row.ResourceType,
		"external_id":               derefString(row.ExternalID),
		"display_name":              derefString(row.DisplayName),
		"space_id":                  row.SpaceID,
		"space_name":                spaceName,
		"group_id":                  derefString(row.GroupID),
		"group_path":                groupPath,
		"owner_member_id":           derefString(row.OwnerMemberID),
		"owner_member_display_name": ownerMemberDisplayName,
		"visibility":                row.Visibility,
		"metadata":                  nonNilMap(row.Metadata),
		"status":                    row.Status,
		"created_at":                formatTime(row.CreatedAt),
		"updated_at":                formatTime(row.UpdatedAt),
		"deleted_at":                optionalTime(row.DeletedAt),
	}
}

func resourceTypeMap(row *coreent.ResourceType) map[string]any {
	return map[string]any{
		"id":           row.ID,
		"key":          row.Key,
		"display_name": row.DisplayName,
		"description":  derefString(row.Description),
		"status":       row.Status,
		"source":       row.Source,
		"metadata":     nonNilMap(row.Metadata),
		"created_at":   formatTime(row.CreatedAt),
		"updated_at":   formatTime(row.UpdatedAt),
	}
}

func resourceActionMap(row *coreent.ResourceAction) map[string]any {
	return map[string]any{
		"id":            row.ID,
		"key":           row.Key,
		"display_name":  row.DisplayName,
		"description":   derefString(row.Description),
		"risk_level":    row.RiskLevel,
		"audit_default": row.AuditDefault,
		"metadata":      nonNilMap(row.Metadata),
	}
}

func resourceMappingMap(row *coreent.ResourceMapping) map[string]any {
	return map[string]any{
		"id":                 row.ID,
		"resource_type_id":   row.ResourceTypeID,
		"storage_kind":       row.StorageKind,
		"table_name":         derefString(row.TableName),
		"id_field":           row.IDField,
		"space_field":        row.SpaceField,
		"group_field":        derefString(row.GroupField),
		"owner_member_field": derefString(row.OwnerMemberField),
		"visibility_field":   derefString(row.VisibilityField),
		"metadata_field":     derefString(row.MetadataField),
		"status":             row.Status,
		"metadata":           nonNilMap(row.Metadata),
		"created_at":         formatTime(row.CreatedAt),
		"updated_at":         formatTime(row.UpdatedAt),
	}
}

func pluginMap(row *coreent.Plugin) map[string]any {
	manifest := pluginManifestFromMap(row.Manifest)
	pluginType, pluginScope, appID := normalizedPluginGovernance(row, manifest)
	return map[string]any{
		"id":          row.ID,
		"key":         row.Key,
		"name":        row.Name,
		"description": derefString(row.Description),
		"version":     row.Version,
		"type":        pluginType,
		"scope":       pluginScope,
		"app_id":      appID,
		"source":      row.Source,
		"status":      row.Status,
		"manifest":    nonNilMap(row.Manifest),
		"created_at":  formatTime(row.CreatedAt),
		"updated_at":  formatTime(row.UpdatedAt),
	}
}

func auditEventTypeMap(row *coreent.AuditEventType) map[string]any {
	return map[string]any{
		"id":            row.ID,
		"key":           row.Key,
		"plugin_id":     derefString(row.PluginID),
		"display_name":  row.DisplayName,
		"description":   derefString(row.Description),
		"risk_level":    row.RiskLevel,
		"default_audit": row.DefaultAudit,
		"metadata":      nonNilMap(row.Metadata),
		"created_at":    formatTime(row.CreatedAt),
		"updated_at":    formatTime(row.UpdatedAt),
	}
}

func pluginAdminMenuMap(row *coreent.PluginAdminMenu) map[string]any {
	return map[string]any{
		"id":                  row.ID,
		"plugin_id":           row.PluginID,
		"label":               row.Label,
		"path":                row.Path,
		"icon":                derefString(row.Icon),
		"required_permission": derefString(row.RequiredPermission),
		"sort_order":          row.SortOrder,
		"metadata":            nonNilMap(row.Metadata),
		"created_at":          formatTime(row.CreatedAt),
		"updated_at":          formatTime(row.UpdatedAt),
	}
}

func pluginSettingsDefinitionMap(row *coreent.PluginSettingsDefinition, value any) map[string]any {
	return map[string]any{
		"id":            row.ID,
		"key":           row.Key,
		"value_type":    row.ValueType,
		"default_value": row.DefaultValue,
		"value":         value,
		"description":   derefString(row.Description),
		"scope":         row.Scope,
		"metadata":      nonNilMap(row.Metadata),
		"created_at":    formatTime(row.CreatedAt),
		"updated_at":    formatTime(row.UpdatedAt),
	}
}
