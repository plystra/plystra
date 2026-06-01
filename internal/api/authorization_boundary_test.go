package api

import (
	"context"
	"testing"
	"time"

	coreent "github.com/plystra/plystra/ent"
)

func TestAdminGrantSpaceBoundaryRequiresMatchingScope(t *testing.T) {
	ctx := context.Background()
	spaceID := "space_acme"
	grant := &coreent.AdminGrant{
		Level:         adminLevelSpace,
		SpaceID:       optionalString(spaceID),
		PermissionKey: "resources:read",
		Status:        "active",
	}
	server := &Server{}

	allowed, err := server.adminGrantAllows(ctx, grant, adminRequirement{
		PermissionKey: "resources:read",
		SpaceID:       spaceID,
	})
	if err != nil {
		t.Fatalf("adminGrantAllows exact scope error: %v", err)
	}
	if !allowed {
		t.Fatalf("space admin was denied within its own space")
	}

	allowed, err = server.adminGrantAllows(ctx, grant, adminRequirement{
		PermissionKey: "resources:read",
		SpaceID:       "space_other",
	})
	if err != nil {
		t.Fatalf("adminGrantAllows other scope error: %v", err)
	}
	if allowed {
		t.Fatalf("space admin was allowed to access another space")
	}

	allowed, err = server.adminGrantAllows(ctx, grant, adminRequirement{
		PermissionKey: "resources:read",
	})
	if err != nil {
		t.Fatalf("adminGrantAllows unscoped resource error: %v", err)
	}
	if allowed {
		t.Fatalf("space admin was allowed to use a scoped permission without a resolved scope")
	}
}

func TestAdminGrantHandlerResolvedScopeIsLimitedToExplicitHandlers(t *testing.T) {
	ctx := context.Background()
	grant := &coreent.AdminGrant{
		Level:         adminLevelSpace,
		SpaceID:       optionalString("space_acme"),
		PermissionKey: "api_keys:create",
		Status:        "active",
	}
	server := &Server{}

	allowed, err := server.adminGrantAllows(ctx, grant, adminRequirement{PermissionKey: "api_keys:create"})
	if err != nil {
		t.Fatalf("handler-resolved grant error: %v", err)
	}
	if !allowed {
		t.Fatalf("space admin should be allowed through middleware for handler-resolved API key scope")
	}

	grant.PermissionKey = "resources:read"
	allowed, err = server.adminGrantAllows(ctx, grant, adminRequirement{PermissionKey: "resources:read"})
	if err != nil {
		t.Fatalf("non-handler-resolved grant error: %v", err)
	}
	if allowed {
		t.Fatalf("space admin was allowed through middleware for an unscoped resource permission")
	}
}

func TestGroupAdminRequiresGroupScope(t *testing.T) {
	ctx := context.Background()
	groupID := "group_finance"
	grant := &coreent.AdminGrant{
		Level:         adminLevelGroup,
		GroupID:       optionalString(groupID),
		PermissionKey: "resources:read",
		Status:        "active",
	}
	server := &Server{}

	allowed, err := server.adminGrantAllows(ctx, grant, adminRequirement{
		PermissionKey: "resources:read",
		GroupID:       groupID,
	})
	if err != nil {
		t.Fatalf("group exact scope error: %v", err)
	}
	if !allowed {
		t.Fatalf("group admin was denied for its exact group")
	}

	allowed, err = server.adminGrantAllows(ctx, grant, adminRequirement{
		PermissionKey: "resources:read",
		SpaceID:       "space_acme",
	})
	if err != nil {
		t.Fatalf("group space-only scope error: %v", err)
	}
	if allowed {
		t.Fatalf("group admin was allowed for a space-only requirement")
	}

	allowed, err = server.adminGrantAllows(ctx, grant, adminRequirement{
		PermissionKey: "resources:read",
	})
	if err != nil {
		t.Fatalf("group unscoped requirement error: %v", err)
	}
	if allowed {
		t.Fatalf("group admin was allowed without a resolved group scope")
	}
}

func TestAPIKeyBoundaryRejectsInactiveRevokedExpiredAndUnscopedUse(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	revokedAt := now
	expiredAt := now.Add(-time.Minute)
	server := &Server{}

	cases := []struct {
		name string
		key  *coreent.ApiKey
		req  adminRequirement
	}{
		{
			name: "inactive",
			key: &coreent.ApiKey{
				Level:          "instance",
				Status:         "disabled",
				PermissionKeys: []string{"resources:read"},
			},
			req: adminRequirement{PermissionKey: "resources:read"},
		},
		{
			name: "revoked",
			key: &coreent.ApiKey{
				Level:          "instance",
				Status:         "active",
				RevokedAt:      &revokedAt,
				PermissionKeys: []string{"resources:read"},
			},
			req: adminRequirement{PermissionKey: "resources:read"},
		},
		{
			name: "expired",
			key: &coreent.ApiKey{
				Level:          "instance",
				Status:         "active",
				ExpiresAt:      &expiredAt,
				PermissionKeys: []string{"resources:read"},
			},
			req: adminRequirement{PermissionKey: "resources:read"},
		},
		{
			name: "space key missing resolved scope",
			key: &coreent.ApiKey{
				Level:          "space",
				SpaceID:        optionalString("space_acme"),
				Status:         "active",
				PermissionKeys: []string{"resources:read"},
			},
			req: adminRequirement{PermissionKey: "resources:read"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			allowed, err := server.apiKeyAllows(ctx, tc.key, tc.req)
			if err != nil {
				t.Fatalf("apiKeyAllows error: %v", err)
			}
			if allowed {
				t.Fatalf("api key was allowed for denied case %q", tc.name)
			}
		})
	}
}

func TestAPIKeyScopedHandlerResolutionIsLimited(t *testing.T) {
	ctx := context.Background()
	key := &coreent.ApiKey{
		Level:          "space",
		SpaceID:        optionalString("space_acme"),
		Status:         "active",
		PermissionKeys: []string{"authz:check", "api_keys:create"},
	}
	server := &Server{}

	allowed, err := server.apiKeyAllows(ctx, key, adminRequirement{PermissionKey: "authz:check"})
	if err != nil {
		t.Fatalf("authz handler-resolved key error: %v", err)
	}
	if !allowed {
		t.Fatalf("space API key should pass middleware for handler-resolved authz checks")
	}

	allowed, err = server.apiKeyAllows(ctx, key, adminRequirement{PermissionKey: "api_keys:create"})
	if err != nil {
		t.Fatalf("api key handler-resolved key error: %v", err)
	}
	if !allowed {
		t.Fatalf("space API key should pass middleware for handler-resolved API key creation")
	}

	key.PermissionKeys = []string{"resources:read"}
	allowed, err = server.apiKeyAllows(ctx, key, adminRequirement{PermissionKey: "resources:read"})
	if err != nil {
		t.Fatalf("resource key error: %v", err)
	}
	if allowed {
		t.Fatalf("space API key was allowed to use resources:read without a resolved scope")
	}
}

func TestAdminPermissionKeyValidationRejectsAmbiguousOrUnsafeKeys(t *testing.T) {
	valid := []string{
		"*",
		"users:read",
		"users:*",
		"admin_grants:manage",
		"api-keys:read",
	}
	for _, key := range valid {
		if !validAdminPermissionKey(key) {
			t.Fatalf("permission key %q should be valid", key)
		}
	}

	invalid := []string{
		"*:read",
		"users",
		"Users:read",
		"users:Read",
		"users:",
		":read",
		"users:read/write",
		"users:**",
		"users:read:extra",
	}
	for _, key := range invalid {
		if validAdminPermissionKey(key) {
			t.Fatalf("permission key %q should be invalid", key)
		}
	}
}

func TestOnlyHumanSessionCanBeInstanceSuperAdmin(t *testing.T) {
	sessionSuper := adminPrincipal{
		CredentialType: "session",
		Grants: []*coreent.AdminGrant{{
			Level:         adminLevelInstanceSuper,
			PermissionKey: "*",
		}},
	}
	if !adminPrincipalIsSuper(sessionSuper) {
		t.Fatalf("session instance super admin was not recognized")
	}

	sessionInstanceWildcard := adminPrincipal{
		CredentialType: "session",
		Grants: []*coreent.AdminGrant{{
			Level:         adminLevelInstance,
			PermissionKey: "*",
		}},
	}
	if adminPrincipalIsSuper(sessionInstanceWildcard) {
		t.Fatalf("instance admin wildcard was treated as instance super admin")
	}

	apiKeyWildcard := adminPrincipal{
		CredentialType: "api_key",
		APIKey: &coreent.ApiKey{
			Level:          "instance",
			Status:         "active",
			PermissionKeys: []string{"*"},
		},
	}
	if adminPrincipalIsSuper(apiKeyWildcard) {
		t.Fatalf("API key wildcard was treated as instance super admin")
	}
}

func TestAppDataServicePrincipalRequiresScopedAPIKey(t *testing.T) {
	ctx := context.Background()
	server := &Server{}
	spaceID := "space_acme"
	principal := adminPrincipal{
		CredentialType: "api_key",
		APIKey: &coreent.ApiKey{
			Level:          "space",
			SpaceID:        optionalString(spaceID),
			Status:         "active",
			PermissionKeys: []string{"data:read", "data:manage"},
		},
	}

	if !server.appDataServicePrincipalAllowed(ctx, principal, "read", spaceID) {
		t.Fatalf("space data:read API key should allow app data service reads in its space")
	}
	if !server.appDataServicePrincipalAllowed(ctx, principal, "update", spaceID) {
		t.Fatalf("space data:manage API key should allow app data service mutations in its space")
	}
	if server.appDataServicePrincipalAllowed(ctx, principal, "read", "space_other") {
		t.Fatalf("space API key should not allow app data service reads outside its space")
	}

	readOnly := principal
	readOnly.APIKey = &coreent.ApiKey{
		Level:          "space",
		SpaceID:        optionalString(spaceID),
		Status:         "active",
		PermissionKeys: []string{"data:read"},
	}
	if server.appDataServicePrincipalAllowed(ctx, readOnly, "update", spaceID) {
		t.Fatalf("data:read API key should not allow app data service mutations")
	}

	sessionPrincipal := adminPrincipal{CredentialType: "session"}
	if server.appDataServicePrincipalAllowed(ctx, sessionPrincipal, "read", spaceID) {
		t.Fatalf("human session should use record authorization, not app data service authorization")
	}
}
