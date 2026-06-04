package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	coreent "github.com/plystra/core/ent"
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

func TestAppDataRecordQueryPredicatesValidateDataFields(t *testing.T) {
	predicates, err := appDataRecordQueryPredicates(url.Values{
		"data.customer_id": []string{"customer_1"},
		"current_status":   []string{"active"},
		"search":           []string{"invoice"},
	}, appDataDefaultSearchDataFields)
	if err != nil {
		t.Fatalf("valid app data filters rejected: %v", err)
	}
	if len(predicates) != 3 {
		t.Fatalf("predicate count = %d, want 3", len(predicates))
	}

	if _, err := appDataRecordQueryPredicates(url.Values{"data.bad-field": []string{"x"}}, appDataDefaultSearchDataFields); err == nil {
		t.Fatalf("invalid JSON data field was accepted")
	}
	if _, err := appDataRecordQueryPredicates(url.Values{"data.name) OR 1=1 --": []string{"x"}}, appDataDefaultSearchDataFields); err == nil {
		t.Fatalf("unsafe JSON data field was accepted")
	}
	if _, err := appDataRecordQueryPredicates(url.Values{"search": []string{string(make([]byte, 129))}}, appDataDefaultSearchDataFields); err == nil {
		t.Fatalf("oversized search value was accepted")
	}
}

func TestAppDataRecordListOptionsValidateSortOrderAndCursor(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/v1/spaces/space_acme/data/models/tasks/records?sort=created_at&order=asc&limit=75", nil)
	opts, err := appDataRecordListOptionsFromRequest(req)
	if err != nil {
		t.Fatalf("valid list options rejected: %v", err)
	}
	if opts.Limit != 75 || opts.Sort != "created_at" || opts.Order != "asc" || opts.SortField == "" {
		t.Fatalf("unexpected list options: %#v", opts)
	}

	invalidSortReq := httptest.NewRequest("GET", "/api/v1/spaces/space_acme/data/models/tasks/records?sort=data.name", nil)
	if _, err := appDataRecordListOptionsFromRequest(invalidSortReq); err == nil {
		t.Fatalf("unsafe sort field was accepted")
	}

	invalidOrderReq := httptest.NewRequest("GET", "/api/v1/spaces/space_acme/data/models/tasks/records?order=drop", nil)
	if _, err := appDataRecordListOptionsFromRequest(invalidOrderReq); err == nil {
		t.Fatalf("invalid order was accepted")
	}

	badCursorReq := httptest.NewRequest("GET", "/api/v1/spaces/space_acme/data/models/tasks/records?cursor=not-base64", nil)
	if _, err := appDataRecordListOptionsFromRequest(badCursorReq); err == nil {
		t.Fatalf("invalid cursor was accepted")
	}
}

func TestAppDataRecordCursorRoundTripAndSortBinding(t *testing.T) {
	createdAt := time.Date(2026, 6, 1, 12, 0, 0, 123, time.UTC)
	record := &coreent.AppDataRecord{
		ID:         "task_b",
		Status:     "active",
		Visibility: "private",
		CreatedAt:  createdAt,
		UpdatedAt:  createdAt.Add(time.Minute),
	}
	opts := appDataRecordListOptions{
		Limit:     2,
		Sort:      "updated_at",
		SortField: appDataRecordSortColumns["updated_at"],
		Order:     "desc",
	}
	cursor, err := encodeAppDataRecordCursor(opts, record)
	if err != nil {
		t.Fatalf("encode cursor: %v", err)
	}
	decoded, err := decodeAppDataRecordCursor(cursor)
	if err != nil {
		t.Fatalf("decode cursor: %v", err)
	}
	if decoded.Sort != "updated_at" || decoded.Order != "desc" || decoded.Tiebreak != "task_b" || decoded.ValueKind != "time" {
		t.Fatalf("unexpected decoded cursor: %#v", decoded)
	}

	req := httptest.NewRequest("GET", "/api/v1/spaces/space_acme/data/models/tasks/records?cursor="+url.QueryEscape(cursor), nil)
	if _, err := appDataRecordListOptionsFromRequest(req); err != nil {
		t.Fatalf("matching cursor rejected: %v", err)
	}
	mismatchedReq := httptest.NewRequest("GET", "/api/v1/spaces/space_acme/data/models/tasks/records?sort=created_at&cursor="+url.QueryEscape(cursor), nil)
	if _, err := appDataRecordListOptionsFromRequest(mismatchedReq); err == nil {
		t.Fatalf("cursor was accepted for a different sort")
	}

	badPayload, err := json.Marshal(appDataRecordCursor{
		Version:   1,
		Sort:      "updated_at",
		Order:     "desc",
		Value:     "not-a-time",
		Tiebreak:  "task_a",
		ValueKind: "string",
	})
	if err != nil {
		t.Fatalf("marshal bad cursor: %v", err)
	}
	if _, err := decodeAppDataRecordCursor(base64.RawURLEncoding.EncodeToString(badPayload)); err == nil {
		t.Fatalf("cursor with mismatched sort value kind was accepted")
	}
}
