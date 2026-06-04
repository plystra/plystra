package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	coreent "github.com/plystra/core/ent"
	entadmingrant "github.com/plystra/core/ent/admingrant"
	entapikey "github.com/plystra/core/ent/apikey"
	entgroup "github.com/plystra/core/ent/group"
	entmember "github.com/plystra/core/ent/member"
	entresource "github.com/plystra/core/ent/resource"
	entsession "github.com/plystra/core/ent/session"
	entspace "github.com/plystra/core/ent/space"
	entuser "github.com/plystra/core/ent/user"
	entusermember "github.com/plystra/core/ent/usermember"
	"github.com/plystra/core/internal/store/entstore"
)

const (
	boundaryAdminPassword = "boundary-admin-password"
	boundaryGroupPassword = "boundary-group-password"
)

type authorizationBoundaryFixture struct {
	SpaceAID                   string
	SpaceBID                   string
	FinanceGroupID             string
	FinanceAPACGroupID         string
	LegalGroupID               string
	AdminUserID                string
	AdminMemberID              string
	AdminUserMemberID          string
	GroupUserID                string
	GroupMemberID              string
	GroupUserMemberID          string
	FinanceResourceID          string
	LegalResourceID            string
	VisibleAdminGrantID        string
	ForeignAdminGrantID        string
	UnheldAPIKeyID             string
	OtherSpaceAPIKeyID         string
	InstanceEscalationAPIKeyID string
	AllowedAPIKeyID            string
	DirectAdminGrantAPIKeyID   string
	DirectAdminGrantAPIKey     string
	InstanceAPIKeyID           string
	APIKeyCreatedGrantID       string
	InstanceEscalationGrantID  string
	UnheldAdminGrantID         string
}

func TestAdminAuthorizationBoundaryIntegration(t *testing.T) {
	databaseURL := authorizationBoundaryDatabaseURL()
	if databaseURL == "" {
		t.Skip("set PLYSTRA_INTEGRATION_DATABASE_URL or PLYSTRA_DATABASE_URL to run authorization boundary integration tests")
	}

	t.Setenv("PLYSTRA_SESSION_SECRET", "boundary-session-secret-at-least-32-characters")
	t.Setenv("PLYSTRA_API_KEY_SECRET", "boundary-api-key-secret-at-least-32-characters")

	ctx := context.Background()
	store, err := entstore.Open(ctx, databaseURL)
	if err != nil {
		t.Fatalf("open ent store: %v", err)
	}
	defer store.Close()

	fixture := createAuthorizationBoundaryFixture(t, ctx, store.Client())
	t.Cleanup(func() {
		cleanupAuthorizationBoundaryFixture(context.Background(), t, store.Client(), fixture)
	})

	server := NewServer(nil, store, "1.0.0-test")
	handler := server.Routes()

	adminToken := loginForBoundaryTest(t, handler, fixture.AdminUserID, boundaryAdminPassword)
	groupToken := loginForBoundaryTest(t, handler, fixture.GroupUserID, boundaryGroupPassword)

	t.Run("space admin list filters out foreign admin grants", func(t *testing.T) {
		rec := boundaryJSONRequest(handler, http.MethodGet, "/api/v1/admin/grants?limit=200", map[string]string{
			"Authorization": "Bearer " + adminToken,
		}, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
		}
		payload := decodeBoundaryPayload(t, rec)
		rows, ok := payload["data"].([]any)
		if !ok {
			t.Fatalf("data is not a list: %#v", payload["data"])
		}
		if !listContainsID(rows, fixture.VisibleAdminGrantID) {
			t.Fatalf("expected visible admin grant %q in response: %#v", fixture.VisibleAdminGrantID, rows)
		}
		if listContainsID(rows, fixture.ForeignAdminGrantID) {
			t.Fatalf("foreign admin grant %q leaked into space-scoped response: %#v", fixture.ForeignAdminGrantID, rows)
		}
		if listContainsAdminGrantLevel(rows, adminLevelInstance) || listContainsAdminGrantLevel(rows, adminLevelInstanceSuper) {
			t.Fatalf("instance-level admin grant leaked into space-scoped response: %#v", rows)
		}
	})

	t.Run("space admin list filters out instance API keys", func(t *testing.T) {
		rec := boundaryJSONRequest(handler, http.MethodGet, "/api/v1/api-keys?limit=200", map[string]string{
			"Authorization": "Bearer " + adminToken,
		}, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
		}
		payload := decodeBoundaryPayload(t, rec)
		rows, ok := payload["data"].([]any)
		if !ok {
			t.Fatalf("data is not a list: %#v", payload["data"])
		}
		if !listContainsID(rows, fixture.DirectAdminGrantAPIKeyID) {
			t.Fatalf("expected scoped API key %q in response: %#v", fixture.DirectAdminGrantAPIKeyID, rows)
		}
		if listContainsID(rows, fixture.InstanceAPIKeyID) {
			t.Fatalf("instance API key %q leaked into space-scoped response: %#v", fixture.InstanceAPIKeyID, rows)
		}
	})

	t.Run("space admin cannot create API key with unheld permission", func(t *testing.T) {
		rec := boundaryJSONRequest(handler, http.MethodPost, "/api/v1/api-keys", map[string]string{
			"Authorization": "Bearer " + adminToken,
		}, map[string]any{
			"id":              fixture.UnheldAPIKeyID,
			"name":            "Denied unheld key",
			"level":           "space",
			"space_id":        fixture.SpaceAID,
			"permission_keys": []string{"resources:manage"},
		})
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403, body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("space admin cannot create API key outside own space", func(t *testing.T) {
		rec := boundaryJSONRequest(handler, http.MethodPost, "/api/v1/api-keys", map[string]string{
			"Authorization": "Bearer " + adminToken,
		}, map[string]any{
			"id":              fixture.OtherSpaceAPIKeyID,
			"name":            "Denied other space key",
			"level":           "space",
			"space_id":        fixture.SpaceBID,
			"permission_keys": []string{"api_keys:create"},
		})
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403, body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("space admin cannot create instance API key", func(t *testing.T) {
		rec := boundaryJSONRequest(handler, http.MethodPost, "/api/v1/api-keys", map[string]string{
			"Authorization": "Bearer " + adminToken,
		}, map[string]any{
			"id":              fixture.InstanceEscalationAPIKeyID,
			"name":            "Denied instance key",
			"level":           "instance",
			"permission_keys": []string{"api_keys:create"},
		})
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403, body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("space admin can create API key only for own held permission", func(t *testing.T) {
		rec := boundaryJSONRequest(handler, http.MethodPost, "/api/v1/api-keys", map[string]string{
			"Authorization": "Bearer " + adminToken,
		}, map[string]any{
			"id":              fixture.AllowedAPIKeyID,
			"name":            "Allowed scoped key",
			"level":           "space",
			"space_id":        fixture.SpaceAID,
			"permission_keys": []string{"api_keys:create"},
		})
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201, body=%s", rec.Code, rec.Body.String())
		}
		payload := decodeBoundaryPayload(t, rec)
		data, ok := payload["data"].(map[string]any)
		if !ok {
			t.Fatalf("data is not an object: %#v", payload["data"])
		}
		key, _ := data["api_key"].(string)
		if !strings.HasPrefix(key, apiKeyBearerPrefix+fixture.AllowedAPIKeyID+".") {
			t.Fatalf("created API key has unexpected format: %#v", data["api_key"])
		}
	})

	t.Run("api key cannot create human admin grants", func(t *testing.T) {
		rec := boundaryJSONRequest(handler, http.MethodPost, "/api/v1/admin/grants", map[string]string{
			"X-Plystra-API-Key": fixture.DirectAdminGrantAPIKey,
		}, map[string]any{
			"id":             fixture.APIKeyCreatedGrantID,
			"user_id":        fixture.GroupUserID,
			"level":          adminLevelSpace,
			"space_id":       fixture.SpaceAID,
			"permission_key": "admin_grants:read",
		})
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403, body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("space admin cannot promote anyone to instance admin", func(t *testing.T) {
		rec := boundaryJSONRequest(handler, http.MethodPost, "/api/v1/admin/grants", map[string]string{
			"Authorization": "Bearer " + adminToken,
		}, map[string]any{
			"id":             fixture.InstanceEscalationGrantID,
			"user_id":        fixture.GroupUserID,
			"level":          adminLevelInstance,
			"permission_key": "users:read",
		})
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403, body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("space admin cannot delegate unheld admin permission", func(t *testing.T) {
		rec := boundaryJSONRequest(handler, http.MethodPost, "/api/v1/admin/grants", map[string]string{
			"Authorization": "Bearer " + adminToken,
		}, map[string]any{
			"id":             fixture.UnheldAdminGrantID,
			"user_id":        fixture.GroupUserID,
			"level":          adminLevelSpace,
			"space_id":       fixture.SpaceAID,
			"permission_key": "resources:manage",
		})
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403, body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("session authz check cannot impersonate another user actor", func(t *testing.T) {
		rec := boundaryJSONRequest(handler, http.MethodPost, "/api/v1/authz/check", map[string]string{
			"Authorization": "Bearer " + adminToken,
		}, map[string]any{
			"actor": map[string]any{
				"user_id":        fixture.GroupUserID,
				"member_id":      fixture.GroupMemberID,
				"user_member_id": fixture.GroupUserMemberID,
				"space_id":       fixture.SpaceAID,
			},
			"resource_type": "invoice",
			"resource_id":   fixture.FinanceResourceID,
			"action":        "read",
		})
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403, body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("group admin can read descendant resource but not sibling or whole-space resources", func(t *testing.T) {
		allowed := boundaryJSONRequest(handler, http.MethodGet, "/api/v1/resources/invoice/"+fixture.FinanceResourceID, map[string]string{
			"Authorization": "Bearer " + groupToken,
		}, nil)
		if allowed.Code != http.StatusOK {
			t.Fatalf("descendant resource status = %d, body=%s", allowed.Code, allowed.Body.String())
		}

		sibling := boundaryJSONRequest(handler, http.MethodGet, "/api/v1/resources/invoice/"+fixture.LegalResourceID, map[string]string{
			"Authorization": "Bearer " + groupToken,
		}, nil)
		if sibling.Code != http.StatusForbidden {
			t.Fatalf("sibling resource status = %d, want 403, body=%s", sibling.Code, sibling.Body.String())
		}

		spaceList := boundaryJSONRequest(handler, http.MethodGet, "/api/v1/resources?space_id="+fixture.SpaceAID, map[string]string{
			"Authorization": "Bearer " + groupToken,
		}, nil)
		if spaceList.Code != http.StatusForbidden {
			t.Fatalf("space resource list status = %d, want 403, body=%s", spaceList.Code, spaceList.Body.String())
		}
	})
}

func authorizationBoundaryDatabaseURL() string {
	for _, key := range []string{"PLYSTRA_INTEGRATION_DATABASE_URL", "PLYSTRA_DATABASE_URL"} {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return value
		}
	}
	return ""
}

func createAuthorizationBoundaryFixture(t *testing.T, ctx context.Context, client *coreent.Client) authorizationBoundaryFixture {
	t.Helper()
	suffix := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	fixture := authorizationBoundaryFixture{
		SpaceAID:                   "space_boundary_a_" + suffix,
		SpaceBID:                   "space_boundary_b_" + suffix,
		FinanceGroupID:             "group_boundary_finance_" + suffix,
		FinanceAPACGroupID:         "group_boundary_finance_apac_" + suffix,
		LegalGroupID:               "group_boundary_legal_" + suffix,
		AdminUserID:                "user_boundary_admin_" + suffix,
		AdminMemberID:              "member_boundary_admin_" + suffix,
		AdminUserMemberID:          "um_boundary_admin_" + suffix,
		GroupUserID:                "user_boundary_group_" + suffix,
		GroupMemberID:              "member_boundary_group_" + suffix,
		GroupUserMemberID:          "um_boundary_group_" + suffix,
		FinanceResourceID:          "resource_boundary_finance_" + suffix,
		LegalResourceID:            "resource_boundary_legal_" + suffix,
		VisibleAdminGrantID:        "ag_boundary_visible_" + suffix,
		ForeignAdminGrantID:        "ag_boundary_foreign_" + suffix,
		UnheldAPIKeyID:             "ak_boundary_unheld_" + suffix,
		OtherSpaceAPIKeyID:         "ak_boundary_other_space_" + suffix,
		InstanceEscalationAPIKeyID: "ak_boundary_instance_escalation_" + suffix,
		AllowedAPIKeyID:            "ak_boundary_allowed_" + suffix,
		DirectAdminGrantAPIKeyID:   "ak_boundary_admin_grants_" + suffix,
		InstanceAPIKeyID:           "ak_boundary_instance_" + suffix,
		APIKeyCreatedGrantID:       "ag_boundary_by_api_key_" + suffix,
		InstanceEscalationGrantID:  "ag_boundary_instance_escalation_" + suffix,
		UnheldAdminGrantID:         "ag_boundary_unheld_permission_" + suffix,
	}

	adminHash, err := hashPassword(boundaryAdminPassword)
	if err != nil {
		t.Fatalf("hash admin password: %v", err)
	}
	groupHash, err := hashPassword(boundaryGroupPassword)
	if err != nil {
		t.Fatalf("hash group password: %v", err)
	}
	fixture.DirectAdminGrantAPIKey, err = newAPIKeyPlaintext(fixture.DirectAdminGrantAPIKeyID)
	if err != nil {
		t.Fatalf("generate direct API key: %v", err)
	}
	instanceAPIKey, err := newAPIKeyPlaintext(fixture.InstanceAPIKeyID)
	if err != nil {
		t.Fatalf("generate instance API key: %v", err)
	}

	if _, err := client.Space.Create().SetID(fixture.SpaceAID).SetName("Boundary Space A").SetSlug("boundary-a-" + suffix).Save(ctx); err != nil {
		t.Fatalf("create space A: %v", err)
	}
	if _, err := client.Space.Create().SetID(fixture.SpaceBID).SetName("Boundary Space B").SetSlug("boundary-b-" + suffix).Save(ctx); err != nil {
		t.Fatalf("create space B: %v", err)
	}
	if _, err := client.Group.Create().SetID(fixture.FinanceGroupID).SetSpaceID(fixture.SpaceAID).SetName("finance").SetPath("finance").SetDepth(0).Save(ctx); err != nil {
		t.Fatalf("create finance group: %v", err)
	}
	if _, err := client.Group.Create().SetID(fixture.FinanceAPACGroupID).SetSpaceID(fixture.SpaceAID).SetParentGroupID(fixture.FinanceGroupID).SetName("apac").SetPath("finance.apac").SetDepth(1).Save(ctx); err != nil {
		t.Fatalf("create finance APAC group: %v", err)
	}
	if _, err := client.Group.Create().SetID(fixture.LegalGroupID).SetSpaceID(fixture.SpaceAID).SetName("legal").SetPath("legal").SetDepth(0).Save(ctx); err != nil {
		t.Fatalf("create legal group: %v", err)
	}
	if _, err := client.User.Create().SetID(fixture.AdminUserID).SetEmail("boundary.admin." + suffix + "@example.com").SetPasswordHash(adminHash).Save(ctx); err != nil {
		t.Fatalf("create admin user: %v", err)
	}
	if _, err := client.User.Create().SetID(fixture.GroupUserID).SetEmail("boundary.group." + suffix + "@example.com").SetPasswordHash(groupHash).Save(ctx); err != nil {
		t.Fatalf("create group user: %v", err)
	}
	if _, err := client.Member.Create().SetID(fixture.AdminMemberID).SetSpaceID(fixture.SpaceAID).SetDisplayName("Boundary Space Admin").Save(ctx); err != nil {
		t.Fatalf("create admin member: %v", err)
	}
	if _, err := client.Member.Create().SetID(fixture.GroupMemberID).SetSpaceID(fixture.SpaceAID).SetDisplayName("Boundary Group Admin").Save(ctx); err != nil {
		t.Fatalf("create group member: %v", err)
	}
	if _, err := client.UserMember.Create().SetID(fixture.AdminUserMemberID).SetUserID(fixture.AdminUserID).SetMemberID(fixture.AdminMemberID).SetSpaceID(fixture.SpaceAID).SetRelationType("login").SetIsPrimary(true).Save(ctx); err != nil {
		t.Fatalf("create admin user member: %v", err)
	}
	if _, err := client.UserMember.Create().SetID(fixture.GroupUserMemberID).SetUserID(fixture.GroupUserID).SetMemberID(fixture.GroupMemberID).SetSpaceID(fixture.SpaceAID).SetRelationType("login").SetIsPrimary(true).Save(ctx); err != nil {
		t.Fatalf("create group user member: %v", err)
	}
	if _, err := client.Resource.Create().SetID(fixture.FinanceResourceID).SetResourceType("invoice").SetSpaceID(fixture.SpaceAID).SetGroupID(fixture.FinanceAPACGroupID).SetDisplayName("Finance Boundary Resource").Save(ctx); err != nil {
		t.Fatalf("create finance resource: %v", err)
	}
	if _, err := client.Resource.Create().SetID(fixture.LegalResourceID).SetResourceType("invoice").SetSpaceID(fixture.SpaceAID).SetGroupID(fixture.LegalGroupID).SetDisplayName("Legal Boundary Resource").Save(ctx); err != nil {
		t.Fatalf("create legal resource: %v", err)
	}

	createGrant := func(id, userID, level, permissionKey, spaceID, groupID string) {
		t.Helper()
		mutation := client.AdminGrant.Create().
			SetID(id).
			SetUserID(userID).
			SetLevel(level).
			SetPermissionKey(permissionKey)
		if spaceID != "" {
			mutation.SetSpaceID(spaceID)
		}
		if groupID != "" {
			mutation.SetGroupID(groupID)
		}
		if _, err := mutation.Save(ctx); err != nil {
			t.Fatalf("create admin grant %s: %v", id, err)
		}
	}
	createGrant("ag_boundary_api_keys_create_"+suffix, fixture.AdminUserID, adminLevelSpace, "api_keys:create", fixture.SpaceAID, "")
	createGrant("ag_boundary_api_keys_read_"+suffix, fixture.AdminUserID, adminLevelSpace, "api_keys:read", fixture.SpaceAID, "")
	createGrant(fixture.VisibleAdminGrantID, fixture.AdminUserID, adminLevelSpace, "admin_grants:read", fixture.SpaceAID, "")
	createGrant("ag_boundary_admin_grants_manage_"+suffix, fixture.AdminUserID, adminLevelSpace, "admin_grants:manage", fixture.SpaceAID, "")
	createGrant(fixture.ForeignAdminGrantID, fixture.GroupUserID, adminLevelSpace, "admin_grants:read", fixture.SpaceBID, "")
	createGrant("ag_boundary_group_resources_"+suffix, fixture.GroupUserID, adminLevelGroup, "resources:read", fixture.SpaceAID, fixture.FinanceGroupID)

	if _, err := client.ApiKey.Create().
		SetID(fixture.DirectAdminGrantAPIKeyID).
		SetName("Boundary direct admin grant key").
		SetKeyPrefix(apiKeyPrefix(fixture.DirectAdminGrantAPIKeyID)).
		SetKeyHash(apiKeyHash(fixture.DirectAdminGrantAPIKey)).
		SetLevel("space").
		SetSpaceID(fixture.SpaceAID).
		SetPermissionKeys([]string{"admin_grants:manage"}).
		Save(ctx); err != nil {
		t.Fatalf("create direct API key: %v", err)
	}
	if _, err := client.ApiKey.Create().
		SetID(fixture.InstanceAPIKeyID).
		SetName("Boundary instance key").
		SetKeyPrefix(apiKeyPrefix(fixture.InstanceAPIKeyID)).
		SetKeyHash(apiKeyHash(instanceAPIKey)).
		SetLevel("instance").
		SetPermissionKeys([]string{"api_keys:read"}).
		Save(ctx); err != nil {
		t.Fatalf("create instance API key: %v", err)
	}

	return fixture
}

func cleanupAuthorizationBoundaryFixture(ctx context.Context, t *testing.T, client *coreent.Client, fixture authorizationBoundaryFixture) {
	t.Helper()
	now := time.Now().UTC()
	_, _ = client.Session.Update().
		Where(entsession.UserIDIn(fixture.AdminUserID, fixture.GroupUserID)).
		SetRevokedAt(now).
		Save(ctx)
	_, _ = client.ApiKey.Update().
		Where(entapikey.IDIn(
			fixture.UnheldAPIKeyID,
			fixture.OtherSpaceAPIKeyID,
			fixture.InstanceEscalationAPIKeyID,
			fixture.AllowedAPIKeyID,
			fixture.DirectAdminGrantAPIKeyID,
			fixture.InstanceAPIKeyID,
		)).
		SetStatus("revoked").
		SetRevokedAt(now).
		SetDeletedAt(now).
		Save(ctx)
	_, _ = client.AdminGrant.Update().
		Where(entadmingrant.Or(
			entadmingrant.UserIDIn(fixture.AdminUserID, fixture.GroupUserID),
			entadmingrant.IDIn(fixture.APIKeyCreatedGrantID, fixture.InstanceEscalationGrantID, fixture.UnheldAdminGrantID),
		)).
		SetStatus("revoked").
		SetRevokedAt(now).
		SetDeletedAt(now).
		Save(ctx)
	_, _ = client.Resource.Update().
		Where(entresource.IDIn(fixture.FinanceResourceID, fixture.LegalResourceID)).
		SetDeletedAt(now).
		Save(ctx)
	_, _ = client.UserMember.Update().
		Where(entusermember.IDIn(fixture.AdminUserMemberID, fixture.GroupUserMemberID)).
		SetStatus("revoked").
		SetRevokedAt(now).
		SetDeletedAt(now).
		Save(ctx)
	_, _ = client.Member.Update().
		Where(entmember.IDIn(fixture.AdminMemberID, fixture.GroupMemberID)).
		SetStatus("disabled").
		SetDeletedAt(now).
		Save(ctx)
	_, _ = client.Group.Update().
		Where(entgroup.IDIn(fixture.FinanceAPACGroupID, fixture.FinanceGroupID, fixture.LegalGroupID)).
		SetStatus("disabled").
		SetDeletedAt(now).
		Save(ctx)
	_, _ = client.User.Update().
		Where(entuser.IDIn(fixture.AdminUserID, fixture.GroupUserID)).
		SetStatus("disabled").
		SetDeletedAt(now).
		Save(ctx)
	_, _ = client.Space.Update().
		Where(entspace.IDIn(fixture.SpaceAID, fixture.SpaceBID)).
		SetStatus("disabled").
		SetDeletedAt(now).
		Save(ctx)
}

func loginForBoundaryTest(t *testing.T, handler http.Handler, userID, password string) string {
	t.Helper()
	email := strings.TrimPrefix(userID, "user_boundary_")
	email = strings.ReplaceAll(email, "_", ".")
	email = "boundary." + email + "@example.com"
	parts := strings.Split(userID, "_")
	if len(parts) > 0 {
		suffix := parts[len(parts)-1]
		if strings.Contains(userID, "_admin_") {
			email = "boundary.admin." + suffix + "@example.com"
		} else {
			email = "boundary.group." + suffix + "@example.com"
		}
	}
	rec := boundaryJSONRequest(handler, http.MethodPost, "/api/v1/auth/login", nil, map[string]any{
		"email":    email,
		"password": password,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("login %s status = %d, body=%s", userID, rec.Code, rec.Body.String())
	}
	payload := decodeBoundaryPayload(t, rec)
	data, ok := payload["data"].(map[string]any)
	if !ok {
		t.Fatalf("login data is not an object: %#v", payload["data"])
	}
	token, _ := data["access_token"].(string)
	if token == "" {
		t.Fatalf("login did not return access_token: %#v", data)
	}
	return token
}

func boundaryJSONRequest(handler http.Handler, method, path string, headers map[string]string, body any) *httptest.ResponseRecorder {
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		payload, _ := json.Marshal(body)
		reader = bytes.NewReader(payload)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-Request-ID", "req_boundary_test")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeBoundaryPayload(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response %q: %v", rec.Body.String(), err)
	}
	return payload
}

func listContainsID(rows []any, id string) bool {
	for _, row := range rows {
		object, ok := row.(map[string]any)
		if !ok {
			continue
		}
		if object["id"] == id {
			return true
		}
	}
	return false
}

func listContainsAdminGrantLevel(rows []any, level string) bool {
	for _, row := range rows {
		object, ok := row.(map[string]any)
		if !ok {
			continue
		}
		if object["level"] == level {
			return true
		}
	}
	return false
}
