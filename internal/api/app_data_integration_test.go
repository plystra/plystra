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
	entappdatamodel "github.com/plystra/core/ent/appdatamodel"
	entappdatarecord "github.com/plystra/core/ent/appdatarecord"
	entappdatarecordrevision "github.com/plystra/core/ent/appdatarecordrevision"
	entauditlog "github.com/plystra/core/ent/auditlog"
	entgroup "github.com/plystra/core/ent/group"
	entmember "github.com/plystra/core/ent/member"
	entmemberrole "github.com/plystra/core/ent/memberrole"
	entpermission "github.com/plystra/core/ent/permission"
	entresourcetype "github.com/plystra/core/ent/resourcetype"
	entrole "github.com/plystra/core/ent/role"
	entrolepermission "github.com/plystra/core/ent/rolepermission"
	entsession "github.com/plystra/core/ent/session"
	entspace "github.com/plystra/core/ent/space"
	entuser "github.com/plystra/core/ent/user"
	entusermember "github.com/plystra/core/ent/usermember"
	"github.com/plystra/core/internal/authz"
	"github.com/plystra/core/internal/store/entstore"
)

const (
	appDataOwnerPassword   = "app-data-owner-password"
	appDataSiblingPassword = "app-data-sibling-password"
)

type appDataFixture struct {
	Suffix              string
	SpaceID             string
	RootGroupID         string
	AllowedGroupID      string
	SiblingGroupID      string
	OwnerUserID         string
	OwnerMemberID       string
	OwnerUserMemberID   string
	SiblingUserID       string
	SiblingMemberID     string
	SiblingUserMemberID string
	SpaceAdminGrantID   string
	AllowedRoleID       string
	AllowedMemberRoleID string
	SiblingRoleID       string
	SiblingMemberRoleID string
	RecordID            string
	ModelKey            string
	ModelResource       string
	PermissionIDs       []string
	RolePermissionIDs   []string
}

func TestAppDataStoreIntegration(t *testing.T) {
	databaseURL := appDataTestDatabaseURL()
	if databaseURL == "" {
		t.Skip("set PLYSTRA_INTEGRATION_DATABASE_URL or PLYSTRA_DATABASE_URL to run app data integration tests")
	}
	t.Setenv("PLYSTRA_SESSION_SECRET", "app-data-session-secret-at-least-32-characters")

	ctx := context.Background()
	store, err := entstore.Open(ctx, databaseURL)
	if err != nil {
		t.Fatalf("open ent store: %v", err)
	}
	defer store.Close()

	fixture := createAppDataFixture(t, ctx, store.Client())
	t.Cleanup(func() {
		cleanupAppDataFixture(context.Background(), t, store.Client(), fixture)
	})

	server := NewServer(nil, store, "1.0.0-test")
	handler := server.Routes()
	ownerToken := loginAppDataUser(t, handler, "appdata.owner."+fixture.Suffix+"@example.com", appDataOwnerPassword)
	siblingToken := loginAppDataUser(t, handler, "appdata.sibling."+fixture.Suffix+"@example.com", appDataSiblingPassword)

	t.Run("space admin creates model and model-specific authorization surface", func(t *testing.T) {
		rec := appDataJSONRequest(handler, http.MethodPost, "/api/v1/spaces/"+fixture.SpaceID+"/data/models", ownerToken, map[string]any{
			"id":           "model_appdata_" + fixture.Suffix,
			"key":          fixture.ModelKey,
			"display_name": "Customer",
			"schema": map[string]any{
				"required": []any{"name"},
			},
			"metadata": map[string]any{"purpose": "integration-test"},
		})
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201, body=%s", rec.Code, rec.Body.String())
		}
		if exists, err := store.Client().ResourceType.Query().Where(entresourcetype.Key(fixture.ModelResource), entresourcetype.Status("active")).Exist(ctx); err != nil || !exists {
			t.Fatalf("model resource type exists=%t err=%v, want active %q", exists, err, fixture.ModelResource)
		}
		payload := decodeAppDataPayload(t, rec)
		model := payload["data"].(map[string]any)
		permissions := model["permissions"].([]any)
		if len(permissions) != 5 {
			t.Fatalf("model permissions count = %d, want 5: %#v", len(permissions), permissions)
		}
		if count, err := store.Client().Permission.Query().Where(entpermission.Resource(fixture.ModelResource), entpermission.Scope(string(authz.ScopeSpace))).Count(ctx); err != nil {
			t.Fatalf("count generated model permissions: %v", err)
		} else if count != 5 {
			t.Fatalf("generated model permissions count = %d, want 5", count)
		}
	})

	grantModelPermissions(t, ctx, store.Client(), &fixture)

	t.Run("authorized owner creates reads updates and audits record", func(t *testing.T) {
		create := appDataJSONRequest(handler, http.MethodPost, "/api/v1/spaces/"+fixture.SpaceID+"/data/models/"+fixture.ModelKey+"/records", ownerToken, map[string]any{
			"id":               fixture.RecordID,
			"group_id":         fixture.AllowedGroupID,
			"display_name":     "Acme Customer",
			"visibility":       "group",
			"data":             map[string]any{"name": "Acme", "secret_note": "never-copy-this-to-audit"},
			"metadata":         map[string]any{"tier": "gold"},
			"owner_member_id":  fixture.OwnerMemberID,
			"unexpected_field": nil,
		})
		if create.Code != http.StatusBadRequest {
			t.Fatalf("unknown JSON field status = %d, want 400, body=%s", create.Code, create.Body.String())
		}

		create = appDataJSONRequest(handler, http.MethodPost, "/api/v1/spaces/"+fixture.SpaceID+"/data/models/"+fixture.ModelKey+"/records", ownerToken, map[string]any{
			"id":              fixture.RecordID,
			"group_id":        fixture.AllowedGroupID,
			"display_name":    "Acme Customer",
			"visibility":      "group",
			"data":            map[string]any{"name": "Acme", "secret_note": "never-copy-this-to-audit"},
			"metadata":        map[string]any{"tier": "gold"},
			"owner_member_id": fixture.OwnerMemberID,
		})
		if create.Code != http.StatusCreated {
			t.Fatalf("create status = %d, want 201, body=%s", create.Code, create.Body.String())
		}
		payload := decodeAppDataPayload(t, create)
		data := payload["data"].(map[string]any)
		record := data["record"].(map[string]any)
		if record["model_key"] != fixture.ModelKey || record["group_id"] != fixture.AllowedGroupID {
			t.Fatalf("created record mismatch: %#v", record)
		}

		read := appDataJSONRequest(handler, http.MethodGet, "/api/v1/spaces/"+fixture.SpaceID+"/data/models/"+fixture.ModelKey+"/records/"+fixture.RecordID, ownerToken, nil)
		if read.Code != http.StatusOK {
			t.Fatalf("read status = %d, want 200, body=%s", read.Code, read.Body.String())
		}

		update := appDataJSONRequest(handler, http.MethodPatch, "/api/v1/spaces/"+fixture.SpaceID+"/data/models/"+fixture.ModelKey+"/records/"+fixture.RecordID, ownerToken, map[string]any{
			"data": map[string]any{"name": "Acme Updated", "secret_note": "still-not-in-audit"},
		})
		if update.Code != http.StatusOK {
			t.Fatalf("update status = %d, want 200, body=%s", update.Code, update.Body.String())
		}

		revisions := appDataJSONRequest(handler, http.MethodGet, "/api/v1/spaces/"+fixture.SpaceID+"/data/models/"+fixture.ModelKey+"/records/"+fixture.RecordID+"/revisions", ownerToken, nil)
		if revisions.Code != http.StatusOK {
			t.Fatalf("revisions status = %d, want 200, body=%s", revisions.Code, revisions.Body.String())
		}
		revisionPayload := decodeAppDataPayload(t, revisions)
		rows := revisionPayload["data"].([]any)
		if len(rows) != 2 {
			t.Fatalf("revision count = %d, want 2: %#v", len(rows), rows)
		}

		log, err := store.Client().AuditLog.Query().
			Where(entauditlog.ResourceID(fixture.RecordID), entauditlog.Action("app_data.record.updated")).
			Order(coreent.Desc(entauditlog.FieldCreatedAt)).
			First(ctx)
		if err != nil {
			t.Fatalf("load update audit log: %v", err)
		}
		rawTrace, err := json.Marshal(log.Trace)
		if err != nil {
			t.Fatalf("marshal trace: %v", err)
		}
		trace := string(rawTrace)
		if strings.Contains(trace, "still-not-in-audit") || strings.Contains(trace, "never-copy-this-to-audit") {
			t.Fatalf("audit trace leaked business data value: %s", trace)
		}
		if !strings.Contains(trace, "secret_note") {
			t.Fatalf("audit trace should include changed key names for explainability: %s", trace)
		}
	})

	t.Run("sibling group cannot read outside granted group tree", func(t *testing.T) {
		rec := appDataJSONRequest(handler, http.MethodGet, "/api/v1/spaces/"+fixture.SpaceID+"/data/models/"+fixture.ModelKey+"/records/"+fixture.RecordID, siblingToken, nil)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403, body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("generic lookup is governed by model-specific authorization", func(t *testing.T) {
		allowed := appDataJSONRequest(handler, http.MethodGet, "/api/v1/app-data/"+fixture.ModelKey+"/"+fixture.RecordID, ownerToken, nil)
		if allowed.Code != http.StatusOK {
			t.Fatalf("owner generic lookup status = %d, want 200, body=%s", allowed.Code, allowed.Body.String())
		}
		denied := appDataJSONRequest(handler, http.MethodGet, "/api/v1/app-data/"+fixture.ModelKey+"/"+fixture.RecordID, siblingToken, nil)
		if denied.Code != http.StatusForbidden {
			t.Fatalf("sibling generic lookup status = %d, want 403, body=%s", denied.Code, denied.Body.String())
		}
	})

	t.Run("batch records are transactional across operations", func(t *testing.T) {
		firstID := "record_appdata_batch_first_" + fixture.Suffix
		secondID := "record_appdata_batch_second_" + fixture.Suffix
		rec := appDataJSONRequest(handler, http.MethodPost, "/api/v1/spaces/"+fixture.SpaceID+"/data/records/batch", ownerToken, map[string]any{
			"actor": map[string]any{"space_id": fixture.SpaceID},
			"operations": []any{
				map[string]any{
					"operation": "create",
					"model_key": fixture.ModelKey,
					"record_id": firstID,
					"request": map[string]any{
						"group_id":        fixture.AllowedGroupID,
						"owner_member_id": fixture.OwnerMemberID,
						"display_name":    "Batch First",
						"visibility":      "group",
						"data":            map[string]any{"name": "Batch First"},
					},
				},
				map[string]any{
					"operation": "update",
					"model_key": fixture.ModelKey,
					"record_id": "missing_appdata_batch_" + fixture.Suffix,
					"request":   map[string]any{"data": map[string]any{"name": "Missing"}},
				},
			},
		})
		if rec.Code != http.StatusNotFound {
			t.Fatalf("failed batch status = %d, want 404, body=%s", rec.Code, rec.Body.String())
		}
		if exists, err := store.Client().AppDataRecord.Query().Where(entappdatarecord.ID(firstID)).Exist(ctx); err != nil || exists {
			t.Fatalf("failed batch persisted first record exists=%t err=%v", exists, err)
		}
		if count, err := store.Client().AppDataRecordRevision.Query().Where(entappdatarecordrevision.RecordID(firstID)).Count(ctx); err != nil || count != 0 {
			t.Fatalf("failed batch revision count=%d err=%v, want 0", count, err)
		}

		rec = appDataJSONRequest(handler, http.MethodPost, "/api/v1/spaces/"+fixture.SpaceID+"/data/records/batch", ownerToken, map[string]any{
			"actor": map[string]any{"space_id": fixture.SpaceID},
			"operations": []any{
				map[string]any{
					"operation": "create",
					"model_key": fixture.ModelKey,
					"record_id": firstID,
					"request": map[string]any{
						"group_id":        fixture.AllowedGroupID,
						"owner_member_id": fixture.OwnerMemberID,
						"display_name":    "Batch First",
						"visibility":      "group",
						"data":            map[string]any{"name": "Batch First"},
					},
				},
				map[string]any{
					"operation": "create",
					"model_key": fixture.ModelKey,
					"record_id": secondID,
					"request": map[string]any{
						"group_id":        fixture.AllowedGroupID,
						"owner_member_id": fixture.OwnerMemberID,
						"display_name":    "Batch Second",
						"visibility":      "group",
						"data":            map[string]any{"name": "Batch Second"},
					},
				},
			},
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("successful batch status = %d, want 200, body=%s", rec.Code, rec.Body.String())
		}
		payload := decodeAppDataPayload(t, rec)
		data := payload["data"].(map[string]any)
		if int(data["operation_count"].(float64)) != 2 {
			t.Fatalf("operation_count = %#v, want 2", data["operation_count"])
		}
		for _, id := range []string{firstID, secondID} {
			if exists, err := store.Client().AppDataRecord.Query().Where(entappdatarecord.ID(id), entappdatarecord.DeletedAtIsNil()).Exist(ctx); err != nil || !exists {
				t.Fatalf("successful batch record %s exists=%t err=%v", id, exists, err)
			}
			if count, err := store.Client().AppDataRecordRevision.Query().Where(entappdatarecordrevision.RecordID(id)).Count(ctx); err != nil || count != 1 {
				t.Fatalf("successful batch revision count for %s=%d err=%v, want 1", id, count, err)
			}
		}
	})
}

func appDataTestDatabaseURL() string {
	for _, key := range []string{"PLYSTRA_INTEGRATION_DATABASE_URL", "PLYSTRA_DATABASE_URL"} {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return value
		}
	}
	return ""
}

func createAppDataFixture(t *testing.T, ctx context.Context, client *coreent.Client) appDataFixture {
	t.Helper()
	suffix := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	fixture := appDataFixture{
		Suffix:              suffix,
		SpaceID:             "space_appdata_" + suffix,
		RootGroupID:         "group_appdata_root_" + suffix,
		AllowedGroupID:      "group_appdata_allowed_" + suffix,
		SiblingGroupID:      "group_appdata_sibling_" + suffix,
		OwnerUserID:         "user_appdata_owner_" + suffix,
		OwnerMemberID:       "member_appdata_owner_" + suffix,
		OwnerUserMemberID:   "um_appdata_owner_" + suffix,
		SiblingUserID:       "user_appdata_sibling_" + suffix,
		SiblingMemberID:     "member_appdata_sibling_" + suffix,
		SiblingUserMemberID: "um_appdata_sibling_" + suffix,
		SpaceAdminGrantID:   "ag_appdata_space_admin_" + suffix,
		AllowedRoleID:       "role_appdata_allowed_" + suffix,
		AllowedMemberRoleID: "mr_appdata_allowed_" + suffix,
		SiblingRoleID:       "role_appdata_sibling_" + suffix,
		SiblingMemberRoleID: "mr_appdata_sibling_" + suffix,
		RecordID:            "record_appdata_" + suffix,
		ModelKey:            "customer_" + suffix,
	}
	fixture.ModelResource = appDataModelResourceType(fixture.ModelKey)

	ownerHash, err := hashPassword(appDataOwnerPassword)
	if err != nil {
		t.Fatalf("hash owner password: %v", err)
	}
	siblingHash, err := hashPassword(appDataSiblingPassword)
	if err != nil {
		t.Fatalf("hash sibling password: %v", err)
	}
	if _, err := client.Space.Create().SetID(fixture.SpaceID).SetName("App Data Space " + suffix).SetSlug("app-data-" + suffix).Save(ctx); err != nil {
		t.Fatalf("create space: %v", err)
	}
	if _, err := client.Group.Create().SetID(fixture.RootGroupID).SetSpaceID(fixture.SpaceID).SetName("root").SetPath("root").SetDepth(0).Save(ctx); err != nil {
		t.Fatalf("create root group: %v", err)
	}
	if _, err := client.Group.Create().SetID(fixture.AllowedGroupID).SetSpaceID(fixture.SpaceID).SetParentGroupID(fixture.RootGroupID).SetName("allowed").SetPath("root.allowed").SetDepth(1).Save(ctx); err != nil {
		t.Fatalf("create allowed group: %v", err)
	}
	if _, err := client.Group.Create().SetID(fixture.SiblingGroupID).SetSpaceID(fixture.SpaceID).SetParentGroupID(fixture.RootGroupID).SetName("sibling").SetPath("root.sibling").SetDepth(1).Save(ctx); err != nil {
		t.Fatalf("create sibling group: %v", err)
	}
	if _, err := client.User.Create().SetID(fixture.OwnerUserID).SetEmail("appdata.owner." + suffix + "@example.com").SetPasswordHash(ownerHash).Save(ctx); err != nil {
		t.Fatalf("create owner user: %v", err)
	}
	if _, err := client.User.Create().SetID(fixture.SiblingUserID).SetEmail("appdata.sibling." + suffix + "@example.com").SetPasswordHash(siblingHash).Save(ctx); err != nil {
		t.Fatalf("create sibling user: %v", err)
	}
	if _, err := client.Member.Create().SetID(fixture.OwnerMemberID).SetSpaceID(fixture.SpaceID).SetDisplayName("App Data Owner").Save(ctx); err != nil {
		t.Fatalf("create owner member: %v", err)
	}
	if _, err := client.Member.Create().SetID(fixture.SiblingMemberID).SetSpaceID(fixture.SpaceID).SetDisplayName("App Data Sibling").Save(ctx); err != nil {
		t.Fatalf("create sibling member: %v", err)
	}
	if _, err := client.UserMember.Create().SetID(fixture.OwnerUserMemberID).SetUserID(fixture.OwnerUserID).SetMemberID(fixture.OwnerMemberID).SetSpaceID(fixture.SpaceID).SetRelationType("login").SetIsPrimary(true).Save(ctx); err != nil {
		t.Fatalf("create owner user-member: %v", err)
	}
	if _, err := client.UserMember.Create().SetID(fixture.SiblingUserMemberID).SetUserID(fixture.SiblingUserID).SetMemberID(fixture.SiblingMemberID).SetSpaceID(fixture.SpaceID).SetRelationType("login").SetIsPrimary(true).Save(ctx); err != nil {
		t.Fatalf("create sibling user-member: %v", err)
	}
	if _, err := client.AdminGrant.Create().
		SetID(fixture.SpaceAdminGrantID).
		SetUserID(fixture.OwnerUserID).
		SetMemberID(fixture.OwnerMemberID).
		SetLevel(adminLevelSpace).
		SetSpaceID(fixture.SpaceID).
		SetPermissionKey("data:manage").
		Save(ctx); err != nil {
		t.Fatalf("create space admin grant: %v", err)
	}
	return fixture
}

func grantModelPermissions(t *testing.T, ctx context.Context, client *coreent.Client, fixture *appDataFixture) {
	t.Helper()
	if _, err := client.Role.Create().SetID(fixture.AllowedRoleID).SetSpaceID(fixture.SpaceID).SetKey("appdata_allowed_" + fixture.Suffix).SetName("App Data Allowed").Save(ctx); err != nil {
		t.Fatalf("create allowed role: %v", err)
	}
	if _, err := client.Role.Create().SetID(fixture.SiblingRoleID).SetSpaceID(fixture.SpaceID).SetKey("appdata_sibling_" + fixture.Suffix).SetName("App Data Sibling").Save(ctx); err != nil {
		t.Fatalf("create sibling role: %v", err)
	}
	for _, action := range []string{"read", "create", "update", "delete", "archive"} {
		permID := "perm_appdata_" + action + "_" + fixture.Suffix
		fixture.PermissionIDs = append(fixture.PermissionIDs, permID)
		if exists, err := client.Permission.Query().
			Where(entpermission.Resource(fixture.ModelResource), entpermission.Action(action), entpermission.Scope(string(authz.ScopeGroupTree))).
			Exist(ctx); err != nil {
			t.Fatalf("check permission %s: %v", action, err)
		} else if !exists {
			if _, err := client.Permission.Create().
				SetID(permID).
				SetResource(fixture.ModelResource).
				SetAction(action).
				SetScope(string(authz.ScopeGroupTree)).
				SetDescription("App data test " + action).
				Save(ctx); err != nil {
				t.Fatalf("create permission %s: %v", action, err)
			}
		}
		rpID := "rp_appdata_allowed_" + action + "_" + fixture.Suffix
		fixture.RolePermissionIDs = append(fixture.RolePermissionIDs, rpID)
		if _, err := client.RolePermission.Create().SetID(rpID).SetRoleID(fixture.AllowedRoleID).SetPermissionID(permID).Save(ctx); err != nil {
			t.Fatalf("create allowed role permission %s: %v", action, err)
		}
		rpSiblingID := "rp_appdata_sibling_" + action + "_" + fixture.Suffix
		fixture.RolePermissionIDs = append(fixture.RolePermissionIDs, rpSiblingID)
		if _, err := client.RolePermission.Create().SetID(rpSiblingID).SetRoleID(fixture.SiblingRoleID).SetPermissionID(permID).Save(ctx); err != nil {
			t.Fatalf("create sibling role permission %s: %v", action, err)
		}
	}
	if _, err := client.MemberRole.Create().SetID(fixture.AllowedMemberRoleID).SetSpaceID(fixture.SpaceID).SetMemberID(fixture.OwnerMemberID).SetRoleID(fixture.AllowedRoleID).SetScopeAnchorGroupID(fixture.AllowedGroupID).Save(ctx); err != nil {
		t.Fatalf("create allowed member role: %v", err)
	}
	if _, err := client.MemberRole.Create().SetID(fixture.SiblingMemberRoleID).SetSpaceID(fixture.SpaceID).SetMemberID(fixture.SiblingMemberID).SetRoleID(fixture.SiblingRoleID).SetScopeAnchorGroupID(fixture.SiblingGroupID).Save(ctx); err != nil {
		t.Fatalf("create sibling member role: %v", err)
	}
}

func cleanupAppDataFixture(ctx context.Context, t *testing.T, client *coreent.Client, fixture appDataFixture) {
	t.Helper()
	now := time.Now().UTC()
	_, _ = client.AppDataRecordRevision.Delete().Where(entappdatarecordrevision.SpaceID(fixture.SpaceID)).Exec(ctx)
	_, _ = client.AppDataRecord.Delete().Where(entappdatarecord.SpaceID(fixture.SpaceID)).Exec(ctx)
	_, _ = client.AppDataModel.Delete().Where(entappdatamodel.SpaceID(fixture.SpaceID)).Exec(ctx)
	_, _ = client.AuditLog.Delete().Where(entauditlog.SpaceID(fixture.SpaceID)).Exec(ctx)
	_, _ = client.Session.Update().Where(entsession.UserIDIn(fixture.OwnerUserID, fixture.SiblingUserID)).SetRevokedAt(now).Save(ctx)
	_, _ = client.RolePermission.Delete().Where(entrolepermission.IDIn(fixture.RolePermissionIDs...)).Exec(ctx)
	_, _ = client.MemberRole.Update().Where(entmemberrole.IDIn(fixture.AllowedMemberRoleID, fixture.SiblingMemberRoleID)).SetStatus("revoked").SetDeletedAt(now).Save(ctx)
	_, _ = client.Permission.Update().Where(entpermission.Resource(fixture.ModelResource)).SetStatus("disabled").SetDeletedAt(now).Save(ctx)
	_, _ = client.Role.Update().Where(entrole.IDIn(fixture.AllowedRoleID, fixture.SiblingRoleID)).SetStatus("disabled").SetDeletedAt(now).Save(ctx)
	_, _ = client.AdminGrant.Update().Where(entadmingrant.ID(fixture.SpaceAdminGrantID)).SetStatus("revoked").SetRevokedAt(now).SetDeletedAt(now).Save(ctx)
	_, _ = client.UserMember.Update().Where(entusermember.IDIn(fixture.OwnerUserMemberID, fixture.SiblingUserMemberID)).SetStatus("revoked").SetRevokedAt(now).SetDeletedAt(now).Save(ctx)
	_, _ = client.Member.Update().Where(entmember.IDIn(fixture.OwnerMemberID, fixture.SiblingMemberID)).SetStatus("disabled").SetDeletedAt(now).Save(ctx)
	_, _ = client.Group.Update().Where(entgroup.IDIn(fixture.AllowedGroupID, fixture.SiblingGroupID, fixture.RootGroupID)).SetStatus("disabled").SetDeletedAt(now).Save(ctx)
	_, _ = client.User.Update().Where(entuser.IDIn(fixture.OwnerUserID, fixture.SiblingUserID)).SetStatus("disabled").SetDeletedAt(now).Save(ctx)
	_, _ = client.Space.Update().Where(entspace.ID(fixture.SpaceID)).SetStatus("disabled").SetDeletedAt(now).Save(ctx)
}

func loginAppDataUser(t *testing.T, handler http.Handler, email, password string) string {
	t.Helper()
	rec := appDataJSONRequest(handler, http.MethodPost, "/api/v1/auth/login", "", map[string]any{
		"email":    email,
		"password": password,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("login status = %d, body=%s", rec.Code, rec.Body.String())
	}
	payload := decodeAppDataPayload(t, rec)
	data := payload["data"].(map[string]any)
	token, _ := data["access_token"].(string)
	if token == "" {
		t.Fatalf("login did not return access token: %#v", data)
	}
	return token
}

func appDataJSONRequest(handler http.Handler, method, path, token string, body any) *httptest.ResponseRecorder {
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		payload, _ := json.Marshal(body)
		reader = bytes.NewReader(payload)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("X-Request-ID", "req_app_data_test")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeAppDataPayload(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response %q: %v", rec.Body.String(), err)
	}
	return payload
}
