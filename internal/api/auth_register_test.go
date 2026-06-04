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

	entadmingrant "github.com/plystra/core/ent/admingrant"
	entmember "github.com/plystra/core/ent/member"
	entsession "github.com/plystra/core/ent/session"
	entspace "github.com/plystra/core/ent/space"
	entuser "github.com/plystra/core/ent/user"
	entusermember "github.com/plystra/core/ent/usermember"
	"github.com/plystra/core/internal/store/entstore"
)

func TestAuthRegisterIsDisabledByDefault(t *testing.T) {
	server, handler := newRegisterTestServer(t)
	email := uniqueRegisterEmail(t, "disabled")

	rec := registerJSONRequest(handler, map[string]any{
		"email":               email,
		"password":            "long-enough-password",
		"space_name":          "register-test disabled",
		"member_display_name": "register-test disabled",
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body=%s", rec.Code, rec.Body.String())
	}
	if count, err := server.ent.User.Query().Where(entuser.Email(email)).Count(context.Background()); err != nil || count != 0 {
		t.Fatalf("created users for %s = %d, err=%v, want 0", email, count, err)
	}
}

func TestAuthRegisterBootstrapsFirstSuperAdminWithToken(t *testing.T) {
	t.Setenv("PLYSTRA_BOOTSTRAP_REGISTRATION_ENABLED", "true")
	t.Setenv("PLYSTRA_BOOTSTRAP_REGISTRATION_TOKEN", "bootstrap-registration-token-at-least-32-characters")
	server, handler := newRegisterTestServer(t)
	if available, err := server.bootstrapRegistrationAvailable(context.Background()); err != nil {
		t.Fatalf("check bootstrap availability: %v", err)
	} else if !available {
		t.Skip("shared integration database already has an active instance super admin")
	}
	email := uniqueRegisterEmail(t, "founder")

	rec := registerJSONRequest(handler, map[string]any{
		"email":               email,
		"password":            "long-enough-password",
		"username":            "founder",
		"space_name":          "register-test founder space",
		"member_display_name": "register-test founder",
		"registration_token":  "bootstrap-registration-token-at-least-32-characters",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body=%s", rec.Code, rec.Body.String())
	}
	payload := decodeRegisterPayload(t, rec)
	data := payload["data"].(map[string]any)
	if data["bootstrap_super_admin"] != true {
		t.Fatalf("bootstrap_super_admin = %#v, want true", data["bootstrap_super_admin"])
	}
	token, _ := data["access_token"].(string)
	if token == "" {
		t.Fatalf("access_token is missing: %#v", data)
	}
	admin := registerAuthedRequest(handler, http.MethodGet, "/api/v1/admin/me", token, nil)
	if admin.Code != http.StatusOK {
		t.Fatalf("admin/me status = %d, body=%s", admin.Code, admin.Body.String())
	}
	userData, _ := data["user"].(map[string]any)
	userID, _ := userData["id"].(string)
	if userID == "" {
		t.Fatalf("registered user id is missing: %#v", data["user"])
	}
	if count, err := server.ent.AdminGrant.Query().Where(entadmingrant.UserID(userID), entadmingrant.DeletedAtIsNil()).Count(context.Background()); err != nil || count != 2 {
		t.Fatalf("admin grant count for %s = %d, err=%v, want space admin + bootstrap super", userID, count, err)
	}
}

func TestAuthRegisterRequiresBootstrapBeforeOrdinaryRegistration(t *testing.T) {
	t.Setenv("PLYSTRA_AUTH_REGISTRATION_ENABLED", "true")
	t.Setenv("PLYSTRA_AUTH_REGISTRATION_TOKEN", "ordinary-registration-token-at-least-32-chars")
	server, handler := newRegisterTestServer(t)
	if available, err := server.bootstrapRegistrationAvailable(context.Background()); err != nil {
		t.Fatalf("check bootstrap availability: %v", err)
	} else if !available {
		t.Skip("shared integration database already has an active instance super admin")
	}
	email := uniqueRegisterEmail(t, "first")

	rec := registerJSONRequest(handler, map[string]any{
		"email":               email,
		"password":            "long-enough-password",
		"space_name":          "register-test ordinary",
		"member_display_name": "register-test ordinary",
		"registration_token":  "ordinary-registration-token-at-least-32-chars",
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "first instance super admin") {
		t.Fatalf("body did not mention bootstrap requirement: %s", rec.Body.String())
	}
	if count, err := server.ent.User.Query().Where(entuser.Email(email)).Count(context.Background()); err != nil || count != 0 {
		t.Fatalf("created users for %s = %d, err=%v, want 0", email, count, err)
	}
}

func TestAuthRegisterAllowsOrdinaryRegistrationAfterBootstrap(t *testing.T) {
	t.Setenv("PLYSTRA_AUTH_REGISTRATION_ENABLED", "true")
	t.Setenv("PLYSTRA_AUTH_REGISTRATION_TOKEN", "ordinary-registration-token-at-least-32-chars")
	server, handler := newRegisterTestServer(t)
	seedRegisterTestSuperAdmin(t, context.Background(), server)
	email := uniqueRegisterEmail(t, "ordinary")

	rec := registerJSONRequest(handler, map[string]any{
		"email":               email,
		"password":            "long-enough-password",
		"space_name":          "register-test ordinary space",
		"member_display_name": "register-test ordinary member",
		"registration_token":  "ordinary-registration-token-at-least-32-chars",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body=%s", rec.Code, rec.Body.String())
	}
	payload := decodeRegisterPayload(t, rec)
	data := payload["data"].(map[string]any)
	if data["bootstrap_super_admin"] != false {
		t.Fatalf("bootstrap_super_admin = %#v, want false", data["bootstrap_super_admin"])
	}
	userData, _ := data["user"].(map[string]any)
	userID, _ := userData["id"].(string)
	if userID == "" {
		t.Fatalf("registered user id is missing: %#v", data["user"])
	}
	if count, err := server.ent.User.Query().Where(entuser.Email(email), entuser.DeletedAtIsNil()).Count(context.Background()); err != nil || count != 1 {
		t.Fatalf("active registered users for %s = %d, err=%v, want 1", email, count, err)
	}
	if count, err := server.ent.AdminGrant.Query().Where(entadmingrant.UserID(userID), entadmingrant.DeletedAtIsNil()).Count(context.Background()); err != nil || count != 1 {
		t.Fatalf("admin grant count for %s = %d, err=%v, want space admin grant", userID, count, err)
	}
}

func TestAuthRegisterUsesOneDefaultSpaceForSimpleMode(t *testing.T) {
	t.Setenv("PLYSTRA_AUTH_REGISTRATION_ENABLED", "true")
	t.Setenv("PLYSTRA_AUTH_REGISTRATION_TOKEN", "ordinary-registration-token-at-least-32-chars")
	server, handler := newRegisterTestServer(t)
	seedRegisterTestSuperAdmin(t, context.Background(), server)

	var spaceIDs []string
	for i := 0; i < 2; i++ {
		email := uniqueRegisterEmail(t, fmt.Sprintf("simple-%d", i))
		rec := registerJSONRequest(handler, map[string]any{
			"email":               email,
			"password":            "long-enough-password",
			"member_display_name": fmt.Sprintf("register-test simple member %d", i),
			"registration_token":  "ordinary-registration-token-at-least-32-chars",
		})
		if rec.Code != http.StatusCreated {
			t.Fatalf("register %d status = %d, want 201, body=%s", i, rec.Code, rec.Body.String())
		}
		payload := decodeRegisterPayload(t, rec)
		data := payload["data"].(map[string]any)
		actor := data["actor"].(map[string]any)
		spaceID, _ := actor["space_id"].(string)
		spaceIDs = append(spaceIDs, spaceID)
	}
	if spaceIDs[0] != defaultSpaceID || spaceIDs[1] != defaultSpaceID {
		t.Fatalf("registered users used spaces %#v, want %q", spaceIDs, defaultSpaceID)
	}
	if count, err := server.ent.Space.Query().Where(entspace.ID(defaultSpaceID), entspace.DeletedAtIsNil()).Count(context.Background()); err != nil || count != 1 {
		t.Fatalf("default space count = %d, err=%v, want 1", count, err)
	}
}

func TestAuthRegisterRestoresSoftDeletedDefaultSpace(t *testing.T) {
	t.Setenv("PLYSTRA_AUTH_REGISTRATION_ENABLED", "true")
	t.Setenv("PLYSTRA_AUTH_REGISTRATION_TOKEN", "ordinary-registration-token-at-least-32-chars")
	server, handler := newRegisterTestServer(t)
	seedRegisterTestSuperAdmin(t, context.Background(), server)
	ctx := context.Background()
	deletedAt := time.Now().UTC()
	space, err := ensureDefaultRegistrationSpace(ctx, server.ent, defaultSpaceID, "register-test default space", "")
	if err != nil {
		t.Fatalf("seed default space: %v", err)
	}
	if err := server.ent.Space.UpdateOneID(space.ID).SetStatus("disabled").SetDeletedAt(deletedAt).Exec(ctx); err != nil {
		t.Fatalf("soft-delete default space: %v", err)
	}

	rec := registerJSONRequest(handler, map[string]any{
		"email":               uniqueRegisterEmail(t, "restore-default-space"),
		"password":            "long-enough-password",
		"member_display_name": "register-test restored default member",
		"registration_token":  "ordinary-registration-token-at-least-32-chars",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body=%s", rec.Code, rec.Body.String())
	}
	restored, err := server.ent.Space.Query().Where(entspace.ID(defaultSpaceID)).Only(ctx)
	if err != nil {
		t.Fatalf("load restored default space: %v", err)
	}
	if restored.DeletedAt != nil || restored.Status != "active" || restored.Type != "default" {
		t.Fatalf("restored default space = status:%q type:%q deleted_at:%v, want active default nil", restored.Status, restored.Type, restored.DeletedAt)
	}
}

func TestAuthRegisterPublicUserOnlyDoesNotCreateActorOrAdminState(t *testing.T) {
	t.Setenv(publicUserRegistrationEnv, "true")
	server, handler := newRegisterTestServer(t)
	seedRegisterTestSuperAdmin(t, context.Background(), server)
	email := uniqueRegisterEmail(t, "public")

	rec := registerJSONRequest(handler, map[string]any{
		"email":    email,
		"password": "long-enough-password",
		"username": "public-user",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body=%s", rec.Code, rec.Body.String())
	}
	payload := decodeRegisterPayload(t, rec)
	data := payload["data"].(map[string]any)
	if data["user_only"] != true {
		t.Fatalf("user_only = %#v, want true", data["user_only"])
	}
	if data["registration_mode"] != string(registrationModePublicUserOnly) {
		t.Fatalf("registration_mode = %#v, want %q", data["registration_mode"], registrationModePublicUserOnly)
	}
	if token, _ := data["access_token"].(string); token != "" {
		t.Fatalf("access_token = %q, want empty for user-only registration", token)
	}
	if members, ok := data["available_members"].([]any); !ok || len(members) != 0 {
		t.Fatalf("available_members = %#v, want empty list", data["available_members"])
	}
	userData, _ := data["user"].(map[string]any)
	userID, _ := userData["id"].(string)
	if userID == "" {
		t.Fatalf("registered user id is missing: %#v", data["user"])
	}
	ctx := context.Background()
	if count, err := server.ent.User.Query().Where(entuser.ID(userID), entuser.Email(email), entuser.DeletedAtIsNil()).Count(ctx); err != nil || count != 1 {
		t.Fatalf("active registered users for %s = %d, err=%v, want 1", email, count, err)
	}
	if count, err := server.ent.UserMember.Query().Where(entusermember.UserID(userID), entusermember.DeletedAtIsNil()).Count(ctx); err != nil || count != 0 {
		t.Fatalf("user_member count for %s = %d, err=%v, want 0", userID, count, err)
	}
	if count, err := server.ent.AdminGrant.Query().Where(entadmingrant.UserID(userID), entadmingrant.DeletedAtIsNil()).Count(ctx); err != nil || count != 0 {
		t.Fatalf("admin grant count for %s = %d, err=%v, want 0", userID, count, err)
	}
}

func TestAuthRegisterPublicUserOnlyCanCreateUserBeforeBootstrap(t *testing.T) {
	t.Setenv(publicUserRegistrationEnv, "true")
	server, handler := newRegisterTestServer(t)
	if available, err := server.bootstrapRegistrationAvailable(context.Background()); err != nil {
		t.Fatalf("check bootstrap availability: %v", err)
	} else if !available {
		t.Skip("shared integration database already has an active instance super admin")
	}
	email := uniqueRegisterEmail(t, "public-first")

	rec := registerJSONRequest(handler, map[string]any{
		"email":    email,
		"password": "long-enough-password",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body=%s", rec.Code, rec.Body.String())
	}
	payload := decodeRegisterPayload(t, rec)
	data := payload["data"].(map[string]any)
	if data["registration_mode"] != string(registrationModePublicUserOnly) {
		t.Fatalf("registration_mode = %#v, want %q", data["registration_mode"], registrationModePublicUserOnly)
	}
	if data["bootstrap_super_admin"] != false {
		t.Fatalf("bootstrap_super_admin = %#v, want false", data["bootstrap_super_admin"])
	}
	userData, _ := data["user"].(map[string]any)
	userID, _ := userData["id"].(string)
	if userID == "" {
		t.Fatalf("registered user id is missing: %#v", data["user"])
	}
	if count, err := server.ent.AdminGrant.Query().Where(entadmingrant.UserID(userID), entadmingrant.DeletedAtIsNil()).Count(context.Background()); err != nil || count != 0 {
		t.Fatalf("admin grant count for %s = %d, err=%v, want 0", userID, count, err)
	}
}

func TestAuthRegisterRequestValidation(t *testing.T) {
	if err := validateRegisterRequest(authRegisterRequest{Email: "", Password: "long-enough-password"}); err == nil || !strings.Contains(err.Error(), "email") {
		t.Fatalf("missing email validation error = %v", err)
	}
	if err := validateRegisterRequest(authRegisterRequest{Email: "alice@example.com", Password: "short"}); err == nil || !strings.Contains(err.Error(), "password") {
		t.Fatalf("short password validation error = %v", err)
	}
	if err := validateRegisterRequest(authRegisterRequest{Email: "alice@example.com", Password: "long-enough-password"}); err != nil {
		t.Fatalf("valid register request rejected: %v", err)
	}
}

func newRegisterTestServer(t *testing.T) (*Server, http.Handler) {
	t.Helper()
	databaseURL := registerTestDatabaseURL()
	if databaseURL == "" {
		t.Skip("set PLYSTRA_INTEGRATION_DATABASE_URL or PLYSTRA_DATABASE_URL to run registration integration tests")
	}
	t.Setenv("PLYSTRA_SESSION_SECRET", "test-session-secret-at-least-32-characters")
	store, err := entstore.Open(context.Background(), databaseURL)
	if err != nil {
		t.Fatalf("open ent store: %v", err)
	}
	t.Cleanup(func() {
		cleanupRegisterTestData(context.Background(), store, t)
		_ = store.Close()
	})
	server := NewServer(nil, store, "1.0.0-test")
	return server, server.Routes()
}

func registerTestDatabaseURL() string {
	for _, key := range []string{"PLYSTRA_INTEGRATION_DATABASE_URL", "PLYSTRA_DATABASE_URL"} {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return value
		}
	}
	return ""
}

func uniqueRegisterEmail(t *testing.T, prefix string) string {
	t.Helper()
	name := strings.NewReplacer("/", "-", "_", "-").Replace(strings.ToLower(t.Name()))
	return fmt.Sprintf("%s.%s.%d@register-test.plystra.local", prefix, name, time.Now().UTC().UnixNano())
}

func seedRegisterTestSuperAdmin(t *testing.T, ctx context.Context, server *Server) {
	t.Helper()
	now := time.Now().UTC()
	suffix := fmt.Sprintf("%d", now.UnixNano())
	userID := "user_register_super_" + suffix
	spaceID := "space_register_super_" + suffix
	memberID := "member_register_super_" + suffix
	userMemberID := "um_register_super_" + suffix
	passwordHash, err := hashPassword("register-test-super-admin-password")
	if err != nil {
		t.Fatalf("hash super admin password: %v", err)
	}
	if _, err := server.ent.User.Create().
		SetID(userID).
		SetEmail(uniqueRegisterEmail(t, "super")).
		SetPasswordHash(passwordHash).
		SetStatus("active").
		Save(ctx); err != nil {
		t.Fatalf("create super admin user: %v", err)
	}
	if _, err := server.ent.Space.Create().
		SetID(spaceID).
		SetName("register-test super admin space").
		SetStatus("active").
		Save(ctx); err != nil {
		t.Fatalf("create super admin space: %v", err)
	}
	if _, err := server.ent.Member.Create().
		SetID(memberID).
		SetSpaceID(spaceID).
		SetDisplayName("register-test super admin member").
		SetStatus("active").
		Save(ctx); err != nil {
		t.Fatalf("create super admin member: %v", err)
	}
	if _, err := server.ent.UserMember.Create().
		SetID(userMemberID).
		SetUserID(userID).
		SetMemberID(memberID).
		SetSpaceID(spaceID).
		SetRelationType("self").
		SetStatus("active").
		SetIsPrimary(true).
		Save(ctx); err != nil {
		t.Fatalf("create super admin user-member binding: %v", err)
	}
	if _, err := server.ent.AdminGrant.Create().
		SetID("ag_register_super_" + suffix).
		SetUserID(userID).
		SetMemberID(memberID).
		SetLevel(adminLevelInstanceSuper).
		SetPermissionKey("*").
		SetStatus("active").
		SetGrantedByUserID(userID).
		SetGrantedByMemberID(memberID).
		Save(ctx); err != nil {
		t.Fatalf("create super admin grant: %v", err)
	}
}

func cleanupRegisterTestData(ctx context.Context, store *entstore.Store, t *testing.T) {
	t.Helper()
	client := store.Client()
	now := time.Now().UTC()
	userIDs := []string{}
	users, _ := client.User.Query().Where(entuser.EmailContains("@register-test.plystra.local")).All(ctx)
	for _, user := range users {
		userIDs = append(userIDs, user.ID)
	}
	if len(userIDs) == 0 {
		return
	}
	_, _ = client.Session.Update().Where(entsession.UserIDIn(userIDs...)).SetRevokedAt(now).Save(ctx)
	_, _ = client.AdminGrant.Update().Where(entadmingrant.UserIDIn(userIDs...)).SetStatus("revoked").SetRevokedAt(now).SetDeletedAt(now).Save(ctx)
	_, _ = client.UserMember.Update().Where(entusermember.UserIDIn(userIDs...)).SetStatus("revoked").SetRevokedAt(now).SetDeletedAt(now).Save(ctx)
	_, _ = client.Member.Update().Where(entmember.DisplayNameContains("register-test")).SetStatus("disabled").SetDeletedAt(now).Save(ctx)
	_, _ = client.Space.Update().Where(entspace.NameContains("register-test")).SetStatus("disabled").SetDeletedAt(now).Save(ctx)
	_, _ = client.User.Update().Where(entuser.IDIn(userIDs...)).SetStatus("disabled").SetDeletedAt(now).Save(ctx)
}

func registerJSONRequest(handler http.Handler, body map[string]any) *httptest.ResponseRecorder {
	return registerAuthedRequest(handler, http.MethodPost, "/api/v1/auth/register", "", body)
}

func registerAuthedRequest(handler http.Handler, method, path, token string, body any) *httptest.ResponseRecorder {
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		payload, _ := json.Marshal(body)
		reader = bytes.NewReader(payload)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("X-Request-ID", "req_register_test")
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

func decodeRegisterPayload(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response %q: %v", rec.Body.String(), err)
	}
	return payload
}
