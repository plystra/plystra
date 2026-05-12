package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	entadmingrant "github.com/plystra/plystra/ent/admingrant"
	entmember "github.com/plystra/plystra/ent/member"
	entsession "github.com/plystra/plystra/ent/session"
	entspace "github.com/plystra/plystra/ent/space"
	entuser "github.com/plystra/plystra/ent/user"
	entusermember "github.com/plystra/plystra/ent/usermember"
	"github.com/plystra/plystra/internal/store/entstore"
)

func TestAuthRegisterIsDisabledByDefault(t *testing.T) {
	server, handler := newRegisterTestServer(t)

	rec := registerJSONRequest(handler, map[string]any{
		"email":               "disabled@register-test.plystra.local",
		"password":            "long-enough-password",
		"space_name":          "register-test disabled",
		"member_display_name": "register-test disabled",
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body=%s", rec.Code, rec.Body.String())
	}
	if count, err := server.ent.User.Query().Count(context.Background()); err != nil || count != 0 {
		t.Fatalf("user count = %d, err=%v, want 0", count, err)
	}
}

func TestAuthRegisterBootstrapsFirstSuperAdminWithToken(t *testing.T) {
	t.Setenv("PLYSTRA_BOOTSTRAP_REGISTRATION_ENABLED", "true")
	t.Setenv("PLYSTRA_BOOTSTRAP_REGISTRATION_TOKEN", "bootstrap-registration-token-at-least-32-characters")
	server, handler := newRegisterTestServer(t)

	rec := registerJSONRequest(handler, map[string]any{
		"email":               "founder@register-test.plystra.local",
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
	if count, err := server.ent.AdminGrant.Query().Count(context.Background()); err != nil || count != 2 {
		t.Fatalf("admin grant count = %d, err=%v, want space admin + bootstrap super", count, err)
	}
}

func TestAuthRegisterRequiresBootstrapBeforeOrdinaryRegistration(t *testing.T) {
	t.Setenv("PLYSTRA_AUTH_REGISTRATION_ENABLED", "true")
	t.Setenv("PLYSTRA_AUTH_REGISTRATION_TOKEN", "ordinary-registration-token-at-least-32-chars")
	_, handler := newRegisterTestServer(t)

	rec := registerJSONRequest(handler, map[string]any{
		"email":               "first@register-test.plystra.local",
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
