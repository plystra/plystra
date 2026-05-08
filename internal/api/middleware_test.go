package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	coreent "github.com/plystra/plystra/ent"
	"github.com/plystra/plystra/internal/authz"
)

func TestResponseEnvelopeRequestIDCompatibility(t *testing.T) {
	server := NewServer(nil, &captureAuthzStore{}, "1.0.0-test")
	handler := server.requestMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeData(w, r, http.StatusOK, map[string]any{"ok": true})
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	req.Header.Set("X-Request-ID", "req_test_envelope")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["request_id"] != "req_test_envelope" {
		t.Fatalf("request_id = %v", body["request_id"])
	}
	meta, ok := body["meta"].(map[string]any)
	if !ok {
		t.Fatalf("meta missing or wrong type: %T", body["meta"])
	}
	if meta["request_id"] != body["request_id"] {
		t.Fatalf("meta.request_id = %v, want %v", meta["request_id"], body["request_id"])
	}
}

func TestErrorEnvelopeIncludesMetaRequestID(t *testing.T) {
	server := NewServer(nil, &captureAuthzStore{}, "1.0.0-test")
	handler := server.requestMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "bad request", nil)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	req.Header.Set("X-Request-ID", "req_test_error")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["request_id"] != "req_test_error" {
		t.Fatalf("request_id = %v", body["request_id"])
	}
	meta := body["meta"].(map[string]any)
	if meta["request_id"] != body["request_id"] {
		t.Fatalf("meta.request_id = %v, want %v", meta["request_id"], body["request_id"])
	}
}

func TestRecoveryHidesPanicDetailsInProduction(t *testing.T) {
	t.Setenv("SERVER_MODE", "production")
	server := NewServer(nil, &captureAuthzStore{}, "1.0.0-test")
	handler := server.requestMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("secret panic detail")
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	req.Header.Set("X-Request-ID", "req_test_panic")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	var body struct {
		Error struct {
			Details any `json:"details"`
		} `json:"error"`
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.RequestID != "req_test_panic" {
		t.Fatalf("request_id = %s", body.RequestID)
	}
	if body.Error.Details != nil {
		t.Fatalf("panic details leaked in production: %v", body.Error.Details)
	}
}

func TestStructuredLogContainsReleaseFields(t *testing.T) {
	t.Setenv("LOG_FORMAT", "json")
	oldStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = writer
	defer func() { os.Stdout = oldStdout }()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	req = req.WithContext(context.WithValue(req.Context(), requestIDKey, "req_test_log"))
	req.RemoteAddr = "192.0.2.10:1234"
	req.Header.Set("User-Agent", "plystra-test")
	logHTTPRequest(req, http.Header{}, http.StatusOK, 42, 3*time.Millisecond, "")
	_ = writer.Close()

	var entry map[string]any
	if err := json.NewDecoder(reader).Decode(&entry); err != nil {
		t.Fatalf("decode log entry: %v", err)
	}
	for _, field := range []string{"timestamp", "level", "request_id", "method", "path", "status", "latency_ms", "remote_ip", "user_agent"} {
		if _, ok := entry[field]; !ok {
			t.Fatalf("log field %s missing in %#v", field, entry)
		}
	}
	if entry["request_id"] != "req_test_log" {
		t.Fatalf("request_id = %v", entry["request_id"])
	}
}

func TestBearerSessionProtectsSensitiveRoutes(t *testing.T) {
	server := NewServer(nil, &captureAuthzStore{}, "1.0.0-test")
	handler := server.requestMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeData(w, r, http.StatusOK, map[string]any{"ok": true})
	}))

	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/api/v1/audit-logs", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("status without bearer session = %d, want %d", unauthorized.Code, http.StatusUnauthorized)
	}

	tokenReq := httptest.NewRequest(http.MethodGet, "/api/v1/audit-logs", nil)
	tokenReq.Header.Set("X-Plystra-Admin-Token", "test-admin-token-at-least-32-characters")
	tokenRec := httptest.NewRecorder()
	handler.ServeHTTP(tokenRec, tokenReq)
	if tokenRec.Code != http.StatusUnauthorized {
		t.Fatalf("status with legacy admin token header = %d, want %d", tokenRec.Code, http.StatusUnauthorized)
	}
}

func TestPublicOperationalRoutesDoNotRequireBearerSession(t *testing.T) {
	server := NewServer(nil, &captureAuthzStore{}, "1.0.0-test")
	handler := server.requestMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeData(w, r, http.StatusOK, map[string]any{"ok": true})
	}))
	for _, path := range []string{"/api/v1/health", "/api/v1/ready", "/api/v1/version", "/system/health"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status = %d, want %d", path, rec.Code, http.StatusOK)
		}
	}
}

func TestAdminGrantPermissionMatching(t *testing.T) {
	server := NewServer(nil, &captureAuthzStore{}, "1.0.0-test")
	for _, tc := range []struct {
		name        string
		grant       *coreent.AdminGrant
		requirement adminRequirement
		want        bool
	}{
		{
			name:        "super admin allows everything",
			grant:       &coreent.AdminGrant{Level: adminLevelInstanceSuper, PermissionKey: "users:read"},
			requirement: adminRequirement{PermissionKey: "templates:manage"},
			want:        true,
		},
		{
			name:        "instance admin manage implies read",
			grant:       &coreent.AdminGrant{Level: adminLevelInstance, PermissionKey: "users:manage"},
			requirement: adminRequirement{PermissionKey: "users:read"},
			want:        true,
		},
		{
			name:        "instance admin does not cross permission domain",
			grant:       &coreent.AdminGrant{Level: adminLevelInstance, PermissionKey: "users:read"},
			requirement: adminRequirement{PermissionKey: "spaces:read"},
			want:        false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := server.adminGrantAllows(context.Background(), tc.grant, tc.requirement)
			if err != nil {
				t.Fatalf("adminGrantAllows error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("allowed = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDataConsoleAndMetricsDisabledByDefault(t *testing.T) {
	server := NewServer(nil, &captureAuthzStore{}, "1.0.0-test")

	dataRec := httptest.NewRecorder()
	server.handleDataTables(dataRec, httptest.NewRequest(http.MethodGet, "/api/v1/data/tables", nil))
	if dataRec.Code != http.StatusNotFound {
		t.Fatalf("data console status = %d, want %d", dataRec.Code, http.StatusNotFound)
	}

	metricsRec := httptest.NewRecorder()
	server.handleMetrics(metricsRec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if metricsRec.Code != http.StatusNotFound {
		t.Fatalf("metrics status = %d, want %d", metricsRec.Code, http.StatusNotFound)
	}
}

func TestHTTPAuthzIgnoresClientSuppliedAuditMetadata(t *testing.T) {
	t.Setenv("AUDIT_WRITE_MODE", "always")
	store := &captureAuthzStore{}
	server := NewServer(nil, store, "1.0.0-test")
	body := []byte(`{
		"actor": {
			"user_id": "user_alice",
			"member_id": "member_finance_reviewer",
			"user_member_id": "um_alice_finance_reviewer",
			"space_id": "space_acme"
		},
		"resource_type": "invoice",
		"resource_id": "invoice_001",
		"action": "approve",
		"request_id": "req_body_should_be_ignored",
		"ip": "198.51.100.200",
		"user_agent": "spoofed-agent"
	}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/authz/check", bytes.NewReader(body))
	req.RemoteAddr = "203.0.113.10:12345"
	req.Header.Set("User-Agent", "real-agent")
	req = req.WithContext(context.WithValue(req.Context(), requestIDKey, "req_from_middleware"))
	rec := httptest.NewRecorder()

	server.handleAuthzCheck(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if store.lastDecision.Request.RequestID != "req_from_middleware" {
		t.Fatalf("request_id = %q, want middleware request id", store.lastDecision.Request.RequestID)
	}
	if store.lastDecision.Request.IP != "203.0.113.10" {
		t.Fatalf("ip = %q, want server-derived remote ip", store.lastDecision.Request.IP)
	}
	if store.lastDecision.Request.UserAgent != "real-agent" {
		t.Fatalf("user_agent = %q, want request user agent", store.lastDecision.Request.UserAgent)
	}
}

func TestUserResponseNeverIncludesPasswordHash(t *testing.T) {
	row := map[string]any{
		"id":            "user_alice",
		"email":         "alice@example.com",
		"password_hash": "hashed-secret",
		"status":        "active",
	}

	response := userResponse(row)

	if _, ok := response["password_hash"]; ok {
		t.Fatalf("user response leaked password_hash: %#v", response)
	}
	if row["password_hash"] != "hashed-secret" {
		t.Fatalf("userResponse mutated the persistence row: %#v", row)
	}
	response["email"] = "changed@example.com"
	if row["email"] == response["email"] {
		t.Fatalf("userResponse did not return an isolated DTO copy")
	}
}

func TestTokenHashUsesConfiguredSessionSecret(t *testing.T) {
	t.Setenv("JWT_SECRET", "legacy-session-secret-at-least-32-characters")
	t.Setenv("PLYSTRA_SESSION_SECRET", "primary-session-secret-at-least-32-characters")

	primaryHash := tokenHash("ply_at_test_token")
	if sessionTokenSecret() != "primary-session-secret-at-least-32-characters" {
		t.Fatalf("session token secret did not prefer PLYSTRA_SESSION_SECRET")
	}

	t.Setenv("PLYSTRA_SESSION_SECRET", "rotated-session-secret-at-least-32-characters")
	rotatedHash := tokenHash("ply_at_test_token")
	if primaryHash == rotatedHash {
		t.Fatalf("token hash did not change when the session secret changed")
	}
}

type captureAuthzStore struct {
	lastDecision authz.Decision
}

func (s *captureAuthzStore) LoadActor(context.Context, authz.ActorContext) (authz.ActorSnapshot, error) {
	return authz.ActorSnapshot{
		User: authz.UserSnapshot{ID: "user_alice", Email: "alice@example.com", Status: authz.StatusActive},
		Member: authz.MemberSnapshot{
			ID:          "member_finance_reviewer",
			SpaceID:     "space_acme",
			DisplayName: "Finance Reviewer",
			Status:      authz.StatusActive,
		},
		UserMember: authz.UserMemberSnapshot{
			ID:           "um_alice_finance_reviewer",
			UserID:       "user_alice",
			MemberID:     "member_finance_reviewer",
			SpaceID:      "space_acme",
			RelationType: "delegate",
			Status:       authz.StatusActive,
		},
		Space: authz.SpaceSnapshot{ID: "space_acme", Name: "Acme", Status: authz.StatusActive},
	}, nil
}

func (s *captureAuthzStore) LoadResourceRegistration(context.Context, string, string) (authz.ResourceRegistrySnapshot, error) {
	return authz.ResourceRegistrySnapshot{
		ResourceType: authz.ResourceTypeSnapshot{ID: "rt_invoice", Key: "invoice", DisplayName: "Invoice", Status: "active", Source: "core"},
		Action:       authz.ResourceActionSnapshot{ID: "ra_invoice_approve", ResourceTypeID: "rt_invoice", Key: "approve", DisplayName: "Approve", RiskLevel: "high", AuditDefault: true},
		Mapping:      authz.ResourceMappingSnapshot{ID: "rm_invoice", ResourceTypeID: "rt_invoice", StorageKind: "internal_table", TableName: "resources", IDField: "id", SpaceField: "space_id", GroupField: "group_id", OwnerMemberField: "owner_member_id", Status: "active"},
	}, nil
}

func (s *captureAuthzStore) LoadTarget(context.Context, string, string) (authz.TargetSnapshot, error) {
	return authz.TargetSnapshot{
		Resource: authz.ResourceSnapshot{ID: "invoice_001", Type: "invoice", SpaceID: "space_acme", GroupID: "group_finance_apac", OwnerMemberID: "member_finance_reviewer", Status: "active"},
		Group:    &authz.GroupSnapshot{ID: "group_finance_apac", SpaceID: "space_acme", Path: "finance.apac", Status: authz.StatusActive},
	}, nil
}

func (s *captureAuthzStore) LoadPermissionCandidates(context.Context, authz.CandidateQuery) ([]authz.PermissionCandidate, error) {
	return []authz.PermissionCandidate{{
		Role:              authz.RoleSnapshot{ID: "role_finance_approver", Key: "finance_approver", SpaceID: "space_acme"},
		Permission:        authz.PermissionSnapshot{ID: "perm_invoice_approve", Resource: "invoice", Action: "approve", Scope: authz.ScopeSpace},
		MemberRoleSpaceID: "space_acme",
	}}, nil
}

func (s *captureAuthzStore) WriteAuditLog(_ context.Context, decision authz.Decision) error {
	s.lastDecision = decision
	return nil
}
