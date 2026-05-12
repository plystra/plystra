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

	coreent "github.com/plystra/plystra/ent"
	"github.com/plystra/plystra/internal/authz"
)

func TestResponseEnvelopeIncludesOnlyTopLevelRequestID(t *testing.T) {
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
	if _, ok := body["meta"]; ok {
		t.Fatalf("legacy meta envelope must not be returned: %#v", body["meta"])
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("security header X-Content-Type-Options missing")
	}
	if rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("security header X-Frame-Options missing")
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", rec.Header().Get("Cache-Control"))
	}
}

func TestRequestIDIsNormalized(t *testing.T) {
	server := NewServer(nil, &captureAuthzStore{}, "1.0.0-test")
	handler := server.requestMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeData(w, r, http.StatusOK, map[string]any{"ok": true})
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	req.Header.Set("X-Request-ID", strings.Repeat("a", maxRequestIDLength+1))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("X-Request-ID"); got == "" || got == req.Header.Get("X-Request-ID") {
		t.Fatalf("request id was not regenerated for unsafe input: %q", got)
	}
}

func TestDefaultCORSOriginsAreNotWildcard(t *testing.T) {
	t.Setenv("CORS_ALLOWED_ORIGINS", "")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	req.Header.Set("Origin", "https://example.com")
	if got := allowedCORSOrigin(req); got != "" {
		t.Fatalf("unexpected default CORS origin = %q", got)
	}
	req.Header.Set("Origin", "http://localhost:3000")
	if got := allowedCORSOrigin(req); got != "http://localhost:3000" {
		t.Fatalf("localhost CORS origin = %q", got)
	}
}

func TestErrorEnvelopeIncludesOnlyTopLevelRequestID(t *testing.T) {
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
	if _, ok := body["meta"]; ok {
		t.Fatalf("legacy meta envelope must not be returned: %#v", body["meta"])
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
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/api/v1/audit/logs", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("status without bearer session = %d, want %d", unauthorized.Code, http.StatusUnauthorized)
	}

	tokenReq := httptest.NewRequest(http.MethodGet, "/api/v1/audit/logs", nil)
	tokenReq.Header.Set("X-Plystra-Admin-Token", "test-admin-token-at-least-32-characters")
	tokenRec := httptest.NewRecorder()
	handler.ServeHTTP(tokenRec, tokenReq)
	if tokenRec.Code != http.StatusUnauthorized {
		t.Fatalf("status with unsupported admin token header = %d, want %d", tokenRec.Code, http.StatusUnauthorized)
	}
}

func TestPublicOperationalRoutesDoNotRequireBearerSession(t *testing.T) {
	server := NewServer(nil, &captureAuthzStore{}, "1.0.0-test")
	handler := server.requestMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeData(w, r, http.StatusOK, map[string]any{"ok": true})
	}))
	for _, path := range []string{"/api/v1/health", "/api/v1/ready", "/api/v1/version"} {
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
			name:        "manage covers explicit create action",
			grant:       &coreent.AdminGrant{Level: adminLevelInstance, PermissionKey: "api_keys:manage"},
			requirement: adminRequirement{PermissionKey: "api_keys:create"},
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

func TestAPIKeyPermissionAndScopeMatching(t *testing.T) {
	server := NewServer(nil, &captureAuthzStore{}, "1.0.0-test")
	spaceID := "space_acme"
	key := &coreent.ApiKey{
		Level:          "space",
		SpaceID:        &spaceID,
		Status:         "active",
		PermissionKeys: []string{"authz:check", "api_keys:create"},
	}
	allowed, err := server.apiKeyAllows(context.Background(), key, adminRequirement{PermissionKey: "authz:check", SpaceID: "space_acme"})
	if err != nil {
		t.Fatalf("apiKeyAllows error: %v", err)
	}
	if !allowed {
		t.Fatalf("space API key did not allow matching space authz check")
	}
	allowed, err = server.apiKeyAllows(context.Background(), key, adminRequirement{PermissionKey: "authz:check", SpaceID: "space_other"})
	if err != nil {
		t.Fatalf("apiKeyAllows error: %v", err)
	}
	if allowed {
		t.Fatalf("space API key allowed a different space")
	}
}

func TestAPIKeyCreationCannotDelegateUnheldPermissions(t *testing.T) {
	spaceID := "space_acme"
	principal := adminPrincipal{
		CredentialType: "api_key",
		APIKey: &coreent.ApiKey{
			Level:          "space",
			SpaceID:        &spaceID,
			Status:         "active",
			PermissionKeys: []string{"api_keys:create"},
		},
	}
	server := NewServer(nil, &captureAuthzStore{}, "1.0.0-test")

	allowed, denied, err := server.principalCanDelegatePermissions(context.Background(), principal, []string{"resources:manage"}, "space_acme", "")
	if err != nil {
		t.Fatalf("principalCanDelegatePermissions error: %v", err)
	}
	if allowed || denied != "resources:manage" {
		t.Fatalf("delegation allowed=%v denied=%q, want denied resources:manage", allowed, denied)
	}

	allowed, denied, err = server.principalCanDelegatePermissions(context.Background(), principal, []string{"api_keys:create"}, "space_acme", "")
	if err != nil {
		t.Fatalf("principalCanDelegatePermissions error: %v", err)
	}
	if !allowed || denied != "" {
		t.Fatalf("same-permission delegation allowed=%v denied=%q, want allowed", allowed, denied)
	}
}

func TestAdminGrantCreationCannotDelegateUnheldPermissions(t *testing.T) {
	spaceID := "space_acme"
	principal := adminPrincipal{
		CredentialType: "session",
		Grants: []*coreent.AdminGrant{
			{Level: adminLevelSpace, SpaceID: &spaceID, PermissionKey: "admin_grants:manage"},
		},
	}
	server := NewServer(nil, &captureAuthzStore{}, "1.0.0-test")

	allowed, denied, err := server.principalCanDelegatePermissions(context.Background(), principal, []string{"resources:manage"}, "space_acme", "")
	if err != nil {
		t.Fatalf("principalCanDelegatePermissions error: %v", err)
	}
	if allowed || denied != "resources:manage" {
		t.Fatalf("delegation allowed=%v denied=%q, want denied resources:manage", allowed, denied)
	}
}

func TestScopedAuthzCheckRequiresConcreteScope(t *testing.T) {
	spaceID := "space_acme"
	principal := adminPrincipal{
		CredentialType: "session",
		Grants: []*coreent.AdminGrant{
			{Level: adminLevelSpace, SpaceID: &spaceID, PermissionKey: "authz:check"},
		},
	}
	if adminPrincipalHasInstanceReach(principal, "authz:check") {
		t.Fatalf("space scoped principal unexpectedly has instance reach")
	}
	instancePrincipal := adminPrincipal{
		CredentialType: "session",
		Grants: []*coreent.AdminGrant{
			{Level: adminLevelInstance, PermissionKey: "authz:check"},
		},
	}
	if !adminPrincipalHasInstanceReach(instancePrincipal, "authz:check") {
		t.Fatalf("instance principal should have instance reach")
	}
}

func TestAPIKeyTokenFormatAndHashRotation(t *testing.T) {
	t.Setenv("PLYSTRA_API_KEY_SECRET", "old-api-key-secret-at-least-32-characters")
	token, err := newAPIKeyPlaintext("ak_test")
	if err != nil {
		t.Fatalf("newAPIKeyPlaintext error: %v", err)
	}
	if got := apiKeyIDFromToken(token); got != "ak_test" {
		t.Fatalf("api key id = %q, want ak_test", got)
	}
	oldHash := apiKeyHash(token)

	t.Setenv("PLYSTRA_API_KEY_SECRET", "new-api-key-secret-at-least-32-characters")
	t.Setenv("PLYSTRA_API_KEY_SECRET_PREVIOUS", "old-api-key-secret-at-least-32-characters")
	hashes := apiKeyHashesForLookup(token)
	if len(hashes) != 2 {
		t.Fatalf("hash count = %d, want primary and previous", len(hashes))
	}
	if hashes[0] == oldHash {
		t.Fatalf("primary API key hash unexpectedly used previous secret first")
	}
	if hashes[1] != oldHash {
		t.Fatalf("previous API key hash not present")
	}
}

func TestAdminRequirementParsesTypedResourceDetailPath(t *testing.T) {
	req := adminRequirementFor(http.MethodGet, "/api/v1/resources/invoice/invoice_001", "")
	if req.PermissionKey != "resources:read" {
		t.Fatalf("permission = %q, want resources:read", req.PermissionKey)
	}
	if req.EntityKind != "resource" {
		t.Fatalf("entity kind = %q, want resource", req.EntityKind)
	}
	if req.EntityID != "invoice_001" {
		t.Fatalf("entity id = %q, want invoice_001", req.EntityID)
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

func TestHTTPAuthzRejectsClientSuppliedAuditMetadata(t *testing.T) {
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
		"request_id": "req_body_should_be_rejected"
	}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/authz/check", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	server.handleAuthzCheck(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if store.lastDecision.Decision != "" {
		t.Fatalf("authz store was called for rejected metadata: %#v", store.lastDecision)
	}
}

func TestHTTPAuthzUsesServerDerivedAuditMetadata(t *testing.T) {
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
		"action": "approve"
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

func TestHTTPAuthzRequiresActorForAPIKeyPrincipal(t *testing.T) {
	store := &captureAuthzStore{}
	server := NewServer(nil, store, "1.0.0-test")
	body := []byte(`{"resource_type":"invoice","resource_id":"invoice_001","action":"approve"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/authz/check", bytes.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), requestIDKey, "req_api_key_no_actor"))
	req = req.WithContext(context.WithValue(req.Context(), adminPrincipalKey, adminPrincipal{CredentialType: "api_key"}))
	rec := httptest.NewRecorder()

	server.handleAuthzCheck(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if store.lastDecision.Decision != "" {
		t.Fatalf("authz store was called for missing actor: %#v", store.lastDecision)
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

func TestPasswordHashInputIsIgnoredWithoutPlaintextPassword(t *testing.T) {
	var req userMutationRequest
	if err := json.Unmarshal([]byte(`{"password_hash":"client-controlled-hash"}`), &req); err != nil {
		t.Fatalf("decode request: %v", err)
	}
	got, ok := (&Server{}).passwordHashFromRequest(httptest.NewRecorder(), httptest.NewRequest(http.MethodPatch, "/api/v1/users/user_alice", nil), req, "existing-hash")
	if !ok {
		t.Fatalf("passwordHashFromRequest rejected request")
	}
	if got != "existing-hash" {
		t.Fatalf("password hash = %q, want existing hash", got)
	}
}

func TestTokenHashUsesConfiguredSessionSecret(t *testing.T) {
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

func TestHashPasswordProducesVerifiableEncodedHash(t *testing.T) {
	encoded, err := hashPassword("new-user-password")
	if err != nil {
		t.Fatalf("hashPassword error: %v", err)
	}
	if !verifyPassword("new-user-password", encoded) {
		t.Fatalf("hashed password did not verify")
	}
	if verifyPassword("wrong-password", encoded) {
		t.Fatalf("wrong password verified")
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
