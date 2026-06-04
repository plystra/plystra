package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	coreent "github.com/plystra/core/ent"
	entactionexecution "github.com/plystra/core/ent/actionexecution"
	entpluginsettingsdefinition "github.com/plystra/core/ent/pluginsettingsdefinition"
	"github.com/plystra/core/internal/store/entstore"
)

func TestActionGatewayRequestValidation(t *testing.T) {
	valid := actionGatewayRequest{
		SpaceID:        "spc_acme",
		Capability:     "payment.charge",
		Operation:      "charge",
		Executor:       capabilityGrantExecutor{PluginID: "plugin.invoice"},
		IdempotencyKey: "inv_1.charge.v1",
	}
	if err := validateActionGatewayRequest(valid); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	cases := map[string]actionGatewayRequest{
		"missing space":      {Capability: "payment.charge", Operation: "charge", Executor: capabilityGrantExecutor{PluginID: "p"}, IdempotencyKey: "k"},
		"bad capability":     {SpaceID: "s", Capability: "nope", Operation: "charge", Executor: capabilityGrantExecutor{PluginID: "p"}, IdempotencyKey: "k"},
		"missing operation":  {SpaceID: "s", Capability: "payment.charge", Executor: capabilityGrantExecutor{PluginID: "p"}, IdempotencyKey: "k"},
		"missing executor":   {SpaceID: "s", Capability: "payment.charge", Operation: "charge", IdempotencyKey: "k"},
		"missing idempotency": {SpaceID: "s", Capability: "payment.charge", Operation: "charge", Executor: capabilityGrantExecutor{PluginID: "p"}},
	}
	for name, req := range cases {
		if err := validateActionGatewayRequest(req); err == nil {
			t.Fatalf("%s: expected validation error", name)
		}
	}
}

func TestActionHandlerOutcomeClassification(t *testing.T) {
	t.Setenv("PLYSTRA_CAPABILITY_GRANT_SECRET", "action-gateway-signing-secret-at-least-32-characters")

	var (
		mu   sync.Mutex
		mode string
		last *http.Request
		body []byte
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		last = r.Clone(context.Background())
		body, _ = io.ReadAll(r.Body)
		current := mode
		mu.Unlock()
		switch current {
		case "succeeded":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true,"business_event":{"type":"payment.charged","external_id":"inv_1"},"result_ref":{"resource_type":"charge","resource_id":"chg_1"}}`))
		case "rejected":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":false,"reason":"insufficient_funds"}`))
		default:
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"ok":false,"reason":"boom"}`))
		}
	}))
	defer server.Close()

	srv := &Server{}
	provider := capabilityProviderBinding{ProviderID: "plugin.payments", Endpoint: server.URL, OperationPath: "/charge"}
	req := actionGatewayRequest{
		SpaceID:        "spc_acme",
		Capability:     "payment.charge",
		Operation:      "charge",
		Principal:      capabilityGrantPrincipal{UserID: "usr_1", MemberID: "mem_1", UserMemberID: "um_1"},
		Executor:       capabilityGrantExecutor{PluginID: "plugin.invoice"},
		IdempotencyKey: "inv_1.charge.v1",
	}

	mu.Lock()
	mode = "succeeded"
	mu.Unlock()
	resp, status := srv.invokeActionHandler(context.Background(), provider, req, "act_1", "dec_1", "cor_1", 2000)
	if status != "succeeded" {
		t.Fatalf("status = %q, want succeeded", status)
	}
	if resp == nil || businessEventType(resp.BusinessEvent) != "payment.charged" {
		t.Fatalf("business event not parsed: %#v", resp)
	}
	mu.Lock()
	gotSignature := last.Header.Get("X-Plystra-Signature")
	gotExecID := last.Header.Get("X-Plystra-Action-Execution-Id")
	capturedBody := append([]byte(nil), body...)
	mu.Unlock()
	if gotSignature == "" {
		t.Fatalf("handler request was not signed")
	}
	if gotExecID != "act_1" {
		t.Fatalf("action execution id header = %q, want act_1", gotExecID)
	}
	var decoded map[string]any
	if err := json.Unmarshal(capturedBody, &decoded); err != nil {
		t.Fatalf("decode handler body: %v", err)
	}
	request, _ := decoded["request"].(map[string]any)
	if request["idempotency_key"] != "inv_1.charge.v1" || request["action_execution_id"] != "act_1" {
		t.Fatalf("handler request envelope missing idempotency/exec id: %#v", request)
	}

	mu.Lock()
	mode = "rejected"
	mu.Unlock()
	if _, status := srv.invokeActionHandler(context.Background(), provider, req, "act_1", "dec_1", "cor_1", 2000); status != "rejected" {
		t.Fatalf("status = %q, want rejected", status)
	}

	mu.Lock()
	mode = "failed"
	mu.Unlock()
	if _, status := srv.invokeActionHandler(context.Background(), provider, req, "act_1", "dec_1", "cor_1", 2000); status != "failed" {
		t.Fatalf("status = %q, want failed", status)
	}

	// Transport failure (connection refused) cannot confirm completion.
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()
	deadProvider := capabilityProviderBinding{ProviderID: "plugin.payments", Endpoint: deadURL, OperationPath: "/charge"}
	if _, status := srv.invokeActionHandler(context.Background(), deadProvider, req, "act_1", "dec_1", "cor_1", 2000); status != "result_unknown" {
		t.Fatalf("status = %q, want result_unknown", status)
	}
}

func TestActionGatewayIntegration(t *testing.T) {
	databaseURL := capabilityGrantTestDatabaseURL()
	if databaseURL == "" {
		t.Skip("set PLYSTRA_INTEGRATION_DATABASE_URL or PLYSTRA_DATABASE_URL to run action gateway integration tests")
	}

	t.Setenv("PLYSTRA_API_KEY_SECRET", "action-gateway-api-key-secret-at-least-32-characters")
	t.Setenv("PLYSTRA_CAPABILITY_GRANT_SECRET", "action-gateway-token-secret-at-least-32-characters")

	ctx := context.Background()
	store, err := entstore.Open(ctx, databaseURL)
	if err != nil {
		t.Fatalf("open ent store: %v", err)
	}
	defer store.Close()

	fixture := createCapabilityGrantFixture(t, ctx, store.Client())
	defer cleanupCapabilityGrantFixture(context.Background(), t, store.Client(), fixture)

	client := store.Client()
	defer func() {
		_, _ = client.ActionExecution.Delete().Where(entactionexecution.SpaceID(fixture.SpaceID)).Exec(context.Background())
	}()
	handler := NewServer(nil, store, "1.0.0-test").Routes()

	var (
		mu    sync.Mutex
		mode  string
		calls int
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		current := mode
		mu.Unlock()
		switch current {
		case "rejected":
			_, _ = w.Write([]byte(`{"ok":false,"reason":"insufficient_funds"}`))
		case "failed":
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`{"ok":false}`))
		default:
			_, _ = w.Write([]byte(`{"ok":true,"business_event":{"type":"payment.charged"},"result_ref":{"resource_type":"charge","resource_id":"chg_1"}}`))
		}
	}))
	defer server.Close()

	setEndpoint := func(t *testing.T, url string) {
		t.Helper()
		if _, err := client.PluginSettingsDefinition.Update().
			Where(entpluginsettingsdefinition.PluginID(fixture.ProviderRowID), entpluginsettingsdefinition.Key("provider.endpoint")).
			SetDefaultValue(map[string]any{"value": url}).
			Save(ctx); err != nil {
			t.Fatalf("set provider endpoint: %v", err)
		}
	}
	setEndpoint(t, server.URL)

	body := func(idempotencyKey string) map[string]any {
		return map[string]any{
			"space_id":   fixture.SpaceID,
			"capability": fixture.BrokeredCapabilityID,
			"operation":  "charge",
			"principal": map[string]any{
				"user_id":        fixture.PrincipalUserID,
				"member_id":      fixture.PrincipalMemberID,
				"user_member_id": fixture.PrincipalUserMemberID,
			},
			"executor":        map[string]any{"plugin_id": fixture.CallerPluginID},
			"resource":        map[string]any{"type": "invoice", "id": "inv_1"},
			"input":           map[string]any{"amount": 12000, "currency": "USD"},
			"idempotency_key": idempotencyKey,
			"correlation_id":  "cor_action_" + fixture.Suffix,
		}
	}

	loadExecution := func(t *testing.T, id string) *coreent.ActionExecution {
		t.Helper()
		row, err := client.ActionExecution.Get(ctx, id)
		if err != nil {
			t.Fatalf("load action execution %s: %v", id, err)
		}
		return row
	}

	invoke := func(idempotencyKey string) *httptest.ResponseRecorder {
		return capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/action-gateway", fixture.SpaceID), fixture.APIKey, body(idempotencyKey))
	}

	t.Run("succeeded controlled action records execution and business event", func(t *testing.T) {
		mu.Lock()
		mode = "succeeded"
		mu.Unlock()
		rec := invoke("charge.success.v1")
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
		}
		data := decodeCapabilityGrantData(t, rec)
		if data["status"] != "succeeded" {
			t.Fatalf("status = %#v, want succeeded", data["status"])
		}
		execID := requireStringField(t, data, "action_execution_id")
		if requireStringField(t, data, "decision_id") == "" {
			t.Fatalf("decision_id missing: %#v", data)
		}
		row := loadExecution(t, execID)
		if row.Status != "succeeded" {
			t.Fatalf("stored status = %q, want succeeded", row.Status)
		}
		event, ok := row.Metadata["business_event"].(map[string]any)
		if !ok || event["type"] != "payment.charged" {
			t.Fatalf("business_event not journaled: %#v", row.Metadata)
		}
	})

	t.Run("in-window idempotent replay resolves to the same execution", func(t *testing.T) {
		mu.Lock()
		mode = "succeeded"
		calls = 0
		mu.Unlock()
		first := invoke("charge.idem.v1")
		if first.Code != http.StatusOK {
			t.Fatalf("first status = %d, body=%s", first.Code, first.Body.String())
		}
		firstID := requireStringField(t, decodeCapabilityGrantData(t, first), "action_execution_id")
		second := invoke("charge.idem.v1")
		if second.Code != http.StatusOK {
			t.Fatalf("second status = %d, body=%s", second.Code, second.Body.String())
		}
		secondID := requireStringField(t, decodeCapabilityGrantData(t, second), "action_execution_id")
		if firstID != secondID {
			t.Fatalf("idempotent replay returned different executions: %q vs %q", firstID, secondID)
		}
		mu.Lock()
		gotCalls := calls
		mu.Unlock()
		if gotCalls != 1 {
			t.Fatalf("handler invoked %d times, want 1 (replay must not re-invoke)", gotCalls)
		}
	})

	t.Run("handler rejection is recorded as rejected", func(t *testing.T) {
		mu.Lock()
		mode = "rejected"
		mu.Unlock()
		rec := invoke("charge.rejected.v1")
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
		}
		if decodeCapabilityGrantData(t, rec)["status"] != "rejected" {
			t.Fatalf("status not rejected: %s", rec.Body.String())
		}
	})

	t.Run("handler server error is recorded as failed", func(t *testing.T) {
		mu.Lock()
		mode = "failed"
		mu.Unlock()
		rec := invoke("charge.failed.v1")
		if decodeCapabilityGrantData(t, rec)["status"] != "failed" {
			t.Fatalf("status not failed: %s", rec.Body.String())
		}
	})

	t.Run("transport failure is recorded as result_unknown", func(t *testing.T) {
		dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		deadURL := dead.URL
		dead.Close()
		setEndpoint(t, deadURL)
		defer setEndpoint(t, server.URL)
		rec := invoke("charge.unknown.v1")
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
		}
		data := decodeCapabilityGrantData(t, rec)
		if data["status"] != "result_unknown" {
			t.Fatalf("status = %#v, want result_unknown", data["status"])
		}
		if data["reconciliation_required"] != true {
			t.Fatalf("reconciliation_required not set: %#v", data)
		}
	})

	t.Run("rejects a non-controlled operation", func(t *testing.T) {
		mediated := map[string]any{
			"space_id":   fixture.SpaceID,
			"capability": fixture.MediatedCapabilityID,
			"operation":  "create_request",
			"principal": map[string]any{
				"user_id":        fixture.PrincipalUserID,
				"member_id":      fixture.PrincipalMemberID,
				"user_member_id": fixture.PrincipalUserMemberID,
			},
			"executor":        map[string]any{"plugin_id": fixture.CallerPluginID},
			"idempotency_key": "charge.mediated.v1",
		}
		rec := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/action-gateway", fixture.SpaceID), fixture.APIKey, mediated)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d, want 422, body=%s", rec.Code, rec.Body.String())
		}
		errorPayload := requireObjectField(t, decodeCapabilityGrantEnvelope(t, rec), "error")
		if errorPayload["code"] != "ACTION_NOT_CONTROLLED" {
			t.Fatalf("error code = %#v, want ACTION_NOT_CONTROLLED", errorPayload["code"])
		}
	})
}
