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
	entcapabilitygrant "github.com/plystra/core/ent/capabilitygrant"
	entmember "github.com/plystra/core/ent/member"
	entplugin "github.com/plystra/core/ent/plugin"
	entpluginsettingsdefinition "github.com/plystra/core/ent/pluginsettingsdefinition"
	entpluginsettingsvalue "github.com/plystra/core/ent/pluginsettingsvalue"
	entuser "github.com/plystra/core/ent/user"
	entusermember "github.com/plystra/core/ent/usermember"
	"github.com/plystra/core/internal/plugins"
	"github.com/plystra/core/internal/store/entstore"
)

type capabilityGrantFixture struct {
	Suffix                string
	SpaceID               string
	APIKeyID              string
	APIKey                string
	ProviderRowID         string
	ProviderPluginID      string
	ProviderEndpoint      string
	CallerRowID           string
	CallerPluginID        string
	CallerCapabilityID    string
	DisallowedRowID       string
	DisallowedPluginID    string
	NoRequiresRowID       string
	NoRequiresPluginID    string
	LocalProviderRowID    string
	LocalProviderPluginID string
	LocalCallerRowID      string
	LocalCallerPluginID   string
	ForeignCallerRowID    string
	ForeignCallerPluginID string
	MediatedCapabilityID  string
	BrokeredCapabilityID  string
	LocalCapabilityID     string
	PrincipalUserID       string
	PrincipalMemberID     string
	PrincipalUserMemberID string
}

func TestCapabilityGrantLedgerIntegration(t *testing.T) {
	databaseURL := capabilityGrantTestDatabaseURL()
	if databaseURL == "" {
		t.Skip("set PLYSTRA_INTEGRATION_DATABASE_URL or PLYSTRA_DATABASE_URL to run capability grant ledger integration tests")
	}

	t.Setenv("PLYSTRA_API_KEY_SECRET", "capability-grant-api-key-secret-at-least-32-characters")
	t.Setenv("PLYSTRA_CAPABILITY_GRANT_SECRET", "capability-grant-token-secret-at-least-32-characters")

	ctx := context.Background()
	store, err := entstore.Open(ctx, databaseURL)
	if err != nil {
		t.Fatalf("open ent store: %v", err)
	}
	defer store.Close()

	fixture := createCapabilityGrantFixture(t, ctx, store.Client())
	defer cleanupCapabilityGrantFixture(context.Background(), t, store.Client(), fixture)

	handler := NewServer(nil, store, "1.0.0-test").Routes()

	var issuedGrantID string
	var issuedGrantToken string
	var issuedTargetIdempotencyKey string

	t.Run("issues and reissues mediated grant by caller idempotency key", func(t *testing.T) {
		body := capabilityGrantIssueBody(fixture, "invoice.inv_123.approval.v1")
		rec := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/capability-grants", fixture.SpaceID), fixture.APIKey, body)
		if rec.Code != http.StatusCreated {
			t.Fatalf("issue status = %d, body=%s", rec.Code, rec.Body.String())
		}
		data := decodeCapabilityGrantData(t, rec)
		issuedGrantToken = requireStringField(t, data, "grant")
		issuedGrantID = requireStringField(t, data, "grant_id")
		issuedTargetIdempotencyKey = requireStringField(t, data, "target_idempotency_key")
		if issuedGrantID == "" || issuedTargetIdempotencyKey == "" {
			t.Fatalf("grant_id and target_idempotency_key must be present: %#v", data)
		}
		target := requireObjectField(t, data, "target")
		if target["provider_id"] != fixture.ProviderPluginID {
			t.Fatalf("target provider_id = %#v, want %q", target["provider_id"], fixture.ProviderPluginID)
		}
		if target["endpoint"] != fixture.ProviderEndpoint {
			t.Fatalf("target endpoint = %#v, want %q", target["endpoint"], fixture.ProviderEndpoint)
		}
		if target["operation_url"] == "" {
			t.Fatalf("target operation_url missing: %#v", target)
		}

		reissue := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/capability-grants", fixture.SpaceID), fixture.APIKey, body)
		if reissue.Code != http.StatusOK {
			t.Fatalf("reissue status = %d, body=%s", reissue.Code, reissue.Body.String())
		}
		reissuedData := decodeCapabilityGrantData(t, reissue)
		if got := requireStringField(t, reissuedData, "grant_id"); got != issuedGrantID {
			t.Fatalf("reissued grant_id = %q, want original %q", got, issuedGrantID)
		}
		if got := requireStringField(t, reissuedData, "target_idempotency_key"); got != issuedTargetIdempotencyKey {
			t.Fatalf("reissued target_idempotency_key = %q, want original %q", got, issuedTargetIdempotencyKey)
		}
		issuedGrantToken = requireStringField(t, reissuedData, "grant")
	})

	t.Run("introspects active grant metadata", func(t *testing.T) {
		if issuedGrantToken == "" {
			t.Fatalf("grant token was not issued")
		}
		rec := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/grants/introspect", fixture.SpaceID), fixture.APIKey, map[string]any{
			"grant":              issuedGrantToken,
			"target_provider_id": fixture.ProviderPluginID,
			"capability":         fixture.MediatedCapabilityID,
			"operation":          "create_request",
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("introspect status = %d, body=%s", rec.Code, rec.Body.String())
		}
		data := decodeCapabilityGrantData(t, rec)
		if active, ok := data["active"].(bool); !ok || !active {
			t.Fatalf("introspection active = %#v, want true; data=%#v", data["active"], data)
		}
		if got := requireStringField(t, data, "grant_id"); got != issuedGrantID {
			t.Fatalf("introspection grant_id = %q, want %q", got, issuedGrantID)
		}
		if got := requireStringField(t, data, "target_idempotency_key"); got != issuedTargetIdempotencyKey {
			t.Fatalf("introspection target_idempotency_key = %q, want %q", got, issuedTargetIdempotencyKey)
		}
		caller := requireObjectField(t, data, "caller")
		if caller["plugin_id"] != fixture.CallerPluginID {
			t.Fatalf("caller plugin_id = %#v, want %q", caller["plugin_id"], fixture.CallerPluginID)
		}
		principal := requireObjectField(t, data, "principal")
		if principal["user_id"] != fixture.PrincipalUserID || principal["member_id"] != fixture.PrincipalMemberID {
			t.Fatalf("principal metadata mismatch: %#v", principal)
		}
	})

	t.Run("records outcome receipt in grant ledger", func(t *testing.T) {
		rec := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/capability-outcomes", fixture.SpaceID), fixture.APIKey, map[string]any{
			"grant_id":               issuedGrantID,
			"target_idempotency_key": issuedTargetIdempotencyKey,
			"status":                 "succeeded",
			"outcome_event_id":       "evt_" + fixture.Suffix,
			"result_ref":             map[string]any{"resource_type": "approval", "resource_id": "apr_123"},
			"events":                 []any{map[string]any{"type": "approval.created", "resource_id": "apr_123"}},
			"metadata":               map[string]any{"receipt_source": "test"},
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("outcome status = %d, body=%s", rec.Code, rec.Body.String())
		}
		data := decodeCapabilityGrantData(t, rec)
		if data["status"] != "used" {
			t.Fatalf("grant status after outcome = %#v, want used", data["status"])
		}
		if data["outcome_status"] != "succeeded" {
			t.Fatalf("outcome_status = %#v, want succeeded", data["outcome_status"])
		}
		row, err := store.Client().CapabilityGrant.Query().Where(entcapabilitygrant.ID(issuedGrantID)).Only(ctx)
		if err != nil {
			t.Fatalf("load updated grant: %v", err)
		}
		if row.Status != "used" || row.OutcomeStatus != "succeeded" {
			t.Fatalf("stored grant status=%q outcome_status=%q, want used/succeeded", row.Status, row.OutcomeStatus)
		}
		outcome, ok := row.Metadata["outcome"].(map[string]any)
		if !ok {
			t.Fatalf("stored outcome metadata missing: %#v", row.Metadata)
		}
		if outcome["status"] != "succeeded" {
			t.Fatalf("stored outcome status = %#v, want succeeded", outcome["status"])
		}
	})

	t.Run("introspection fails closed after principal binding revocation", func(t *testing.T) {
		body := capabilityGrantIssueBody(fixture, "invoice.inv_125.approval.v1")
		rec := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/capability-grants", fixture.SpaceID), fixture.APIKey, body)
		if rec.Code != http.StatusCreated {
			t.Fatalf("issue revocation test grant status = %d, body=%s", rec.Code, rec.Body.String())
		}
		data := decodeCapabilityGrantData(t, rec)
		grantToken := requireStringField(t, data, "grant")
		now := time.Now().UTC()
		if err := store.Client().UserMember.UpdateOneID(fixture.PrincipalUserMemberID).
			SetStatus("revoked").
			SetRevokedAt(now).
			SetRevokedReason("test revocation").
			Exec(ctx); err != nil {
			t.Fatalf("revoke principal binding: %v", err)
		}
		rec = capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/grants/introspect", fixture.SpaceID), fixture.APIKey, map[string]any{
			"grant":              grantToken,
			"target_provider_id": fixture.ProviderPluginID,
			"capability":         fixture.MediatedCapabilityID,
			"operation":          "create_request",
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("introspect revoked principal status = %d, body=%s", rec.Code, rec.Body.String())
		}
		inactive := decodeCapabilityGrantData(t, rec)
		if active, _ := inactive["active"].(bool); active {
			t.Fatalf("revoked principal grant introspected active: %#v", inactive)
		}
		if inactive["reason"] != "principal_membership_revoked" {
			t.Fatalf("revoked principal reason = %#v, want principal_membership_revoked", inactive["reason"])
		}
		if err := store.Client().UserMember.UpdateOneID(fixture.PrincipalUserMemberID).
			SetStatus("active").
			ClearRevokedAt().
			ClearRevokedReason().
			Exec(ctx); err != nil {
			t.Fatalf("restore principal binding: %v", err)
		}
	})

	t.Run("forbids caller without required capability", func(t *testing.T) {
		body := capabilityGrantIssueBody(fixture, "invoice.inv_124.approval.v1")
		body["executor"] = map[string]any{"plugin_id": fixture.NoRequiresPluginID}
		rec := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/capability-grants", fixture.SpaceID), fixture.APIKey, body)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("missing requires status = %d, want 403, body=%s", rec.Code, rec.Body.String())
		}
		payload := decodeCapabilityGrantEnvelope(t, rec)
		errorPayload := requireObjectField(t, payload, "error")
		if errorPayload["code"] != "CAPABILITY_REQUIREMENT_MISSING" {
			t.Fatalf("error code = %#v, want CAPABILITY_REQUIREMENT_MISSING", errorPayload["code"])
		}
		assertNoGrantForIdempotencyKey(t, ctx, store.Client(), fixture.SpaceID, fixture.NoRequiresPluginID, "invoice.inv_124.approval.v1")
	})

	t.Run("forbids provider self-call without required capability", func(t *testing.T) {
		body := capabilityGrantIssueBody(fixture, "workflow.self_call.v1")
		body["executor"] = map[string]any{"plugin_id": fixture.ProviderPluginID}
		rec := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/capability-grants", fixture.SpaceID), fixture.APIKey, body)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("provider self-call missing requires status = %d, want 403, body=%s", rec.Code, rec.Body.String())
		}
		payload := decodeCapabilityGrantEnvelope(t, rec)
		errorPayload := requireObjectField(t, payload, "error")
		if errorPayload["code"] != "CAPABILITY_REQUIREMENT_MISSING" {
			t.Fatalf("error code = %#v, want CAPABILITY_REQUIREMENT_MISSING", errorPayload["code"])
		}
		assertNoGrantForIdempotencyKey(t, ctx, store.Client(), fixture.SpaceID, fixture.ProviderPluginID, "workflow.self_call.v1")
	})

	t.Run("enforces call graph allowed callers and depth", func(t *testing.T) {
		body := capabilityGrantIssueBody(fixture, "invoice.inv_126.approval.v1")
		body["executor"] = map[string]any{"plugin_id": fixture.DisallowedPluginID}
		rec := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/capability-grants", fixture.SpaceID), fixture.APIKey, body)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("allowed caller denial status = %d, want 403, body=%s", rec.Code, rec.Body.String())
		}
		payload := decodeCapabilityGrantEnvelope(t, rec)
		errorPayload := requireObjectField(t, payload, "error")
		if errorPayload["code"] != "CAPABILITY_CALL_GRAPH_DENIED" {
			t.Fatalf("error code = %#v, want CAPABILITY_CALL_GRAPH_DENIED", errorPayload["code"])
		}
		assertNoGrantForIdempotencyKey(t, ctx, store.Client(), fixture.SpaceID, fixture.DisallowedPluginID, "invoice.inv_126.approval.v1")

		body = capabilityGrantIssueBody(fixture, "invoice.inv_127.approval.v1")
		body["ttl_ms"] = 60000
		root := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/capability-grants", fixture.SpaceID), fixture.APIKey, body)
		if root.Code != http.StatusCreated {
			t.Fatalf("root grant status = %d, body=%s", root.Code, root.Body.String())
		}
		rootGrantID := requireStringField(t, decodeCapabilityGrantData(t, root), "grant_id")
		childBody := capabilityGrantIssueBody(fixture, "invoice.inv_128.approval.v1")
		childBody["parent_grant_id"] = rootGrantID
		child := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/capability-grants", fixture.SpaceID), fixture.APIKey, childBody)
		if child.Code != http.StatusForbidden {
			t.Fatalf("depth denial status = %d, want 403, body=%s", child.Code, child.Body.String())
		}
	})

	t.Run("allows same app module caller for local capability", func(t *testing.T) {
		body := capabilityGrantIssueBody(fixture, "local.same_app.v1")
		body["capability"] = fixture.LocalCapabilityID
		body["operation"] = "execute"
		body["executor"] = map[string]any{"plugin_id": fixture.LocalCallerPluginID}
		rec := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/capability-grants", fixture.SpaceID), fixture.APIKey, body)
		if rec.Code != http.StatusCreated {
			t.Fatalf("same-app local capability status = %d, want 201, body=%s", rec.Code, rec.Body.String())
		}
		data := decodeCapabilityGrantData(t, rec)
		target := requireObjectField(t, data, "target")
		if target["provider_id"] != fixture.LocalProviderPluginID {
			t.Fatalf("local capability target provider_id = %#v, want %q", target["provider_id"], fixture.LocalProviderPluginID)
		}
	})

	t.Run("uses manifest governance when row metadata still has defaults", func(t *testing.T) {
		body := capabilityGrantIssueBody(fixture, "local.row_defaults.v1")
		body["capability"] = fixture.LocalCapabilityID
		body["operation"] = "execute"
		body["executor"] = map[string]any{"plugin_id": fixture.LocalCallerPluginID}
		rec := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/capability-grants", fixture.SpaceID), fixture.APIKey, body)
		if rec.Code != http.StatusCreated {
			t.Fatalf("same-app local capability with row defaults status = %d, want 201, body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("denies foreign app module caller for local capability", func(t *testing.T) {
		body := capabilityGrantIssueBody(fixture, "local.foreign_app.v1")
		body["capability"] = fixture.LocalCapabilityID
		body["operation"] = "execute"
		body["executor"] = map[string]any{"plugin_id": fixture.ForeignCallerPluginID}
		rec := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/capability-grants", fixture.SpaceID), fixture.APIKey, body)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("foreign-app local capability status = %d, want 403, body=%s", rec.Code, rec.Body.String())
		}
		payload := decodeCapabilityGrantEnvelope(t, rec)
		errorPayload := requireObjectField(t, payload, "error")
		if errorPayload["code"] != "CAPABILITY_SCOPE_DENIED" {
			t.Fatalf("error code = %#v, want CAPABILITY_SCOPE_DENIED", errorPayload["code"])
		}
		assertNoGrantForIdempotencyKey(t, ctx, store.Client(), fixture.SpaceID, fixture.ForeignCallerPluginID, "local.foreign_app.v1")
	})

	t.Run("rejects brokered operation through mediated grant endpoint", func(t *testing.T) {
		body := capabilityGrantIssueBody(fixture, "payment.pay_123.charge.v1")
		body["capability"] = fixture.BrokeredCapabilityID
		body["operation"] = "charge"
		rec := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/capability-grants", fixture.SpaceID), fixture.APIKey, body)
		if rec.Code < http.StatusBadRequest || rec.Code == http.StatusCreated {
			t.Fatalf("brokered operation status = %d, want rejection, body=%s", rec.Code, rec.Body.String())
		}
		assertNoGrantForIdempotencyKey(t, ctx, store.Client(), fixture.SpaceID, fixture.CallerPluginID, "payment.pay_123.charge.v1")
	})
}

func capabilityGrantTestDatabaseURL() string {
	for _, key := range []string{"PLYSTRA_INTEGRATION_DATABASE_URL", "PLYSTRA_DATABASE_URL"} {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return value
		}
	}
	return ""
}

func createCapabilityGrantFixture(t *testing.T, ctx context.Context, client *coreent.Client) capabilityGrantFixture {
	t.Helper()
	suffix := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	fixture := capabilityGrantFixture{
		Suffix:                suffix,
		SpaceID:               "space_capability_grants_" + suffix,
		APIKeyID:              "ak_capability_grants_" + suffix,
		ProviderRowID:         "plugin_capability_grants_provider_" + suffix,
		ProviderPluginID:      "test.workflow_" + suffix,
		ProviderEndpoint:      "http://workflow-provider-" + suffix + ".internal",
		CallerRowID:           "plugin_capability_grants_caller_" + suffix,
		CallerPluginID:        "test.invoice_" + suffix,
		CallerCapabilityID:    "resource.invoice_" + suffix,
		DisallowedRowID:       "plugin_capability_grants_disallowed_" + suffix,
		DisallowedPluginID:    "test.disallowed_" + suffix,
		NoRequiresRowID:       "plugin_capability_grants_no_requires_" + suffix,
		NoRequiresPluginID:    "test.no_requires_" + suffix,
		LocalProviderRowID:    "plugin_capability_grants_local_provider_" + suffix,
		LocalProviderPluginID: "app.delivery.local_provider_" + suffix,
		LocalCallerRowID:      "plugin_capability_grants_local_caller_" + suffix,
		LocalCallerPluginID:   "app.delivery.local_caller_" + suffix,
		ForeignCallerRowID:    "plugin_capability_grants_foreign_caller_" + suffix,
		ForeignCallerPluginID: "app.other.local_caller_" + suffix,
		MediatedCapabilityID:  "workflow.approval_" + suffix,
		BrokeredCapabilityID:  "payment.charge_" + suffix,
		LocalCapabilityID:     "delivery.operations_" + suffix,
		PrincipalUserID:       "user_capability_grants_" + suffix,
		PrincipalMemberID:     "member_capability_grants_" + suffix,
		PrincipalUserMemberID: "um_capability_grants_" + suffix,
	}

	apiKey, err := newAPIKeyPlaintext(fixture.APIKeyID)
	if err != nil {
		t.Fatalf("generate api key: %v", err)
	}
	fixture.APIKey = apiKey

	if _, err := client.Space.Create().SetID(fixture.SpaceID).SetName("Capability Grant Test Space").SetSlug("capability-grants-" + suffix).Save(ctx); err != nil {
		t.Fatalf("create space: %v", err)
	}
	if _, err := client.User.Create().
		SetID(fixture.PrincipalUserID).
		SetEmail("capability-grants-" + suffix + "@example.test").
		SetStatus("active").
		Save(ctx); err != nil {
		t.Fatalf("create principal user: %v", err)
	}
	if _, err := client.Member.Create().
		SetID(fixture.PrincipalMemberID).
		SetSpaceID(fixture.SpaceID).
		SetDisplayName("Capability Grant Principal").
		SetStatus("active").
		Save(ctx); err != nil {
		t.Fatalf("create principal member: %v", err)
	}
	if _, err := client.UserMember.Create().
		SetID(fixture.PrincipalUserMemberID).
		SetUserID(fixture.PrincipalUserID).
		SetMemberID(fixture.PrincipalMemberID).
		SetSpaceID(fixture.SpaceID).
		SetRelationType("test").
		SetStatus("active").
		SetIsPrimary(true).
		Save(ctx); err != nil {
		t.Fatalf("create principal user member: %v", err)
	}
	if _, err := client.ApiKey.Create().
		SetID(fixture.APIKeyID).
		SetName("Capability grant test key").
		SetKeyPrefix(apiKeyPrefix(fixture.APIKeyID)).
		SetKeyHash(apiKeyHash(apiKey)).
		SetLevel("space").
		SetSpaceID(fixture.SpaceID).
		SetPermissionKeys([]string{"capabilities:invoke", "capabilities:manage"}).
		Save(ctx); err != nil {
		t.Fatalf("create api key: %v", err)
	}

	providerManifest := capabilityGrantProviderManifest(fixture)
	createPluginRow(t, ctx, client, fixture.ProviderRowID, fixture.ProviderPluginID, providerManifest)
	if _, err := client.PluginSettingsDefinition.Create().
		SetID("psd_capability_grants_endpoint_" + suffix).
		SetPluginID(fixture.ProviderRowID).
		SetKey("provider.endpoint").
		SetValueType("string").
		SetScope("instance").
		SetDefaultValue(map[string]any{"value": fixture.ProviderEndpoint}).
		Save(ctx); err != nil {
		t.Fatalf("create provider endpoint setting definition: %v", err)
	}

	createPluginRow(t, ctx, client, fixture.CallerRowID, fixture.CallerPluginID, capabilityGrantCallerManifest(fixture, true))
	createPluginRow(t, ctx, client, fixture.DisallowedRowID, fixture.DisallowedPluginID, capabilityGrantDisallowedCallerManifest(fixture))
	createPluginRow(t, ctx, client, fixture.NoRequiresRowID, fixture.NoRequiresPluginID, capabilityGrantCallerManifest(fixture, false))
	createPluginRow(t, ctx, client, fixture.LocalProviderRowID, fixture.LocalProviderPluginID, capabilityGrantLocalProviderManifest(fixture))
	createPluginRow(t, ctx, client, fixture.LocalCallerRowID, fixture.LocalCallerPluginID, capabilityGrantLocalCallerManifest(fixture, fixture.LocalCallerPluginID, "delivery"))
	createPluginRow(t, ctx, client, fixture.ForeignCallerRowID, fixture.ForeignCallerPluginID, capabilityGrantLocalCallerManifest(fixture, fixture.ForeignCallerPluginID, "other"))

	return fixture
}

func createPluginRow(t *testing.T, ctx context.Context, client *coreent.Client, rowID, pluginID string, manifest plugins.Manifest) {
	t.Helper()
	manifestMap, err := pluginManifestMap(manifest)
	if err != nil {
		t.Fatalf("encode manifest %s: %v", pluginID, err)
	}
	if _, err := client.Plugin.Create().
		SetID(rowID).
		SetKey(pluginID).
		SetName(manifest.Name).
		SetVersion(manifest.Version).
		SetSource("test").
		SetStatus("enabled").
		SetManifest(manifestMap).
		Save(ctx); err != nil {
		t.Fatalf("create plugin %s: %v", pluginID, err)
	}
}

func capabilityGrantProviderManifest(fixture capabilityGrantFixture) plugins.Manifest {
	return plugins.Manifest{
		ID:               fixture.ProviderPluginID,
		Name:             "Capability Grant Workflow Provider",
		Version:          "1.0.0",
		Source:           "test",
		Status:           "enabled",
		ManifestVersion:  "1.0",
		PluginAPIVersion: "1.0",
		RequiresCore:     ">=1.0.0",
		Settings: []plugins.SettingDefinition{{
			Key:       "provider.endpoint",
			ValueType: "string",
			Scope:     "instance",
			Default:   fixture.ProviderEndpoint,
		}},
		Runtime: plugins.ProviderRuntimeDefinition{
			Type:               "external",
			Protocol:           "http_json",
			Version:            "1.0.0",
			EndpointSettingKey: "provider.endpoint",
		},
		Capabilities: []plugins.CapabilityDefinition{
			{
				ID:      fixture.MediatedCapabilityID,
				Version: "1.0.0",
				Level:   "standard",
				Audit:   plugins.CapabilityAuditDefinition{Enforcement: "reported_event"},
				Operations: []plugins.CapabilityOperationDefinition{{
					Name: "create_request",
					Invocation: plugins.CapabilityInvocationDefinition{
						Mode:           "revocable_mediated_grant",
						GrantTTLMS:     60000,
						Introspection:  "required",
						OutcomeReceipt: "required",
						Idempotency:    "required",
					},
					Delegation: plugins.CapabilityDelegationDefinition{Mode: "preserve_principal"},
					CallGraph: plugins.CapabilityCallGraphDefinition{
						MaxDepth:       1,
						AllowedCallers: []string{fixture.CallerCapabilityID},
					},
				}},
			},
			{
				ID:      fixture.BrokeredCapabilityID,
				Version: "1.0.0",
				Level:   "standard",
				Audit:   plugins.CapabilityAuditDefinition{Enforcement: "controlled_action"},
				Operations: []plugins.CapabilityOperationDefinition{{
					Name: "charge",
					Invocation: plugins.CapabilityInvocationDefinition{
						Mode:                        "brokered_action_gateway",
						Idempotency:                 "required",
						ResultUnknownReconciliation: "required",
					},
					Delegation: plugins.CapabilityDelegationDefinition{Mode: "preserve_principal"},
				}},
			},
		},
		Routes: []plugins.RouteDefinition{
			{Method: "POST", Path: "/v1/capabilities/" + strings.ReplaceAll(fixture.MediatedCapabilityID, ".", "/") + "/create_request", Handler: "create_request"},
			{Method: "POST", Path: "/v1/capabilities/" + strings.ReplaceAll(fixture.BrokeredCapabilityID, ".", "/") + "/charge", Handler: "charge"},
		},
	}
}

func capabilityGrantCallerManifest(fixture capabilityGrantFixture, includeRequires bool) plugins.Manifest {
	manifest := plugins.Manifest{
		ID:               fixture.CallerPluginID,
		Name:             "Capability Grant Caller",
		Version:          "1.0.0",
		Source:           "test",
		Status:           "enabled",
		ManifestVersion:  "1.0",
		PluginAPIVersion: "1.0",
		RequiresCore:     ">=1.0.0",
	}
	if !includeRequires {
		manifest.ID = fixture.NoRequiresPluginID
		manifest.Name = "Capability Grant Caller Without Requires"
		return manifest
	}
	manifest.Capabilities = []plugins.CapabilityDefinition{{
		ID:        fixture.CallerCapabilityID,
		Version:   "1.0.0",
		Level:     "declared",
		Audit:     plugins.CapabilityAuditDefinition{Enforcement: "grant_only"},
		DataPlane: plugins.CapabilityDataPlaneDefinition{Allowed: []string{"direct_db"}},
	}}
	manifest.Requires = []plugins.CapabilityRequirement{
		{ID: fixture.MediatedCapabilityID, Version: "1.0.0", MinLevel: "standard"},
		{ID: fixture.BrokeredCapabilityID, Version: "1.0.0", MinLevel: "standard"},
	}
	return manifest
}

func capabilityGrantDisallowedCallerManifest(fixture capabilityGrantFixture) plugins.Manifest {
	manifest := capabilityGrantCallerManifest(fixture, true)
	manifest.ID = fixture.DisallowedPluginID
	manifest.Name = "Capability Grant Caller Outside Call Graph"
	manifest.Capabilities = []plugins.CapabilityDefinition{{
		ID:        "resource.other_" + fixture.Suffix,
		Version:   "1.0.0",
		Level:     "declared",
		Audit:     plugins.CapabilityAuditDefinition{Enforcement: "grant_only"},
		DataPlane: plugins.CapabilityDataPlaneDefinition{Allowed: []string{"direct_db"}},
	}}
	return manifest
}

func capabilityGrantLocalProviderManifest(fixture capabilityGrantFixture) plugins.Manifest {
	return plugins.Manifest{
		ID:               fixture.LocalProviderPluginID,
		Type:             "app_module",
		Scope:            "app",
		AppID:            "delivery",
		Name:             "Delivery Local Capability Provider",
		Version:          "1.0.0",
		Source:           "test",
		Status:           "enabled",
		ManifestVersion:  "1.0",
		PluginAPIVersion: "1.0",
		RequiresCore:     ">=1.0.0",
		Runtime: plugins.ProviderRuntimeDefinition{
			Type:     "external",
			Protocol: "http_json",
			Version:  "1.0.0",
		},
		LocalCapabilities: []plugins.CapabilityDefinition{{
			ID:        fixture.LocalCapabilityID,
			Version:   "1.0.0",
			Level:     "standard",
			Audit:     plugins.CapabilityAuditDefinition{Enforcement: "reported_event"},
			DataPlane: plugins.CapabilityDataPlaneDefinition{Allowed: []string{"core_data_api"}},
			Operations: []plugins.CapabilityOperationDefinition{{
				Name: "execute",
				Invocation: plugins.CapabilityInvocationDefinition{
					Mode:           "revocable_mediated_grant",
					GrantTTLMS:     60000,
					Introspection:  "required",
					OutcomeReceipt: "required",
					Idempotency:    "required",
				},
				Delegation: plugins.CapabilityDelegationDefinition{Mode: "preserve_principal"},
				CallGraph:  plugins.CapabilityCallGraphDefinition{MaxDepth: 4},
			}},
		}},
		Routes: []plugins.RouteDefinition{{Method: "POST", Path: "/v1/local/delivery/execute", Handler: "execute"}},
	}
}

func capabilityGrantLocalCallerManifest(fixture capabilityGrantFixture, pluginID, appID string) plugins.Manifest {
	return plugins.Manifest{
		ID:               pluginID,
		Type:             "app_module",
		Scope:            "app",
		AppID:            appID,
		Name:             "App Module Local Capability Caller",
		Version:          "1.0.0",
		Source:           "test",
		Status:           "enabled",
		ManifestVersion:  "1.0",
		PluginAPIVersion: "1.0",
		RequiresCore:     ">=1.0.0",
		LocalCapabilities: []plugins.CapabilityDefinition{{
			ID:        appID + ".caller_" + fixture.Suffix,
			Version:   "1.0.0",
			Level:     "declared",
			Audit:     plugins.CapabilityAuditDefinition{Enforcement: "reported_event"},
			DataPlane: plugins.CapabilityDataPlaneDefinition{Allowed: []string{"core_data_api"}},
		}},
		Requires: []plugins.CapabilityRequirement{{ID: fixture.LocalCapabilityID, Version: "1.0.0", MinLevel: "standard"}},
	}
}

func cleanupCapabilityGrantFixture(ctx context.Context, t *testing.T, client *coreent.Client, fixture capabilityGrantFixture) {
	t.Helper()
	now := time.Now().UTC()
	ignore := func(label string, err error) {
		t.Helper()
		if err != nil && !coreent.IsNotFound(err) {
			t.Logf("cleanup %s: %v", label, err)
		}
	}
	_, err := client.CapabilityGrant.Delete().Where(entcapabilitygrant.SpaceID(fixture.SpaceID)).Exec(ctx)
	ignore("capability grants", err)
	_, err = client.PluginSettingsValue.Delete().Where(entpluginsettingsvalue.PluginID(fixture.ProviderRowID)).Exec(ctx)
	ignore("plugin setting values", err)
	_, err = client.PluginSettingsDefinition.Delete().Where(entpluginsettingsdefinition.PluginID(fixture.ProviderRowID)).Exec(ctx)
	ignore("plugin setting definitions", err)
	_, err = client.Plugin.Delete().Where(entplugin.IDIn(
		fixture.ProviderRowID,
		fixture.CallerRowID,
		fixture.DisallowedRowID,
		fixture.NoRequiresRowID,
		fixture.LocalProviderRowID,
		fixture.LocalCallerRowID,
		fixture.ForeignCallerRowID,
	)).Exec(ctx)
	ignore("plugins", err)
	ignore("api key", client.ApiKey.UpdateOneID(fixture.APIKeyID).
		SetStatus("revoked").
		SetRevokedAt(now).
		SetRevokedReason("test cleanup").
		SetDeletedAt(now).
		Exec(ctx))
	_, err = client.UserMember.Delete().Where(entusermember.ID(fixture.PrincipalUserMemberID)).Exec(ctx)
	ignore("principal user member", err)
	_, err = client.Member.Delete().Where(entmember.ID(fixture.PrincipalMemberID)).Exec(ctx)
	ignore("principal member", err)
	_, err = client.User.Delete().Where(entuser.ID(fixture.PrincipalUserID)).Exec(ctx)
	ignore("principal user", err)
	ignore("space", client.Space.UpdateOneID(fixture.SpaceID).SetStatus("disabled").SetDeletedAt(now).Exec(ctx))
}

func capabilityGrantIssueBody(fixture capabilityGrantFixture, idempotencyKey string) map[string]any {
	return map[string]any{
		"space_id":   fixture.SpaceID,
		"capability": fixture.MediatedCapabilityID,
		"operation":  "create_request",
		"principal": map[string]any{
			"user_id":        fixture.PrincipalUserID,
			"member_id":      fixture.PrincipalMemberID,
			"user_member_id": fixture.PrincipalUserMemberID,
		},
		"executor": map[string]any{"plugin_id": fixture.CallerPluginID},
		"resource": map[string]any{
			"type": "invoice",
			"id":   "inv_123",
		},
		"input_summary": map[string]any{
			"amount":   12000,
			"currency": "USD",
		},
		"idempotency_key": idempotencyKey,
		"correlation_id":  "cor_capability_grants_" + fixture.Suffix,
		"ttl_ms":          60000,
	}
}

func capabilityGrantPath(path, spaceID string) string {
	return path + "?space_id=" + spaceID
}

func capabilityGrantJSONRequest(handler http.Handler, method, path, apiKey string, body any) *httptest.ResponseRecorder {
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		payload, _ := json.Marshal(body)
		reader = bytes.NewReader(payload)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("X-Request-ID", "req_capability_grants_test")
	req.Header.Set("X-Plystra-API-Key", apiKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeCapabilityGrantEnvelope(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response %q: %v", rec.Body.String(), err)
	}
	return payload
}

func decodeCapabilityGrantData(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	payload := decodeCapabilityGrantEnvelope(t, rec)
	return requireObjectField(t, payload, "data")
}

func requireObjectField(t *testing.T, values map[string]any, key string) map[string]any {
	t.Helper()
	object, ok := values[key].(map[string]any)
	if !ok {
		t.Fatalf("%s is not an object: %#v", key, values[key])
	}
	return object
}

func requireStringField(t *testing.T, values map[string]any, key string) string {
	t.Helper()
	value, ok := values[key].(string)
	if !ok || strings.TrimSpace(value) == "" {
		t.Fatalf("%s is not a non-empty string: %#v", key, values[key])
	}
	return value
}

func assertNoGrantForIdempotencyKey(t *testing.T, ctx context.Context, client *coreent.Client, spaceID, callerPluginID, idempotencyKey string) {
	t.Helper()
	count, err := client.CapabilityGrant.Query().Where(
		entcapabilitygrant.SpaceID(spaceID),
		entcapabilitygrant.CallerPluginID(callerPluginID),
		entcapabilitygrant.IdempotencyKey(idempotencyKey),
	).Count(ctx)
	if err != nil {
		t.Fatalf("count grants for %s: %v", idempotencyKey, err)
	}
	if count != 0 {
		t.Fatalf("grant row exists for rejected idempotency key %q", idempotencyKey)
	}
}
