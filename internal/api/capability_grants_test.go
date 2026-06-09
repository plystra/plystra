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
	entactionexecution "github.com/plystra/core/ent/actionexecution"
	entauditlog "github.com/plystra/core/ent/auditlog"
	entcapabilitygrant "github.com/plystra/core/ent/capabilitygrant"
	entcapabilityproviderbinding "github.com/plystra/core/ent/capabilityproviderbinding"
	entgroup "github.com/plystra/core/ent/group"
	entmember "github.com/plystra/core/ent/member"
	entmemberrole "github.com/plystra/core/ent/memberrole"
	entpermission "github.com/plystra/core/ent/permission"
	entplugin "github.com/plystra/core/ent/plugin"
	entproviderrequestcontext "github.com/plystra/core/ent/providerrequestcontext"
	entresource "github.com/plystra/core/ent/resource"
	entresourceaction "github.com/plystra/core/ent/resourceaction"
	entresourcemapping "github.com/plystra/core/ent/resourcemapping"
	entresourcetype "github.com/plystra/core/ent/resourcetype"
	entrole "github.com/plystra/core/ent/role"
	entrolepermission "github.com/plystra/core/ent/rolepermission"
	entuser "github.com/plystra/core/ent/user"
	entusermember "github.com/plystra/core/ent/usermember"
	"github.com/plystra/core/internal/plugins"
	"github.com/plystra/core/internal/store/entstore"
)

type capabilityGrantFixture struct {
	Suffix                    string
	SpaceID                   string
	APIKeyID                  string
	APIKey                    string
	ProviderAPIKeyID          string
	ProviderAPIKey            string
	ProviderRowID             string
	ProviderPluginID          string
	ProviderEndpoint          string
	SpaceProviderEndpoint     string
	SpaceBindingEpoch         int
	CallerRowID               string
	CallerPluginID            string
	CallerCapabilityID        string
	DisallowedRowID           string
	DisallowedPluginID        string
	NoRequiresRowID           string
	NoRequiresPluginID        string
	LocalProviderRowID        string
	LocalProviderPluginID     string
	LocalCallerRowID          string
	LocalCallerPluginID       string
	OtherBundleCallerRowID    string
	OtherBundleCallerPluginID string
	ForeignCallerRowID        string
	ForeignCallerPluginID     string
	MediatedCapabilityID      string
	BrokeredCapabilityID      string
	LocalCapabilityID         string
	PrincipalUserID           string
	PrincipalMemberID         string
	PrincipalUserMemberID     string
	GroupID                   string
	ResourceTypeID            string
	ResourceActionID          string
	ResourceMappingID         string
	PermissionID              string
	RoleID                    string
	RolePermissionID          string
	MemberRoleID              string
	InvoiceResourceID         string
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

	server := NewServer(nil, store, "1.0.0-test")
	handler := server.Routes()

	var issuedGrantID string
	var issuedGrantToken string
	var issuedTargetIdempotencyKey string
	var issuedGrantDecisionID string

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
		issuedGrantDecisionID = requireStringField(t, data, "decision_id")
		target := requireObjectField(t, data, "target")
		if target["provider_id"] != fixture.ProviderPluginID {
			t.Fatalf("target provider_id = %#v, want %q", target["provider_id"], fixture.ProviderPluginID)
		}
		if target["endpoint"] != fixture.SpaceProviderEndpoint {
			t.Fatalf("target endpoint = %#v, want %q", target["endpoint"], fixture.SpaceProviderEndpoint)
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

	t.Run("resolves provider binding from request space without query parameter", func(t *testing.T) {
		body := capabilityGrantIssueBody(fixture, "invoice.inv_space_binding.approval.v1")
		rec := capabilityGrantJSONRequest(handler, http.MethodPost, "/api/v1/capability-grants", fixture.APIKey, body)
		if rec.Code != http.StatusCreated {
			t.Fatalf("issue without query space status = %d, body=%s", rec.Code, rec.Body.String())
		}
		data := decodeCapabilityGrantData(t, rec)
		target := requireObjectField(t, data, "target")
		if target["endpoint"] != fixture.SpaceProviderEndpoint {
			t.Fatalf("target endpoint without query = %#v, want %q", target["endpoint"], fixture.SpaceProviderEndpoint)
		}
		if got := intField(t, data, "binding_epoch"); got != fixture.SpaceBindingEpoch {
			t.Fatalf("binding_epoch without query = %d, want %d", got, fixture.SpaceBindingEpoch)
		}
	})

	t.Run("introspects active grant metadata", func(t *testing.T) {
		if issuedGrantToken == "" {
			t.Fatalf("grant token was not issued")
		}
		rec := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/grants/introspect", fixture.SpaceID), fixture.ProviderAPIKey, map[string]any{
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

	t.Run("issues provider request context only for active mediated grant", func(t *testing.T) {
		if issuedGrantID == "" {
			t.Fatalf("grant was not issued")
		}
		body := providerRequestContextBody(fixture)
		body["capability_grant_id"] = issuedGrantID
		body["capability"] = fixture.MediatedCapabilityID
		body["operation"] = "create_request"
		body["authorization_decision_id"] = issuedGrantDecisionID
		rec := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/provider-request-contexts", fixture.SpaceID), fixture.ProviderAPIKey, body)
		if rec.Code != http.StatusCreated {
			t.Fatalf("provider context from grant status = %d, want 201, body=%s", rec.Code, rec.Body.String())
		}
		data := decodeCapabilityGrantData(t, rec)
		if requireStringField(t, data, "context_token") == "" {
			t.Fatalf("context token missing: %#v", data)
		}
		if data["capability_grant_id"] != issuedGrantID {
			t.Fatalf("capability_grant_id = %#v, want %q", data["capability_grant_id"], issuedGrantID)
		}
		if data["capability"] != fixture.MediatedCapabilityID || data["operation"] != "create_request" {
			t.Fatalf("capability operation mismatch: %#v", data)
		}

		wrongActor := providerRequestContextBody(fixture)
		wrongActor["capability_grant_id"] = issuedGrantID
		wrongActor["capability"] = fixture.MediatedCapabilityID
		wrongActor["operation"] = "create_request"
		actor := requireObjectField(t, wrongActor, "actor")
		actor["member_id"] = "member_wrong_" + fixture.Suffix
		denied := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/provider-request-contexts", fixture.SpaceID), fixture.ProviderAPIKey, wrongActor)
		if denied.Code != http.StatusForbidden {
			t.Fatalf("provider context wrong actor status = %d, want 403, body=%s", denied.Code, denied.Body.String())
		}
	})

	t.Run("provider runtime calls fail closed when provider is disabled", func(t *testing.T) {
		if issuedGrantToken == "" || issuedGrantID == "" || issuedTargetIdempotencyKey == "" {
			t.Fatalf("grant was not issued")
		}
		if err := store.Client().Plugin.UpdateOneID(fixture.ProviderRowID).SetStatus("disabled").Exec(ctx); err != nil {
			t.Fatalf("disable provider plugin: %v", err)
		}
		t.Cleanup(func() {
			_ = store.Client().Plugin.UpdateOneID(fixture.ProviderRowID).SetStatus("enabled").Exec(context.Background())
		})

		introspect := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/grants/introspect", fixture.SpaceID), fixture.ProviderAPIKey, map[string]any{
			"grant":              issuedGrantToken,
			"target_provider_id": fixture.ProviderPluginID,
			"capability":         fixture.MediatedCapabilityID,
			"operation":          "create_request",
		})
		if introspect.Code != http.StatusForbidden {
			t.Fatalf("disabled provider introspect status = %d, want 403, body=%s", introspect.Code, introspect.Body.String())
		}
		payload := decodeCapabilityGrantEnvelope(t, introspect)
		errorPayload := requireObjectField(t, payload, "error")
		if errorPayload["code"] != "CAPABILITY_PROVIDER_INACTIVE" {
			t.Fatalf("disabled provider introspect code = %#v, want CAPABILITY_PROVIDER_INACTIVE", errorPayload["code"])
		}

		outcome := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/capability-outcomes", fixture.SpaceID), fixture.ProviderAPIKey, map[string]any{
			"grant_id":               issuedGrantID,
			"target_idempotency_key": issuedTargetIdempotencyKey,
			"target_provider_id":     fixture.ProviderPluginID,
			"status":                 "failed",
			"outcome_event_id":       "evt_disabled_provider_" + fixture.Suffix,
		})
		if outcome.Code != http.StatusForbidden {
			t.Fatalf("disabled provider outcome status = %d, want 403, body=%s", outcome.Code, outcome.Body.String())
		}
		payload = decodeCapabilityGrantEnvelope(t, outcome)
		errorPayload = requireObjectField(t, payload, "error")
		if errorPayload["code"] != "CAPABILITY_PROVIDER_INACTIVE" {
			t.Fatalf("disabled provider outcome code = %#v, want CAPABILITY_PROVIDER_INACTIVE", errorPayload["code"])
		}

		if err := store.Client().Plugin.UpdateOneID(fixture.ProviderRowID).SetStatus("enabled").Exec(ctx); err != nil {
			t.Fatalf("re-enable provider plugin: %v", err)
		}
	})

	t.Run("records outcome receipt in grant ledger", func(t *testing.T) {
		rec := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/capability-outcomes", fixture.SpaceID), fixture.APIKey, map[string]any{
			"grant_id":               issuedGrantID,
			"target_idempotency_key": issuedTargetIdempotencyKey,
			"target_provider_id":     fixture.NoRequiresPluginID,
			"status":                 "succeeded",
			"outcome_event_id":       "evt_wrong_target_" + fixture.Suffix,
		})
		if rec.Code != http.StatusForbidden {
			t.Fatalf("outcome wrong target status = %d, want 403, body=%s", rec.Code, rec.Body.String())
		}
		rec = capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/capability-outcomes", fixture.SpaceID), fixture.ProviderAPIKey, map[string]any{
			"grant_id":               issuedGrantID,
			"target_idempotency_key": issuedTargetIdempotencyKey,
			"target_provider_id":     fixture.ProviderPluginID,
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

		replay := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/capability-outcomes", fixture.SpaceID), fixture.ProviderAPIKey, map[string]any{
			"grant_id":               issuedGrantID,
			"target_idempotency_key": issuedTargetIdempotencyKey,
			"target_provider_id":     fixture.ProviderPluginID,
			"status":                 "succeeded",
			"outcome_event_id":       "evt_" + fixture.Suffix,
		})
		if replay.Code != http.StatusOK {
			t.Fatalf("outcome replay status = %d, want 200, body=%s", replay.Code, replay.Body.String())
		}
		replayData := decodeCapabilityGrantData(t, replay)
		if replayData["outcome_status"] != "succeeded" {
			t.Fatalf("replayed outcome_status = %#v, want succeeded", replayData["outcome_status"])
		}

		conflict := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/capability-outcomes", fixture.SpaceID), fixture.ProviderAPIKey, map[string]any{
			"grant_id":               issuedGrantID,
			"target_idempotency_key": issuedTargetIdempotencyKey,
			"target_provider_id":     fixture.ProviderPluginID,
			"status":                 "failed",
			"outcome_event_id":       "evt_conflict_" + fixture.Suffix,
		})
		if conflict.Code != http.StatusConflict {
			t.Fatalf("outcome conflict status = %d, want 409, body=%s", conflict.Code, conflict.Body.String())
		}

		reissueUsedBody := capabilityGrantIssueBody(fixture, "invoice.inv_123.approval.v1")
		reissueUsed := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/capability-grants", fixture.SpaceID), fixture.APIKey, reissueUsedBody)
		if reissueUsed.Code != http.StatusConflict {
			t.Fatalf("reissue used grant status = %d, want 409, body=%s", reissueUsed.Code, reissueUsed.Body.String())
		}
		payload := decodeCapabilityGrantEnvelope(t, reissueUsed)
		errorPayload := requireObjectField(t, payload, "error")
		if errorPayload["code"] != "CAPABILITY_GRANT_REISSUE_DENIED" {
			t.Fatalf("reissue used grant error code = %#v, want CAPABILITY_GRANT_REISSUE_DENIED", errorPayload["code"])
		}

		introspectUsed := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/grants/introspect", fixture.SpaceID), fixture.ProviderAPIKey, map[string]any{
			"grant":              issuedGrantToken,
			"target_provider_id": fixture.ProviderPluginID,
			"capability":         fixture.MediatedCapabilityID,
			"operation":          "create_request",
		})
		if introspectUsed.Code != http.StatusOK {
			t.Fatalf("introspect used grant status = %d, body=%s", introspectUsed.Code, introspectUsed.Body.String())
		}
		inactive := decodeCapabilityGrantData(t, introspectUsed)
		if active, _ := inactive["active"].(bool); active {
			t.Fatalf("used grant introspected active: %#v", inactive)
		}
		if inactive["reason"] != "grant_inactive" {
			t.Fatalf("used grant reason = %#v, want grant_inactive", inactive["reason"])
		}
	})

	t.Run("reconciles overdue pending outcomes as missing", func(t *testing.T) {
		body := capabilityGrantIssueBody(fixture, "invoice.outcome_missing.v1")
		rec := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/capability-grants", fixture.SpaceID), fixture.APIKey, body)
		if rec.Code != http.StatusCreated {
			t.Fatalf("issue missing outcome grant status = %d, body=%s", rec.Code, rec.Body.String())
		}
		data := decodeCapabilityGrantData(t, rec)
		grantID := requireStringField(t, data, "grant_id")
		past := time.Now().UTC().Add(-time.Minute)
		if err := store.Client().CapabilityGrant.UpdateOneID(grantID).
			SetExpectedOutcomeBy(past).
			SetExpiresAt(past.Add(time.Minute)).
			Exec(ctx); err != nil {
			t.Fatalf("age grant outcome window: %v", err)
		}
		result, err := server.ReconcileCapabilityGrantOutcomes(ctx, time.Now().UTC(), 10)
		if err != nil {
			t.Fatalf("reconcile outcomes: %v", err)
		}
		if result.Marked != 1 {
			t.Fatalf("marked = %d, want 1; result=%#v", result.Marked, result)
		}
		row, err := store.Client().CapabilityGrant.Query().Where(entcapabilitygrant.ID(grantID)).Only(ctx)
		if err != nil {
			t.Fatalf("load reconciled grant: %v", err)
		}
		if row.Status != "expired" || row.OutcomeStatus != "missing" {
			t.Fatalf("reconciled status=%q outcome_status=%q, want expired/missing", row.Status, row.OutcomeStatus)
		}
		outcome := requireObjectFromAny(t, row.Metadata["outcome"], "outcome metadata")
		if outcome["status"] != "missing" || outcome["reconciled_by"] != "core_capability_grant_reconciler" {
			t.Fatalf("missing outcome metadata mismatch: %#v", outcome)
		}
		exists, err := store.Client().AuditLog.Query().
			Where(entauditlog.Action("capability.outcome.missing"), entauditlog.ResourceID(grantID)).
			Exist(ctx)
		if err != nil {
			t.Fatalf("query missing outcome audit: %v", err)
		}
		if !exists {
			t.Fatalf("missing outcome audit was not written for grant %s", grantID)
		}
		replay, err := server.ReconcileCapabilityGrantOutcomes(ctx, time.Now().UTC(), 10)
		if err != nil {
			t.Fatalf("reconcile outcomes replay: %v", err)
		}
		if replay.Marked != 0 {
			t.Fatalf("replay marked = %d, want 0; result=%#v", replay.Marked, replay)
		}
	})

	t.Run("does not mark revoked pending grants as missing", func(t *testing.T) {
		body := capabilityGrantIssueBody(fixture, "invoice.outcome_revoked_before_missing.v1")
		rec := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/capability-grants", fixture.SpaceID), fixture.APIKey, body)
		if rec.Code != http.StatusCreated {
			t.Fatalf("issue revoked pending grant status = %d, body=%s", rec.Code, rec.Body.String())
		}
		grantID := requireStringField(t, decodeCapabilityGrantData(t, rec), "grant_id")
		past := time.Now().UTC().Add(-time.Minute)
		if err := store.Client().CapabilityGrant.UpdateOneID(grantID).
			SetStatus("revoked").
			SetRevokedAt(past).
			SetExpectedOutcomeBy(past).
			Exec(ctx); err != nil {
			t.Fatalf("revoke overdue grant: %v", err)
		}
		result, err := server.ReconcileCapabilityGrantOutcomes(ctx, time.Now().UTC(), 10)
		if err != nil {
			t.Fatalf("reconcile revoked pending grant: %v", err)
		}
		if result.Marked != 0 {
			t.Fatalf("revoked grant marked = %d, want 0; result=%#v", result.Marked, result)
		}
		row, err := store.Client().CapabilityGrant.Query().Where(entcapabilitygrant.ID(grantID)).Only(ctx)
		if err != nil {
			t.Fatalf("load revoked grant: %v", err)
		}
		if row.OutcomeStatus != "pending" {
			t.Fatalf("revoked grant outcome_status = %q, want pending", row.OutcomeStatus)
		}
	})

	t.Run("explicit revoke makes mediated grant fail closed", func(t *testing.T) {
		body := capabilityGrantIssueBody(fixture, "invoice.inv_explicit_revoke.approval.v1")
		rec := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/capability-grants", fixture.SpaceID), fixture.APIKey, body)
		if rec.Code != http.StatusCreated {
			t.Fatalf("issue explicit revoke grant status = %d, body=%s", rec.Code, rec.Body.String())
		}
		data := decodeCapabilityGrantData(t, rec)
		grantID := requireStringField(t, data, "grant_id")
		grantToken := requireStringField(t, data, "grant")
		revoke := capabilityGrantJSONRequest(handler, http.MethodPost, "/api/v1/capability-grants/"+grantID+"/revoke", fixture.APIKey, map[string]any{
			"reason": "test explicit revoke",
		})
		if revoke.Code != http.StatusOK {
			t.Fatalf("revoke status = %d, want 200, body=%s", revoke.Code, revoke.Body.String())
		}
		revoked := decodeCapabilityGrantData(t, revoke)
		if revoked["status"] != "revoked" || revoked["revoked_reason"] != "test explicit revoke" {
			t.Fatalf("revoked grant mismatch: %#v", revoked)
		}
		introspect := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/grants/introspect", fixture.SpaceID), fixture.ProviderAPIKey, map[string]any{
			"grant":              grantToken,
			"target_provider_id": fixture.ProviderPluginID,
			"capability":         fixture.MediatedCapabilityID,
			"operation":          "create_request",
		})
		if introspect.Code != http.StatusOK {
			t.Fatalf("introspect revoked grant status = %d, body=%s", introspect.Code, introspect.Body.String())
		}
		inactive := decodeCapabilityGrantData(t, introspect)
		if active, _ := inactive["active"].(bool); active {
			t.Fatalf("explicitly revoked grant introspected active: %#v", inactive)
		}
		if inactive["reason"] != "grant_revoked" {
			t.Fatalf("explicit revoke reason = %#v, want grant_revoked", inactive["reason"])
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
		if rec.Code != http.StatusForbidden {
			t.Fatalf("introspect with caller key status = %d, want 403, body=%s", rec.Code, rec.Body.String())
		}
		rec = capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/grants/introspect", fixture.SpaceID), fixture.ProviderAPIKey, map[string]any{
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

	t.Run("denies grant when principal lacks resource action permission", func(t *testing.T) {
		if err := store.Client().MemberRole.UpdateOneID(fixture.MemberRoleID).
			SetStatus("revoked").
			Exec(ctx); err != nil {
			t.Fatalf("revoke member role: %v", err)
		}
		body := capabilityGrantIssueBody(fixture, "invoice.authz_denied.v1")
		rec := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/capability-grants", fixture.SpaceID), fixture.APIKey, body)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("resource authorization denial status = %d, want 403, body=%s", rec.Code, rec.Body.String())
		}
		payload := decodeCapabilityGrantEnvelope(t, rec)
		errorPayload := requireObjectField(t, payload, "error")
		if errorPayload["code"] != "AUTHORIZATION_DENIED" {
			t.Fatalf("error code = %#v, want AUTHORIZATION_DENIED", errorPayload["code"])
		}
		assertNoGrantForIdempotencyKey(t, ctx, store.Client(), fixture.SpaceID, fixture.CallerPluginID, "invoice.authz_denied.v1")
		if err := store.Client().MemberRole.UpdateOneID(fixture.MemberRoleID).
			SetStatus("active").
			Exec(ctx); err != nil {
			t.Fatalf("restore member role: %v", err)
		}
	})

	t.Run("introspection fails closed after resource authorization revocation", func(t *testing.T) {
		body := capabilityGrantIssueBody(fixture, "invoice.authz_revoked_after_issue.v1")
		rec := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/capability-grants", fixture.SpaceID), fixture.APIKey, body)
		if rec.Code != http.StatusCreated {
			t.Fatalf("issue authz revocation grant status = %d, body=%s", rec.Code, rec.Body.String())
		}
		grantToken := requireStringField(t, decodeCapabilityGrantData(t, rec), "grant")
		if err := store.Client().MemberRole.UpdateOneID(fixture.MemberRoleID).
			SetStatus("revoked").
			Exec(ctx); err != nil {
			t.Fatalf("revoke member role after issue: %v", err)
		}
		introspect := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/grants/introspect", fixture.SpaceID), fixture.ProviderAPIKey, map[string]any{
			"grant":              grantToken,
			"target_provider_id": fixture.ProviderPluginID,
			"capability":         fixture.MediatedCapabilityID,
			"operation":          "create_request",
		})
		if introspect.Code != http.StatusOK {
			t.Fatalf("introspect authz revoked grant status = %d, body=%s", introspect.Code, introspect.Body.String())
		}
		inactive := decodeCapabilityGrantData(t, introspect)
		if active, _ := inactive["active"].(bool); active {
			t.Fatalf("authz revoked grant introspected active: %#v", inactive)
		}
		if inactive["reason"] != "principal_authorization_revoked" {
			t.Fatalf("authz revoked reason = %#v, want principal_authorization_revoked", inactive["reason"])
		}
		if err := store.Client().MemberRole.UpdateOneID(fixture.MemberRoleID).
			SetStatus("active").
			Exec(ctx); err != nil {
			t.Fatalf("restore member role after authz revocation: %v", err)
		}
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

	t.Run("provider runtime cannot omit parent grant for child capability calls", func(t *testing.T) {
		body := capabilityGrantIssueBody(fixture, "invoice.provider_runtime_missing_parent.v1")
		body["executor"] = map[string]any{"plugin_id": fixture.ProviderPluginID}
		rec := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/capability-grants", fixture.SpaceID), fixture.ProviderAPIKey, body)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("provider-runtime missing parent status = %d, want 403, body=%s", rec.Code, rec.Body.String())
		}
		payload := decodeCapabilityGrantEnvelope(t, rec)
		errorPayload := requireObjectField(t, payload, "error")
		if errorPayload["code"] != "CAPABILITY_CALL_GRAPH_DENIED" {
			t.Fatalf("error code = %#v, want CAPABILITY_CALL_GRAPH_DENIED", errorPayload["code"])
		}
		assertNoGrantForIdempotencyKey(t, ctx, store.Client(), fixture.SpaceID, fixture.ProviderPluginID, "invoice.provider_runtime_missing_parent.v1")
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

	t.Run("denies same app caller outside trust bundle for local capability", func(t *testing.T) {
		body := capabilityGrantIssueBody(fixture, "local.other_bundle.v1")
		body["capability"] = fixture.LocalCapabilityID
		body["operation"] = "execute"
		body["executor"] = map[string]any{"plugin_id": fixture.OtherBundleCallerPluginID}
		rec := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/capability-grants", fixture.SpaceID), fixture.APIKey, body)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("same-app other-bundle local capability status = %d, want 403, body=%s", rec.Code, rec.Body.String())
		}
		payload := decodeCapabilityGrantEnvelope(t, rec)
		errorPayload := requireObjectField(t, payload, "error")
		if errorPayload["code"] != "CAPABILITY_SCOPE_DENIED" {
			t.Fatalf("error code = %#v, want CAPABILITY_SCOPE_DENIED", errorPayload["code"])
		}
		assertNoGrantForIdempotencyKey(t, ctx, store.Client(), fixture.SpaceID, fixture.OtherBundleCallerPluginID, "local.other_bundle.v1")
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

	t.Run("begins and completes brokered action execution", func(t *testing.T) {
		body := actionExecutionBeginBody(fixture, "payment.pay_123.charge.v1")
		rec := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/action-executions", fixture.SpaceID), fixture.APIKey, body)
		if rec.Code != http.StatusCreated {
			t.Fatalf("begin action status = %d, want 201, body=%s", rec.Code, rec.Body.String())
		}
		data := decodeCapabilityGrantData(t, rec)
		actionExecutionID := requireStringField(t, data, "action_execution_id")
		if data["status"] != "running" {
			t.Fatalf("action status = %#v, want running", data["status"])
		}
		timeoutAt := requireStringField(t, data, "timeout_at")
		if _, err := time.Parse(time.RFC3339, timeoutAt); err != nil {
			t.Fatalf("timeout_at is not RFC3339: %q", timeoutAt)
		}
		if data["provider_plugin_id"] != fixture.ProviderPluginID {
			t.Fatalf("provider_plugin_id = %#v, want %q", data["provider_plugin_id"], fixture.ProviderPluginID)
		}
		if data["decision_id"] == "" {
			t.Fatalf("decision_id missing: %#v", data)
		}

		contextBody := providerRequestContextBody(fixture)
		contextBody["action_execution_id"] = actionExecutionID
		contextBody["authorization_decision_id"] = requireStringField(t, data, "decision_id")
		context := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/provider-request-contexts", fixture.SpaceID), fixture.ProviderAPIKey, contextBody)
		if context.Code != http.StatusCreated {
			t.Fatalf("provider context from action status = %d, want 201, body=%s", context.Code, context.Body.String())
		}
		contextData := decodeCapabilityGrantData(t, context)
		if contextData["action_execution_id"] != actionExecutionID {
			t.Fatalf("action_execution_id = %#v, want %q", contextData["action_execution_id"], actionExecutionID)
		}
		if contextData["capability"] != fixture.BrokeredCapabilityID || contextData["operation"] != "charge" {
			t.Fatalf("action context capability operation mismatch: %#v", contextData)
		}

		replay := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/action-executions", fixture.SpaceID), fixture.APIKey, body)
		if replay.Code != http.StatusOK {
			t.Fatalf("begin replay status = %d, want 200, body=%s", replay.Code, replay.Body.String())
		}
		replayData := decodeCapabilityGrantData(t, replay)
		if got := requireStringField(t, replayData, "action_execution_id"); got != actionExecutionID {
			t.Fatalf("replayed action_execution_id=%q, want %q", got, actionExecutionID)
		}

		conflictBody := actionExecutionBeginBody(fixture, "payment.pay_123.charge.v1")
		conflictSummary := requireObjectField(t, conflictBody, "input_summary")
		conflictSummary["amount_minor"] = 24000
		conflict := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/action-executions", fixture.SpaceID), fixture.APIKey, conflictBody)
		if conflict.Code != http.StatusConflict {
			t.Fatalf("begin conflict status = %d, want 409, body=%s", conflict.Code, conflict.Body.String())
		}

		completeWrongProvider := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/action-executions/"+actionExecutionID+"/complete", fixture.SpaceID), fixture.APIKey, map[string]any{
			"provider_plugin_id": fixture.NoRequiresPluginID,
			"status":             "succeeded",
			"result_ref":         map[string]any{"resource_type": "payment", "resource_id": "pay_123"},
		})
		if completeWrongProvider.Code != http.StatusForbidden {
			t.Fatalf("complete wrong provider status = %d, want 403, body=%s", completeWrongProvider.Code, completeWrongProvider.Body.String())
		}

		complete := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/action-executions/"+actionExecutionID+"/complete", fixture.SpaceID), fixture.ProviderAPIKey, map[string]any{
			"provider_plugin_id": fixture.ProviderPluginID,
			"status":             "succeeded",
			"result_ref":         map[string]any{"resource_type": "payment", "resource_id": "pay_123"},
			"metadata":           map[string]any{"completion_source": "test"},
		})
		if complete.Code != http.StatusOK {
			t.Fatalf("complete status = %d, want 200, body=%s", complete.Code, complete.Body.String())
		}
		completed := decodeCapabilityGrantData(t, complete)
		if completed["status"] != "succeeded" {
			t.Fatalf("completed status = %#v, want succeeded", completed["status"])
		}
		if completed["completed_at"] == nil {
			t.Fatalf("completed_at missing: %#v", completed)
		}

		contextAfterCompletion := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/provider-request-contexts", fixture.SpaceID), fixture.ProviderAPIKey, contextBody)
		if contextAfterCompletion.Code != http.StatusForbidden {
			t.Fatalf("provider context after action completion status = %d, want 403, body=%s", contextAfterCompletion.Code, contextAfterCompletion.Body.String())
		}

		completeReplay := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/action-executions/"+actionExecutionID+"/complete", fixture.SpaceID), fixture.ProviderAPIKey, map[string]any{
			"provider_plugin_id": fixture.ProviderPluginID,
			"status":             "succeeded",
			"result_ref":         map[string]any{"resource_type": "payment", "resource_id": "pay_123"},
		})
		if completeReplay.Code != http.StatusOK {
			t.Fatalf("complete replay status = %d, want 200, body=%s", completeReplay.Code, completeReplay.Body.String())
		}

		completeConflict := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/action-executions/"+actionExecutionID+"/complete", fixture.SpaceID), fixture.ProviderAPIKey, map[string]any{
			"provider_plugin_id": fixture.ProviderPluginID,
			"status":             "failed",
			"error_code":         "PROVIDER_FAILED",
		})
		if completeConflict.Code != http.StatusConflict {
			t.Fatalf("complete conflict status = %d, want 409, body=%s", completeConflict.Code, completeConflict.Body.String())
		}

		list := capabilityGrantJSONRequest(handler, http.MethodGet, "/api/v1/action-executions?space_id="+fixture.SpaceID+"&status=succeeded", fixture.APIKey, nil)
		if list.Code != http.StatusOK {
			t.Fatalf("list actions status = %d, body=%s", list.Code, list.Body.String())
		}
		payload := decodeCapabilityGrantEnvelope(t, list)
		rows, ok := payload["data"].([]any)
		if !ok || len(rows) == 0 {
			t.Fatalf("list actions returned no rows: %#v", payload["data"])
		}
	})

	t.Run("reconciles timed out action execution as result unknown", func(t *testing.T) {
		body := actionExecutionBeginBody(fixture, "payment.pay_timeout.charge.v1")
		rec := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/action-executions", fixture.SpaceID), fixture.APIKey, body)
		if rec.Code != http.StatusCreated {
			t.Fatalf("begin timed action status = %d, want 201, body=%s", rec.Code, rec.Body.String())
		}
		actionExecutionID := requireStringField(t, decodeCapabilityGrantData(t, rec), "action_execution_id")
		past := time.Now().UTC().Add(-time.Minute)
		if err := store.Client().ActionExecution.UpdateOneID(actionExecutionID).
			SetTimeoutAt(past).
			Exec(ctx); err != nil {
			t.Fatalf("age action execution timeout: %v", err)
		}
		result, err := server.ReconcileActionExecutions(ctx, time.Now().UTC(), 10)
		if err != nil {
			t.Fatalf("reconcile actions: %v", err)
		}
		if result.Marked != 1 {
			t.Fatalf("marked = %d, want 1; result=%#v", result.Marked, result)
		}
		row, err := store.Client().ActionExecution.Query().Where(entactionexecution.ID(actionExecutionID)).Only(ctx)
		if err != nil {
			t.Fatalf("load reconciled action: %v", err)
		}
		if row.Status != "result_unknown" || row.CompletedAt == nil || derefString(row.ErrorCode) != "ACTION_EXECUTION_TIMEOUT" {
			t.Fatalf("reconciled action mismatch: status=%q completed_at=%v error_code=%q", row.Status, row.CompletedAt, derefString(row.ErrorCode))
		}
		reconciliation := requireObjectFromAny(t, row.Metadata["result_unknown_reconciliation"], "result_unknown_reconciliation metadata")
		if reconciliation["reconciled_by"] != "core_action_execution_reconciler" || reconciliation["status"] != "result_unknown" {
			t.Fatalf("result_unknown reconciliation metadata mismatch: %#v", reconciliation)
		}
		exists, err := store.Client().AuditLog.Query().
			Where(entauditlog.Action("action_execution.result_unknown"), entauditlog.ResourceID(actionExecutionID)).
			Exist(ctx)
		if err != nil {
			t.Fatalf("query result_unknown audit: %v", err)
		}
		if !exists {
			t.Fatalf("result_unknown audit was not written for action execution %s", actionExecutionID)
		}
		replay, err := server.ReconcileActionExecutions(ctx, time.Now().UTC(), 10)
		if err != nil {
			t.Fatalf("reconcile actions replay: %v", err)
		}
		if replay.Marked != 0 {
			t.Fatalf("replay marked = %d, want 0; result=%#v", replay.Marked, replay)
		}
	})

	t.Run("manages provider binding and revokes resolver path by binding status", func(t *testing.T) {
		bindingID := "cpb_" + safeIdentifier(fixture.SpaceID+"_"+fixture.MediatedCapabilityID+"_create_request")
		list := capabilityGrantJSONRequest(handler, http.MethodGet, "/api/v1/capability-provider-bindings?space_id="+fixture.SpaceID, fixture.APIKey, nil)
		if list.Code != http.StatusOK {
			t.Fatalf("list bindings status = %d, body=%s", list.Code, list.Body.String())
		}
		listPayload := decodeCapabilityGrantEnvelope(t, list)
		rows, ok := listPayload["data"].([]any)
		if !ok || len(rows) == 0 {
			t.Fatalf("list bindings returned no rows: %#v", listPayload["data"])
		}

		upsert := capabilityGrantJSONRequest(handler, http.MethodPost, "/api/v1/capability-provider-bindings", fixture.APIKey, map[string]any{
			"space_id":           fixture.SpaceID,
			"capability":         fixture.MediatedCapabilityID,
			"operation":          "create_request",
			"provider_plugin_id": fixture.ProviderPluginID,
			"endpoint":           "https://workflow-new-" + fixture.Suffix + ".space.internal",
			"operation_path":     "/v1/capabilities/" + strings.ReplaceAll(fixture.MediatedCapabilityID, ".", "/") + "/create_request",
			"identity":           map[string]any{"provider_id": fixture.ProviderPluginID, "endpoint_id": "ep_new_" + fixture.Suffix},
			"metadata":           map[string]any{"reason": "test_rebind"},
			"status":             "active",
		})
		if upsert.Code != http.StatusOK {
			t.Fatalf("upsert existing binding status = %d, body=%s", upsert.Code, upsert.Body.String())
		}
		upsertData := decodeCapabilityGrantData(t, upsert)
		if got := intField(t, upsertData, "binding_epoch"); got != fixture.SpaceBindingEpoch+1 {
			t.Fatalf("rebinding epoch = %d, want %d", got, fixture.SpaceBindingEpoch+1)
		}

		staleBody := capabilityGrantIssueBody(fixture, "invoice.stale_provider.v1")
		staleGrant := capabilityGrantJSONRequest(handler, http.MethodPost, "/api/v1/capability-grants", fixture.APIKey, staleBody)
		if staleGrant.Code != http.StatusCreated {
			t.Fatalf("stale grant issue status = %d, body=%s", staleGrant.Code, staleGrant.Body.String())
		}
		staleData := decodeCapabilityGrantData(t, staleGrant)
		staleToken := requireStringField(t, staleData, "grant")
		staleEpoch := intField(t, staleData, "binding_epoch")

		body := capabilityGrantIssueBody(fixture, "invoice.rebound_provider.v1")
		grant := capabilityGrantJSONRequest(handler, http.MethodPost, "/api/v1/capability-grants", fixture.APIKey, body)
		if grant.Code != http.StatusCreated {
			t.Fatalf("grant after rebind status = %d, body=%s", grant.Code, grant.Body.String())
		}
		grantData := decodeCapabilityGrantData(t, grant)
		target := requireObjectField(t, grantData, "target")
		if target["endpoint"] != "https://workflow-new-"+fixture.Suffix+".space.internal" {
			t.Fatalf("grant target endpoint after rebind = %#v", target["endpoint"])
		}
		if got := intField(t, grantData, "binding_epoch"); got != fixture.SpaceBindingEpoch+1 {
			t.Fatalf("grant binding_epoch after rebind = %d, want %d", got, fixture.SpaceBindingEpoch+1)
		}

		secondRebind := capabilityGrantJSONRequest(handler, http.MethodPost, "/api/v1/capability-provider-bindings", fixture.APIKey, map[string]any{
			"space_id":           fixture.SpaceID,
			"capability":         fixture.MediatedCapabilityID,
			"operation":          "create_request",
			"provider_plugin_id": fixture.ProviderPluginID,
			"endpoint":           "https://workflow-next-" + fixture.Suffix + ".space.internal",
			"operation_path":     "/v1/capabilities/" + strings.ReplaceAll(fixture.MediatedCapabilityID, ".", "/") + "/create_request",
			"identity":           map[string]any{"provider_id": fixture.ProviderPluginID, "endpoint_id": "ep_next_" + fixture.Suffix},
			"status":             "active",
		})
		if secondRebind.Code != http.StatusOK {
			t.Fatalf("second rebind status = %d, body=%s", secondRebind.Code, secondRebind.Body.String())
		}
		staleIntrospect := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/grants/introspect", fixture.SpaceID), fixture.ProviderAPIKey, map[string]any{
			"grant":              staleToken,
			"target_provider_id": fixture.ProviderPluginID,
			"capability":         fixture.MediatedCapabilityID,
			"operation":          "create_request",
		})
		if staleIntrospect.Code != http.StatusOK {
			t.Fatalf("stale binding introspect status = %d, body=%s", staleIntrospect.Code, staleIntrospect.Body.String())
		}
		staleInactive := decodeCapabilityGrantData(t, staleIntrospect)
		if active, _ := staleInactive["active"].(bool); active {
			t.Fatalf("stale binding grant introspected active: %#v", staleInactive)
		}
		if staleInactive["reason"] != "provider_binding_stale" {
			t.Fatalf("stale binding reason = %#v, want provider_binding_stale; grant_epoch=%d", staleInactive["reason"], staleEpoch)
		}

		bad := capabilityGrantJSONRequest(handler, http.MethodPost, "/api/v1/capability-provider-bindings", fixture.APIKey, map[string]any{
			"space_id":           fixture.SpaceID,
			"capability":         fixture.MediatedCapabilityID,
			"operation":          "create_request",
			"provider_plugin_id": fixture.ProviderPluginID,
			"endpoint":           "https://user:pass@workflow.example.test",
			"identity":           map[string]any{"provider_id": fixture.ProviderPluginID},
		})
		if bad.Code != http.StatusBadRequest {
			t.Fatalf("credential endpoint binding status = %d, want 400, body=%s", bad.Code, bad.Body.String())
		}

		disabled := capabilityGrantJSONRequest(handler, http.MethodDelete, "/api/v1/capability-provider-bindings/"+bindingID, fixture.APIKey, nil)
		if disabled.Code != http.StatusOK {
			t.Fatalf("disable binding status = %d, body=%s", disabled.Code, disabled.Body.String())
		}
		disabledData := decodeCapabilityGrantData(t, disabled)
		if disabledData["status"] != "disabled" {
			t.Fatalf("disabled binding status = %#v, want disabled", disabledData["status"])
		}
		body = capabilityGrantIssueBody(fixture, "invoice.disabled_provider.v1")
		deniedGrant := capabilityGrantJSONRequest(handler, http.MethodPost, "/api/v1/capability-grants", fixture.APIKey, body)
		if deniedGrant.Code != http.StatusNotFound {
			t.Fatalf("grant with disabled binding status = %d, want 404, body=%s", deniedGrant.Code, deniedGrant.Body.String())
		}
	})
}

func TestAPIKeyProviderRuntimeIDIgnoresMetadataAliases(t *testing.T) {
	pluginID := "test.workflow_provider"
	if got := apiKeyProviderRuntimeID(&coreent.ApiKey{Metadata: map[string]any{"provider_plugin_id": pluginID}}); got != "" {
		t.Fatalf("metadata provider alias must not bind runtime identity, got %q", got)
	}
	if got := apiKeyProviderRuntimeID(&coreent.ApiKey{ProviderRuntimePluginID: &pluginID, Metadata: map[string]any{"provider_plugin_id": "other.provider"}}); got != pluginID {
		t.Fatalf("provider_runtime_plugin_id should be the only trusted runtime identity, got %q", got)
	}
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
		Suffix:                    suffix,
		SpaceID:                   "space_capability_grants_" + suffix,
		APIKeyID:                  "ak_capability_grants_" + suffix,
		ProviderAPIKeyID:          "ak_capability_grants_provider_" + suffix,
		ProviderRowID:             "plugin_capability_grants_provider_" + suffix,
		ProviderPluginID:          "test.workflow_" + suffix,
		ProviderEndpoint:          "http://workflow-provider-" + suffix + ".internal",
		SpaceProviderEndpoint:     "http://workflow-provider-" + suffix + ".space.internal",
		SpaceBindingEpoch:         7,
		CallerRowID:               "plugin_capability_grants_caller_" + suffix,
		CallerPluginID:            "test.invoice_" + suffix,
		CallerCapabilityID:        "resource.invoice_" + suffix,
		DisallowedRowID:           "plugin_capability_grants_disallowed_" + suffix,
		DisallowedPluginID:        "test.disallowed_" + suffix,
		NoRequiresRowID:           "plugin_capability_grants_no_requires_" + suffix,
		NoRequiresPluginID:        "test.no_requires_" + suffix,
		LocalProviderRowID:        "plugin_capability_grants_local_provider_" + suffix,
		LocalProviderPluginID:     "app.delivery.local_provider_" + suffix,
		LocalCallerRowID:          "plugin_capability_grants_local_caller_" + suffix,
		LocalCallerPluginID:       "app.delivery.local_caller_" + suffix,
		OtherBundleCallerRowID:    "plugin_capability_grants_other_bundle_" + suffix,
		OtherBundleCallerPluginID: "app.delivery.other_bundle_" + suffix,
		ForeignCallerRowID:        "plugin_capability_grants_foreign_caller_" + suffix,
		ForeignCallerPluginID:     "app.other.local_caller_" + suffix,
		MediatedCapabilityID:      "workflow.approval_" + suffix,
		BrokeredCapabilityID:      "payment.charge_" + suffix,
		LocalCapabilityID:         "delivery.operations_" + suffix,
		PrincipalUserID:           "user_capability_grants_" + suffix,
		PrincipalMemberID:         "member_capability_grants_" + suffix,
		PrincipalUserMemberID:     "um_capability_grants_" + suffix,
		GroupID:                   "group_capability_grants_" + suffix,
		ResourceTypeID:            "rt_capability_grants_invoice_" + suffix,
		ResourceActionID:          "ra_capability_grants_invoice_approve_" + suffix,
		ResourceMappingID:         "rm_capability_grants_invoice_" + suffix,
		PermissionID:              "perm_capability_grants_invoice_approve_" + suffix,
		RoleID:                    "role_capability_grants_approver_" + suffix,
		RolePermissionID:          "rp_capability_grants_approve_" + suffix,
		MemberRoleID:              "mr_capability_grants_approver_" + suffix,
		InvoiceResourceID:         "invoice_capability_grants_" + suffix,
	}

	apiKey, err := newAPIKeyPlaintext(fixture.APIKeyID)
	if err != nil {
		t.Fatalf("generate api key: %v", err)
	}
	fixture.APIKey = apiKey
	providerAPIKey, err := newAPIKeyPlaintext(fixture.ProviderAPIKeyID)
	if err != nil {
		t.Fatalf("generate provider api key: %v", err)
	}
	fixture.ProviderAPIKey = providerAPIKey

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
	if _, err := client.Group.Create().
		SetID(fixture.GroupID).
		SetSpaceID(fixture.SpaceID).
		SetName("capability-grants").
		SetDisplayName("Capability Grants").
		SetPath("capability_grants").
		SetDepth(0).
		Save(ctx); err != nil {
		t.Fatalf("create authorization group: %v", err)
	}
	if _, err := client.ResourceType.Create().
		SetID(fixture.ResourceTypeID).
		SetKey("invoice").
		SetDisplayName("Invoice").
		SetSource("test").
		SetStatus("active").
		Save(ctx); err != nil {
		t.Fatalf("create invoice resource type: %v", err)
	}
	if _, err := client.ResourceAction.Create().
		SetID(fixture.ResourceActionID).
		SetResourceTypeID(fixture.ResourceTypeID).
		SetKey("approve").
		SetDisplayName("Approve").
		SetRiskLevel("normal").
		SetAuditDefault(true).
		Save(ctx); err != nil {
		t.Fatalf("create invoice approve action: %v", err)
	}
	if _, err := client.ResourceMapping.Create().
		SetID(fixture.ResourceMappingID).
		SetResourceTypeID(fixture.ResourceTypeID).
		SetStorageKind("internal_table").
		SetTableName("resources").
		SetIDField("id").
		SetSpaceField("space_id").
		SetGroupField("group_id").
		SetOwnerMemberField("owner_member_id").
		SetMetadataField("metadata").
		SetStatus("active").
		Save(ctx); err != nil {
		t.Fatalf("create invoice resource mapping: %v", err)
	}
	if _, err := client.Permission.Create().
		SetID(fixture.PermissionID).
		SetResource("invoice").
		SetAction("approve").
		SetScope("space").
		SetStatus("active").
		Save(ctx); err != nil {
		t.Fatalf("create invoice approve permission: %v", err)
	}
	if _, err := client.Role.Create().
		SetID(fixture.RoleID).
		SetSpaceID(fixture.SpaceID).
		SetKey("capability_approver").
		SetName("Capability Approver").
		SetStatus("active").
		Save(ctx); err != nil {
		t.Fatalf("create capability approver role: %v", err)
	}
	if _, err := client.RolePermission.Create().
		SetID(fixture.RolePermissionID).
		SetRoleID(fixture.RoleID).
		SetPermissionID(fixture.PermissionID).
		Save(ctx); err != nil {
		t.Fatalf("create role permission: %v", err)
	}
	if _, err := client.MemberRole.Create().
		SetID(fixture.MemberRoleID).
		SetMemberID(fixture.PrincipalMemberID).
		SetRoleID(fixture.RoleID).
		SetSpaceID(fixture.SpaceID).
		SetStatus("active").
		Save(ctx); err != nil {
		t.Fatalf("create member role: %v", err)
	}
	if _, err := client.Resource.Create().
		SetID(fixture.InvoiceResourceID).
		SetResourceType("invoice").
		SetSpaceID(fixture.SpaceID).
		SetGroupID(fixture.GroupID).
		SetOwnerMemberID(fixture.PrincipalMemberID).
		SetDisplayName("Capability Grant Invoice").
		SetVisibility("private").
		SetStatus("active").
		Save(ctx); err != nil {
		t.Fatalf("create invoice resource: %v", err)
	}
	if _, err := client.ApiKey.Create().
		SetID(fixture.APIKeyID).
		SetName("Capability grant test key").
		SetKeyPrefix(apiKeyPrefix(fixture.APIKeyID)).
		SetKeyHash(apiKeyHash(apiKey)).
		SetLevel("instance").
		SetPermissionKeys([]string{"capabilities:invoke", "capabilities:manage", "plugins:read", "plugins:manage"}).
		Save(ctx); err != nil {
		t.Fatalf("create api key: %v", err)
	}
	if _, err := client.ApiKey.Create().
		SetID(fixture.ProviderAPIKeyID).
		SetName("Capability grant provider runtime key").
		SetKeyPrefix(apiKeyPrefix(fixture.ProviderAPIKeyID)).
		SetKeyHash(apiKeyHash(providerAPIKey)).
		SetLevel("instance").
		SetPermissionKeys([]string{"capabilities:manage"}).
		SetProviderRuntimePluginID(fixture.ProviderPluginID).
		Save(ctx); err != nil {
		t.Fatalf("create provider api key: %v", err)
	}

	providerManifest := capabilityGrantProviderManifest(fixture)
	createPluginRow(t, ctx, client, fixture.ProviderRowID, fixture.ProviderPluginID, providerManifest)

	createPluginRow(t, ctx, client, fixture.CallerRowID, fixture.CallerPluginID, capabilityGrantCallerManifest(fixture, true))
	createPluginRow(t, ctx, client, fixture.DisallowedRowID, fixture.DisallowedPluginID, capabilityGrantDisallowedCallerManifest(fixture))
	createPluginRow(t, ctx, client, fixture.NoRequiresRowID, fixture.NoRequiresPluginID, capabilityGrantCallerManifest(fixture, false))
	createPluginRow(t, ctx, client, fixture.LocalProviderRowID, fixture.LocalProviderPluginID, capabilityGrantLocalProviderManifest(fixture))
	createPluginRow(t, ctx, client, fixture.LocalCallerRowID, fixture.LocalCallerPluginID, capabilityGrantLocalCallerManifest(fixture, fixture.LocalCallerPluginID, "delivery", "delivery.default"))
	createPluginRow(t, ctx, client, fixture.OtherBundleCallerRowID, fixture.OtherBundleCallerPluginID, capabilityGrantLocalCallerManifest(fixture, fixture.OtherBundleCallerPluginID, "delivery", "delivery.separate"))
	createPluginRow(t, ctx, client, fixture.ForeignCallerRowID, fixture.ForeignCallerPluginID, capabilityGrantLocalCallerManifest(fixture, fixture.ForeignCallerPluginID, "other", "other.default"))
	createCapabilityProviderBinding(t, ctx, client, fixture, fixture.MediatedCapabilityID, "create_request", fixture.ProviderPluginID, fixture.SpaceProviderEndpoint, "/v1/capabilities/"+strings.ReplaceAll(fixture.MediatedCapabilityID, ".", "/")+"/create_request", fixture.SpaceBindingEpoch)
	createCapabilityProviderBinding(t, ctx, client, fixture, fixture.BrokeredCapabilityID, "charge", fixture.ProviderPluginID, fixture.SpaceProviderEndpoint, "/v1/capabilities/"+strings.ReplaceAll(fixture.BrokeredCapabilityID, ".", "/")+"/charge", fixture.SpaceBindingEpoch)
	createCapabilityProviderBinding(t, ctx, client, fixture, fixture.LocalCapabilityID, "execute", fixture.LocalProviderPluginID, "http://local-provider-"+suffix+".space.internal", "/v1/local/delivery/execute", 3)

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
		SetType(firstNonEmpty(manifest.Type, "plugin")).
		SetScope(firstNonEmpty(manifest.Scope, "public")).
		SetNillableAppID(optionalString(manifest.AppID)).
		SetNillableTrustBundleID(optionalString(manifest.TrustBundleID)).
		SetSource("test").
		SetStatus("enabled").
		SetManifest(manifestMap).
		Save(ctx); err != nil {
		t.Fatalf("create plugin %s: %v", pluginID, err)
	}
}

func createCapabilityProviderBinding(t *testing.T, ctx context.Context, client *coreent.Client, fixture capabilityGrantFixture, capabilityID, operation, providerID, endpoint, operationPath string, epoch int) {
	t.Helper()
	bindingID := "cpb_" + safeIdentifier(fixture.SpaceID+"_"+capabilityID+"_"+operation)
	create := client.CapabilityProviderBinding.Create().
		SetID(bindingID).
		SetSpaceID(fixture.SpaceID).
		SetCapability(capabilityID).
		SetOperation(operation).
		SetProviderPluginID(providerID).
		SetEndpoint(endpoint).
		SetBindingEpoch(epoch).
		SetStatus("active").
		SetIdentity(map[string]any{"provider_id": providerID, "binding_id": bindingID}).
		SetMetadata(map[string]any{"test": "capability_grants"})
	if operationPath != "" {
		create.SetOperationPath(operationPath)
	}
	if _, err := create.Save(ctx); err != nil {
		t.Fatalf("create capability provider binding %s %s: %v", capabilityID, operation, err)
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
		Runtime: plugins.ProviderRuntimeDefinition{
			Type:     "external",
			Protocol: "http_json",
			Version:  "1.0.0",
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
		TrustBundleID:    "delivery.default",
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

func capabilityGrantLocalCallerManifest(fixture capabilityGrantFixture, pluginID, appID, trustBundleID string) plugins.Manifest {
	return plugins.Manifest{
		ID:               pluginID,
		Type:             "app_module",
		Scope:            "app",
		AppID:            appID,
		TrustBundleID:    trustBundleID,
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
	_, err = client.ActionExecution.Delete().Where(entactionexecution.SpaceID(fixture.SpaceID)).Exec(ctx)
	ignore("action executions", err)
	_, err = client.ProviderRequestContext.Delete().Where(entproviderrequestcontext.SpaceID(fixture.SpaceID)).Exec(ctx)
	ignore("provider request contexts", err)
	_, err = client.CapabilityProviderBinding.Delete().Where(entcapabilityproviderbinding.SpaceID(fixture.SpaceID)).Exec(ctx)
	ignore("capability provider bindings", err)
	_, err = client.AuditLog.Delete().Where(entauditlog.SpaceID(fixture.SpaceID)).Exec(ctx)
	ignore("audit logs", err)
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
	_, err = client.Resource.Delete().Where(entresource.SpaceID(fixture.SpaceID)).Exec(ctx)
	ignore("resources", err)
	_, err = client.MemberRole.Delete().Where(entmemberrole.SpaceID(fixture.SpaceID)).Exec(ctx)
	ignore("member roles", err)
	_, err = client.RolePermission.Delete().Where(entrolepermission.RoleID(fixture.RoleID)).Exec(ctx)
	ignore("role permissions", err)
	_, err = client.Role.Delete().Where(entrole.SpaceID(fixture.SpaceID)).Exec(ctx)
	ignore("roles", err)
	_, err = client.Permission.Delete().Where(entpermission.ID(fixture.PermissionID)).Exec(ctx)
	ignore("permissions", err)
	_, err = client.ResourceMapping.Delete().Where(entresourcemapping.ResourceTypeID(fixture.ResourceTypeID)).Exec(ctx)
	ignore("resource mappings", err)
	_, err = client.ResourceAction.Delete().Where(entresourceaction.ResourceTypeID(fixture.ResourceTypeID)).Exec(ctx)
	ignore("resource actions", err)
	_, err = client.ResourceType.Delete().Where(entresourcetype.ID(fixture.ResourceTypeID)).Exec(ctx)
	ignore("resource types", err)
	_, err = client.Group.Delete().Where(entgroup.SpaceID(fixture.SpaceID)).Exec(ctx)
	ignore("groups", err)
	ignore("api key", client.ApiKey.UpdateOneID(fixture.APIKeyID).
		SetStatus("revoked").
		SetRevokedAt(now).
		SetRevokedReason("test cleanup").
		SetDeletedAt(now).
		Exec(ctx))
	ignore("provider api key", client.ApiKey.UpdateOneID(fixture.ProviderAPIKeyID).
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
			"resource_type": "invoice",
			"resource_id":   fixture.InvoiceResourceID,
			"action":        "approve",
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

func actionExecutionBeginBody(fixture capabilityGrantFixture, idempotencyKey string) map[string]any {
	return map[string]any{
		"space_id":   fixture.SpaceID,
		"capability": fixture.BrokeredCapabilityID,
		"operation":  "charge",
		"principal": map[string]any{
			"user_id":        fixture.PrincipalUserID,
			"member_id":      fixture.PrincipalMemberID,
			"user_member_id": fixture.PrincipalUserMemberID,
		},
		"executor": map[string]any{"plugin_id": fixture.CallerPluginID},
		"provider": map[string]any{"plugin_id": fixture.ProviderPluginID},
		"resource": map[string]any{
			"resource_type": "invoice",
			"resource_id":   fixture.InvoiceResourceID,
			"action":        "approve",
		},
		"input_summary": map[string]any{
			"amount_minor": 12000,
			"currency":     "USD",
		},
		"idempotency_key": idempotencyKey,
		"correlation_id":  "cor_action_execution_" + fixture.Suffix,
		"metadata":        map[string]any{"test": "action_execution"},
	}
}

func providerRequestContextBody(fixture capabilityGrantFixture) map[string]any {
	return map[string]any{
		"provider_plugin_id": fixture.ProviderPluginID,
		"space_id":           fixture.SpaceID,
		"actor": map[string]any{
			"user_id":        fixture.PrincipalUserID,
			"member_id":      fixture.PrincipalMemberID,
			"user_member_id": fixture.PrincipalUserMemberID,
		},
		"purpose": "capability_execution_test",
		"ttl_ms":  60000,
		"metadata": map[string]any{
			"test": "provider_request_context",
		},
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

func requireObjectFromAny(t *testing.T, value any, label string) map[string]any {
	t.Helper()
	object, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("%s is not an object: %#v", label, value)
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

func intField(t *testing.T, values map[string]any, key string) int {
	t.Helper()
	switch value := values[key].(type) {
	case float64:
		return int(value)
	case int:
		return value
	default:
		t.Fatalf("%s is not a number: %#v", key, values[key])
		return 0
	}
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
