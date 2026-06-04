package api

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	coreent "github.com/plystra/core/ent"
	"github.com/plystra/core/internal/store/entstore"
)

func TestCapabilityGrantRevokeSelector(t *testing.T) {
	cases := []struct {
		name    string
		req     capabilityGrantRevokeRequest
		want    string
		wantErr bool
	}{
		{"grant_id", capabilityGrantRevokeRequest{GrantID: "grt_1"}, "grant_id", false},
		{"member_id", capabilityGrantRevokeRequest{MemberID: "mem_1"}, "member_id", false},
		{"parent_grant_id", capabilityGrantRevokeRequest{ParentGrantID: "grt_1"}, "parent_grant_id", false},
		{"binding_epoch_with_provider", capabilityGrantRevokeRequest{BindingEpoch: 7, TargetProviderID: "plugin.workflow"}, "binding_epoch", false},
		{"binding_epoch_without_provider", capabilityGrantRevokeRequest{BindingEpoch: 7}, "", true},
		{"negative_epoch", capabilityGrantRevokeRequest{BindingEpoch: -1, TargetProviderID: "plugin.workflow"}, "", true},
		{"no_selector", capabilityGrantRevokeRequest{}, "", true},
		{"multiple_selectors", capabilityGrantRevokeRequest{GrantID: "grt_1", MemberID: "mem_1"}, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.req.selector()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("selector() = %q, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("selector() unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("selector() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDefaultRevocationReason(t *testing.T) {
	cases := map[string]string{
		"grant_id":        "manual_revocation",
		"member_id":       "principal_revoked",
		"parent_grant_id": "parent_grant_revoked",
		"binding_epoch":   "binding_epoch_superseded",
		"unknown":         "manual_revocation",
	}
	for selector, want := range cases {
		if got := defaultRevocationReason(selector); got != want {
			t.Fatalf("defaultRevocationReason(%q) = %q, want %q", selector, got, want)
		}
	}
}

func TestGrantIsRevocable(t *testing.T) {
	now := time.Now().UTC()
	cases := []struct {
		name string
		row  *coreent.CapabilityGrant
		want bool
	}{
		{"nil", nil, false},
		{"active", &coreent.CapabilityGrant{Status: "active"}, true},
		{"used", &coreent.CapabilityGrant{Status: "used"}, true},
		{"already_revoked", &coreent.CapabilityGrant{Status: "active", RevokedAt: &now}, false},
		{"expired", &coreent.CapabilityGrant{Status: "expired"}, false},
		{"superseded", &coreent.CapabilityGrant{Status: "superseded"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := grantIsRevocable(tc.row); got != tc.want {
				t.Fatalf("grantIsRevocable() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAdminRequirementForCapabilityGrantLifecycle(t *testing.T) {
	for _, path := range []string{"/api/v1/grants/revoke", "/api/v1/grants/reconcile"} {
		req := adminRequirementFor(http.MethodPost, path, "spc_acme")
		if req.PermissionKey != "capabilities:manage" {
			t.Fatalf("%s permission = %q, want capabilities:manage", path, req.PermissionKey)
		}
		if req.SpaceID != "spc_acme" {
			t.Fatalf("%s space = %q, want spc_acme", path, req.SpaceID)
		}
	}
}

func TestCapabilityGrantRevocationAndReconciliation(t *testing.T) {
	databaseURL := capabilityGrantTestDatabaseURL()
	if databaseURL == "" {
		t.Skip("set PLYSTRA_INTEGRATION_DATABASE_URL or PLYSTRA_DATABASE_URL to run capability grant lifecycle integration tests")
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

	client := store.Client()
	handler := NewServer(nil, store, "1.0.0-test").Routes()

	var rowSeq int
	insertGrant := func(t *testing.T, mutate func(*coreent.CapabilityGrantCreate)) *coreent.CapabilityGrant {
		t.Helper()
		rowSeq++
		unique := fmt.Sprintf("%s_%d", fixture.Suffix, rowSeq)
		now := time.Now().UTC()
		create := client.CapabilityGrant.Create().
			SetID(newEntityID("grt")).
			SetTokenHash("hash_" + unique).
			SetSpaceID(fixture.SpaceID).
			SetCapability(fixture.MediatedCapabilityID).
			SetOperation("create_request").
			SetPrincipalUserID(fixture.PrincipalUserID).
			SetPrincipalMemberID(fixture.PrincipalMemberID).
			SetPrincipalUserMemberID(fixture.PrincipalUserMemberID).
			SetCallerPluginID(fixture.CallerPluginID).
			SetTargetProviderID(fixture.ProviderPluginID).
			SetCorrelationID("cor_" + unique).
			SetIdempotencyKey("idem_" + unique).
			SetTargetIdempotencyKey("tgidem_" + unique).
			SetBindingEpoch(1).
			SetStatus("active").
			SetOutcomeStatus("pending").
			SetExpectedOutcomeBy(now.Add(time.Hour)).
			SetExpiresAt(now.Add(time.Hour))
		if mutate != nil {
			mutate(create)
		}
		row, err := create.Save(ctx)
		if err != nil {
			t.Fatalf("insert capability grant: %v", err)
		}
		return row
	}

	loadGrant := func(t *testing.T, id string) *coreent.CapabilityGrant {
		t.Helper()
		row, err := client.CapabilityGrant.Get(ctx, id)
		if err != nil {
			t.Fatalf("load grant %s: %v", id, err)
		}
		return row
	}

	t.Run("revokes a single grant by grant_id and introspection fails closed", func(t *testing.T) {
		body := capabilityGrantIssueBody(fixture, "lifecycle.revoke.single.v1")
		issue := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/capability-grants", fixture.SpaceID), fixture.APIKey, body)
		if issue.Code != http.StatusCreated {
			t.Fatalf("issue status = %d, body=%s", issue.Code, issue.Body.String())
		}
		issued := decodeCapabilityGrantData(t, issue)
		grantID := requireStringField(t, issued, "grant_id")
		grantToken := requireStringField(t, issued, "grant")

		rec := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/grants/revoke", fixture.SpaceID), fixture.APIKey, map[string]any{
			"space_id": fixture.SpaceID,
			"grant_id": grantID,
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("revoke status = %d, body=%s", rec.Code, rec.Body.String())
		}
		data := decodeCapabilityGrantData(t, rec)
		if count, _ := data["revoked_count"].(float64); int(count) != 1 {
			t.Fatalf("revoked_count = %#v, want 1", data["revoked_count"])
		}
		if data["selector"] != "grant_id" {
			t.Fatalf("selector = %#v, want grant_id", data["selector"])
		}

		row := loadGrant(t, grantID)
		if row.Status != "revoked" || row.RevokedAt == nil || derefString(row.RevokedReason) != "manual_revocation" {
			t.Fatalf("grant not revoked: status=%q revoked_at=%v reason=%q", row.Status, row.RevokedAt, derefString(row.RevokedReason))
		}

		introspect := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/grants/introspect", fixture.SpaceID), fixture.APIKey, map[string]any{
			"grant":              grantToken,
			"target_provider_id": fixture.ProviderPluginID,
			"capability":         fixture.MediatedCapabilityID,
			"operation":          "create_request",
		})
		if introspect.Code != http.StatusOK {
			t.Fatalf("introspect status = %d, body=%s", introspect.Code, introspect.Body.String())
		}
		state := decodeCapabilityGrantData(t, introspect)
		if active, _ := state["active"].(bool); active {
			t.Fatalf("revoked grant introspected active: %#v", state)
		}
		if state["reason"] != "grant_revoked" {
			t.Fatalf("introspect reason = %#v, want grant_revoked", state["reason"])
		}

		// Revocation must be durable: re-requesting with the same idempotency
		// key must not resurrect the revoked grant.
		reissue := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/capability-grants", fixture.SpaceID), fixture.APIKey, body)
		if reissue.Code != http.StatusConflict {
			t.Fatalf("reissue revoked grant status = %d, want 409, body=%s", reissue.Code, reissue.Body.String())
		}
		errorPayload := requireObjectField(t, decodeCapabilityGrantEnvelope(t, reissue), "error")
		if errorPayload["code"] != "CAPABILITY_GRANT_REVOKED" {
			t.Fatalf("reissue error code = %#v, want CAPABILITY_GRANT_REVOKED", errorPayload["code"])
		}
	})

	t.Run("returns 404 for an unknown grant_id", func(t *testing.T) {
		rec := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/grants/revoke", fixture.SpaceID), fixture.APIKey, map[string]any{
			"space_id": fixture.SpaceID,
			"grant_id": "grt_does_not_exist_" + fixture.Suffix,
		})
		if rec.Code != http.StatusNotFound {
			t.Fatalf("unknown grant revoke status = %d, want 404, body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("rejects requests without a single selector", func(t *testing.T) {
		rec := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/grants/revoke", fixture.SpaceID), fixture.APIKey, map[string]any{
			"space_id": fixture.SpaceID,
		})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("no-selector revoke status = %d, want 400, body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("revokes every grant for a principal member", func(t *testing.T) {
		first := insertGrant(t, nil)
		second := insertGrant(t, nil)
		other := insertGrant(t, func(c *coreent.CapabilityGrantCreate) {
			c.SetPrincipalMemberID("member_other_" + fixture.Suffix)
		})

		rec := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/grants/revoke", fixture.SpaceID), fixture.APIKey, map[string]any{
			"space_id":  fixture.SpaceID,
			"member_id": fixture.PrincipalMemberID,
			"reason":    "offboarded",
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("member revoke status = %d, body=%s", rec.Code, rec.Body.String())
		}
		data := decodeCapabilityGrantData(t, rec)
		if count, _ := data["revoked_count"].(float64); int(count) < 2 {
			t.Fatalf("revoked_count = %#v, want >= 2", data["revoked_count"])
		}
		for _, id := range []string{first.ID, second.ID} {
			row := loadGrant(t, id)
			if row.Status != "revoked" || derefString(row.RevokedReason) != "offboarded" {
				t.Fatalf("member grant %s not revoked with reason: status=%q reason=%q", id, row.Status, derefString(row.RevokedReason))
			}
		}
		if row := loadGrant(t, other.ID); row.Status == "revoked" {
			t.Fatalf("grant for a different member was revoked: %s", other.ID)
		}
	})

	t.Run("revokes the parent grant subtree but leaves siblings active", func(t *testing.T) {
		root := insertGrant(t, nil)
		child := insertGrant(t, func(c *coreent.CapabilityGrantCreate) { c.SetParentGrantID(root.ID) })
		grandchild := insertGrant(t, func(c *coreent.CapabilityGrantCreate) { c.SetParentGrantID(child.ID) })
		sibling := insertGrant(t, nil)

		rec := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/grants/revoke", fixture.SpaceID), fixture.APIKey, map[string]any{
			"space_id":        fixture.SpaceID,
			"parent_grant_id": root.ID,
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("subtree revoke status = %d, body=%s", rec.Code, rec.Body.String())
		}
		data := decodeCapabilityGrantData(t, rec)
		if count, _ := data["revoked_count"].(float64); int(count) != 3 {
			t.Fatalf("subtree revoked_count = %#v, want 3", data["revoked_count"])
		}
		for _, id := range []string{root.ID, child.ID, grandchild.ID} {
			if row := loadGrant(t, id); row.Status != "revoked" || derefString(row.RevokedReason) != "parent_grant_revoked" {
				t.Fatalf("subtree grant %s not revoked: status=%q reason=%q", id, row.Status, derefString(row.RevokedReason))
			}
		}
		if row := loadGrant(t, sibling.ID); row.Status == "revoked" {
			t.Fatalf("sibling grant was revoked: %s", sibling.ID)
		}
	})

	t.Run("revokes only grants below a superseded binding_epoch", func(t *testing.T) {
		stale := insertGrant(t, func(c *coreent.CapabilityGrantCreate) { c.SetBindingEpoch(1) })
		current := insertGrant(t, func(c *coreent.CapabilityGrantCreate) { c.SetBindingEpoch(2) })

		rec := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/grants/revoke", fixture.SpaceID), fixture.APIKey, map[string]any{
			"space_id":           fixture.SpaceID,
			"binding_epoch":      2,
			"target_provider_id": fixture.ProviderPluginID,
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("binding_epoch revoke status = %d, body=%s", rec.Code, rec.Body.String())
		}
		if row := loadGrant(t, stale.ID); row.Status != "revoked" || derefString(row.RevokedReason) != "binding_epoch_superseded" {
			t.Fatalf("stale-epoch grant not revoked: status=%q reason=%q", row.Status, derefString(row.RevokedReason))
		}
		if row := loadGrant(t, current.ID); row.Status == "revoked" {
			t.Fatalf("current-epoch grant was revoked: %s", current.ID)
		}
	})

	t.Run("marks hanging outcomes missing and lapses expired grants", func(t *testing.T) {
		past := time.Now().UTC().Add(-time.Hour)
		future := time.Now().UTC().Add(time.Hour)

		missing := insertGrant(t, func(c *coreent.CapabilityGrantCreate) {
			c.SetStatus("used").SetOutcomeStatus("pending").SetExpectedOutcomeBy(past)
		})
		pendingFuture := insertGrant(t, func(c *coreent.CapabilityGrantCreate) {
			c.SetStatus("used").SetOutcomeStatus("pending").SetExpectedOutcomeBy(future)
		})
		succeeded := insertGrant(t, func(c *coreent.CapabilityGrantCreate) {
			c.SetStatus("used").SetOutcomeStatus("succeeded").SetExpectedOutcomeBy(past)
		})
		expired := insertGrant(t, func(c *coreent.CapabilityGrantCreate) {
			c.SetStatus("active").SetOutcomeStatus("succeeded").SetExpiresAt(past)
		})

		rec := capabilityGrantJSONRequest(handler, http.MethodPost, capabilityGrantPath("/api/v1/grants/reconcile", fixture.SpaceID), fixture.APIKey, map[string]any{
			"space_id": fixture.SpaceID,
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("reconcile status = %d, body=%s", rec.Code, rec.Body.String())
		}
		data := decodeCapabilityGrantData(t, rec)
		if count, _ := data["marked_missing"].(float64); int(count) < 1 {
			t.Fatalf("marked_missing = %#v, want >= 1", data["marked_missing"])
		}
		if count, _ := data["expired"].(float64); int(count) < 1 {
			t.Fatalf("expired = %#v, want >= 1", data["expired"])
		}

		if row := loadGrant(t, missing.ID); row.OutcomeStatus != "missing" {
			t.Fatalf("hanging grant outcome_status = %q, want missing", row.OutcomeStatus)
		}
		if row := loadGrant(t, pendingFuture.ID); row.OutcomeStatus != "pending" {
			t.Fatalf("timing-normal grant outcome_status = %q, want pending", row.OutcomeStatus)
		}
		if row := loadGrant(t, succeeded.ID); row.OutcomeStatus != "succeeded" {
			t.Fatalf("succeeded grant outcome_status = %q, want succeeded", row.OutcomeStatus)
		}
		if row := loadGrant(t, expired.ID); row.Status != "expired" {
			t.Fatalf("expired grant status = %q, want expired", row.Status)
		}
	})
}
