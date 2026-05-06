package entstore

import (
	"context"
	"os"
	"testing"
	"time"

	coreent "github.com/plystra/plystra/ent"
	"github.com/plystra/plystra/ent/auditlog"
	"github.com/plystra/plystra/internal/authz"
	"github.com/plystra/plystra/internal/demo"
)

func TestEntStoreIntegrationConformance(t *testing.T) {
	databaseURL := os.Getenv("PLYSTRA_INTEGRATION_DATABASE_URL")
	if databaseURL == "" {
		databaseURL = os.Getenv("PLYSTRA_DATABASE_URL")
	}
	if databaseURL == "" {
		t.Skip("set PLYSTRA_INTEGRATION_DATABASE_URL or PLYSTRA_DATABASE_URL to run EntStore integration tests")
	}

	ctx := context.Background()
	store, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	engine := authz.NewEngineWithClock(store, func() time.Time {
		return time.Date(2026, 5, 6, 0, 0, 0, 0, time.UTC)
	})

	for _, scenario := range demo.FinanceReviewerScenarios() {
		t.Run(scenario.Name, func(t *testing.T) {
			decision, err := engine.Check(ctx, scenario.Input)
			if err != nil {
				t.Fatalf("Check() error = %v", err)
			}
			if !scenario.Matches(decision) {
				t.Fatalf("scenario mismatch: decision=%s deny_code=%v", decision.Decision, decision.DenyCode)
			}
			if len(decision.MatchedCandidates) != 1 {
				t.Fatalf("matched candidates = %d, want 1", len(decision.MatchedCandidates))
			}
		})
	}

	candidates, err := store.LoadPermissionCandidates(ctx, authz.CandidateQuery{
		MemberID:     "member_finance_reviewer",
		ResourceType: "invoice",
		Action:       "approve",
	})
	if err != nil {
		t.Fatalf("LoadPermissionCandidates(approve) error = %v", err)
	}
	if len(candidates) == 0 {
		t.Fatalf("LoadPermissionCandidates(approve) returned no candidates")
	}

	candidates, err = store.LoadPermissionCandidates(ctx, authz.CandidateQuery{
		MemberID:     "member_finance_reviewer",
		ResourceType: "invoice",
		Action:       "nonexistent_action",
	})
	if err != nil {
		t.Fatalf("LoadPermissionCandidates(nonexistent_action) error = %v", err)
	}
	if len(candidates) != 0 {
		t.Fatalf("LoadPermissionCandidates(nonexistent_action) = %d, want 0", len(candidates))
	}

	logEntry, err := store.client.AuditLog.Query().
		Order(coreent.Desc(auditlog.FieldCreatedAt)).
		First(ctx)
	if err != nil {
		t.Fatalf("load latest audit log: %v", err)
	}
	if _, err := logEntry.Update().SetDecision(authz.DecisionAllow).Save(ctx); err == nil {
		t.Fatalf("AuditLog update unexpectedly succeeded")
	}
	if err := store.client.AuditLog.DeleteOneID(logEntry.ID).Exec(ctx); err == nil {
		t.Fatalf("AuditLog delete unexpectedly succeeded")
	}
}

func TestEntStoreIntegrationSameSpaceHooks(t *testing.T) {
	databaseURL := os.Getenv("PLYSTRA_INTEGRATION_DATABASE_URL")
	if databaseURL == "" {
		databaseURL = os.Getenv("PLYSTRA_DATABASE_URL")
	}
	if databaseURL == "" {
		t.Skip("set PLYSTRA_INTEGRATION_DATABASE_URL or PLYSTRA_DATABASE_URL to run EntStore integration tests")
	}

	ctx := context.Background()
	store, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	cleanupEntHookFixtures(t, ctx, store)
	defer func() {
		cleanupEntHookFixtures(t, ctx, store)
		_ = store.Close()
	}()

	if _, err := store.client.Space.Create().SetID("space_ent_hook_other").SetName("Other").Save(ctx); err != nil {
		t.Fatalf("create fixture space: %v", err)
	}
	if _, err := store.client.Member.Create().SetID("member_ent_hook_other").SetSpaceID("space_ent_hook_other").SetDisplayName("Other Member").Save(ctx); err != nil {
		t.Fatalf("create fixture member: %v", err)
	}
	if _, err := store.client.Role.Create().SetID("role_ent_hook_other").SetSpaceID("space_ent_hook_other").SetKey("other_role").SetName("Other Role").Save(ctx); err != nil {
		t.Fatalf("create fixture role: %v", err)
	}
	if _, err := store.client.Group.Create().SetID("group_ent_hook_other").SetSpaceID("space_ent_hook_other").SetPath("other").SetName("Other").SetDisplayName("Other").Save(ctx); err != nil {
		t.Fatalf("create fixture group: %v", err)
	}

	if _, err := store.client.UserMember.Create().
		SetID("um_ent_hook_cross_space").
		SetUserID("user_alice").
		SetMemberID("member_ent_hook_other").
		SetSpaceID("space_acme").
		SetRelationType("delegate").
		Save(ctx); err == nil {
		t.Fatalf("cross-space UserMember creation unexpectedly succeeded")
	}

	if _, err := store.client.MemberRole.Create().
		SetID("mr_ent_hook_cross_space").
		SetMemberID("member_finance_reviewer").
		SetRoleID("role_ent_hook_other").
		SetSpaceID("space_acme").
		Save(ctx); err == nil {
		t.Fatalf("cross-space MemberRole creation unexpectedly succeeded")
	}

	if _, err := store.client.Resource.Create().
		SetID("resource_ent_hook_cross_space").
		SetResourceType("invoice").
		SetSpaceID("space_acme").
		SetGroupID("group_ent_hook_other").
		Save(ctx); err == nil {
		t.Fatalf("cross-space Resource group assignment unexpectedly succeeded")
	}
}

func cleanupEntHookFixtures(t *testing.T, ctx context.Context, store *Store) {
	t.Helper()
	if store == nil || store.db == nil {
		return
	}
	statements := []string{
		`DELETE FROM resources WHERE id = 'resource_ent_hook_cross_space'`,
		`DELETE FROM member_roles WHERE id = 'mr_ent_hook_cross_space'`,
		`DELETE FROM user_members WHERE id = 'um_ent_hook_cross_space'`,
		`DELETE FROM groups WHERE id = 'group_ent_hook_other'`,
		`DELETE FROM roles WHERE id = 'role_ent_hook_other'`,
		`DELETE FROM members WHERE id = 'member_ent_hook_other'`,
		`DELETE FROM spaces WHERE id = 'space_ent_hook_other'`,
	}
	for _, statement := range statements {
		if _, err := store.db.ExecContext(ctx, statement); err != nil {
			t.Fatalf("cleanup fixture with %q: %v", statement, err)
		}
	}
}
