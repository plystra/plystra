package entstore

import (
	"context"
	"fmt"
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
	fixtures := newEntHookFixtureIDs()
	cleanupEntHookFixtures(t, ctx, store, fixtures)
	defer func() {
		cleanupEntHookFixtures(t, ctx, store, fixtures)
		_ = store.Close()
	}()

	if _, err := store.client.Space.Create().SetID(fixtures.SpaceID).SetName("Other").Save(ctx); err != nil {
		t.Fatalf("create fixture space: %v", err)
	}
	if _, err := store.client.Member.Create().SetID(fixtures.MemberID).SetSpaceID(fixtures.SpaceID).SetDisplayName("Other Member").Save(ctx); err != nil {
		t.Fatalf("create fixture member: %v", err)
	}
	if _, err := store.client.Role.Create().SetID(fixtures.RoleID).SetSpaceID(fixtures.SpaceID).SetKey(fixtures.RoleKey).SetName("Other Role").Save(ctx); err != nil {
		t.Fatalf("create fixture role: %v", err)
	}
	if _, err := store.client.Group.Create().SetID(fixtures.GroupID).SetSpaceID(fixtures.SpaceID).SetPath(fixtures.GroupPath).SetName("Other").SetDisplayName("Other").Save(ctx); err != nil {
		t.Fatalf("create fixture group: %v", err)
	}

	if _, err := store.client.UserMember.Create().
		SetID(fixtures.UserMemberID).
		SetUserID("user_alice").
		SetMemberID(fixtures.MemberID).
		SetSpaceID("space_acme").
		SetRelationType("delegate").
		Save(ctx); err == nil {
		t.Fatalf("cross-space UserMember creation unexpectedly succeeded")
	}

	if _, err := store.client.MemberRole.Create().
		SetID(fixtures.MemberRoleID).
		SetMemberID("member_finance_reviewer").
		SetRoleID(fixtures.RoleID).
		SetSpaceID("space_acme").
		Save(ctx); err == nil {
		t.Fatalf("cross-space MemberRole creation unexpectedly succeeded")
	}

	if _, err := store.client.Resource.Create().
		SetID(fixtures.ResourceID).
		SetResourceType("invoice").
		SetSpaceID("space_acme").
		SetGroupID(fixtures.GroupID).
		Save(ctx); err == nil {
		t.Fatalf("cross-space Resource group assignment unexpectedly succeeded")
	}
}

type entHookFixtureIDs struct {
	SpaceID      string
	MemberID     string
	RoleID       string
	RoleKey      string
	GroupID      string
	GroupPath    string
	UserMemberID string
	MemberRoleID string
	ResourceID   string
}

func newEntHookFixtureIDs() entHookFixtureIDs {
	suffix := fmt.Sprintf("ent_hook_%d", time.Now().UTC().UnixNano())
	return entHookFixtureIDs{
		SpaceID:      "space_" + suffix,
		MemberID:     "member_" + suffix,
		RoleID:       "role_" + suffix,
		RoleKey:      "role_" + suffix,
		GroupID:      "group_" + suffix,
		GroupPath:    "other_" + suffix,
		UserMemberID: "um_" + suffix,
		MemberRoleID: "mr_" + suffix,
		ResourceID:   "resource_" + suffix,
	}
}

func cleanupEntHookFixtures(t *testing.T, ctx context.Context, store *Store, fixtures entHookFixtureIDs) {
	t.Helper()
	if store == nil || store.client == nil {
		return
	}
	now := time.Now().UTC()
	ignoreNotFound := func(label string, err error) {
		t.Helper()
		if err != nil && !coreent.IsNotFound(err) {
			t.Fatalf("cleanup %s: %v", label, err)
		}
	}
	ignoreNotFound("resource", store.client.Resource.UpdateOneID(fixtures.ResourceID).SetDeletedAt(now).Exec(ctx))
	ignoreNotFound("member_role", store.client.MemberRole.UpdateOneID(fixtures.MemberRoleID).SetDeletedAt(now).Exec(ctx))
	ignoreNotFound("user_member", store.client.UserMember.UpdateOneID(fixtures.UserMemberID).SetDeletedAt(now).Exec(ctx))
	ignoreNotFound("group", store.client.Group.UpdateOneID(fixtures.GroupID).SetDeletedAt(now).Exec(ctx))
	ignoreNotFound("role", store.client.Role.UpdateOneID(fixtures.RoleID).SetDeletedAt(now).Exec(ctx))
	ignoreNotFound("member", store.client.Member.UpdateOneID(fixtures.MemberID).SetDeletedAt(now).Exec(ctx))
	ignoreNotFound("space", store.client.Space.UpdateOneID(fixtures.SpaceID).SetDeletedAt(now).Exec(ctx))
}
