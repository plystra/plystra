package entstore

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	coreent "github.com/plystra/plystra/ent"
	"github.com/plystra/plystra/ent/auditlog"
	"github.com/plystra/plystra/ent/resourceaction"
	"github.com/plystra/plystra/ent/resourcemapping"
	"github.com/plystra/plystra/ent/resourcetype"
	"github.com/plystra/plystra/internal/authz"
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
	fixture := createEntStoreConformanceFixture(t, ctx, store.client)
	defer func() {
		cleanupEntStoreConformanceFixture(t, context.Background(), store.client, fixture)
		_ = store.Close()
	}()

	engine := authz.NewEngineWithClock(store, func() time.Time {
		return time.Date(2026, 5, 6, 0, 0, 0, 0, time.UTC)
	})

	for _, scenario := range entStoreConformanceScenarios(fixture) {
		t.Run(scenario.Name, func(t *testing.T) {
			decision, err := engine.Check(ctx, scenario.Input)
			if err != nil {
				t.Fatalf("Check() error = %v", err)
			}
			if decision == nil || decision.Decision != scenario.ExpectedDecision {
				t.Fatalf("scenario mismatch: decision=%s deny_code=%v", decision.Decision, decision.DenyCode)
			}
			if scenario.ExpectedDenyCode == nil && decision.DenyCode != nil {
				t.Fatalf("deny_code = %v, want nil", decision.DenyCode)
			}
			if scenario.ExpectedDenyCode != nil && (decision.DenyCode == nil || *decision.DenyCode != *scenario.ExpectedDenyCode) {
				t.Fatalf("deny_code = %v, want %v", decision.DenyCode, scenario.ExpectedDenyCode)
			}
			if len(decision.MatchedCandidates) != 1 {
				t.Fatalf("matched candidates = %d, want 1", len(decision.MatchedCandidates))
			}
		})
	}

	candidates, err := store.LoadPermissionCandidates(ctx, authz.CandidateQuery{
		MemberID:     fixture.MemberID,
		ResourceType: fixture.ResourceType,
		Action:       "approve",
	})
	if err != nil {
		t.Fatalf("LoadPermissionCandidates(approve) error = %v", err)
	}
	if len(candidates) == 0 {
		t.Fatalf("LoadPermissionCandidates(approve) returned no candidates")
	}

	candidates, err = store.LoadPermissionCandidates(ctx, authz.CandidateQuery{
		MemberID:     fixture.MemberID,
		ResourceType: fixture.ResourceType,
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

type entStoreConformanceFixture struct {
	SpaceID             string
	GroupRootID         string
	GroupAllowedID      string
	GroupDeniedID       string
	UserID              string
	MemberID            string
	UserMemberID        string
	UserMemberRevokedID string
	RoleID              string
	MemberRoleID        string
	PermissionID        string
	RolePermissionID    string
	ResourceTypeID      string
	ResourceActionID    string
	ResourceMappingID   string
	ResourceType        string
	ResourceAllowedID   string
	ResourceDeniedID    string
}

type entStoreScenario struct {
	Name             string
	Input            authz.CheckInput
	ExpectedDecision string
	ExpectedDenyCode *authz.DenyCode
}

func createEntStoreConformanceFixture(t *testing.T, ctx context.Context, client *coreent.Client) entStoreConformanceFixture {
	t.Helper()
	suffix := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	fixture := entStoreConformanceFixture{
		SpaceID:             "space_store_conf_" + suffix,
		GroupRootID:         "group_store_conf_root_" + suffix,
		GroupAllowedID:      "group_store_conf_allowed_" + suffix,
		GroupDeniedID:       "group_store_conf_denied_" + suffix,
		UserID:              "user_store_conf_" + suffix,
		MemberID:            "member_store_conf_" + suffix,
		UserMemberID:        "um_store_conf_" + suffix,
		UserMemberRevokedID: "um_store_conf_revoked_" + suffix,
		RoleID:              "role_store_conf_" + suffix,
		MemberRoleID:        "mr_store_conf_" + suffix,
		PermissionID:        "perm_store_conf_" + suffix,
		RolePermissionID:    "rp_store_conf_" + suffix,
		ResourceTypeID:      "rt_store_conf_" + suffix,
		ResourceActionID:    "ra_store_conf_" + suffix,
		ResourceMappingID:   "rm_store_conf_" + suffix,
		ResourceType:        "store_conf_" + suffix,
		ResourceAllowedID:   "resource_store_conf_allowed_" + suffix,
		ResourceDeniedID:    "resource_store_conf_denied_" + suffix,
	}
	if _, err := client.Space.Create().SetID(fixture.SpaceID).SetName("Store Conformance").Save(ctx); err != nil {
		t.Fatalf("create space: %v", err)
	}
	if _, err := client.Group.Create().SetID(fixture.GroupRootID).SetSpaceID(fixture.SpaceID).SetName("root").SetPath("root").SetDepth(0).Save(ctx); err != nil {
		t.Fatalf("create root group: %v", err)
	}
	if _, err := client.Group.Create().SetID(fixture.GroupAllowedID).SetSpaceID(fixture.SpaceID).SetParentGroupID(fixture.GroupRootID).SetName("allowed").SetPath("root.allowed").SetDepth(1).Save(ctx); err != nil {
		t.Fatalf("create allowed group: %v", err)
	}
	if _, err := client.Group.Create().SetID(fixture.GroupDeniedID).SetSpaceID(fixture.SpaceID).SetName("denied").SetPath("denied").SetDepth(0).Save(ctx); err != nil {
		t.Fatalf("create denied group: %v", err)
	}
	if _, err := client.User.Create().SetID(fixture.UserID).SetEmail("store.conf." + suffix + "@example.com").Save(ctx); err != nil {
		t.Fatalf("create user: %v", err)
	}
	if _, err := client.Member.Create().SetID(fixture.MemberID).SetSpaceID(fixture.SpaceID).SetDisplayName("Store Conformance Member").Save(ctx); err != nil {
		t.Fatalf("create member: %v", err)
	}
	if _, err := client.UserMember.Create().SetID(fixture.UserMemberID).SetUserID(fixture.UserID).SetMemberID(fixture.MemberID).SetSpaceID(fixture.SpaceID).SetRelationType("login").SetIsPrimary(true).Save(ctx); err != nil {
		t.Fatalf("create user member: %v", err)
	}
	if _, err := client.UserMember.Create().SetID(fixture.UserMemberRevokedID).SetUserID(fixture.UserID).SetMemberID(fixture.MemberID).SetSpaceID(fixture.SpaceID).SetRelationType("delegate").SetStatus("revoked").Save(ctx); err != nil {
		t.Fatalf("create revoked user member: %v", err)
	}
	if _, err := client.ResourceType.Create().SetID(fixture.ResourceTypeID).SetKey(fixture.ResourceType).SetDisplayName("Store Conformance Resource").Save(ctx); err != nil {
		t.Fatalf("create resource type: %v", err)
	}
	if _, err := client.ResourceAction.Create().SetID(fixture.ResourceActionID).SetResourceTypeID(fixture.ResourceTypeID).SetKey("approve").SetDisplayName("Approve").SetRiskLevel("high").SetAuditDefault(true).Save(ctx); err != nil {
		t.Fatalf("create resource action: %v", err)
	}
	if _, err := client.ResourceMapping.Create().SetID(fixture.ResourceMappingID).SetResourceTypeID(fixture.ResourceTypeID).SetTableName("resources").SetGroupField("group_id").SetOwnerMemberField("owner_member_id").SetVisibilityField("visibility").SetMetadataField("metadata").Save(ctx); err != nil {
		t.Fatalf("create resource mapping: %v", err)
	}
	if _, err := client.Role.Create().SetID(fixture.RoleID).SetSpaceID(fixture.SpaceID).SetKey("store_conf_role_" + suffix).SetName("Store Conformance Role").Save(ctx); err != nil {
		t.Fatalf("create role: %v", err)
	}
	if _, err := client.Permission.Create().SetID(fixture.PermissionID).SetResource(fixture.ResourceType).SetAction("approve").SetScope(string(authz.ScopeGroupTree)).Save(ctx); err != nil {
		t.Fatalf("create permission: %v", err)
	}
	if _, err := client.RolePermission.Create().SetID(fixture.RolePermissionID).SetRoleID(fixture.RoleID).SetPermissionID(fixture.PermissionID).Save(ctx); err != nil {
		t.Fatalf("create role permission: %v", err)
	}
	if _, err := client.MemberRole.Create().SetID(fixture.MemberRoleID).SetMemberID(fixture.MemberID).SetRoleID(fixture.RoleID).SetSpaceID(fixture.SpaceID).SetScopeAnchorGroupID(fixture.GroupRootID).Save(ctx); err != nil {
		t.Fatalf("create member role: %v", err)
	}
	if _, err := client.Resource.Create().SetID(fixture.ResourceAllowedID).SetResourceType(fixture.ResourceType).SetSpaceID(fixture.SpaceID).SetGroupID(fixture.GroupAllowedID).SetOwnerMemberID(fixture.MemberID).Save(ctx); err != nil {
		t.Fatalf("create allowed resource: %v", err)
	}
	if _, err := client.Resource.Create().SetID(fixture.ResourceDeniedID).SetResourceType(fixture.ResourceType).SetSpaceID(fixture.SpaceID).SetGroupID(fixture.GroupDeniedID).SetOwnerMemberID(fixture.MemberID).Save(ctx); err != nil {
		t.Fatalf("create denied resource: %v", err)
	}
	return fixture
}

func entStoreConformanceScenarios(fixture entStoreConformanceFixture) []entStoreScenario {
	return []entStoreScenario{
		{
			Name: "member approves record in anchor tree",
			Input: authz.CheckInput{
				ActorUserID:       fixture.UserID,
				ActorMemberID:     fixture.MemberID,
				ActorUserMemberID: fixture.UserMemberID,
				SpaceID:           fixture.SpaceID,
				ResourceType:      fixture.ResourceType,
				ResourceID:        fixture.ResourceAllowedID,
				Action:            "approve",
			},
			ExpectedDecision: authz.DecisionAllow,
		},
		{
			Name: "member denied outside anchor tree",
			Input: authz.CheckInput{
				ActorUserID:       fixture.UserID,
				ActorMemberID:     fixture.MemberID,
				ActorUserMemberID: fixture.UserMemberID,
				SpaceID:           fixture.SpaceID,
				ResourceType:      fixture.ResourceType,
				ResourceID:        fixture.ResourceDeniedID,
				Action:            "approve",
			},
			ExpectedDecision: authz.DecisionDeny,
			ExpectedDenyCode: denyCode(authz.DenyScopeOutOfBounds),
		},
		{
			Name: "revoked user member denied",
			Input: authz.CheckInput{
				ActorUserID:       fixture.UserID,
				ActorMemberID:     fixture.MemberID,
				ActorUserMemberID: fixture.UserMemberRevokedID,
				SpaceID:           fixture.SpaceID,
				ResourceType:      fixture.ResourceType,
				ResourceID:        fixture.ResourceAllowedID,
				Action:            "approve",
			},
			ExpectedDecision: authz.DecisionDeny,
			ExpectedDenyCode: denyCode(authz.DenyUserMemberRevoked),
		},
	}
}

func cleanupEntStoreConformanceFixture(t *testing.T, ctx context.Context, client *coreent.Client, fixture entStoreConformanceFixture) {
	t.Helper()
	now := time.Now().UTC()
	ignoreNotFound := func(label string, err error) {
		t.Helper()
		if err != nil && !coreent.IsNotFound(err) {
			t.Fatalf("cleanup %s: %v", label, err)
		}
	}
	_, _ = client.AuditLog.Delete().Where(auditlog.SpaceID(fixture.SpaceID)).Exec(ctx)
	ignoreNotFound("allowed resource", client.Resource.UpdateOneID(fixture.ResourceAllowedID).SetDeletedAt(now).Exec(ctx))
	ignoreNotFound("denied resource", client.Resource.UpdateOneID(fixture.ResourceDeniedID).SetDeletedAt(now).Exec(ctx))
	ignoreNotFound("member role", client.MemberRole.UpdateOneID(fixture.MemberRoleID).SetDeletedAt(now).Exec(ctx))
	ignoreNotFound("role permission", client.RolePermission.UpdateOneID(fixture.RolePermissionID).SetDeletedAt(now).Exec(ctx))
	ignoreNotFound("permission", client.Permission.UpdateOneID(fixture.PermissionID).SetDeletedAt(now).Exec(ctx))
	ignoreNotFound("role", client.Role.UpdateOneID(fixture.RoleID).SetDeletedAt(now).Exec(ctx))
	ignoreNotFound("active user member", client.UserMember.UpdateOneID(fixture.UserMemberID).SetDeletedAt(now).Exec(ctx))
	ignoreNotFound("revoked user member", client.UserMember.UpdateOneID(fixture.UserMemberRevokedID).SetDeletedAt(now).Exec(ctx))
	ignoreNotFound("member", client.Member.UpdateOneID(fixture.MemberID).SetDeletedAt(now).Exec(ctx))
	ignoreNotFound("allowed group", client.Group.UpdateOneID(fixture.GroupAllowedID).SetDeletedAt(now).Exec(ctx))
	ignoreNotFound("denied group", client.Group.UpdateOneID(fixture.GroupDeniedID).SetDeletedAt(now).Exec(ctx))
	ignoreNotFound("root group", client.Group.UpdateOneID(fixture.GroupRootID).SetDeletedAt(now).Exec(ctx))
	ignoreNotFound("user", client.User.UpdateOneID(fixture.UserID).SetDeletedAt(now).Exec(ctx))
	ignoreNotFound("space", client.Space.UpdateOneID(fixture.SpaceID).SetDeletedAt(now).Exec(ctx))
	_, _ = client.ResourceMapping.Delete().Where(resourcemapping.ID(fixture.ResourceMappingID)).Exec(ctx)
	_, _ = client.ResourceAction.Delete().Where(resourceaction.ID(fixture.ResourceActionID)).Exec(ctx)
	_, _ = client.ResourceType.Delete().Where(resourcetype.ID(fixture.ResourceTypeID)).Exec(ctx)
}

func denyCode(code authz.DenyCode) *authz.DenyCode {
	return &code
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

func TestEntStoreIntegrationSameSpaceHooksUseTransactionClient(t *testing.T) {
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

	tx, err := store.client.Tx(ctx)
	if err != nil {
		t.Fatalf("start transaction: %v", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	if _, err := tx.Space.Create().SetID(fixtures.SpaceID).SetName("Transaction Space").Save(ctx); err != nil {
		t.Fatalf("create transaction fixture space: %v", err)
	}
	if _, err := tx.Member.Create().SetID(fixtures.MemberID).SetSpaceID(fixtures.SpaceID).SetDisplayName("Transaction Member").Save(ctx); err != nil {
		t.Fatalf("create transaction fixture member: %v", err)
	}
	if _, err := tx.UserMember.Create().
		SetID(fixtures.UserMemberID).
		SetUserID("user_alice").
		SetMemberID(fixtures.MemberID).
		SetSpaceID(fixtures.SpaceID).
		SetRelationType("delegate").
		Save(ctx); err != nil {
		t.Fatalf("same-space UserMember create in transaction failed: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit transaction: %v", err)
	}
	committed = true
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
