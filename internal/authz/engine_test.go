package authz_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/plystra/plystra/internal/authz"
)

func TestEngineFinanceReviewerScenarios(t *testing.T) {
	store := newMemoryStore()
	engine := authz.NewEngineWithClock(store, func() time.Time {
		return time.Date(2026, 5, 6, 0, 0, 0, 0, time.UTC)
	})

	tests := []struct {
		name         string
		input        authz.CheckInput
		wantDecision string
		wantDenyCode *authz.DenyCode
	}{
		{
			name:         "alice finance apac allow",
			input:        checkInput("user_alice", "um_alice_finance_reviewer", "invoice_001"),
			wantDecision: authz.DecisionAllow,
		},
		{
			name:         "alice legal emea out of bounds",
			input:        checkInput("user_alice", "um_alice_finance_reviewer", "invoice_002"),
			wantDecision: authz.DecisionDeny,
			wantDenyCode: ptrDeny(authz.DenyScopeOutOfBounds),
		},
		{
			name:         "bob same member allow",
			input:        checkInput("user_bob", "um_bob_finance_reviewer", "invoice_001"),
			wantDecision: authz.DecisionAllow,
		},
		{
			name:         "revoked user member denies",
			input:        checkInput("user_alice", "um_alice_finance_reviewer_revoked", "invoice_001"),
			wantDecision: authz.DecisionDeny,
			wantDenyCode: ptrDeny(authz.DenyUserMemberRevoked),
		},
		{
			name:         "expired user member denies",
			input:        checkInput("user_alice", "um_alice_finance_reviewer_expired", "invoice_001"),
			wantDecision: authz.DecisionDeny,
			wantDenyCode: ptrDeny(authz.DenyUserMemberExpired),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, err := engine.Check(context.Background(), tt.input)
			if err != nil {
				t.Fatalf("Check() error = %v", err)
			}
			if decision.Decision != tt.wantDecision {
				t.Fatalf("decision = %s, want %s", decision.Decision, tt.wantDecision)
			}
			if !sameDenyCode(decision.DenyCode, tt.wantDenyCode) {
				t.Fatalf("deny code = %v, want %v", decision.DenyCode, tt.wantDenyCode)
			}
			if len(decision.MatchedCandidates) != 1 {
				t.Fatalf("matched candidates = %d, want 1", len(decision.MatchedCandidates))
			}
			if decision.Audit.ActorUserID != tt.input.ActorUserID {
				t.Fatalf("audit actor_user_id = %s, want %s", decision.Audit.ActorUserID, tt.input.ActorUserID)
			}
			if decision.Audit.ActorMemberID != "member_finance_reviewer" {
				t.Fatalf("audit actor_member_id = %s", decision.Audit.ActorMemberID)
			}
		})
	}

	if len(store.audits) != len(tests) {
		t.Fatalf("audit writes = %d, want %d", len(store.audits), len(tests))
	}
}

func TestPackageLevelCheckAndExplain(t *testing.T) {
	store := newMemoryStore()
	input := checkInput("user_alice", "um_alice_finance_reviewer", "invoice_001")

	checkDecision, err := authz.Check(context.Background(), store, input)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !checkDecision.IsAllowed() {
		t.Fatalf("Check() allowed = false")
	}

	explainDecision, err := authz.Explain(context.Background(), store, input)
	if err != nil {
		t.Fatalf("Explain() error = %v", err)
	}
	if !explainDecision.IsAllowed() {
		t.Fatalf("Explain() allowed = false")
	}
}

func TestEngineAllowsProposedTargetWithoutLoadingExistingResource(t *testing.T) {
	store := newMemoryStore()
	engine := newTestEngine(store)
	input := checkInput("user_alice", "um_alice_finance_reviewer", "invoice_draft_001")
	input.Target = &authz.TargetSnapshot{
		Resource: authz.ResourceSnapshot{
			ID:            "invoice_draft_001",
			Type:          "invoice",
			SpaceID:       "space_acme",
			GroupID:       "group_finance_apac",
			OwnerMemberID: "member_invoice_creator",
		},
		Group: &authz.GroupSnapshot{ID: "group_finance_apac", SpaceID: "space_acme", Path: "finance.apac", Status: authz.StatusActive},
	}

	decision, err := engine.Check(context.Background(), input)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	assertDecision(t, decision, authz.DecisionAllow, nil)
	if decision.Target.Resource.ID != "invoice_draft_001" {
		t.Fatalf("target id = %s, want invoice_draft_001", decision.Target.Resource.ID)
	}
}

func TestEngineDeniesWithoutMatchingPermission(t *testing.T) {
	store := newMemoryStore()
	engine := newTestEngine(store)
	input := checkInput("user_alice", "um_alice_finance_reviewer", "invoice_001")
	input.Action = "reject"

	decision, err := engine.Check(context.Background(), input)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	assertDecision(t, decision, authz.DecisionDeny, ptrDeny(authz.DenyNoMatchingPermission))
	if len(decision.MatchedCandidates) != 0 {
		t.Fatalf("matched candidates = %d, want 0", len(decision.MatchedCandidates))
	}
}

func TestEngineDeniesUnknownResourceRegistryEntries(t *testing.T) {
	tests := []struct {
		name         string
		resourceType string
		action       string
		wantCode     authz.DenyCode
	}{
		{name: "unknown resource type", resourceType: "contract", action: "approve", wantCode: authz.DenyInvalidResourceType},
		{name: "unknown action", resourceType: "invoice", action: "void", wantCode: authz.DenyInvalidResourceAction},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newMemoryStore()
			engine := newTestEngine(store)
			input := checkInput("user_alice", "um_alice_finance_reviewer", "invoice_001")
			input.ResourceType = tt.resourceType
			input.Action = tt.action

			decision, err := engine.Check(context.Background(), input)
			if err != nil {
				t.Fatalf("Check() error = %v", err)
			}
			assertDecision(t, decision, authz.DecisionDeny, ptrDeny(tt.wantCode))
		})
	}
}

func TestEngineDisablesGlobalScope(t *testing.T) {
	store := newMemoryStore()
	store.candidates[0].Permission.Scope = authz.ScopeGlobal
	engine := newTestEngine(store)

	decision, err := engine.Check(context.Background(), checkInput("user_alice", "um_alice_finance_reviewer", "invoice_001"))
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	assertDecision(t, decision, authz.DecisionDeny, ptrDeny(authz.DenyGlobalScopeDisabled))
}

func TestEngineSameSpaceViolations(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*memoryStore)
	}{
		{
			name: "member space mismatch",
			mutate: func(store *memoryStore) {
				actor := store.primaryAliceActor()
				actor.Member.SpaceID = "space_other"
				store.setPrimaryAliceActor(actor)
			},
		},
		{
			name: "user member points at another member",
			mutate: func(store *memoryStore) {
				actor := store.primaryAliceActor()
				actor.UserMember.MemberID = "member_other"
				store.setPrimaryAliceActor(actor)
			},
		},
		{
			name: "resource space mismatch",
			mutate: func(store *memoryStore) {
				target := store.targets["invoice:invoice_001"]
				target.Resource.SpaceID = "space_other"
				store.targets["invoice:invoice_001"] = target
			},
		},
		{
			name: "target group space mismatch",
			mutate: func(store *memoryStore) {
				target := store.targets["invoice:invoice_001"]
				target.Group.SpaceID = "space_other"
				store.targets["invoice:invoice_001"] = target
			},
		},
		{
			name: "role space mismatch",
			mutate: func(store *memoryStore) {
				store.candidates[0].Role.SpaceID = "space_other"
			},
		},
		{
			name: "member role space mismatch",
			mutate: func(store *memoryStore) {
				store.candidates[0].MemberRoleSpaceID = "space_other"
			},
		},
		{
			name: "scope anchor space mismatch",
			mutate: func(store *memoryStore) {
				store.candidates[0].ScopeAnchor.SpaceID = "space_other"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newMemoryStore()
			tt.mutate(store)
			engine := newTestEngine(store)

			decision, err := engine.Check(context.Background(), checkInput("user_alice", "um_alice_finance_reviewer", "invoice_001"))
			if err != nil {
				t.Fatalf("Check() error = %v", err)
			}
			assertDecision(t, decision, authz.DecisionDeny, ptrDeny(authz.DenyCrossSpaceViolation))
		})
	}
}

func TestResolveScopeMatrix(t *testing.T) {
	actor := authz.ActorSnapshot{
		Member: authz.MemberSnapshot{ID: "member_finance_reviewer", SpaceID: "space_acme"},
	}
	target := authz.TargetSnapshot{
		Resource: authz.ResourceSnapshot{
			ID:            "invoice_001",
			Type:          "invoice",
			SpaceID:       "space_acme",
			GroupID:       "group_finance_apac",
			OwnerMemberID: "member_finance_reviewer",
		},
		Group: &authz.GroupSnapshot{ID: "group_finance_apac", SpaceID: "space_acme", Path: "finance.apac"},
	}
	anchor := &authz.GroupSnapshot{ID: "group_finance", SpaceID: "space_acme", Path: "finance"}

	tests := []struct {
		name        string
		scope       authz.Scope
		target      authz.TargetSnapshot
		anchor      *authz.GroupSnapshot
		wantCovered bool
		wantDeny    *authz.DenyCode
	}{
		{name: "self covers owner", scope: authz.ScopeSelf, target: target, wantCovered: true},
		{name: "group direct miss", scope: authz.ScopeGroup, target: target, anchor: anchor, wantCovered: false, wantDeny: ptrDeny(authz.DenyScopeOutOfBounds)},
		{name: "group tree covers descendant", scope: authz.ScopeGroupTree, target: target, anchor: anchor, wantCovered: true},
		{name: "space covers same space", scope: authz.ScopeSpace, target: target, wantCovered: true},
		{name: "global disabled", scope: authz.ScopeGlobal, target: target, wantCovered: false, wantDeny: ptrDeny(authz.DenyGlobalScopeDisabled)},
		{name: "missing anchor", scope: authz.ScopeGroupTree, target: target, wantCovered: false, wantDeny: ptrDeny(authz.DenyScopeAnchorMissing)},
		{
			name:  "missing target group",
			scope: authz.ScopeGroupTree,
			target: authz.TargetSnapshot{Resource: authz.ResourceSnapshot{
				ID: "invoice_003", Type: "invoice", SpaceID: "space_acme",
			}},
			anchor:      anchor,
			wantCovered: false,
			wantDeny:    ptrDeny(authz.DenyTargetGroupMissing),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check := authz.ResolveScope(tt.scope, actor, tt.target, tt.anchor)
			if check.Covered != tt.wantCovered {
				t.Fatalf("covered = %t, want %t", check.Covered, tt.wantCovered)
			}
			if !sameDenyCode(check.DenyCode, tt.wantDeny) {
				t.Fatalf("deny code = %v, want %v", check.DenyCode, tt.wantDeny)
			}
		})
	}
}

func checkInput(userID, userMemberID, resourceID string) authz.CheckInput {
	return authz.CheckInput{
		ActorUserID:       userID,
		ActorMemberID:     "member_finance_reviewer",
		ActorUserMemberID: userMemberID,
		SpaceID:           "space_acme",
		ResourceType:      "invoice",
		ResourceID:        resourceID,
		Action:            "approve",
	}
}

func newTestEngine(store authz.Store) *authz.Engine {
	return authz.NewEngineWithClock(store, func() time.Time {
		return time.Date(2026, 5, 6, 0, 0, 0, 0, time.UTC)
	})
}

type memoryStore struct {
	actors     map[string]authz.ActorSnapshot
	targets    map[string]authz.TargetSnapshot
	registry   map[string]authz.ResourceRegistrySnapshot
	candidates []authz.PermissionCandidate
	audits     []authz.Decision
}

func newMemoryStore() *memoryStore {
	space := authz.SpaceSnapshot{ID: "space_acme", Name: "Acme", Status: authz.StatusActive}
	member := authz.MemberSnapshot{
		ID:          "member_finance_reviewer",
		SpaceID:     "space_acme",
		DisplayName: "Finance Reviewer",
		Status:      authz.StatusActive,
	}
	expiredAt := time.Date(2026, 5, 5, 0, 0, 0, 0, time.UTC)

	return &memoryStore{
		actors: map[string]authz.ActorSnapshot{
			actorKey("user_alice", "member_finance_reviewer", "um_alice_finance_reviewer", "space_acme"): {
				User:   authz.UserSnapshot{ID: "user_alice", Email: "alice@example.com", Status: authz.StatusActive},
				Member: member,
				UserMember: authz.UserMemberSnapshot{
					ID:           "um_alice_finance_reviewer",
					UserID:       "user_alice",
					MemberID:     "member_finance_reviewer",
					SpaceID:      "space_acme",
					RelationType: "delegate",
					Status:       authz.StatusActive,
					IsPrimary:    true,
				},
				Space: space,
			},
			actorKey("user_bob", "member_finance_reviewer", "um_bob_finance_reviewer", "space_acme"): {
				User:   authz.UserSnapshot{ID: "user_bob", Email: "bob@example.com", Status: authz.StatusActive},
				Member: member,
				UserMember: authz.UserMemberSnapshot{
					ID:           "um_bob_finance_reviewer",
					UserID:       "user_bob",
					MemberID:     "member_finance_reviewer",
					SpaceID:      "space_acme",
					RelationType: "login",
					Status:       authz.StatusActive,
					IsPrimary:    true,
				},
				Space: space,
			},
			actorKey("user_alice", "member_finance_reviewer", "um_alice_finance_reviewer_revoked", "space_acme"): {
				User:   authz.UserSnapshot{ID: "user_alice", Email: "alice@example.com", Status: authz.StatusActive},
				Member: member,
				UserMember: authz.UserMemberSnapshot{
					ID:           "um_alice_finance_reviewer_revoked",
					UserID:       "user_alice",
					MemberID:     "member_finance_reviewer",
					SpaceID:      "space_acme",
					RelationType: "delegate",
					Status:       "revoked",
				},
				Space: space,
			},
			actorKey("user_alice", "member_finance_reviewer", "um_alice_finance_reviewer_expired", "space_acme"): {
				User:   authz.UserSnapshot{ID: "user_alice", Email: "alice@example.com", Status: authz.StatusActive},
				Member: member,
				UserMember: authz.UserMemberSnapshot{
					ID:           "um_alice_finance_reviewer_expired",
					UserID:       "user_alice",
					MemberID:     "member_finance_reviewer",
					SpaceID:      "space_acme",
					RelationType: "temporary",
					Status:       authz.StatusActive,
					ExpiresAt:    &expiredAt,
				},
				Space: space,
			},
		},
		targets: map[string]authz.TargetSnapshot{
			"invoice:invoice_001": {
				Resource: authz.ResourceSnapshot{
					ID:            "invoice_001",
					Type:          "invoice",
					SpaceID:       "space_acme",
					GroupID:       "group_finance_apac",
					OwnerMemberID: "member_invoice_creator",
				},
				Group: &authz.GroupSnapshot{ID: "group_finance_apac", SpaceID: "space_acme", Path: "finance.apac", Status: authz.StatusActive},
			},
			"invoice:invoice_002": {
				Resource: authz.ResourceSnapshot{
					ID:            "invoice_002",
					Type:          "invoice",
					SpaceID:       "space_acme",
					GroupID:       "group_legal_emea",
					OwnerMemberID: "member_invoice_creator",
				},
				Group: &authz.GroupSnapshot{ID: "group_legal_emea", SpaceID: "space_acme", Path: "legal.emea", Status: authz.StatusActive},
			},
		},
		registry: map[string]authz.ResourceRegistrySnapshot{
			"invoice:approve": {
				ResourceType: authz.ResourceTypeSnapshot{
					ID:          "rt_invoice",
					Key:         "invoice",
					DisplayName: "Invoice",
					Status:      authz.StatusActive,
					Source:      "core",
				},
				Action: authz.ResourceActionSnapshot{
					ID:             "ra_invoice_approve",
					ResourceTypeID: "rt_invoice",
					Key:            "approve",
					DisplayName:    "Approve",
					RiskLevel:      "high",
					AuditDefault:   true,
				},
				Mapping: authz.ResourceMappingSnapshot{
					ID:               "rm_invoice_resources",
					ResourceTypeID:   "rt_invoice",
					StorageKind:      "internal_table",
					TableName:        "resources",
					IDField:          "id",
					SpaceField:       "space_id",
					GroupField:       "group_id",
					OwnerMemberField: "owner_member_id",
					VisibilityField:  "visibility",
					MetadataField:    "metadata",
					Status:           authz.StatusActive,
				},
			},
			"invoice:reject": {
				ResourceType: authz.ResourceTypeSnapshot{
					ID:          "rt_invoice",
					Key:         "invoice",
					DisplayName: "Invoice",
					Status:      authz.StatusActive,
					Source:      "core",
				},
				Action: authz.ResourceActionSnapshot{
					ID:             "ra_invoice_reject",
					ResourceTypeID: "rt_invoice",
					Key:            "reject",
					DisplayName:    "Reject",
					RiskLevel:      "high",
					AuditDefault:   true,
				},
				Mapping: authz.ResourceMappingSnapshot{
					ID:               "rm_invoice_resources",
					ResourceTypeID:   "rt_invoice",
					StorageKind:      "internal_table",
					TableName:        "resources",
					IDField:          "id",
					SpaceField:       "space_id",
					GroupField:       "group_id",
					OwnerMemberField: "owner_member_id",
					VisibilityField:  "visibility",
					MetadataField:    "metadata",
					Status:           authz.StatusActive,
				},
			},
		},
		candidates: []authz.PermissionCandidate{
			{
				Role:              authz.RoleSnapshot{ID: "role_finance_approver", Key: "finance_approver", SpaceID: "space_acme"},
				Permission:        authz.PermissionSnapshot{ID: "perm_invoice_approve_group_tree", Resource: "invoice", Action: "approve", Scope: authz.ScopeGroupTree},
				ScopeAnchor:       &authz.GroupSnapshot{ID: "group_finance", SpaceID: "space_acme", Path: "finance", Status: authz.StatusActive},
				MemberRoleSpaceID: "space_acme",
			},
		},
	}
}

func (m *memoryStore) primaryAliceActor() authz.ActorSnapshot {
	return m.actors[actorKey("user_alice", "member_finance_reviewer", "um_alice_finance_reviewer", "space_acme")]
}

func (m *memoryStore) setPrimaryAliceActor(actor authz.ActorSnapshot) {
	m.actors[actorKey("user_alice", "member_finance_reviewer", "um_alice_finance_reviewer", "space_acme")] = actor
}

func (m *memoryStore) LoadActor(_ context.Context, actor authz.ActorContext) (authz.ActorSnapshot, error) {
	value, ok := m.actors[actorKey(actor.UserID, actor.MemberID, actor.UserMemberID, actor.SpaceID)]
	if !ok {
		return authz.ActorSnapshot{}, authz.ErrNotFound
	}

	return value, nil
}

func (m *memoryStore) LoadTarget(_ context.Context, resourceType, resourceID string) (authz.TargetSnapshot, error) {
	value, ok := m.targets[resourceType+":"+resourceID]
	if !ok {
		return authz.TargetSnapshot{}, authz.ErrNotFound
	}

	return value, nil
}

func (m *memoryStore) LoadResourceRegistration(_ context.Context, resourceType, action string) (authz.ResourceRegistrySnapshot, error) {
	value, ok := m.registry[resourceType+":"+action]
	if ok {
		return value, nil
	}
	for key := range m.registry {
		if strings.HasPrefix(key, resourceType+":") {
			return authz.ResourceRegistrySnapshot{}, authz.ErrResourceActionNotFound
		}
	}
	return authz.ResourceRegistrySnapshot{}, authz.ErrResourceTypeNotFound
}

func (m *memoryStore) LoadPermissionCandidates(_ context.Context, query authz.CandidateQuery) ([]authz.PermissionCandidate, error) {
	if query.MemberID != "member_finance_reviewer" || query.ResourceType != "invoice" || query.Action != "approve" {
		return nil, nil
	}

	out := make([]authz.PermissionCandidate, len(m.candidates))
	copy(out, m.candidates)
	return out, nil
}

func (m *memoryStore) WriteAuditLog(_ context.Context, decision authz.Decision) error {
	m.audits = append(m.audits, decision)
	return nil
}

func actorKey(userID, memberID, userMemberID, spaceID string) string {
	return userID + ":" + memberID + ":" + userMemberID + ":" + spaceID
}

func ptrDeny(code authz.DenyCode) *authz.DenyCode {
	return &code
}

func assertDecision(t *testing.T, decision *authz.Decision, wantDecision string, wantDenyCode *authz.DenyCode) {
	t.Helper()
	if decision.Decision != wantDecision {
		t.Fatalf("decision = %s, want %s", decision.Decision, wantDecision)
	}
	if !sameDenyCode(decision.DenyCode, wantDenyCode) {
		t.Fatalf("deny code = %v, want %v", decision.DenyCode, wantDenyCode)
	}
}

func sameDenyCode(got, want *authz.DenyCode) bool {
	if got == nil || want == nil {
		return got == want
	}

	return *got == *want
}
