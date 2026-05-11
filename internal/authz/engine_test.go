package authz_test

import (
	"context"
	"testing"

	"github.com/plystra/plystra/internal/authz"
)

func TestEngineFinanceReviewerScenarios(t *testing.T) {
	store := newMemoryStore()
	engine := newTestEngine(store)

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
