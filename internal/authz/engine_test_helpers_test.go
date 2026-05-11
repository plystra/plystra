package authz_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/plystra/plystra/internal/authz"
)

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
		registry: registryFixtures(),
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

func registryFixtures() map[string]authz.ResourceRegistrySnapshot {
	invoiceType := authz.ResourceTypeSnapshot{
		ID:          "rt_invoice",
		Key:         "invoice",
		DisplayName: "Invoice",
		Status:      authz.StatusActive,
		Source:      "core",
	}
	mapping := authz.ResourceMappingSnapshot{
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
	}
	return map[string]authz.ResourceRegistrySnapshot{
		"invoice:approve": {
			ResourceType: invoiceType,
			Action: authz.ResourceActionSnapshot{
				ID:             "ra_invoice_approve",
				ResourceTypeID: "rt_invoice",
				Key:            "approve",
				DisplayName:    "Approve",
				RiskLevel:      "high",
				AuditDefault:   true,
			},
			Mapping: mapping,
		},
		"invoice:reject": {
			ResourceType: invoiceType,
			Action: authz.ResourceActionSnapshot{
				ID:             "ra_invoice_reject",
				ResourceTypeID: "rt_invoice",
				Key:            "reject",
				DisplayName:    "Reject",
				RiskLevel:      "high",
				AuditDefault:   true,
			},
			Mapping: mapping,
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
