package demo

import "github.com/plystra/core/internal/authz"

type Scenario struct {
	Case             int
	Name             string
	Input            authz.CheckInput
	ExpectedDecision string
	ExpectedDenyCode *authz.DenyCode
}

func FinanceReviewerScenarios() []Scenario {
	return []Scenario{
		{
			Case: 1,
			Name: "Alice approves Finance APAC invoice",
			Input: authz.CheckInput{
				ActorUserID:       "user_alice",
				ActorMemberID:     "member_finance_reviewer",
				ActorUserMemberID: "um_alice_finance_reviewer",
				SpaceID:           "space_acme",
				ResourceType:      "invoice",
				ResourceID:        "invoice_001",
				Action:            "approve",
			},
			ExpectedDecision: authz.DecisionAllow,
		},
		{
			Case: 2,
			Name: "Alice tries to approve Legal EMEA invoice",
			Input: authz.CheckInput{
				ActorUserID:       "user_alice",
				ActorMemberID:     "member_finance_reviewer",
				ActorUserMemberID: "um_alice_finance_reviewer",
				SpaceID:           "space_acme",
				ResourceType:      "invoice",
				ResourceID:        "invoice_002",
				Action:            "approve",
			},
			ExpectedDecision: authz.DecisionDeny,
			ExpectedDenyCode: denyCode(authz.DenyScopeOutOfBounds),
		},
		{
			Case: 3,
			Name: "Bob approves Finance APAC invoice through the same Member",
			Input: authz.CheckInput{
				ActorUserID:       "user_bob",
				ActorMemberID:     "member_finance_reviewer",
				ActorUserMemberID: "um_bob_finance_reviewer",
				SpaceID:           "space_acme",
				ResourceType:      "invoice",
				ResourceID:        "invoice_001",
				Action:            "approve",
			},
			ExpectedDecision: authz.DecisionAllow,
		},
		{
			Case: 4,
			Name: "Alice tries to approve with a revoked UserMember binding",
			Input: authz.CheckInput{
				ActorUserID:       "user_alice",
				ActorMemberID:     "member_finance_reviewer",
				ActorUserMemberID: "um_alice_finance_reviewer_revoked",
				SpaceID:           "space_acme",
				ResourceType:      "invoice",
				ResourceID:        "invoice_001",
				Action:            "approve",
			},
			ExpectedDecision: authz.DecisionDeny,
			ExpectedDenyCode: denyCode(authz.DenyUserMemberRevoked),
		},
	}
}

func (s Scenario) Matches(decision *authz.Decision) bool {
	if decision == nil || decision.Decision != s.ExpectedDecision {
		return false
	}
	if s.ExpectedDenyCode == nil {
		return decision.DenyCode == nil
	}
	if decision.DenyCode == nil {
		return false
	}

	return *decision.DenyCode == *s.ExpectedDenyCode
}

func denyCode(code authz.DenyCode) *authz.DenyCode {
	return &code
}
