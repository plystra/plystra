package authz_test

import (
	"testing"

	"github.com/plystra/core/internal/authz"
)

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
