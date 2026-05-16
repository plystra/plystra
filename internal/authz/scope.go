package authz

import (
	"fmt"
	"strings"

	contractauthz "github.com/plystra/plystra/internal/kernel/contracts/authz"
)

const groupTreeRule = "target_path = anchor_path OR target_path LIKE anchor_path || '.%'"

func resolveScope(scope contractauthz.Scope, actor contractauthz.ActorSnapshot, target contractauthz.TargetSnapshot, anchor *contractauthz.GroupSnapshot) contractauthz.ScopeCheck {
	switch scope {
	case contractauthz.ScopeSelf:
		covered := target.Resource.OwnerMemberID == actor.Member.ID
		if covered {
			return contractauthz.ScopeCheck{Covered: true, Rule: "resource.owner_member_id == actor.member_id", Reason: "target resource is owned by the active Member identity."}
		}
		return contractauthz.ScopeCheck{Covered: false, Rule: "resource.owner_member_id == actor.member_id", Reason: "target resource is not owned by the active Member identity.", DenyCode: denyCodePtr(contractauthz.DenyScopeOutOfBounds)}
	case contractauthz.ScopeGroup:
		if anchor == nil {
			return missingAnchorCheck()
		}
		if target.Group == nil {
			return missingTargetGroupCheck()
		}
		covered := target.Group.ID == anchor.ID
		if covered {
			return contractauthz.ScopeCheck{Covered: true, Rule: "target_group_id = scope_anchor_group_id", Reason: fmt.Sprintf("target group %s matches anchor group %s.", target.Group.Path, anchor.Path)}
		}
		return contractauthz.ScopeCheck{Covered: false, Rule: "target_group_id = scope_anchor_group_id", Reason: fmt.Sprintf("target group %s does not match anchor group %s.", target.Group.Path, anchor.Path), DenyCode: denyCodePtr(contractauthz.DenyScopeOutOfBounds)}
	case contractauthz.ScopeGroupTree:
		if anchor == nil {
			return missingAnchorCheck()
		}
		if target.Group == nil {
			return missingTargetGroupCheck()
		}
		covered := target.Group.Path == anchor.Path || strings.HasPrefix(target.Group.Path, anchor.Path+".")
		if covered {
			return contractauthz.ScopeCheck{Covered: true, Rule: groupTreeRule, Reason: fmt.Sprintf("target group %s is inside anchor group %s.", target.Group.Path, anchor.Path)}
		}
		return contractauthz.ScopeCheck{Covered: false, Rule: groupTreeRule, Reason: fmt.Sprintf("target group %s is outside anchor group %s.", target.Group.Path, anchor.Path), DenyCode: denyCodePtr(contractauthz.DenyScopeOutOfBounds)}
	case contractauthz.ScopeSpace:
		covered := target.Resource.SpaceID == actor.Member.SpaceID
		if covered {
			return contractauthz.ScopeCheck{Covered: true, Rule: "resource.space_id == actor.space_id", Reason: "target resource belongs to the active Space."}
		}
		return contractauthz.ScopeCheck{Covered: false, Rule: "resource.space_id == actor.space_id", Reason: "target resource does not belong to the active Space.", DenyCode: denyCodePtr(contractauthz.DenyScopeOutOfBounds)}
	case contractauthz.ScopeGlobal:
		return contractauthz.ScopeCheck{Covered: false, Rule: "global scope disabled for ordinary Members", Reason: "global scope is reserved and disabled in v1.0.", DenyCode: denyCodePtr(contractauthz.DenyGlobalScopeDisabled)}
	default:
		return contractauthz.ScopeCheck{Covered: false, Rule: "known permission scope", Reason: fmt.Sprintf("unsupported scope %q.", scope), DenyCode: denyCodePtr(contractauthz.DenyScopeOutOfBounds)}
	}
}

func missingAnchorCheck() contractauthz.ScopeCheck {
	return contractauthz.ScopeCheck{Covered: false, Rule: "scope_anchor_group_id is required", Reason: "permission grant is missing a scope anchor group.", DenyCode: denyCodePtr(contractauthz.DenyScopeAnchorMissing)}
}

func missingTargetGroupCheck() contractauthz.ScopeCheck {
	return contractauthz.ScopeCheck{Covered: false, Rule: "target resource must have group_id", Reason: "target resource is missing a group.", DenyCode: denyCodePtr(contractauthz.DenyTargetGroupMissing)}
}
