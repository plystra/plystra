package authz

import (
	"fmt"
	"strings"
)

const groupTreeRule = "target_path = anchor_path OR target_path LIKE anchor_path || '.%'"

func ResolveScope(scope Scope, actor ActorSnapshot, target TargetSnapshot, anchor *GroupSnapshot) ScopeCheck {
	switch scope {
	case ScopeSelf:
		covered := target.Resource.OwnerMemberID == actor.Member.ID
		if covered {
			return ScopeCheck{
				Covered: true,
				Rule:    "resource.owner_member_id == actor.member_id",
				Reason:  "target resource is owned by the active Member identity.",
			}
		}

		return ScopeCheck{
			Covered:  false,
			Rule:     "resource.owner_member_id == actor.member_id",
			Reason:   "target resource is not owned by the active Member identity.",
			DenyCode: denyCodePtr(DenyScopeOutOfBounds),
		}

	case ScopeGroup:
		if anchor == nil {
			return missingAnchorCheck()
		}
		if target.Group == nil {
			return missingTargetGroupCheck()
		}

		covered := target.Group.ID == anchor.ID
		if covered {
			return ScopeCheck{
				Covered: true,
				Rule:    "target_group_id = scope_anchor_group_id",
				Reason:  fmt.Sprintf("target group %s matches anchor group %s.", target.Group.Path, anchor.Path),
			}
		}

		return ScopeCheck{
			Covered:  false,
			Rule:     "target_group_id = scope_anchor_group_id",
			Reason:   fmt.Sprintf("target group %s does not match anchor group %s.", target.Group.Path, anchor.Path),
			DenyCode: denyCodePtr(DenyScopeOutOfBounds),
		}

	case ScopeGroupTree:
		if anchor == nil {
			return missingAnchorCheck()
		}
		if target.Group == nil {
			return missingTargetGroupCheck()
		}

		covered := target.Group.Path == anchor.Path || strings.HasPrefix(target.Group.Path, anchor.Path+".")
		if covered {
			return ScopeCheck{
				Covered: true,
				Rule:    groupTreeRule,
				Reason:  fmt.Sprintf("target group %s is inside anchor group %s.", target.Group.Path, anchor.Path),
			}
		}

		return ScopeCheck{
			Covered:  false,
			Rule:     groupTreeRule,
			Reason:   fmt.Sprintf("target group %s is outside anchor group %s.", target.Group.Path, anchor.Path),
			DenyCode: denyCodePtr(DenyScopeOutOfBounds),
		}

	case ScopeSpace:
		covered := target.Resource.SpaceID == actor.Member.SpaceID
		if covered {
			return ScopeCheck{
				Covered: true,
				Rule:    "resource.space_id == actor.space_id",
				Reason:  "target resource belongs to the active Space.",
			}
		}

		return ScopeCheck{
			Covered:  false,
			Rule:     "resource.space_id == actor.space_id",
			Reason:   "target resource does not belong to the active Space.",
			DenyCode: denyCodePtr(DenyScopeOutOfBounds),
		}

	case ScopeGlobal:
		return ScopeCheck{
			Covered:  false,
			Rule:     "global scope disabled for ordinary Members",
			Reason:   "global scope is reserved and disabled in v1.0.",
			DenyCode: denyCodePtr(DenyGlobalScopeDisabled),
		}

	default:
		return ScopeCheck{
			Covered:  false,
			Rule:     "known permission scope",
			Reason:   fmt.Sprintf("unsupported scope %q.", scope),
			DenyCode: denyCodePtr(DenyScopeOutOfBounds),
		}
	}
}

func missingAnchorCheck() ScopeCheck {
	return ScopeCheck{
		Covered:  false,
		Rule:     "scope_anchor_group_id is required",
		Reason:   "permission grant is missing a scope anchor group.",
		DenyCode: denyCodePtr(DenyScopeAnchorMissing),
	}
}

func missingTargetGroupCheck() ScopeCheck {
	return ScopeCheck{
		Covered:  false,
		Rule:     "target resource must have group_id",
		Reason:   "target resource is missing a group.",
		DenyCode: denyCodePtr(DenyTargetGroupMissing),
	}
}
