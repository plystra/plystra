package demo

import (
	"fmt"
	"io"

	"github.com/plystra/plystra/internal/authz"
)

func PrintDecision(w io.Writer, scenario Scenario, decision *authz.Decision) {
	fmt.Fprintf(w, "case: %d\n", scenario.Case)
	fmt.Fprintf(w, "name: %s\n", scenario.Name)
	fmt.Fprintf(w, "decision: %s\n", decision.Decision)
	fmt.Fprintf(w, "deny_code: %s\n\n", nullableDenyCode(decision.DenyCode))

	fmt.Fprintln(w, "actor:")
	fmt.Fprintln(w, "  user:")
	fmt.Fprintf(w, "    id: %s\n", decision.Actor.User.ID)
	fmt.Fprintf(w, "    email: %s\n", decision.Actor.User.Email)
	fmt.Fprintln(w, "  member:")
	fmt.Fprintf(w, "    id: %s\n", decision.Actor.Member.ID)
	fmt.Fprintf(w, "    display_name: %s\n", decision.Actor.Member.DisplayName)
	fmt.Fprintln(w, "  user_member:")
	fmt.Fprintf(w, "    id: %s\n", decision.Actor.UserMember.ID)
	fmt.Fprintf(w, "    relation_type: %s\n", decision.Actor.UserMember.RelationType)
	fmt.Fprintf(w, "    status: %s\n\n", decision.Actor.UserMember.Status)

	fmt.Fprintln(w, "space:")
	fmt.Fprintf(w, "  id: %s\n", decision.Space.ID)
	fmt.Fprintf(w, "  name: %s\n\n", decision.Space.Name)

	fmt.Fprintln(w, "target:")
	fmt.Fprintln(w, "  resource:")
	fmt.Fprintf(w, "    id: %s\n", decision.Target.Resource.ID)
	fmt.Fprintf(w, "    type: %s\n", decision.Target.Resource.Type)
	fmt.Fprintln(w, "  group:")
	if decision.Target.Group == nil {
		fmt.Fprintln(w, "    id: null")
		fmt.Fprintln(w, "    path: null")
	} else {
		fmt.Fprintf(w, "    id: %s\n", decision.Target.Group.ID)
		fmt.Fprintf(w, "    path: %s\n", decision.Target.Group.Path)
	}

	fmt.Fprintln(w, "\nmatched_candidates:")
	if len(decision.MatchedCandidates) == 0 {
		fmt.Fprintln(w, "  []")
	} else {
		for _, candidate := range decision.MatchedCandidates {
			printCandidate(w, candidate)
		}
	}

	fmt.Fprintf(w, "\nreason: %s\n\n", decision.Reason)
	fmt.Fprintln(w, "audit:")
	fmt.Fprintf(w, "  actor_user_id: %s\n", decision.Audit.ActorUserID)
	fmt.Fprintf(w, "  actor_member_id: %s\n", decision.Audit.ActorMemberID)
	fmt.Fprintf(w, "  actor_user_member_id: %s\n", decision.Audit.ActorUserMemberID)
	fmt.Fprintf(w, "  space_id: %s\n", decision.Audit.SpaceID)
	fmt.Fprintf(w, "  action: %s\n", decision.Audit.Action)
	fmt.Fprintf(w, "  resource_type: %s\n", decision.Audit.ResourceType)
	fmt.Fprintf(w, "  resource_id: %s\n", decision.Audit.ResourceID)
	fmt.Fprintf(w, "  decision: %s\n", decision.Audit.Decision)
	fmt.Fprintln(w, "---")
}

func printCandidate(w io.Writer, candidate authz.PermissionCandidate) {
	fmt.Fprintln(w, "  - role:")
	fmt.Fprintf(w, "      id: %s\n", candidate.Role.ID)
	fmt.Fprintf(w, "      key: %s\n", candidate.Role.Key)
	fmt.Fprintln(w, "    permission:")
	fmt.Fprintf(w, "      resource: %s\n", candidate.Permission.Resource)
	fmt.Fprintf(w, "      action: %s\n", candidate.Permission.Action)
	fmt.Fprintf(w, "      scope: %s\n", candidate.Permission.Scope)
	fmt.Fprintln(w, "    scope_anchor:")
	if candidate.ScopeAnchor == nil {
		fmt.Fprintln(w, "      group_id: null")
		fmt.Fprintln(w, "      path: null")
	} else {
		fmt.Fprintf(w, "      group_id: %s\n", candidate.ScopeAnchor.ID)
		fmt.Fprintf(w, "      path: %s\n", candidate.ScopeAnchor.Path)
	}
	fmt.Fprintln(w, "    scope_check:")
	fmt.Fprintf(w, "      covered: %t\n", candidate.ScopeCheck.Covered)
	fmt.Fprintf(w, "      rule: %s\n", candidate.ScopeCheck.Rule)
	fmt.Fprintf(w, "      reason: %s\n", candidate.ScopeCheck.Reason)
}

func nullableDenyCode(code *authz.DenyCode) string {
	if code == nil {
		return "null"
	}

	return string(*code)
}
