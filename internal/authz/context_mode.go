package authz

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"

	contractauthz "github.com/plystra/plystra/internal/kernel/contracts/authz"
)

func buildInlineAuthorizationContext(ctx context.Context, store contractauthz.Store, input contractauthz.CheckInput) (contractauthz.AuthorizationContext, error) {
	actorContext := input.NormalizedActor()
	actor, err := inlineActorSnapshot(actorContext)
	if err != nil {
		return contractauthz.AuthorizationContext{}, err
	}

	registry, registryErr := store.LoadResourceRegistration(ctx, input.ResourceType, input.Action)
	if registryErr != nil {
		if registryErr == contractauthz.ErrResourceTypeNotFound || registryErr == contractauthz.ErrResourceActionNotFound {
			return contractauthz.AuthorizationContext{Actor: actor, ResourceRegistry: registry, RegistryErr: registryErr, RegistryError: registryErr.Error()}, nil
		}
		return contractauthz.AuthorizationContext{}, fmt.Errorf("load resource registry metadata: %w", registryErr)
	}

	target, err := inlineTargetSnapshot(input)
	if err != nil {
		return contractauthz.AuthorizationContext{}, err
	}
	candidates, err := inlinePermissionCandidates(input)
	if err != nil {
		return contractauthz.AuthorizationContext{}, err
	}

	return contractauthz.AuthorizationContext{
		Actor:              actor,
		ResourceRegistry:   registry,
		Target:             target,
		PermissionGrants:   candidates,
		PermissionFiltered: true,
	}, nil
}

func validateInlineContextInput(input contractauthz.CheckInput) error {
	input = input.Normalized()
	if _, err := inlineActorSnapshot(input.Actor); err != nil {
		return err
	}
	if _, err := inlineTargetSnapshot(input); err != nil {
		return err
	}
	if _, err := inlinePermissionCandidates(input); err != nil {
		return err
	}
	return nil
}

func inlineActorSnapshot(actor contractauthz.ActorContext) (contractauthz.ActorSnapshot, error) {
	if actor.UserID == "" || actor.MemberID == "" || actor.UserMemberID == "" || actor.SpaceID == "" {
		return contractauthz.ActorSnapshot{}, fmt.Errorf("inline actor requires user_id, member_id, user_member_id or binding_id, and space_id")
	}
	userStatus := defaultStatus(actor.UserStatus)
	memberStatus := defaultStatus(actor.MemberStatus)
	bindingStatus := defaultStatus(actor.BindingStatus)
	spaceStatus := defaultStatus(actor.SpaceStatus)
	spaceName := actor.SpaceName
	if spaceName == "" {
		spaceName = actor.SpaceID
	}
	memberName := actor.MemberName
	if memberName == "" {
		memberName = actor.MemberID
	}
	relationType := actor.RelationType
	if relationType == "" {
		relationType = "external"
	}
	return contractauthz.ActorSnapshot{
		User: contractauthz.UserSnapshot{ID: actor.UserID, Email: actor.UserEmail, Status: userStatus},
		Member: contractauthz.MemberSnapshot{
			ID:          actor.MemberID,
			SpaceID:     actor.SpaceID,
			DisplayName: memberName,
			Status:      memberStatus,
		},
		UserMember: contractauthz.UserMemberSnapshot{
			ID:           actor.UserMemberID,
			UserID:       actor.UserID,
			MemberID:     actor.MemberID,
			SpaceID:      actor.SpaceID,
			RelationType: relationType,
			Status:       bindingStatus,
			IsPrimary:    true,
		},
		Space: contractauthz.SpaceSnapshot{ID: actor.SpaceID, Name: spaceName, Status: spaceStatus},
	}, nil
}

func inlineTargetSnapshot(input contractauthz.CheckInput) (contractauthz.TargetSnapshot, error) {
	if input.Target == nil {
		return contractauthz.TargetSnapshot{}, fmt.Errorf("inline resource context is required in Context Mode")
	}
	target := *input.Target
	if target.Resource.Type == "" {
		target.Resource.Type = input.ResourceType
	}
	if target.Resource.Type != input.ResourceType {
		return contractauthz.TargetSnapshot{}, fmt.Errorf("inline resource type %q does not match requested resource_type %q", target.Resource.Type, input.ResourceType)
	}
	if target.Resource.ID == "" {
		target.Resource.ID = firstNonEmpty(target.Resource.ExternalID, input.ResourceID)
	}
	if target.Resource.ExternalID == "" {
		target.Resource.ExternalID = target.Resource.ID
	}
	if target.Resource.Type == "" || target.Resource.ID == "" || target.Resource.SpaceID == "" {
		return contractauthz.TargetSnapshot{}, fmt.Errorf("inline resource requires type, external_id or id, and space_id")
	}
	if target.Resource.Status == "" {
		target.Resource.Status = contractauthz.StatusActive
	}
	if target.Group == nil && (target.Resource.GroupID != "" || target.Resource.GroupPath != "") {
		path := target.Resource.GroupPath
		id := target.Resource.GroupID
		if path == "" {
			path = id
		}
		if id == "" {
			id = syntheticGroupID(target.Resource.SpaceID, path)
		}
		target.Group = &contractauthz.GroupSnapshot{ID: id, SpaceID: target.Resource.SpaceID, Path: path, Status: contractauthz.StatusActive}
	}
	if target.Group != nil {
		if target.Group.SpaceID == "" {
			target.Group.SpaceID = target.Resource.SpaceID
		}
		if target.Group.Path == "" {
			target.Group.Path = firstNonEmpty(target.Resource.GroupPath, target.Group.ID)
		}
		if target.Group.ID == "" {
			target.Group.ID = syntheticGroupID(target.Group.SpaceID, target.Group.Path)
		}
		if target.Group.Status == "" {
			target.Group.Status = contractauthz.StatusActive
		}
		if target.Resource.GroupID == "" {
			target.Resource.GroupID = target.Group.ID
		}
		if target.Resource.GroupPath == "" {
			target.Resource.GroupPath = target.Group.Path
		}
	}
	return target, nil
}

func inlinePermissionCandidates(input contractauthz.CheckInput) ([]contractauthz.PermissionCandidate, error) {
	candidates := make([]contractauthz.PermissionCandidate, 0, len(input.InlineGrants))
	actor := input.NormalizedActor()
	for idx, grant := range input.InlineGrants {
		resource := firstNonEmpty(grant.Resource, input.ResourceType)
		action := firstNonEmpty(grant.Action, input.Action)
		spaceID := firstNonEmpty(grant.SpaceID, actor.SpaceID)
		if resource == "" || action == "" || grant.Scope == "" || spaceID == "" {
			return nil, fmt.Errorf("inline grant %d requires resource, action, scope, and space_id or actor.space_id", idx)
		}
		if !validInlineScope(grant.Scope) {
			return nil, fmt.Errorf("inline grant %d has unsupported scope %q", idx, grant.Scope)
		}
		if resource != input.ResourceType || action != input.Action {
			continue
		}
		roleKey := grant.RoleKey
		if roleKey == "" {
			roleKey = "inline"
		}
		roleID := grant.RoleID
		if roleID == "" {
			roleID = "role_inline_" + safeToken(roleKey)
		}
		permissionID := grant.PermissionID
		if permissionID == "" {
			permissionID = "perm_inline_" + safeToken(resource+"_"+action+"_"+string(grant.Scope))
		}
		var anchor *contractauthz.GroupSnapshot
		if grant.ScopeAnchorGroupID != "" || grant.ScopeAnchorGroupPath != "" {
			path := firstNonEmpty(grant.ScopeAnchorGroupPath, grant.ScopeAnchorGroupID)
			id := firstNonEmpty(grant.ScopeAnchorGroupID, syntheticGroupID(spaceID, path))
			anchor = &contractauthz.GroupSnapshot{ID: id, SpaceID: spaceID, Path: path, Status: contractauthz.StatusActive}
		}
		candidates = append(candidates, contractauthz.PermissionCandidate{
			Role:              contractauthz.RoleSnapshot{ID: roleID, Key: roleKey, SpaceID: spaceID},
			Permission:        contractauthz.PermissionSnapshot{ID: permissionID, Resource: resource, Action: action, Scope: grant.Scope},
			ScopeAnchor:       anchor,
			MemberRoleSpaceID: spaceID,
		})
	}
	return candidates, nil
}

func validInlineScope(scope contractauthz.Scope) bool {
	switch scope {
	case contractauthz.ScopeSelf, contractauthz.ScopeGroup, contractauthz.ScopeGroupTree, contractauthz.ScopeSpace, contractauthz.ScopeGlobal:
		return true
	default:
		return false
	}
}

func defaultStatus(status string) string {
	status = strings.TrimSpace(status)
	if status == "" {
		return contractauthz.StatusActive
	}
	return status
}

func syntheticGroupID(spaceID, path string) string {
	hash := sha1.Sum([]byte(spaceID + "\x00" + path))
	return "group_inline_" + hex.EncodeToString(hash[:])[:16]
}

func safeToken(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := strings.Trim(b.String(), "_")
	if out == "" {
		return "value"
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
