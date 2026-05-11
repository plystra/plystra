package entstore

import (
	"context"
	"sort"

	coreent "github.com/plystra/plystra/ent"
	"github.com/plystra/plystra/ent/group"
	"github.com/plystra/plystra/ent/member"
	"github.com/plystra/plystra/ent/memberrole"
	"github.com/plystra/plystra/ent/permission"
	"github.com/plystra/plystra/ent/resource"
	"github.com/plystra/plystra/ent/resourceaction"
	"github.com/plystra/plystra/ent/resourcemapping"
	"github.com/plystra/plystra/ent/resourcetype"
	"github.com/plystra/plystra/ent/role"
	"github.com/plystra/plystra/ent/rolepermission"
	"github.com/plystra/plystra/ent/space"
	"github.com/plystra/plystra/ent/user"
	"github.com/plystra/plystra/ent/usermember"
	"github.com/plystra/plystra/internal/authz"
)

func (s *Store) LoadActor(ctx context.Context, actor authz.ActorContext) (authz.ActorSnapshot, error) {
	u, err := s.client.User.Query().
		Where(user.ID(actor.UserID), user.DeletedAtIsNil()).
		Only(ctx)
	if isNotFound(err) {
		return authz.ActorSnapshot{}, authz.ErrNotFound
	}
	if err != nil {
		return authz.ActorSnapshot{}, err
	}

	um, err := s.client.UserMember.Query().
		Where(
			usermember.ID(actor.UserMemberID),
			usermember.UserID(actor.UserID),
			usermember.MemberID(actor.MemberID),
			usermember.SpaceID(actor.SpaceID),
			usermember.DeletedAtIsNil(),
		).
		Only(ctx)
	if isNotFound(err) {
		return authz.ActorSnapshot{}, authz.ErrNotFound
	}
	if err != nil {
		return authz.ActorSnapshot{}, err
	}

	m, err := s.client.Member.Query().
		Where(member.ID(actor.MemberID), member.DeletedAtIsNil()).
		Only(ctx)
	if isNotFound(err) {
		return authz.ActorSnapshot{}, authz.ErrNotFound
	}
	if err != nil {
		return authz.ActorSnapshot{}, err
	}

	sp, err := s.client.Space.Query().
		Where(space.ID(actor.SpaceID), space.DeletedAtIsNil()).
		Only(ctx)
	if isNotFound(err) {
		return authz.ActorSnapshot{}, authz.ErrNotFound
	}
	if err != nil {
		return authz.ActorSnapshot{}, err
	}

	return authz.ActorSnapshot{
		User: authz.UserSnapshot{
			ID:     u.ID,
			Email:  u.Email,
			Status: u.Status,
		},
		Member: authz.MemberSnapshot{
			ID:          m.ID,
			SpaceID:     m.SpaceID,
			DisplayName: m.DisplayName,
			Status:      m.Status,
		},
		UserMember: authz.UserMemberSnapshot{
			ID:           um.ID,
			UserID:       um.UserID,
			MemberID:     um.MemberID,
			SpaceID:      um.SpaceID,
			RelationType: um.RelationType,
			Status:       um.Status,
			IsPrimary:    um.IsPrimary,
			ExpiresAt:    um.ExpiresAt,
		},
		Space: authz.SpaceSnapshot{
			ID:     sp.ID,
			Name:   sp.Name,
			Status: sp.Status,
		},
	}, nil
}

func (s *Store) LoadResourceRegistration(ctx context.Context, resourceType, action string) (authz.ResourceRegistrySnapshot, error) {
	rt, err := s.client.ResourceType.Query().
		Where(resourcetype.Key(resourceType)).
		Only(ctx)
	if isNotFound(err) {
		return authz.ResourceRegistrySnapshot{}, authz.ErrResourceTypeNotFound
	}
	if err != nil {
		return authz.ResourceRegistrySnapshot{}, err
	}

	ra, err := s.client.ResourceAction.Query().
		Where(resourceaction.ResourceTypeID(rt.ID), resourceaction.Key(action)).
		Only(ctx)
	if isNotFound(err) {
		return authz.ResourceRegistrySnapshot{}, authz.ErrResourceActionNotFound
	}
	if err != nil {
		return authz.ResourceRegistrySnapshot{}, err
	}

	rm, err := s.client.ResourceMapping.Query().
		Where(resourcemapping.ResourceTypeID(rt.ID)).
		Only(ctx)
	if err != nil {
		return authz.ResourceRegistrySnapshot{}, err
	}

	return authz.ResourceRegistrySnapshot{
		ResourceType: mapResourceType(rt),
		Action:       mapResourceAction(ra),
		Mapping:      mapResourceMapping(rm),
	}, nil
}

func (s *Store) LoadTarget(ctx context.Context, resourceType, resourceID string) (authz.TargetSnapshot, error) {
	res, err := s.client.Resource.Query().
		Where(resource.ID(resourceID), resource.ResourceType(resourceType), resource.DeletedAtIsNil()).
		Only(ctx)
	if isNotFound(err) {
		return authz.TargetSnapshot{}, authz.ErrNotFound
	}
	if err != nil {
		return authz.TargetSnapshot{}, err
	}

	target := authz.TargetSnapshot{Resource: mapResource(res)}
	if res.GroupID != nil {
		g, err := s.client.Group.Query().
			Where(group.ID(*res.GroupID), group.DeletedAtIsNil()).
			Only(ctx)
		if isNotFound(err) {
			return target, nil
		}
		if err != nil {
			return authz.TargetSnapshot{}, err
		}
		target.Group = &authz.GroupSnapshot{
			ID:      g.ID,
			SpaceID: g.SpaceID,
			Path:    g.Path,
			Status:  g.Status,
		}
	}

	return target, nil
}

func (s *Store) loadTargetSnapshot(ctx context.Context, input authz.CheckInput) (authz.TargetSnapshot, error) {
	if input.Target != nil {
		target := *input.Target
		if target.Resource.ID == "" {
			target.Resource.ID = input.ResourceID
		}
		if target.Resource.Type == "" {
			target.Resource.Type = input.ResourceType
		}
		return target, nil
	}
	return s.LoadTarget(ctx, input.ResourceType, input.ResourceID)
}

func (s *Store) LoadPermissionCandidates(ctx context.Context, query authz.CandidateQuery) ([]authz.PermissionCandidate, error) {
	grants, err := s.client.MemberRole.Query().
		Where(
			memberrole.MemberID(query.MemberID),
			memberrole.Status(authz.StatusActive),
			memberrole.DeletedAtIsNil(),
		).
		All(ctx)
	if err != nil {
		return nil, err
	}
	if len(grants) == 0 {
		return nil, nil
	}

	roleIDs := uniqueStringsFrom(grants, func(grant *coreent.MemberRole) string { return grant.RoleID })
	perms, err := s.client.Permission.Query().
		Where(
			permission.Resource(query.ResourceType),
			permission.Action(query.Action),
			permission.Status(authz.StatusActive),
			permission.DeletedAtIsNil(),
		).
		All(ctx)
	if err != nil {
		return nil, err
	}
	if len(perms) == 0 {
		return nil, nil
	}
	permissionIDs := uniqueStringsFrom(perms, func(perm *coreent.Permission) string { return perm.ID })

	rolePerms, err := s.client.RolePermission.Query().
		Where(
			rolepermission.RoleIDIn(roleIDs...),
			rolepermission.PermissionIDIn(permissionIDs...),
			rolepermission.DeletedAtIsNil(),
		).
		All(ctx)
	if err != nil {
		return nil, err
	}
	if len(rolePerms) == 0 {
		return nil, nil
	}

	roles, err := s.client.Role.Query().
		Where(
			role.IDIn(uniqueStringsFrom(rolePerms, func(rp *coreent.RolePermission) string { return rp.RoleID })...),
			role.Status(authz.StatusActive),
			role.DeletedAtIsNil(),
		).
		All(ctx)
	if err != nil {
		return nil, err
	}

	rolesByID := mapRoles(roles)
	permsByID := mapPermissions(perms)
	grantsByRole := mapMemberRoles(grants)
	anchors, err := s.loadAnchorGroups(ctx, grants)
	if err != nil {
		return nil, err
	}

	var candidates []authz.PermissionCandidate
	for _, rp := range rolePerms {
		roleSnapshot, ok := rolesByID[rp.RoleID]
		if !ok {
			continue
		}
		permissionSnapshot, ok := permsByID[rp.PermissionID]
		if !ok {
			continue
		}
		for _, grant := range grantsByRole[rp.RoleID] {
			candidates = append(candidates, authz.PermissionCandidate{
				Role:              roleSnapshot,
				Permission:        permissionSnapshot,
				ScopeAnchor:       anchors[derefString(grant.ScopeAnchorGroupID)],
				MemberRoleSpaceID: grant.SpaceID,
			})
		}
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		left, right := candidates[i], candidates[j]
		if left.Role.Key != right.Role.Key {
			return left.Role.Key < right.Role.Key
		}
		if left.Permission.Resource != right.Permission.Resource {
			return left.Permission.Resource < right.Permission.Resource
		}
		if left.Permission.Action != right.Permission.Action {
			return left.Permission.Action < right.Permission.Action
		}
		return left.Permission.Scope < right.Permission.Scope
	})

	return candidates, nil
}

func (s *Store) loadAnchorGroups(ctx context.Context, grants []*coreent.MemberRole) (map[string]*authz.GroupSnapshot, error) {
	anchorIDs := uniqueStringsFrom(grants, func(grant *coreent.MemberRole) string {
		return derefString(grant.ScopeAnchorGroupID)
	})
	if len(anchorIDs) == 0 {
		return map[string]*authz.GroupSnapshot{}, nil
	}
	groups, err := s.client.Group.Query().
		Where(group.IDIn(anchorIDs...), group.DeletedAtIsNil()).
		All(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]*authz.GroupSnapshot, len(groups))
	for _, g := range groups {
		value := authz.GroupSnapshot{
			ID:      g.ID,
			SpaceID: g.SpaceID,
			Path:    g.Path,
			Status:  g.Status,
		}
		out[g.ID] = &value
	}
	return out, nil
}
