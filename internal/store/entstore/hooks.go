package entstore

import (
	"context"
	"errors"
	"fmt"

	entgo "entgo.io/ent"

	"github.com/plystra/plystra/ent/group"
	"github.com/plystra/plystra/ent/member"
	"github.com/plystra/plystra/ent/memberrole"
	"github.com/plystra/plystra/ent/resource"
	"github.com/plystra/plystra/ent/role"
	"github.com/plystra/plystra/ent/usermember"
)

func (s *Store) installHooks() {
	if s == nil || s.client == nil {
		return
	}

	rejectSoftDeleteOnly := rejectHardDelete("core entities referenced by AuditLog are soft-delete-only")
	s.client.User.Use(rejectSoftDeleteOnly)
	s.client.Space.Use(rejectSoftDeleteOnly)
	s.client.Group.Use(rejectSoftDeleteOnly)
	s.client.Member.Use(rejectSoftDeleteOnly)
	s.client.UserMember.Use(rejectSoftDeleteOnly, s.enforceUserMemberSameSpace())
	s.client.Role.Use(rejectSoftDeleteOnly)
	s.client.Permission.Use(rejectSoftDeleteOnly)
	s.client.MemberRole.Use(rejectSoftDeleteOnly, s.enforceMemberRoleSameSpace())
	s.client.RolePermission.Use(rejectSoftDeleteOnly)
	s.client.Resource.Use(rejectSoftDeleteOnly, s.enforceResourceSameSpace())
	s.client.AuditLog.Use(rejectAuditLogMutation())
}

func rejectAuditLogMutation() entgo.Hook {
	return func(next entgo.Mutator) entgo.Mutator {
		return entgo.MutateFunc(func(ctx context.Context, m entgo.Mutation) (entgo.Value, error) {
			if m.Op().Is(entgo.OpUpdate | entgo.OpUpdateOne | entgo.OpDelete | entgo.OpDeleteOne) {
				return nil, errors.New("audit logs are append-only")
			}
			return next.Mutate(ctx, m)
		})
	}
}

func rejectHardDelete(message string) entgo.Hook {
	return func(next entgo.Mutator) entgo.Mutator {
		return entgo.MutateFunc(func(ctx context.Context, m entgo.Mutation) (entgo.Value, error) {
			if m.Op().Is(entgo.OpDelete | entgo.OpDeleteOne) {
				return nil, errors.New(message)
			}
			return next.Mutate(ctx, m)
		})
	}
}

func (s *Store) enforceUserMemberSameSpace() entgo.Hook {
	return func(next entgo.Mutator) entgo.Mutator {
		return entgo.MutateFunc(func(ctx context.Context, m entgo.Mutation) (entgo.Value, error) {
			if !m.Op().Is(entgo.OpCreate | entgo.OpUpdate | entgo.OpUpdateOne) {
				return next.Mutate(ctx, m)
			}
			memberID, spaceID, err := finalStrings(ctx, m, usermember.FieldMemberID, usermember.FieldSpaceID)
			if err != nil {
				return nil, err
			}
			if err := s.memberBelongsToSpace(ctx, memberID, spaceID); err != nil {
				return nil, fmt.Errorf("validate UserMember same-space invariant: %w", err)
			}
			return next.Mutate(ctx, m)
		})
	}
}

func (s *Store) enforceMemberRoleSameSpace() entgo.Hook {
	return func(next entgo.Mutator) entgo.Mutator {
		return entgo.MutateFunc(func(ctx context.Context, m entgo.Mutation) (entgo.Value, error) {
			if !m.Op().Is(entgo.OpCreate | entgo.OpUpdate | entgo.OpUpdateOne) {
				return next.Mutate(ctx, m)
			}
			memberID, roleID, spaceID, err := finalThreeStrings(ctx, m, memberrole.FieldMemberID, memberrole.FieldRoleID, memberrole.FieldSpaceID)
			if err != nil {
				return nil, err
			}
			if err := s.memberBelongsToSpace(ctx, memberID, spaceID); err != nil {
				return nil, fmt.Errorf("validate MemberRole member same-space invariant: %w", err)
			}
			roleRecord, err := s.client.Role.Query().Where(role.ID(roleID), role.DeletedAtIsNil()).Only(ctx)
			if err != nil {
				return nil, err
			}
			if roleRecord.SpaceID != spaceID {
				return nil, fmt.Errorf("role %s belongs to space %s, not %s", roleID, roleRecord.SpaceID, spaceID)
			}
			anchorID, err := finalNullableString(ctx, m, memberrole.FieldScopeAnchorGroupID)
			if err != nil {
				return nil, err
			}
			if anchorID != nil {
				if err := s.groupBelongsToSpace(ctx, *anchorID, spaceID); err != nil {
					return nil, fmt.Errorf("validate MemberRole scope anchor same-space invariant: %w", err)
				}
			}
			return next.Mutate(ctx, m)
		})
	}
}

func (s *Store) enforceResourceSameSpace() entgo.Hook {
	return func(next entgo.Mutator) entgo.Mutator {
		return entgo.MutateFunc(func(ctx context.Context, m entgo.Mutation) (entgo.Value, error) {
			if !m.Op().Is(entgo.OpCreate | entgo.OpUpdate | entgo.OpUpdateOne) {
				return next.Mutate(ctx, m)
			}
			spaceID, err := finalString(ctx, m, resource.FieldSpaceID)
			if err != nil {
				return nil, err
			}
			groupID, err := finalNullableString(ctx, m, resource.FieldGroupID)
			if err != nil {
				return nil, err
			}
			if groupID != nil {
				if err := s.groupBelongsToSpace(ctx, *groupID, spaceID); err != nil {
					return nil, fmt.Errorf("validate Resource group same-space invariant: %w", err)
				}
			}
			ownerMemberID, err := finalNullableString(ctx, m, resource.FieldOwnerMemberID)
			if err != nil {
				return nil, err
			}
			if ownerMemberID != nil {
				if err := s.memberBelongsToSpace(ctx, *ownerMemberID, spaceID); err != nil {
					return nil, fmt.Errorf("validate Resource owner same-space invariant: %w", err)
				}
			}
			return next.Mutate(ctx, m)
		})
	}
}

func (s *Store) memberBelongsToSpace(ctx context.Context, memberID, spaceID string) error {
	memberRecord, err := s.client.Member.Query().Where(member.ID(memberID), member.DeletedAtIsNil()).Only(ctx)
	if err != nil {
		return err
	}
	if memberRecord.SpaceID != spaceID {
		return fmt.Errorf("member %s belongs to space %s, not %s", memberID, memberRecord.SpaceID, spaceID)
	}
	return nil
}

func (s *Store) groupBelongsToSpace(ctx context.Context, groupID, spaceID string) error {
	groupRecord, err := s.client.Group.Query().Where(group.ID(groupID), group.DeletedAtIsNil()).Only(ctx)
	if err != nil {
		return err
	}
	if groupRecord.SpaceID != spaceID {
		return fmt.Errorf("group %s belongs to space %s, not %s", groupID, groupRecord.SpaceID, spaceID)
	}
	return nil
}

func finalStrings(ctx context.Context, m entgo.Mutation, first, second string) (string, string, error) {
	firstValue, err := finalString(ctx, m, first)
	if err != nil {
		return "", "", err
	}
	secondValue, err := finalString(ctx, m, second)
	if err != nil {
		return "", "", err
	}
	return firstValue, secondValue, nil
}

func finalThreeStrings(ctx context.Context, m entgo.Mutation, first, second, third string) (string, string, string, error) {
	firstValue, err := finalString(ctx, m, first)
	if err != nil {
		return "", "", "", err
	}
	secondValue, err := finalString(ctx, m, second)
	if err != nil {
		return "", "", "", err
	}
	thirdValue, err := finalString(ctx, m, third)
	if err != nil {
		return "", "", "", err
	}
	return firstValue, secondValue, thirdValue, nil
}

func finalString(ctx context.Context, m entgo.Mutation, field string) (string, error) {
	if value, ok := m.Field(field); ok {
		return asString(field, value)
	}
	if m.Op().Is(entgo.OpUpdateOne) {
		value, err := m.OldField(ctx, field)
		if err != nil {
			return "", err
		}
		return asString(field, value)
	}
	return "", fmt.Errorf("%s is required to validate same-space invariant", field)
}

func finalNullableString(ctx context.Context, m entgo.Mutation, field string) (*string, error) {
	if m.FieldCleared(field) {
		return nil, nil
	}
	if value, ok := m.Field(field); ok {
		return asNullableString(field, value)
	}
	if m.Op().Is(entgo.OpUpdateOne) {
		value, err := m.OldField(ctx, field)
		if err != nil {
			return nil, err
		}
		return asNullableString(field, value)
	}
	return nil, nil
}

func asString(field string, value any) (string, error) {
	out, ok := value.(string)
	if !ok || out == "" {
		return "", fmt.Errorf("%s must be a non-empty string", field)
	}
	return out, nil
}

func asNullableString(field string, value any) (*string, error) {
	switch typed := value.(type) {
	case nil:
		return nil, nil
	case string:
		if typed == "" {
			return nil, nil
		}
		return &typed, nil
	case *string:
		if typed == nil || *typed == "" {
			return nil, nil
		}
		return typed, nil
	default:
		return nil, fmt.Errorf("%s must be a nullable string", field)
	}
}
