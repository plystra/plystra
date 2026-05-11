package entstore

import (
	"context"

	coreent "github.com/plystra/plystra/ent"
	"github.com/plystra/plystra/ent/resourceaction"
	"github.com/plystra/plystra/ent/resourcemapping"
	"github.com/plystra/plystra/ent/resourcetype"
	"github.com/plystra/plystra/internal/authz"
	"github.com/plystra/plystra/internal/resources"
)

func (s *Store) UpsertResourceType(ctx context.Context, input resources.RegisterResourceTypeInput) (*resources.ResourceType, error) {
	existing, err := s.client.ResourceType.Query().Where(resourcetype.Key(input.Key)).Only(ctx)
	if err != nil && !isNotFound(err) {
		return nil, err
	}
	if isNotFound(err) {
		created, err := s.client.ResourceType.Create().
			SetID(newID("rt")).
			SetKey(input.Key).
			SetDisplayName(input.DisplayName).
			SetNillableDescription(nilIfEmpty(input.Description)).
			SetSource(input.Source).
			SetMetadata(nonNilMap(input.Metadata)).
			Save(ctx)
		if err != nil {
			return nil, err
		}
		out := mapResourceType(created)
		return &out, nil
	}

	builder := s.client.ResourceType.UpdateOneID(existing.ID).
		SetDisplayName(input.DisplayName).
		SetSource(input.Source).
		SetMetadata(nonNilMap(input.Metadata))
	if input.Description == "" {
		builder.ClearDescription()
	} else {
		builder.SetDescription(input.Description)
	}
	updated, err := builder.Save(ctx)
	if err != nil {
		return nil, err
	}
	out := mapResourceType(updated)
	return &out, nil
}

func (s *Store) UpsertResourceAction(ctx context.Context, input resources.RegisterResourceActionInput) (*resources.ResourceAction, error) {
	rt, err := s.client.ResourceType.Query().Where(resourcetype.Key(input.ResourceTypeKey)).Only(ctx)
	if isNotFound(err) {
		return nil, authz.ErrResourceTypeNotFound
	}
	if err != nil {
		return nil, err
	}

	existing, err := s.client.ResourceAction.Query().
		Where(resourceaction.ResourceTypeID(rt.ID), resourceaction.Key(input.Key)).
		Only(ctx)
	if err != nil && !isNotFound(err) {
		return nil, err
	}
	if isNotFound(err) {
		created, err := s.client.ResourceAction.Create().
			SetID(newID("ra")).
			SetResourceTypeID(rt.ID).
			SetKey(input.Key).
			SetDisplayName(input.DisplayName).
			SetNillableDescription(nilIfEmpty(input.Description)).
			SetRiskLevel(input.RiskLevel).
			SetAuditDefault(input.AuditDefault).
			SetMetadata(nonNilMap(input.Metadata)).
			Save(ctx)
		if err != nil {
			return nil, err
		}
		out := mapResourceAction(created)
		return &out, nil
	}

	builder := s.client.ResourceAction.UpdateOneID(existing.ID).
		SetDisplayName(input.DisplayName).
		SetRiskLevel(input.RiskLevel).
		SetAuditDefault(input.AuditDefault).
		SetMetadata(nonNilMap(input.Metadata))
	if input.Description == "" {
		builder.ClearDescription()
	} else {
		builder.SetDescription(input.Description)
	}
	updated, err := builder.Save(ctx)
	if err != nil {
		return nil, err
	}
	out := mapResourceAction(updated)
	return &out, nil
}

func (s *Store) UpsertResourceMapping(ctx context.Context, input resources.RegisterResourceMappingInput) (*resources.ResourceMapping, error) {
	rt, err := s.client.ResourceType.Query().Where(resourcetype.Key(input.ResourceTypeKey)).Only(ctx)
	if isNotFound(err) {
		return nil, authz.ErrResourceTypeNotFound
	}
	if err != nil {
		return nil, err
	}

	existing, err := s.client.ResourceMapping.Query().
		Where(resourcemapping.ResourceTypeID(rt.ID)).
		Only(ctx)
	if err != nil && !isNotFound(err) {
		return nil, err
	}
	if isNotFound(err) {
		created, err := s.client.ResourceMapping.Create().
			SetID(newID("rm")).
			SetResourceTypeID(rt.ID).
			SetStorageKind(input.StorageKind).
			SetNillableTableName(nilIfEmpty(input.TableName)).
			SetIDField(input.IDField).
			SetSpaceField(input.SpaceField).
			SetNillableGroupField(nilIfEmpty(input.GroupField)).
			SetNillableOwnerMemberField(nilIfEmpty(input.OwnerMemberField)).
			SetNillableVisibilityField(nilIfEmpty(input.VisibilityField)).
			SetNillableMetadataField(nilIfEmpty(input.MetadataField)).
			SetMetadata(nonNilMap(input.Metadata)).
			Save(ctx)
		if err != nil {
			return nil, err
		}
		out := mapResourceMapping(created)
		return &out, nil
	}

	builder := s.client.ResourceMapping.UpdateOneID(existing.ID).
		SetStorageKind(input.StorageKind).
		SetIDField(input.IDField).
		SetSpaceField(input.SpaceField).
		SetMetadata(nonNilMap(input.Metadata))
	setNullableString(builder.SetTableName, builder.ClearTableName, input.TableName)
	setNullableString(builder.SetGroupField, builder.ClearGroupField, input.GroupField)
	setNullableString(builder.SetOwnerMemberField, builder.ClearOwnerMemberField, input.OwnerMemberField)
	setNullableString(builder.SetVisibilityField, builder.ClearVisibilityField, input.VisibilityField)
	setNullableString(builder.SetMetadataField, builder.ClearMetadataField, input.MetadataField)

	updated, err := builder.Save(ctx)
	if err != nil {
		return nil, err
	}
	out := mapResourceMapping(updated)
	return &out, nil
}

func (s *Store) GetResourceType(ctx context.Context, key string) (*resources.ResourceType, error) {
	rt, err := s.client.ResourceType.Query().Where(resourcetype.Key(key)).Only(ctx)
	if isNotFound(err) {
		return nil, authz.ErrResourceTypeNotFound
	}
	if err != nil {
		return nil, err
	}
	out := mapResourceType(rt)
	return &out, nil
}

func (s *Store) ListResourceActions(ctx context.Context, resourceTypeKey string) ([]resources.ResourceAction, error) {
	rt, err := s.client.ResourceType.Query().Where(resourcetype.Key(resourceTypeKey)).Only(ctx)
	if isNotFound(err) {
		return nil, authz.ErrResourceTypeNotFound
	}
	if err != nil {
		return nil, err
	}

	actions, err := s.client.ResourceAction.Query().
		Where(resourceaction.ResourceTypeID(rt.ID)).
		Order(coreent.Asc(resourceaction.FieldKey)).
		All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]resources.ResourceAction, 0, len(actions))
	for _, action := range actions {
		out = append(out, mapResourceAction(action))
	}
	return out, nil
}

func (s *Store) GetResourceMapping(ctx context.Context, resourceTypeKey string) (*resources.ResourceMapping, error) {
	rt, err := s.client.ResourceType.Query().Where(resourcetype.Key(resourceTypeKey)).Only(ctx)
	if isNotFound(err) {
		return nil, authz.ErrResourceTypeNotFound
	}
	if err != nil {
		return nil, err
	}
	rm, err := s.client.ResourceMapping.Query().Where(resourcemapping.ResourceTypeID(rt.ID)).Only(ctx)
	if isNotFound(err) {
		return nil, authz.ErrResourceTypeNotFound
	}
	if err != nil {
		return nil, err
	}
	out := mapResourceMapping(rm)
	return &out, nil
}
