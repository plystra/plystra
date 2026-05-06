package resources

import (
	"context"
	"fmt"
	"regexp"
)

var keyPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

type Store interface {
	UpsertResourceType(ctx context.Context, input RegisterResourceTypeInput) (*ResourceType, error)
	UpsertResourceAction(ctx context.Context, input RegisterResourceActionInput) (*ResourceAction, error)
	UpsertResourceMapping(ctx context.Context, input RegisterResourceMappingInput) (*ResourceMapping, error)
	GetResourceType(ctx context.Context, key string) (*ResourceType, error)
	ListResourceActions(ctx context.Context, resourceTypeKey string) ([]ResourceAction, error)
	GetResourceMapping(ctx context.Context, resourceTypeKey string) (*ResourceMapping, error)
}

type Registry struct {
	store Store
}

func NewRegistry(store Store) *Registry {
	return &Registry{store: store}
}

func (r *Registry) RegisterResourceType(ctx context.Context, input RegisterResourceTypeInput) (*ResourceType, error) {
	if err := validateKey("resource type key", input.Key); err != nil {
		return nil, err
	}
	if input.DisplayName == "" {
		return nil, fmt.Errorf("display_name is required")
	}
	if input.Source == "" {
		input.Source = DefaultSource
	}
	if input.Metadata == nil {
		input.Metadata = map[string]any{}
	}
	return r.store.UpsertResourceType(ctx, input)
}

func (r *Registry) RegisterResourceAction(ctx context.Context, input RegisterResourceActionInput) (*ResourceAction, error) {
	if err := validateKey("resource type key", input.ResourceTypeKey); err != nil {
		return nil, err
	}
	if err := validateKey("action key", input.Key); err != nil {
		return nil, err
	}
	if input.DisplayName == "" {
		return nil, fmt.Errorf("display_name is required")
	}
	if input.RiskLevel == "" {
		input.RiskLevel = DefaultRiskLevel
	}
	if input.Metadata == nil {
		input.Metadata = map[string]any{}
	}
	return r.store.UpsertResourceAction(ctx, input)
}

func (r *Registry) RegisterResourceMapping(ctx context.Context, input RegisterResourceMappingInput) (*ResourceMapping, error) {
	if err := validateKey("resource type key", input.ResourceTypeKey); err != nil {
		return nil, err
	}
	if input.StorageKind == "" {
		input.StorageKind = DefaultStorageKind
	}
	if input.IDField == "" {
		input.IDField = "id"
	}
	if input.SpaceField == "" {
		input.SpaceField = "space_id"
	}
	if input.MetadataField == "" {
		input.MetadataField = "metadata"
	}
	if input.Metadata == nil {
		input.Metadata = map[string]any{}
	}
	return r.store.UpsertResourceMapping(ctx, input)
}

func (r *Registry) GetResourceType(ctx context.Context, key string) (*ResourceType, error) {
	if err := validateKey("resource type key", key); err != nil {
		return nil, err
	}
	return r.store.GetResourceType(ctx, key)
}

func (r *Registry) ListResourceActions(ctx context.Context, resourceTypeKey string) ([]ResourceAction, error) {
	if err := validateKey("resource type key", resourceTypeKey); err != nil {
		return nil, err
	}
	return r.store.ListResourceActions(ctx, resourceTypeKey)
}

func (r *Registry) GetResourceMapping(ctx context.Context, resourceTypeKey string) (*ResourceMapping, error) {
	if err := validateKey("resource type key", resourceTypeKey); err != nil {
		return nil, err
	}
	return r.store.GetResourceMapping(ctx, resourceTypeKey)
}

func (r *Registry) ValidateResourceAction(ctx context.Context, resourceTypeKey, action string) error {
	actions, err := r.ListResourceActions(ctx, resourceTypeKey)
	if err != nil {
		return err
	}
	for _, candidate := range actions {
		if candidate.Key == action {
			return nil
		}
	}
	return fmt.Errorf("resource action %q is not registered for %q", action, resourceTypeKey)
}

func validateKey(label, value string) error {
	if value == "" {
		return fmt.Errorf("%s is required", label)
	}
	if !keyPattern.MatchString(value) {
		return fmt.Errorf("%s %q must match %s", label, value, keyPattern.String())
	}
	return nil
}
