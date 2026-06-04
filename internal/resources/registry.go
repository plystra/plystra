package resources

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/plystra/core/internal/authz"
)

const (
	DefaultSource      = "core"
	DefaultStatus      = authz.StatusActive
	DefaultStorageKind = "internal_table"
	DefaultRiskLevel   = "normal"
)

var keyPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

type RegisterResourceTypeInput struct {
	Key         string
	DisplayName string
	Description string
	Source      string
	Metadata    map[string]any
}

type RegisterResourceActionInput struct {
	ResourceTypeKey string
	Key             string
	DisplayName     string
	Description     string
	RiskLevel       string
	AuditDefault    bool
	Metadata        map[string]any
}

type RegisterResourceMappingInput struct {
	ResourceTypeKey  string
	StorageKind      string
	TableName        string
	IDField          string
	SpaceField       string
	GroupField       string
	OwnerMemberField string
	VisibilityField  string
	MetadataField    string
	Metadata         map[string]any
}

type ResourceType = authz.ResourceTypeSnapshot
type ResourceAction = authz.ResourceActionSnapshot
type ResourceMapping = authz.ResourceMappingSnapshot

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
	input.Key = normalizeKey(input.Key)
	if err := validateKey("resource type key", input.Key); err != nil {
		return nil, err
	}
	if strings.TrimSpace(input.DisplayName) == "" {
		return nil, fmt.Errorf("display_name is required")
	}
	if input.Source == "" {
		input.Source = DefaultSource
	}
	input.Metadata = nonNilMap(input.Metadata)
	return r.store.UpsertResourceType(ctx, input)
}

func (r *Registry) RegisterResourceAction(ctx context.Context, input RegisterResourceActionInput) (*ResourceAction, error) {
	input.ResourceTypeKey = normalizeKey(input.ResourceTypeKey)
	input.Key = normalizeKey(input.Key)
	if err := validateKey("resource type key", input.ResourceTypeKey); err != nil {
		return nil, err
	}
	if err := validateKey("action key", input.Key); err != nil {
		return nil, err
	}
	if strings.TrimSpace(input.DisplayName) == "" {
		return nil, fmt.Errorf("display_name is required")
	}
	if input.RiskLevel == "" {
		input.RiskLevel = DefaultRiskLevel
	}
	input.Metadata = nonNilMap(input.Metadata)
	return r.store.UpsertResourceAction(ctx, input)
}

func (r *Registry) RegisterResourceMapping(ctx context.Context, input RegisterResourceMappingInput) (*ResourceMapping, error) {
	input.ResourceTypeKey = normalizeKey(input.ResourceTypeKey)
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
	input.Metadata = nonNilMap(input.Metadata)
	return r.store.UpsertResourceMapping(ctx, input)
}

func (r *Registry) GetResourceType(ctx context.Context, key string) (*ResourceType, error) {
	key = normalizeKey(key)
	if err := validateKey("resource type key", key); err != nil {
		return nil, err
	}
	return r.store.GetResourceType(ctx, key)
}

func (r *Registry) ListResourceActions(ctx context.Context, resourceTypeKey string) ([]ResourceAction, error) {
	resourceTypeKey = normalizeKey(resourceTypeKey)
	if err := validateKey("resource type key", resourceTypeKey); err != nil {
		return nil, err
	}
	return r.store.ListResourceActions(ctx, resourceTypeKey)
}

func (r *Registry) GetResourceMapping(ctx context.Context, resourceTypeKey string) (*ResourceMapping, error) {
	resourceTypeKey = normalizeKey(resourceTypeKey)
	if err := validateKey("resource type key", resourceTypeKey); err != nil {
		return nil, err
	}
	return r.store.GetResourceMapping(ctx, resourceTypeKey)
}

func (r *Registry) ValidateResourceAction(ctx context.Context, resourceTypeKey, action string) error {
	action = normalizeKey(action)
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

func ValidateResourceAction(ctx context.Context, store Store, resourceTypeKey, action string) error {
	return NewRegistry(store).ValidateResourceAction(ctx, resourceTypeKey, action)
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

func normalizeKey(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func nonNilMap(value map[string]any) map[string]any {
	if value == nil {
		return map[string]any{}
	}
	return value
}
