package resources

import (
	"context"

	systemregistry "github.com/plystra/system-resource-registry"
)

const (
	DefaultSource      = systemregistry.DefaultSource
	DefaultStatus      = systemregistry.DefaultStatus
	DefaultStorageKind = systemregistry.DefaultStorageKind
	DefaultRiskLevel   = systemregistry.DefaultRiskLevel
)

type (
	RegisterResourceTypeInput    = systemregistry.RegisterResourceTypeInput
	RegisterResourceActionInput  = systemregistry.RegisterResourceActionInput
	RegisterResourceMappingInput = systemregistry.RegisterResourceMappingInput
	ResourceType                 = systemregistry.ResourceType
	ResourceAction               = systemregistry.ResourceAction
	ResourceMapping              = systemregistry.ResourceMapping
	Store                        = systemregistry.Store
	Registry                     = systemregistry.Registry
)

func NewRegistry(store Store) *Registry {
	return systemregistry.NewRegistry(store)
}

func ValidateResourceAction(ctx context.Context, store Store, resourceTypeKey, action string) error {
	return systemregistry.NewRegistry(store).ValidateResourceAction(ctx, resourceTypeKey, action)
}
