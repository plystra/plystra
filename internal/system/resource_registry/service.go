package resource_registry

import (
	"context"
	"fmt"

	"github.com/plystra/core/internal/authz"
	"github.com/plystra/core/internal/resources"
)

type Service struct {
	resourceStore resources.Store
	authzStore    authz.Store
	registry      *resources.Registry
}

func NewService(resourceStore resources.Store, authzStore authz.Store) *Service {
	return &Service{resourceStore: resourceStore, authzStore: authzStore, registry: resources.NewRegistry(resourceStore)}
}

func (s *Service) Ready() error {
	if s == nil || s.resourceStore == nil || s.authzStore == nil || s.registry == nil {
		return fmt.Errorf("resource registry service requires resource and authz stores")
	}
	return nil
}

func (s *Service) LoadResourceRegistration(ctx context.Context, resourceType, action string) (authz.ResourceRegistrySnapshot, error) {
	if err := s.Ready(); err != nil {
		return authz.ResourceRegistrySnapshot{}, err
	}
	return s.authzStore.LoadResourceRegistration(ctx, resourceType, action)
}

func (s *Service) LoadTarget(ctx context.Context, resourceType, resourceID string) (authz.TargetSnapshot, error) {
	if err := s.Ready(); err != nil {
		return authz.TargetSnapshot{}, err
	}
	return s.authzStore.LoadTarget(ctx, resourceType, resourceID)
}

func (s *Service) Registry() *resources.Registry {
	return s.registry
}
