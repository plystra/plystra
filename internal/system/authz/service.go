package authz

import (
	"context"
	"fmt"

	coreauthz "github.com/plystra/plystra/internal/authz"
	"github.com/plystra/plystra/internal/kernel/contracts"
)

type Service struct {
	store     coreauthz.Store
	identity  contracts.IdentityService
	resources contracts.ResourceRegistryService
	audit     contracts.AuditService
}

func NewService(store coreauthz.Store, identity contracts.IdentityService, resources contracts.ResourceRegistryService, audit contracts.AuditService) *Service {
	return &Service{store: store, identity: identity, resources: resources, audit: audit}
}

func (s *Service) Ready() error {
	if s == nil || s.store == nil || s.identity == nil || s.resources == nil || s.audit == nil {
		return fmt.Errorf("authorization service requires store, identity, resource registry, and audit services")
	}
	return nil
}

func (s *Service) Check(ctx context.Context, input coreauthz.CheckInput) (*coreauthz.Decision, error) {
	if err := s.Ready(); err != nil {
		return nil, err
	}
	return coreauthz.Check(ctx, s.store, input)
}

func (s *Service) Explain(ctx context.Context, input coreauthz.CheckInput) (*coreauthz.Decision, error) {
	if err := s.Ready(); err != nil {
		return nil, err
	}
	input.Explain = true
	return coreauthz.Explain(ctx, s.store, input)
}
