package admin

import (
	"context"
	"fmt"

	"github.com/plystra/core/internal/kernel/contracts"
	kadmin "github.com/plystra/core/internal/kernel/contracts/admin"
)

type Service struct {
	identity      contracts.IdentityService
	authorization contracts.AuthorizationService
	audit         contracts.AuditService
}

func NewService(identity contracts.IdentityService, authorization contracts.AuthorizationService, audit contracts.AuditService) *Service {
	return &Service{identity: identity, authorization: authorization, audit: audit}
}

func (s *Service) Ready() error {
	if s == nil || s.identity == nil || s.authorization == nil || s.audit == nil {
		return fmt.Errorf("admin control plane requires identity, authorization, and audit services")
	}
	return nil
}

func (s *Service) AuthorizeAdminAction(context.Context, kadmin.Requirement) (bool, error) {
	if err := s.Ready(); err != nil {
		return false, err
	}
	return false, fmt.Errorf("admin principal context is required")
}
