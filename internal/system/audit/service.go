package audit

import (
	"context"
	"fmt"

	"github.com/plystra/core/internal/authz"
)

type Service struct {
	store authz.Store
}

func NewService(store authz.Store) *Service {
	return &Service{store: store}
}

func (s *Service) Ready() error {
	if s == nil || s.store == nil {
		return fmt.Errorf("audit service requires an authz store")
	}
	return nil
}

func (s *Service) RecordAuthorizationDecision(ctx context.Context, decision authz.Decision) error {
	if err := s.Ready(); err != nil {
		return err
	}
	return s.store.WriteAuditLog(ctx, decision)
}
