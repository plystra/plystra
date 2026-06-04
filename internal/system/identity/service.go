package identity

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
		return fmt.Errorf("identity service requires an authz store")
	}
	return nil
}

func (s *Service) ResolveActor(ctx context.Context, actor authz.ActorContext) (authz.ActorSnapshot, error) {
	if err := s.Ready(); err != nil {
		return authz.ActorSnapshot{}, err
	}
	return s.store.LoadActor(ctx, actor.Normalized())
}

func (s *Service) ValidateActor(ctx context.Context, actor authz.ActorContext) error {
	_, err := s.ResolveActor(ctx, actor)
	return err
}
