package entstore

import (
	"context"
	"database/sql"

	entdialect "entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"

	coreent "github.com/plystra/core/ent"
	_ "github.com/plystra/core/ent/runtime"
	"github.com/plystra/core/internal/authz"
	"github.com/plystra/core/internal/resources"
)

var _ authz.Store = (*Store)(nil)
var _ resources.Store = (*Store)(nil)

type Store struct {
	client *coreent.Client
	db     *sql.DB
}

func Open(ctx context.Context, databaseURL string) (*Store, error) {
	cfg, err := pgx.ParseConfig(databaseURL)
	if err != nil {
		return nil, err
	}
	db := stdlib.OpenDB(*cfg)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	driver := entsql.OpenDB(entdialect.Postgres, db)
	return New(coreent.NewClient(coreent.Driver(driver)), db), nil
}

func New(client *coreent.Client, db *sql.DB) *Store {
	s := &Store{client: client, db: db}
	s.installHooks()
	return s
}

func (s *Store) Client() *coreent.Client {
	if s == nil {
		return nil
	}
	return s.client
}

func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	if s.client != nil {
		if err := s.client.Close(); err != nil {
			return err
		}
	}
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

func (s *Store) LoadAuthorizationContext(ctx context.Context, input authz.CheckInput) (authz.AuthorizationContext, error) {
	actorContext := input.NormalizedActor()
	actor, err := s.LoadActor(ctx, actorContext)
	if err != nil {
		return authz.AuthorizationContext{}, err
	}

	registry, registryErr := s.LoadResourceRegistration(ctx, input.ResourceType, input.Action)
	if registryErr != nil {
		return authz.AuthorizationContext{
			Actor:            actor,
			ResourceRegistry: registry,
			RegistryErr:      registryErr,
		}, nil
	}

	target, err := s.loadTargetSnapshot(ctx, input)
	if err != nil {
		return authz.AuthorizationContext{}, err
	}

	candidates, err := s.LoadPermissionCandidates(ctx, authz.CandidateQuery{
		MemberID:     actorContext.MemberID,
		ResourceType: input.ResourceType,
		Action:       input.Action,
	})
	if err != nil {
		return authz.AuthorizationContext{}, err
	}

	return authz.AuthorizationContext{
		Actor:              actor,
		ResourceRegistry:   registry,
		Target:             target,
		PermissionGrants:   candidates,
		PermissionFiltered: true,
	}, nil
}
