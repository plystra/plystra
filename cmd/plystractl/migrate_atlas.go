package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"ariga.io/atlas/sql/migrate"
	"ariga.io/atlas/sql/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
)

const migrateOperatorVersion = "plystractl/1.0.0-rc2"

func atlasMigrationHashes(path string) (map[string]string, error) {
	dir, err := migrate.NewLocalDir(path)
	if err != nil {
		return nil, err
	}
	sum, err := dir.Checksum()
	if err != nil {
		return nil, err
	}
	hashes := make(map[string]string, len(sum))
	for _, item := range sum {
		hashes[item.N] = item.H
	}
	return hashes, nil
}

func runMigrateUpWithAtlas(ctx context.Context, pool *pgxpool.Pool) error {
	cfg, err := pgx.ParseConfig(databaseURL())
	if err != nil {
		return err
	}
	sqlDB := stdlib.OpenDB(*cfg)
	defer sqlDB.Close()
	if err := sqlDB.PingContext(ctx); err != nil {
		return err
	}

	driver, err := postgres.Open(sqlDB)
	if err != nil {
		return err
	}
	dir, err := migrate.NewLocalDir("migrations")
	if err != nil {
		return err
	}
	executor, err := migrate.NewExecutor(
		driver,
		dir,
		&schemaMigrationRevisionStore{pool: pool},
		migrate.WithAllowDirty(true),
		migrate.WithExecOrder(migrate.ExecOrderLinear),
		migrate.WithOperatorVersion(migrateOperatorVersion),
	)
	if err != nil {
		return err
	}

	pending, err := executor.Pending(ctx)
	if errors.Is(err, migrate.ErrNoPendingFiles) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, file := range pending {
		if err := executor.Execute(ctx, file); err != nil {
			return fmt.Errorf("apply %s: %w", file.Name(), err)
		}
		fmt.Printf("applied %s %s\n", file.Version(), file.Desc())
	}
	return nil
}

type schemaMigrationRevisionStore struct {
	pool *pgxpool.Pool
}

func (s *schemaMigrationRevisionStore) Ident() *migrate.TableIdent {
	return &migrate.TableIdent{Name: "schema_migrations"}
}

func (s *schemaMigrationRevisionStore) ReadRevisions(ctx context.Context) ([]*migrate.Revision, error) {
	if err := ensureMigrationTable(ctx, s.pool); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `
		SELECT version, name, checksum, applied_at, execution_time_ms, revision_type,
		       applied, total, error, error_stmt, partial_hashes, operator_version
		FROM schema_migrations
		ORDER BY version
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var revisions []*migrate.Revision
	for rows.Next() {
		revision, err := scanMigrationRevision(rows)
		if err != nil {
			return nil, err
		}
		revisions = append(revisions, revision)
	}
	return revisions, rows.Err()
}

func (s *schemaMigrationRevisionStore) ReadRevision(ctx context.Context, version string) (*migrate.Revision, error) {
	if err := ensureMigrationTable(ctx, s.pool); err != nil {
		return nil, err
	}
	row := s.pool.QueryRow(ctx, `
		SELECT version, name, checksum, applied_at, execution_time_ms, revision_type,
		       applied, total, error, error_stmt, partial_hashes, operator_version
		FROM schema_migrations
		WHERE version = $1
	`, version)
	revision, err := scanMigrationRevision(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, migrate.ErrRevisionNotExist
	}
	if err != nil {
		return nil, err
	}
	return revision, nil
}

func (s *schemaMigrationRevisionStore) WriteRevision(ctx context.Context, revision *migrate.Revision) error {
	if err := ensureMigrationTable(ctx, s.pool); err != nil {
		return err
	}
	partialHashes, err := json.Marshal(revision.PartialHashes)
	if err != nil {
		return err
	}
	executedAt := revision.ExecutedAt
	if executedAt.IsZero() {
		executedAt = time.Now()
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO schema_migrations (
			version, name, checksum, applied_at, execution_time_ms, revision_type,
			applied, total, error, error_stmt, partial_hashes, operator_version
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, $12)
		ON CONFLICT (version) DO UPDATE SET
			name = EXCLUDED.name,
			checksum = EXCLUDED.checksum,
			applied_at = EXCLUDED.applied_at,
			execution_time_ms = EXCLUDED.execution_time_ms,
			revision_type = EXCLUDED.revision_type,
			applied = EXCLUDED.applied,
			total = EXCLUDED.total,
			error = EXCLUDED.error,
			error_stmt = EXCLUDED.error_stmt,
			partial_hashes = EXCLUDED.partial_hashes,
			operator_version = EXCLUDED.operator_version
	`, revision.Version, revision.Description, revision.Hash, executedAt, int(revision.ExecutionTime.Milliseconds()),
		revisionTypeString(revision.Type), revision.Applied, revision.Total, revision.Error, revision.ErrorStmt,
		string(partialHashes), revision.OperatorVersion)
	return err
}

func (s *schemaMigrationRevisionStore) DeleteRevision(ctx context.Context, version string) error {
	if err := ensureMigrationTable(ctx, s.pool); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, `DELETE FROM schema_migrations WHERE version = $1`, version)
	return err
}

type revisionScanner interface {
	Scan(dest ...any) error
}

func scanMigrationRevision(scanner revisionScanner) (*migrate.Revision, error) {
	var (
		revision        migrate.Revision
		revisionTypeRaw string
		partialRaw      []byte
		elapsedMS       int
	)
	if err := scanner.Scan(
		&revision.Version,
		&revision.Description,
		&revision.Hash,
		&revision.ExecutedAt,
		&elapsedMS,
		&revisionTypeRaw,
		&revision.Applied,
		&revision.Total,
		&revision.Error,
		&revision.ErrorStmt,
		&partialRaw,
		&revision.OperatorVersion,
	); err != nil {
		return nil, err
	}
	revision.Type = parseRevisionType(revisionTypeRaw)
	revision.ExecutionTime = time.Duration(elapsedMS) * time.Millisecond
	if len(partialRaw) > 0 {
		if err := json.Unmarshal(partialRaw, &revision.PartialHashes); err != nil {
			return nil, err
		}
	}
	return &revision, nil
}

func revisionTypeString(t migrate.RevisionType) string {
	switch t {
	case migrate.RevisionTypeBaseline:
		return "baseline"
	case migrate.RevisionTypeExecute:
		return "execute"
	case migrate.RevisionTypeResolved:
		return "resolved"
	case migrate.RevisionTypeExecute | migrate.RevisionTypeResolved:
		return "execute_resolved"
	default:
		return "unknown"
	}
}

func parseRevisionType(raw string) migrate.RevisionType {
	switch raw {
	case "baseline":
		return migrate.RevisionTypeBaseline
	case "resolved", "manually set":
		return migrate.RevisionTypeResolved
	case "execute_resolved", "applied + manually set":
		return migrate.RevisionTypeExecute | migrate.RevisionTypeResolved
	case "", "execute", "applied":
		return migrate.RevisionTypeExecute
	default:
		return migrate.RevisionTypeExecute
	}
}
