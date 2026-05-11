package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

type migrationFile struct {
	Version   string
	Name      string
	Filename  string
	Checksum  string
	AtlasHash string
}

func runMigrate(ctx context.Context, command string) error {
	migrations, err := loadMigrations("migrations")
	if err != nil {
		return err
	}

	pool, err := pgxpool.New(ctx, databaseURL())
	if err != nil {
		return err
	}
	defer pool.Close()

	if err := ensureMigrationTable(ctx, pool); err != nil {
		return err
	}

	applied, err := loadApplied(ctx, pool)
	if err != nil {
		return err
	}

	switch command {
	case "status":
		for _, migration := range migrations {
			status := "pending"
			if record, ok := applied[migration.Version]; ok {
				status = "applied"
				if !record.matches(migration) {
					status = "checksum-mismatch"
				}
			}
			fmt.Printf("%s %s %s\n", migration.Version, migration.Name, status)
		}
	case "plan":
		for _, migration := range migrations {
			if _, ok := applied[migration.Version]; !ok {
				fmt.Printf("%s %s pending\n", migration.Version, migration.Name)
			}
		}
	case "verify":
		pending := []string{}
		for _, migration := range migrations {
			record, ok := applied[migration.Version]
			if !ok {
				pending = append(pending, migration.Version+" "+migration.Name)
				continue
			}
			if !record.matches(migration) {
				return fmt.Errorf("%s checksum mismatch: database=%s file=%s", migration.Version, record.Checksum, migration.expectedChecksums())
			}
		}
		if len(pending) > 0 {
			return fmt.Errorf("pending migrations: %s; run plystractl migrate up", strings.Join(pending, ", "))
		}
		fmt.Println("migrations verified")
	case "up":
		for _, migration := range migrations {
			record, ok := applied[migration.Version]
			if ok && !record.matches(migration) {
				return fmt.Errorf("%s checksum mismatch: database=%s file=%s", migration.Version, record.Checksum, migration.expectedChecksums())
			}
		}
		if err := runMigrateUpWithAtlas(ctx, pool); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown migrate command %q", command)
	}

	return nil
}

type migrationRecord struct {
	Checksum string
}

func (r migrationRecord) matches(m migrationFile) bool {
	for _, checksum := range m.expectedChecksumList() {
		if r.Checksum == checksum {
			return true
		}
	}
	return false
}

func (m migrationFile) expectedChecksums() string {
	return strings.Join(m.expectedChecksumList(), " or ")
}

func (m migrationFile) expectedChecksumList() []string {
	checksums := []string{m.Checksum}
	if m.AtlasHash != "" {
		checksums = append(checksums, m.AtlasHash, "h1:"+m.AtlasHash)
	}
	return checksums
}

func ensureMigrationTable(ctx context.Context, pool *pgxpool.Pool) error {
	if _, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			checksum TEXT NOT NULL,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			execution_time_ms INT NOT NULL
		)
	`); err != nil {
		return err
	}
	_, err := pool.Exec(ctx, `
		ALTER TABLE schema_migrations
			ADD COLUMN IF NOT EXISTS revision_type TEXT NOT NULL DEFAULT 'execute',
			ADD COLUMN IF NOT EXISTS applied INT NOT NULL DEFAULT 1,
			ADD COLUMN IF NOT EXISTS total INT NOT NULL DEFAULT 1,
			ADD COLUMN IF NOT EXISTS error TEXT NOT NULL DEFAULT '',
			ADD COLUMN IF NOT EXISTS error_stmt TEXT NOT NULL DEFAULT '',
			ADD COLUMN IF NOT EXISTS partial_hashes JSONB NOT NULL DEFAULT '[]'::jsonb,
			ADD COLUMN IF NOT EXISTS operator_version TEXT NOT NULL DEFAULT ''
	`)
	return err
}

func loadApplied(ctx context.Context, pool *pgxpool.Pool) (map[string]migrationRecord, error) {
	rows, err := pool.Query(ctx, `SELECT version, checksum FROM schema_migrations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	applied := map[string]migrationRecord{}
	for rows.Next() {
		var version string
		var record migrationRecord
		if err := rows.Scan(&version, &record.Checksum); err != nil {
			return nil, err
		}
		applied[version] = record
	}
	return applied, rows.Err()
}

func loadMigrations(dir string) ([]migrationFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	atlasHashes, err := atlasMigrationHashes(dir)
	if err != nil {
		return nil, err
	}

	var migrations []migrationFile
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".sql" {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		version, name := parseMigrationName(entry.Name())
		sum := sha256.Sum256(raw)
		migrations = append(migrations, migrationFile{
			Version:   version,
			Name:      name,
			Filename:  entry.Name(),
			Checksum:  hex.EncodeToString(sum[:]),
			AtlasHash: atlasHashes[entry.Name()],
		})
	}
	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Version < migrations[j].Version
	})
	return migrations, nil
}

func parseMigrationName(filename string) (string, string) {
	base := strings.TrimSuffix(filename, filepath.Ext(filename))
	parts := strings.SplitN(base, "_", 2)
	if len(parts) == 1 {
		return base, base
	}
	return parts[0], parts[1]
}
