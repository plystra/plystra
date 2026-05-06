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
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const defaultDatabaseURL = "postgres://plystra:plystra@localhost:5432/plystra?sslmode=disable"

type migrationFile struct {
	Version  string
	Name     string
	Path     string
	SQL      string
	Checksum string
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	ctx := context.Background()
	switch os.Args[1] {
	case "migrate":
		if len(os.Args) < 3 {
			usage()
			os.Exit(1)
		}
		if err := runMigrate(ctx, os.Args[2]); err != nil {
			fmt.Fprintf(os.Stderr, "migrate %s: %v\n", os.Args[2], err)
			os.Exit(1)
		}
	case "doctor":
		if err := runDoctor(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "doctor: %v\n", err)
			os.Exit(1)
		}
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: plystractl migrate <status|plan|up|verify>")
	fmt.Fprintln(os.Stderr, "       plystractl doctor")
}

func runDoctor(ctx context.Context) error {
	pool, err := pgxpool.New(ctx, databaseURL())
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("database connectivity failed: %w", err)
	}
	fmt.Println("database: ok")
	if err := ensureMigrationTable(ctx, pool); err != nil {
		return err
	}
	applied, err := loadApplied(ctx, pool)
	if err != nil {
		return err
	}
	migrations, err := loadMigrations("migrations")
	if err != nil {
		return err
	}
	pending := 0
	for _, migration := range migrations {
		record, ok := applied[migration.Version]
		if !ok {
			pending++
			continue
		}
		if record.Checksum != migration.Checksum {
			return fmt.Errorf("migration %s checksum mismatch", migration.Version)
		}
	}
	if pending > 0 {
		fmt.Printf("migrations: %d pending\n", pending)
	} else {
		fmt.Println("migrations: current")
	}
	if len(os.Getenv("PLYSTRA_JWT_SECRET")) < 32 {
		fmt.Println("warning: PLYSTRA_JWT_SECRET is unset or shorter than 32 characters")
	}
	return nil
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
				if record.Checksum != migration.Checksum {
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
		for _, migration := range migrations {
			record, ok := applied[migration.Version]
			if !ok {
				continue
			}
			if record.Checksum != migration.Checksum {
				return fmt.Errorf("%s checksum mismatch: database=%s file=%s", migration.Version, record.Checksum, migration.Checksum)
			}
		}
		fmt.Println("migrations verified")
	case "up":
		for _, migration := range migrations {
			record, ok := applied[migration.Version]
			if ok {
				if record.Checksum != migration.Checksum {
					return fmt.Errorf("%s checksum mismatch: database=%s file=%s", migration.Version, record.Checksum, migration.Checksum)
				}
				continue
			}
			start := time.Now()
			tx, err := pool.Begin(ctx)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, migration.SQL); err != nil {
				_ = tx.Rollback(ctx)
				return fmt.Errorf("apply %s: %w", migration.Name, err)
			}
			elapsed := int(time.Since(start).Milliseconds())
			if _, err := tx.Exec(ctx, `
				INSERT INTO schema_migrations (version, name, checksum, execution_time_ms)
				VALUES ($1, $2, $3, $4)
			`, migration.Version, migration.Name, migration.Checksum, elapsed); err != nil {
				_ = tx.Rollback(ctx)
				return err
			}
			if err := tx.Commit(ctx); err != nil {
				return err
			}
			fmt.Printf("applied %s %s\n", migration.Version, migration.Name)
		}
	default:
		return fmt.Errorf("unknown migrate command %q", command)
	}

	return nil
}

type migrationRecord struct {
	Checksum string
}

func ensureMigrationTable(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			checksum TEXT NOT NULL,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			execution_time_ms INT NOT NULL
		)
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
			Version:  version,
			Name:     name,
			Path:     path,
			SQL:      string(raw),
			Checksum: hex.EncodeToString(sum[:]),
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

func databaseURL() string {
	for _, key := range []string{"PLYSTRA_DATABASE_URL", "DATABASE_URL"} {
		if value := os.Getenv(key); value != "" {
			return value
		}
	}
	return defaultDatabaseURL
}
