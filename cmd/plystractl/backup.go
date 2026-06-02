package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func runBackup(ctx context.Context, command string, args []string) error {
	switch command {
	case "manifest":
		flags := flag.NewFlagSet("backup manifest", flag.ContinueOnError)
		flags.SetOutput(os.Stderr)
		out := flags.String("out", "", "optional output file")
		if err := flags.Parse(args); err != nil {
			return err
		}
		manifest, err := backupManifest(ctx)
		if err != nil {
			return err
		}
		raw, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			return err
		}
		raw = append(raw, '\n')
		if strings.TrimSpace(*out) != "" {
			return os.WriteFile(*out, raw, 0o600)
		}
		_, err = os.Stdout.Write(raw)
		return err
	case "pg-dump-command":
		fmt.Println(pgDumpCommand(databaseURL()))
		return nil
	default:
		return fmt.Errorf("unknown backup command %q", command)
	}
}

func runRestore(ctx context.Context, command string, args []string) error {
	switch command {
	case "pg-restore-command":
		flags := flag.NewFlagSet("restore pg-restore-command", flag.ContinueOnError)
		flags.SetOutput(os.Stderr)
		file := flags.String("file", "plystra.dump", "backup dump file")
		if err := flags.Parse(args); err != nil {
			return err
		}
		fmt.Println(pgRestoreCommand(databaseURL(), *file))
		return nil
	case "verify-backup":
		flags := flag.NewFlagSet("restore verify-backup", flag.ContinueOnError)
		flags.SetOutput(os.Stderr)
		file := flags.String("file", "", "backup manifest JSON file")
		if err := flags.Parse(args); err != nil {
			return err
		}
		if strings.TrimSpace(*file) == "" {
			return fmt.Errorf("--file is required")
		}
		raw, err := os.ReadFile(*file)
		if err != nil {
			return err
		}
		var manifest map[string]any
		if err := json.Unmarshal(raw, &manifest); err != nil {
			return err
		}
		if manifest["database_url_fingerprint"] == "" || manifest["schema_version"] == "" {
			return fmt.Errorf("backup manifest is missing required fields")
		}
		fmt.Println("backup manifest verified")
		return nil
	default:
		return fmt.Errorf("unknown restore command %q", command)
	}
}

func backupManifest(ctx context.Context) (map[string]any, error) {
	pool, err := pgxpool.New(ctx, databaseURL())
	if err != nil {
		return nil, err
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return nil, err
	}
	schemaVersion := ""
	_ = pool.QueryRow(ctx, `SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1`).Scan(&schemaVersion)
	tables := map[string]int64{}
	for _, table := range []string{
		"users",
		"spaces",
		"members",
		"user_members",
		"plugins",
		"plugin_settings_values",
		"template_installations",
		"app_data_models",
		"app_data_records",
		"app_data_record_revisions",
		"audit_logs",
	} {
		value, err := countRequiredTable(ctx, pool, table)
		if err != nil {
			return nil, fmt.Errorf("read %s count: %w", table, err)
		}
		tables[table] = value
	}
	pluginTables := map[string]int64{}
	discoveredPluginTables, err := discoverPluginOwnedTables(ctx, pool)
	if err != nil {
		return nil, fmt.Errorf("discover plugin-owned tables: %w", err)
	}
	for _, table := range discoveredPluginTables {
		value, exists, err := countOptionalTable(ctx, pool, table)
		if err != nil {
			return nil, fmt.Errorf("read optional plugin table %s count: %w", table, err)
		}
		if exists {
			pluginTables[table] = value
		}
	}
	return map[string]any{
		"format":                   "plystra.backup.manifest.v1",
		"created_at":               time.Now().UTC().Format(time.RFC3339),
		"database_url_fingerprint": databaseURLFingerprint(databaseURL()),
		"schema_version":           schemaVersion,
		"tables":                   tables,
		"plugin_tables":            pluginTables,
		"backup_scope": []string{
			"PostgreSQL database dump",
			"environment configuration and secrets from runtime secret store",
			"plugin manifests and plugin-owned tables in the same database",
			"schema_migrations revision metadata",
		},
		"restore_order": []string{
			"stop Plystra Core and plugin processes",
			"restore PostgreSQL dump into an empty database",
			"restore runtime configuration and secrets",
			"run plystractl migrate verify",
			"run plystractl doctor",
			"start Core and plugins",
		},
	}, nil
}

var tableNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

var corePluginSystemTables = map[string]bool{
	"plugin_admin_menus":          true,
	"plugin_migration_state":      true,
	"plugin_settings_definitions": true,
	"plugin_settings_values":      true,
}

func discoverPluginOwnedTables(ctx context.Context, pool *pgxpool.Pool) ([]string, error) {
	rows, err := pool.Query(ctx, `
SELECT table_name
FROM information_schema.tables
WHERE table_schema = current_schema()
  AND table_type = 'BASE TABLE'
  AND table_name LIKE 'plugin\_%' ESCAPE '\'
ORDER BY table_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	tables := []string{}
	for rows.Next() {
		table := ""
		if err := rows.Scan(&table); err != nil {
			return nil, err
		}
		if pluginBackupTableAllowed(table) {
			tables = append(tables, safeTableIdentifier(table))
		}
	}
	return tables, rows.Err()
}

func pluginBackupTableAllowed(table string) bool {
	if !tableNamePattern.MatchString(table) {
		return false
	}
	if !strings.HasPrefix(table, "plugin_") {
		return false
	}
	return !corePluginSystemTables[table]
}

func countRequiredTable(ctx context.Context, pool *pgxpool.Pool, table string) (int64, error) {
	var value int64
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM `+safeTableIdentifier(table)).Scan(&value); err != nil {
		return 0, err
	}
	return value, nil
}

func countOptionalTable(ctx context.Context, pool *pgxpool.Pool, table string) (int64, bool, error) {
	table = safeTableIdentifier(table)
	var exists bool
	if err := pool.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&exists); err != nil {
		return 0, false, err
	}
	if !exists {
		return 0, false, nil
	}
	value, err := countRequiredTable(ctx, pool, table)
	return value, true, err
}

func safeTableIdentifier(table string) string {
	if !tableNamePattern.MatchString(table) {
		panic("invalid static table identifier: " + table)
	}
	return table
}

func pgDumpCommand(rawURL string) string {
	_ = rawURL
	return `pg_dump --format=custom --no-owner --no-acl --dbname "$env:DATABASE_URL" --file plystra.dump`
}

func pgRestoreCommand(rawURL, file string) string {
	_ = rawURL
	if strings.TrimSpace(file) == "" {
		file = "plystra.dump"
	}
	return fmt.Sprintf("pg_restore --clean --if-exists --no-owner --no-acl --dbname \"$env:DATABASE_URL\" %q", file)
}

func redactedDatabaseURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.User == nil {
		return raw
	}
	username := parsed.User.Username()
	if username == "" {
		parsed.User = nil
	} else {
		parsed.User = url.UserPassword(username, "REDACTED")
	}
	return parsed.String()
}

func databaseURLFingerprint(raw string) string {
	redacted := redactedDatabaseURL(raw)
	sum := sha256.Sum256([]byte(redacted))
	return fmt.Sprintf("%x", sum[:])
}
