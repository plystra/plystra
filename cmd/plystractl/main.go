package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/schema"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/plystra/plystra/ent"
	entadmingrant "github.com/plystra/plystra/ent/admingrant"
	entuser "github.com/plystra/plystra/ent/user"
	entusermember "github.com/plystra/plystra/ent/usermember"
)

const defaultDatabaseURL = "postgres://plystra:plystra@localhost:5432/plystra?sslmode=disable"
const defaultSessionSecret = "change-me-session-secret-at-least-32-characters"
const defaultJWTSecret = "change-me-to-at-least-32-characters"

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
	case "ent":
		if len(os.Args) < 3 {
			usage()
			os.Exit(1)
		}
		if err := runEnt(ctx, os.Args[2]); err != nil {
			fmt.Fprintf(os.Stderr, "ent %s: %v\n", os.Args[2], err)
			os.Exit(1)
		}
	case "doctor":
		if err := runDoctor(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "doctor: %v\n", err)
			os.Exit(1)
		}
	case "admin":
		if len(os.Args) < 3 {
			usage()
			os.Exit(1)
		}
		if err := runAdmin(ctx, os.Args[2], os.Args[3:]); err != nil {
			fmt.Fprintf(os.Stderr, "admin %s: %v\n", os.Args[2], err)
			os.Exit(1)
		}
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: plystractl migrate <status|plan|up|verify>")
	fmt.Fprintln(os.Stderr, "       plystractl ent <status|plan|check|apply>")
	fmt.Fprintln(os.Stderr, "       plystractl admin bootstrap-super-admin --user-id <user_id> [--member-id <member_id>] [--grant-id <admin_grant_id>]")
	fmt.Fprintln(os.Stderr, "       plystractl doctor")
}

func runAdmin(ctx context.Context, command string, args []string) error {
	switch command {
	case "bootstrap-super-admin":
		return bootstrapSuperAdmin(ctx, args)
	default:
		return fmt.Errorf("unknown admin command %q", command)
	}
}

func bootstrapSuperAdmin(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("bootstrap-super-admin", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	userID := flags.String("user-id", "", "existing User ID to receive the first instance super admin grant")
	memberID := flags.String("member-id", "", "optional Member ID to annotate the grant")
	grantID := flags.String("grant-id", "", "optional AdminGrant ID")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*userID) == "" {
		return fmt.Errorf("--user-id is required")
	}
	client, db, err := openEntClient(ctx)
	if err != nil {
		return err
	}
	defer client.Close()
	defer db.Close()

	now := time.Now().UTC()
	count, err := client.AdminGrant.Query().
		Where(
			entadmingrant.Level("instance_super_admin"),
			entadmingrant.Status("active"),
			entadmingrant.DeletedAtIsNil(),
			entadmingrant.RevokedAtIsNil(),
			entadmingrant.Or(entadmingrant.ExpiresAtIsNil(), entadmingrant.ExpiresAtGT(now)),
		).
		Count(ctx)
	if err != nil {
		return err
	}
	if count > 0 {
		return fmt.Errorf("active instance_super_admin grant already exists; use the AdminGrant API as an existing super admin")
	}
	if _, err := client.User.Query().Where(entuser.ID(strings.TrimSpace(*userID)), entuser.DeletedAtIsNil()).Only(ctx); err != nil {
		if ent.IsNotFound(err) {
			return fmt.Errorf("user %q was not found", strings.TrimSpace(*userID))
		}
		return err
	}
	resolvedMemberID := strings.TrimSpace(*memberID)
	if resolvedMemberID == "" {
		binding, err := client.UserMember.Query().
			Where(
				entusermember.UserID(strings.TrimSpace(*userID)),
				entusermember.Status("active"),
				entusermember.DeletedAtIsNil(),
				entusermember.RevokedAtIsNil(),
				entusermember.Or(entusermember.ExpiresAtIsNil(), entusermember.ExpiresAtGT(now)),
			).
			Order(entusermember.ByIsPrimary(), entusermember.ByCreatedAt()).
			First(ctx)
		if err == nil {
			resolvedMemberID = binding.MemberID
		} else if !ent.IsNotFound(err) {
			return err
		}
	}
	id := strings.TrimSpace(*grantID)
	if id == "" {
		id = "ag_" + strings.NewReplacer("-", "_", ".", "_", "@", "_").Replace(strings.TrimSpace(*userID)) + "_instance_super_admin"
	}
	grant, err := client.AdminGrant.Create().
		SetID(id).
		SetUserID(strings.TrimSpace(*userID)).
		SetNillableMemberID(optionalStringPtr(resolvedMemberID)).
		SetLevel("instance_super_admin").
		SetPermissionKey("*").
		SetStatus("active").
		SetMetadata(map[string]any{"source": "plystractl bootstrap-super-admin"}).
		Save(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("created instance_super_admin grant %s for user %s\n", grant.ID, grant.UserID)
	return nil
}

func optionalStringPtr(value string) *string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return &value
}

func runEnt(ctx context.Context, command string) error {
	client, db, err := openEntClient(ctx)
	if err != nil {
		return err
	}
	defer client.Close()
	defer db.Close()

	switch command {
	case "status":
		tables := []string{
			"users", "spaces", "groups", "members", "user_members", "roles", "permissions",
			"member_roles", "role_permissions", "resources", "audit_logs", "resource_types",
			"resource_actions", "resource_mappings", "plugins", "plugin_admin_menus",
			"plugin_settings_definitions", "plugin_settings_values", "audit_event_types",
			"background_jobs", "template_installations", "sessions", "admin_grants",
		}
		for _, table := range tables {
			var exists bool
			err := db.QueryRowContext(ctx, `
				SELECT EXISTS (
					SELECT 1
					FROM information_schema.tables
					WHERE table_schema = 'public' AND table_name = $1
				)
			`, table).Scan(&exists)
			if err != nil {
				return err
			}
			status := "missing"
			if exists {
				status = "present"
			}
			fmt.Printf("%s %s\n", table, status)
		}
	case "apply":
		if strings.EqualFold(firstEnv("SERVER_MODE", "PLYSTRA_ENV"), "production") {
			return fmt.Errorf("Ent auto migration is disabled in production. Use versioned migrations through plystractl migrate up")
		}
		if err := client.Schema.Create(ctx, schema.WithDropColumn(false), schema.WithDropIndex(false)); err != nil {
			return err
		}
		fmt.Println("ent schema applied")
	case "plan":
		plan, err := entMigrationPlan(ctx, client)
		if err != nil {
			return err
		}
		if strings.TrimSpace(plan) == "" {
			fmt.Println("ent schema is in sync")
			return nil
		}
		fmt.Print(plan)
	case "check":
		plan, err := entMigrationPlan(ctx, client)
		if err != nil {
			return err
		}
		if strings.TrimSpace(plan) != "" {
			return fmt.Errorf("ent schema drift detected; update versioned migrations:\n%s", strings.TrimSpace(plan))
		}
		fmt.Println("ent schema is in sync")
	default:
		return fmt.Errorf("unknown ent command %q", command)
	}
	return nil
}

func entMigrationPlan(ctx context.Context, client *ent.Client) (string, error) {
	var out strings.Builder
	if err := client.Schema.WriteTo(ctx, &out, schema.WithDropColumn(false), schema.WithDropIndex(false)); err != nil {
		return "", err
	}
	return out.String(), nil
}

func openEntClient(ctx context.Context) (*ent.Client, *sql.DB, error) {
	cfg, err := pgx.ParseConfig(databaseURL())
	if err != nil {
		return nil, nil, err
	}
	db := stdlib.OpenDB(*cfg)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, nil, err
	}
	drv := entsql.OpenDB(dialect.Postgres, db)
	return ent.NewClient(ent.Driver(drv)), db, nil
}

func runDoctor(ctx context.Context) error {
	mode := strings.ToLower(firstEnv("SERVER_MODE", "PLYSTRA_ENV"))
	if mode == "" {
		mode = "development"
	}
	fmt.Printf("environment: %s\n", mode)
	if err := validateDoctorConfig(mode); err != nil {
		return err
	}
	fmt.Println("configuration: ok")

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
		return fmt.Errorf("migrations are pending; run plystractl migrate up")
	} else {
		fmt.Println("migrations: current")
	}

	client, db, err := openEntClient(ctx)
	if err != nil {
		return fmt.Errorf("schema readiness failed: %w", err)
	}
	defer client.Close()
	defer db.Close()
	plan, err := entMigrationPlan(ctx, client)
	if err != nil {
		return fmt.Errorf("schema readiness failed: %w", err)
	}
	if strings.TrimSpace(plan) != "" {
		return fmt.Errorf("schema readiness failed: ent drift detected:\n%s", strings.TrimSpace(plan))
	}
	fmt.Println("schema: ok")
	fmt.Println("service readiness: ok")
	sessionSecret := firstEnv("PLYSTRA_SESSION_SECRET", "SESSION_SECRET", "JWT_SECRET", "PLYSTRA_JWT_SECRET")
	if len(sessionSecret) < 32 || sessionSecret == defaultSessionSecret || sessionSecret == defaultJWTSecret {
		fmt.Println("warning: PLYSTRA_SESSION_SECRET or JWT_SECRET is unset, default, or shorter than 32 characters")
	}
	return nil
}

func validateDoctorConfig(mode string) error {
	if mode != "production" {
		return nil
	}
	if databaseURL() == defaultDatabaseURL && os.Getenv("DATABASE_URL") == "" && os.Getenv("PLYSTRA_DATABASE_URL") == "" {
		return fmt.Errorf("DATABASE_URL is required in production")
	}
	if databaseURL() == defaultDatabaseURL || strings.Contains(databaseURL(), "://plystra:plystra@") {
		return fmt.Errorf("DATABASE_URL must not use the default development database credentials in production")
	}
	sessionSecret := firstEnv("PLYSTRA_SESSION_SECRET", "SESSION_SECRET", "JWT_SECRET", "PLYSTRA_JWT_SECRET")
	if len(sessionSecret) < 32 || sessionSecret == defaultSessionSecret || sessionSecret == defaultJWTSecret {
		return fmt.Errorf("PLYSTRA_SESSION_SECRET or JWT_SECRET must be changed and at least 32 characters in production")
	}
	corsOrigins := strings.TrimSpace(os.Getenv("CORS_ALLOWED_ORIGINS"))
	if corsOrigins == "" || wildcardListContains(corsOrigins) {
		return fmt.Errorf("CORS_ALLOWED_ORIGINS must be explicit and must not include * in production")
	}
	publicURL := firstEnv("SERVER_PUBLIC_URL", "PLYSTRA_SERVER_PUBLIC_URL")
	if publicURL == "" {
		return fmt.Errorf("SERVER_PUBLIC_URL is required in production")
	}
	if isLocalPublicURL(publicURL) {
		return fmt.Errorf("SERVER_PUBLIC_URL must not point to localhost in production")
	}
	return nil
}

func wildcardListContains(value string) bool {
	for _, part := range strings.Split(value, ",") {
		if strings.TrimSpace(part) == "*" {
			return true
		}
	}
	return false
}

func isLocalPublicURL(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil {
		return true
	}
	host := parsed.Hostname()
	if host == "" {
		host = parsed.Host
	}
	host = strings.ToLower(strings.Trim(host, "[]"))
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
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
		pending := []string{}
		for _, migration := range migrations {
			record, ok := applied[migration.Version]
			if !ok {
				pending = append(pending, migration.Version+" "+migration.Name)
				continue
			}
			if record.Checksum != migration.Checksum {
				return fmt.Errorf("%s checksum mismatch: database=%s file=%s", migration.Version, record.Checksum, migration.Checksum)
			}
		}
		if len(pending) > 0 {
			return fmt.Errorf("pending migrations: %s; run plystractl migrate up", strings.Join(pending, ", "))
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
	for _, key := range []string{"DATABASE_URL", "PLYSTRA_DATABASE_URL"} {
		if value := os.Getenv(key); value != "" {
			return value
		}
	}
	return defaultDatabaseURL
}

func firstEnv(keys ...string) string {
	for _, key := range keys {
		if value := os.Getenv(key); value != "" {
			return value
		}
	}
	return ""
}
