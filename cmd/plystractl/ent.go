package main

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/schema"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/plystra/plystra/ent"
)

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
