package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

func runUpgrade(ctx context.Context, command string, args []string) error {
	switch command {
	case "plan":
		migrations, err := loadMigrations("migrations")
		if err != nil {
			return err
		}
		plan := map[string]any{
			"steps": []string{
				"create and verify a PostgreSQL backup",
				"stop plugin processes that write to the database",
				"run plystractl migrate up",
				"run plystractl migrate verify",
				"run plystractl ent check",
				"run plystractl doctor",
				"restart Core and plugins",
				"record upgrade audit event",
			},
			"target_schema_version": migrations[len(migrations)-1].Version,
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(plan)
	case "verify":
		if err := runMigrate(ctx, "verify"); err != nil {
			return err
		}
		if err := runEnt(ctx, "check"); err != nil {
			return err
		}
		if err := runDoctor(ctx); err != nil {
			return err
		}
		fmt.Println("upgrade verification passed")
		return nil
	case "record":
		flags := flag.NewFlagSet("upgrade record", flag.ContinueOnError)
		flags.SetOutput(os.Stderr)
		version := flags.String("version", firstEnv("PLYSTRA_CORE_VERSION", "CORE_VERSION"), "upgraded Core version")
		actorUserID := flags.String("actor-user-id", "", "operator user id")
		actorMemberID := flags.String("actor-member-id", "", "operator member id")
		spaceID := flags.String("space-id", "system", "audit space id")
		if err := flags.Parse(args); err != nil {
			return err
		}
		if strings.TrimSpace(*version) == "" {
			return fmt.Errorf("--version is required")
		}
		return recordUpgradeAudit(ctx, strings.TrimSpace(*version), strings.TrimSpace(*spaceID), strings.TrimSpace(*actorUserID), strings.TrimSpace(*actorMemberID))
	default:
		return fmt.Errorf("unknown upgrade command %q", command)
	}
}

func recordUpgradeAudit(ctx context.Context, version, spaceID, actorUserID, actorMemberID string) error {
	client, db, err := openEntClient(ctx)
	if err != nil {
		return err
	}
	defer client.Close()
	defer db.Close()
	id := "audit_upgrade_" + safeID(version+"_"+time.Now().UTC().Format("20060102150405"))
	trace := map[string]any{
		"trace_version": "1.0",
		"decision":      "allow",
		"reason":        "operator recorded a Plystra upgrade",
		"version":       version,
	}
	create := client.AuditLog.Create().
		SetID(id).
		SetSpaceID(spaceID).
		SetAction("system.upgrade").
		SetResourceType("core").
		SetResourceID(version).
		SetDecision("allow").
		SetTrace(trace).
		SetRequestID(id)
	if actorUserID != "" {
		create.SetActorUserID(actorUserID)
	}
	if actorMemberID != "" {
		create.SetActorMemberID(actorMemberID)
	}
	if _, err := create.Save(ctx); err != nil {
		return err
	}
	fmt.Printf("upgrade audit recorded: %s\n", id)
	return nil
}

func safeID(value string) string {
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + ('a' - 'A'))
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := strings.Trim(b.String(), "_")
	if out == "" {
		return "generated"
	}
	return out
}
