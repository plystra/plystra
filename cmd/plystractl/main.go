package main

import (
	"context"
	"fmt"
	"os"
)

const defaultDatabaseURL = "postgres://plystra:plystra@localhost:5432/plystra?sslmode=disable"

const (
	defaultSessionSecret = "change-me-session-secret-at-least-32-characters"
	defaultAPIKeySecret  = "change-me-api-key-secret-at-least-32-characters"
)

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
