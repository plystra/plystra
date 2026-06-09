package main

import (
	"context"
	"fmt"
	"os"

	"github.com/plystra/core/internal/authz"
	"github.com/plystra/core/internal/demo"
	"github.com/plystra/core/internal/store/entstore"
)

const defaultDatabaseURL = "postgres://plystra:plystra@localhost:5432/plystra?sslmode=disable"

func main() {
	ctx := context.Background()
	databaseURL := os.Getenv("PLYSTRA_DATABASE_URL")
	if databaseURL == "" {
		databaseURL = os.Getenv("DATABASE_URL")
	}
	if databaseURL == "" {
		databaseURL = defaultDatabaseURL
	}

	pgStore, err := entstore.Open(ctx, databaseURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect ent store: %v\n", err)
		fmt.Fprintln(os.Stderr, "hint: run migrations, then apply examples/finance-reviewer/seed.sql")
		os.Exit(1)
	}
	defer func() { _ = pgStore.Close() }()

	engine := authz.NewEngine(pgStore)
	ok := true

	for _, scenario := range demo.FinanceReviewerScenarios() {
		decision, err := engine.Check(ctx, scenario.Input)
		if err != nil {
			fmt.Fprintf(os.Stderr, "case %d failed: %v\n", scenario.Case, err)
			os.Exit(1)
		}

		demo.PrintDecision(os.Stdout, scenario, decision)
		if !scenario.Matches(decision) {
			ok = false
			fmt.Fprintf(os.Stderr, "case %d mismatch: got decision=%s deny_code=%s\n", scenario.Case, decision.Decision, denyCodeString(decision.DenyCode))
		}
	}

	if !ok {
		os.Exit(1)
	}
}

func denyCodeString(code *authz.DenyCode) string {
	if code == nil {
		return "null"
	}

	return string(*code)
}
