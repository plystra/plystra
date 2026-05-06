package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/plystra/plystra/internal/api"
)

const defaultDatabaseURL = "postgres://plystra:plystra@localhost:5432/plystra?sslmode=disable"

func main() {
	ctx := context.Background()
	if err := validateProductionConfig(); err != nil {
		fmt.Fprintf(os.Stderr, "invalid configuration: %v\n", err)
		os.Exit(1)
	}
	pool, err := pgxpool.New(ctx, databaseURL())
	if err != nil {
		fmt.Fprintf(os.Stderr, "configure database: %v\n", err)
		os.Exit(1)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "connect database: %v\n", err)
		os.Exit(1)
	}

	port := os.Getenv("PLYSTRA_SERVER_PORT")
	if port == "" {
		port = "8080"
	}
	coreVersion := os.Getenv("PLYSTRA_CORE_VERSION")
	if coreVersion == "" {
		coreVersion = "1.0.0-dev"
	}

	server := api.NewServer(pool, coreVersion)
	addr := ":" + port
	fmt.Printf("plystrad listening on http://localhost%s\n", addr)
	if err := http.ListenAndServe(addr, server.Routes()); err != nil {
		fmt.Fprintf(os.Stderr, "serve: %v\n", err)
		os.Exit(1)
	}
}

func validateProductionConfig() error {
	env := strings.ToLower(os.Getenv("PLYSTRA_ENV"))
	if env != "production" {
		return nil
	}
	if os.Getenv("PLYSTRA_DATABASE_URL") == "" && os.Getenv("DATABASE_URL") == "" {
		return fmt.Errorf("PLYSTRA_DATABASE_URL is required in production")
	}
	if len(os.Getenv("PLYSTRA_JWT_SECRET")) < 32 {
		return fmt.Errorf("PLYSTRA_JWT_SECRET must be at least 32 characters in production")
	}
	if os.Getenv("PLYSTRA_SERVER_PUBLIC_URL") == "" {
		return fmt.Errorf("PLYSTRA_SERVER_PUBLIC_URL is required in production")
	}
	return nil
}

func databaseURL() string {
	for _, key := range []string{"PLYSTRA_DATABASE_URL", "DATABASE_URL"} {
		if value := os.Getenv(key); value != "" {
			return value
		}
	}
	return defaultDatabaseURL
}
