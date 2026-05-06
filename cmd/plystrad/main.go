package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/plystra/plystra/internal/api"
	"github.com/plystra/plystra/internal/store/entstore"
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

	host := firstEnv("SERVER_HOST", "PLYSTRA_SERVER_HOST")
	port := firstEnv("SERVER_PORT", "PLYSTRA_SERVER_PORT")
	if port == "" {
		port = "8080"
	}
	coreVersion := firstEnv("PLYSTRA_CORE_VERSION", "CORE_VERSION")
	if coreVersion == "" {
		coreVersion = "1.0.0-dev"
	}

	authzStore, err := entstore.Open(ctx, databaseURL())
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect ent store: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = authzStore.Close() }()

	server := api.NewServer(pool, authzStore, coreVersion)
	addr := ":" + port
	if host != "" {
		addr = net.JoinHostPort(host, port)
	}
	displayHost := host
	if displayHost == "" || displayHost == "0.0.0.0" {
		displayHost = "localhost"
	}
	fmt.Printf("plystrad listening on http://%s:%s\n", displayHost, port)
	if err := http.ListenAndServe(addr, server.Routes()); err != nil {
		fmt.Fprintf(os.Stderr, "serve: %v\n", err)
		os.Exit(1)
	}
}

func validateProductionConfig() error {
	env := strings.ToLower(firstEnv("SERVER_MODE", "PLYSTRA_ENV"))
	if env != "production" {
		return nil
	}
	if os.Getenv("PLYSTRA_DATABASE_URL") == "" && os.Getenv("DATABASE_URL") == "" {
		return fmt.Errorf("DATABASE_URL is required in production")
	}
	if len(firstEnv("JWT_SECRET", "PLYSTRA_JWT_SECRET")) < 32 {
		return fmt.Errorf("JWT_SECRET must be at least 32 characters in production")
	}
	if firstEnv("SERVER_PUBLIC_URL", "PLYSTRA_SERVER_PUBLIC_URL") == "" {
		return fmt.Errorf("SERVER_PUBLIC_URL is required in production")
	}
	return nil
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
