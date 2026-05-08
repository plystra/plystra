package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/plystra/plystra/internal/api"
	"github.com/plystra/plystra/internal/store/entstore"
)

const defaultDatabaseURL = "postgres://plystra:plystra@localhost:5432/plystra?sslmode=disable"
const defaultSessionSecret = "change-me-session-secret-at-least-32-characters"
const defaultJWTSecret = "change-me-to-at-least-32-characters"

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
