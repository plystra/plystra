package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

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
	apiKeySecret := firstEnv("PLYSTRA_API_KEY_SECRET", "API_KEY_SECRET")
	if len(apiKeySecret) < 32 || apiKeySecret == defaultSessionSecret || apiKeySecret == defaultJWTSecret {
		fmt.Println("warning: PLYSTRA_API_KEY_SECRET is unset, default, or shorter than 32 characters")
	} else if apiKeySecret == sessionSecret {
		fmt.Println("warning: PLYSTRA_API_KEY_SECRET matches the session secret; use a distinct secret in production")
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
	apiKeySecret := firstEnv("PLYSTRA_API_KEY_SECRET", "API_KEY_SECRET")
	if len(apiKeySecret) < 32 || apiKeySecret == defaultSessionSecret || apiKeySecret == defaultJWTSecret {
		return fmt.Errorf("PLYSTRA_API_KEY_SECRET must be set and at least 32 characters in production")
	}
	if apiKeySecret == sessionSecret {
		return fmt.Errorf("PLYSTRA_API_KEY_SECRET must be distinct from PLYSTRA_SESSION_SECRET in production")
	}
	if err := validatePreviousSessionSecrets(); err != nil {
		return err
	}
	if err := validatePreviousAPIKeySecrets(); err != nil {
		return err
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

func validatePreviousSessionSecrets() error {
	for _, key := range []string{"PLYSTRA_SESSION_SECRET_PREVIOUS", "SESSION_SECRET_PREVIOUS"} {
		for _, value := range strings.Split(os.Getenv(key), ",") {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			if len(value) < 32 || value == defaultSessionSecret || value == defaultJWTSecret {
				return fmt.Errorf("%s contains an unsafe previous session secret", key)
			}
		}
	}
	return nil
}

func validatePreviousAPIKeySecrets() error {
	for _, key := range []string{"PLYSTRA_API_KEY_SECRET_PREVIOUS", "API_KEY_SECRET_PREVIOUS"} {
		for _, value := range strings.Split(os.Getenv(key), ",") {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			if len(value) < 32 || value == defaultSessionSecret || value == defaultJWTSecret {
				return fmt.Errorf("%s contains an unsafe previous API key secret", key)
			}
		}
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
