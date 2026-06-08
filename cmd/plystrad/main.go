package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/plystra/core/internal/api"
	"github.com/plystra/core/internal/kernel"
	"github.com/plystra/core/internal/store/entstore"
	"github.com/plystra/core/internal/system"
)

const defaultDatabaseURL = "postgres://plystra:plystra@localhost:5432/plystra?sslmode=disable"
const defaultCoreVersion = "0.0.1"

const (
	defaultSessionSecret = "change-me-session-secret-at-least-32-characters"
	defaultAPIKeySecret  = "change-me-api-key-secret-at-least-32-characters"
)

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
		coreVersion = defaultCoreVersion
	}

	authzStore, err := entstore.Open(ctx, databaseURL())
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect ent store: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = authzStore.Close() }()

	kernelApp, err := kernel.Boot(ctx, kernel.Options{
		KernelVersion: coreVersion,
		Capabilities:  system.BuiltInCapabilities(authzStore, authzStore),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "boot kernel: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = kernelApp.Stop(context.Background()) }()

	apiServer := api.NewServer(pool, authzStore, coreVersion).WithKernel(kernelApp)
	reconcilerCtx, stopReconciler := context.WithCancel(ctx)
	defer stopReconciler()
	startCapabilityGrantReconciler(reconcilerCtx, apiServer)

	addr := ":" + port
	if host != "" {
		addr = net.JoinHostPort(host, port)
	}
	httpServer, err := newHTTPServer(addr, apiServer.Routes())
	if err != nil {
		fmt.Fprintf(os.Stderr, "configure http server: %v\n", err)
		os.Exit(1)
	}
	displayHost := host
	if displayHost == "" || displayHost == "0.0.0.0" {
		displayHost = "localhost"
	}
	fmt.Printf("plystrad listening on http://%s:%s\n", displayHost, port)
	if err := httpServer.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "serve: %v\n", err)
		os.Exit(1)
	}
}

func newHTTPServer(addr string, handler http.Handler) (*http.Server, error) {
	readHeaderTimeout, err := durationFromEnv("HTTP_READ_HEADER_TIMEOUT", 5*time.Second)
	if err != nil {
		return nil, err
	}
	readTimeout, err := durationFromEnv("HTTP_READ_TIMEOUT", 30*time.Second)
	if err != nil {
		return nil, err
	}
	writeTimeout, err := durationFromEnv("HTTP_WRITE_TIMEOUT", 60*time.Second)
	if err != nil {
		return nil, err
	}
	idleTimeout, err := durationFromEnv("HTTP_IDLE_TIMEOUT", 120*time.Second)
	if err != nil {
		return nil, err
	}
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}, nil
}

func durationFromEnv(key string, fallback time.Duration) (time.Duration, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be a valid Go duration: %w", key, err)
	}
	if parsed <= 0 {
		return 0, fmt.Errorf("%s must be greater than zero", key)
	}
	return parsed, nil
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
	sessionSecret := firstEnv("PLYSTRA_SESSION_SECRET")
	if len(sessionSecret) < 32 || sessionSecret == defaultSessionSecret {
		return fmt.Errorf("PLYSTRA_SESSION_SECRET must be changed and at least 32 characters in production")
	}
	apiKeySecret := firstEnv("PLYSTRA_API_KEY_SECRET")
	if len(apiKeySecret) < 32 || apiKeySecret == defaultSessionSecret || apiKeySecret == defaultAPIKeySecret {
		return fmt.Errorf("PLYSTRA_API_KEY_SECRET must be set and at least 32 characters in production")
	}
	if apiKeySecret == sessionSecret {
		return fmt.Errorf("PLYSTRA_API_KEY_SECRET must be distinct from PLYSTRA_SESSION_SECRET in production")
	}
	if err := validateRegistrationConfig(); err != nil {
		return err
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

func validateRegistrationConfig() error {
	if featureEnabled("PLYSTRA_AUTH_REGISTRATION_ENABLED") && !featureEnabled("PLYSTRA_AUTH_PUBLIC_USER_REGISTRATION_ENABLED") {
		if !registrationSecretSafe("PLYSTRA_AUTH_REGISTRATION_TOKEN") {
			return fmt.Errorf("PLYSTRA_AUTH_REGISTRATION_TOKEN must be set and at least 32 characters when registration is enabled in production")
		}
	}
	if featureEnabled("PLYSTRA_BOOTSTRAP_REGISTRATION_ENABLED") {
		if !registrationSecretSafe("PLYSTRA_BOOTSTRAP_REGISTRATION_TOKEN") {
			return fmt.Errorf("PLYSTRA_BOOTSTRAP_REGISTRATION_TOKEN must be set and at least 32 characters when bootstrap registration is enabled in production")
		}
	}
	return nil
}

func registrationSecretSafe(key string) bool {
	value := strings.TrimSpace(os.Getenv(key))
	return len(value) >= 32
}

func featureEnabled(key string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "on", "enabled":
		return true
	default:
		return false
	}
}

func validatePreviousSessionSecrets() error {
	for _, key := range []string{"PLYSTRA_SESSION_SECRET_PREVIOUS"} {
		for _, value := range strings.Split(os.Getenv(key), ",") {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			if len(value) < 32 || value == defaultSessionSecret {
				return fmt.Errorf("%s contains an unsafe previous session secret", key)
			}
		}
	}
	return nil
}

func validatePreviousAPIKeySecrets() error {
	for _, key := range []string{"PLYSTRA_API_KEY_SECRET_PREVIOUS"} {
		for _, value := range strings.Split(os.Getenv(key), ",") {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			if len(value) < 32 || value == defaultSessionSecret || value == defaultAPIKeySecret {
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
