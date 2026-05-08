package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/plystra/plystra/ent/auditlog"
)

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if !featureEnabled("METRICS_ENABLED") {
		writeError(w, r, http.StatusNotFound, "FEATURE_DISABLED", "Metrics endpoint is disabled.", nil)
		return
	}
	if !metricsAuthorized(r) {
		writeError(w, r, http.StatusUnauthorized, "METRICS_TOKEN_REQUIRED", "A valid metrics token is required.", nil)
		return
	}
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, r)
		return
	}
	var auditLogs int
	var authzDenies int
	if s.ent == nil {
		writeError(w, r, http.StatusServiceUnavailable, "NOT_READY", "Ent client is not configured.", nil)
		return
	}
	var err error
	auditLogs, err = s.ent.AuditLog.Query().Count(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to read audit metrics.", err.Error())
		return
	}
	authzDenies, err = s.ent.AuditLog.Query().Where(auditlog.Decision("deny")).Count(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to read audit metrics.", err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "audit_logs_written_total %d\n", auditLogs)
	fmt.Fprintf(w, "authz_denies_total %d\n", authzDenies)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, r)
		return
	}
	writeData(w, r, http.StatusOK, map[string]any{"status": "ok"})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, r)
		return
	}
	if err := s.pool.Ping(r.Context()); err != nil {
		writeError(w, r, http.StatusServiceUnavailable, "NOT_READY", "Database is not reachable.", err.Error())
		return
	}
	schemaVersion, expectedSchemaVersion, err := s.readySchemaVersions(r.Context())
	if err != nil {
		writeError(w, r, http.StatusServiceUnavailable, "NOT_READY", "Database migrations are not current or schema_migrations is unavailable.", err.Error())
		return
	}
	writeData(w, r, http.StatusOK, map[string]any{
		"status":                  "ready",
		"schema_version":          schemaVersion,
		"expected_schema_version": expectedSchemaVersion,
		"trace_version":           traceVersion(),
	})
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, r)
		return
	}
	schemaVersion, _ := s.latestSchemaVersion(r.Context())
	expectedSchemaVersion, _ := latestMigrationVersion("migrations")
	writeData(w, r, http.StatusOK, map[string]any{
		"core_version":              s.coreVersion,
		"api_version":               "v1",
		"schema_version":            schemaVersion,
		"expected_schema_version":   expectedSchemaVersion,
		"trace_version":             traceVersion(),
		"plugin_api_version":        "1.0",
		"resource_registry_version": "1.0",
		"build_time":                time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) latestSchemaVersion(ctx context.Context) (string, error) {
	// schema_migrations is migration metadata, not a Core business entity.
	// Keep this tiny control-plane read outside Ent so readiness can validate migrations.
	var version string
	err := s.pool.QueryRow(ctx, `SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1`).Scan(&version)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("no migrations have been applied")
	}
	return version, err
}

func (s *Server) readySchemaVersions(ctx context.Context) (string, string, error) {
	appliedVersion, err := s.latestSchemaVersion(ctx)
	if err != nil {
		return "", "", err
	}
	expectedVersions, err := migrationVersions("migrations")
	if err != nil {
		return "", "", err
	}
	expectedVersion := expectedVersions[len(expectedVersions)-1]
	missing, err := s.missingMigrationVersions(ctx, expectedVersions)
	if err != nil {
		return "", "", err
	}
	if len(missing) > 0 {
		return appliedVersion, expectedVersion, fmt.Errorf("pending migrations: %s", strings.Join(missing, ", "))
	}
	if appliedVersion != expectedVersion {
		return appliedVersion, expectedVersion, fmt.Errorf("schema version %s is not current; expected %s", appliedVersion, expectedVersion)
	}
	return appliedVersion, expectedVersion, nil
}

func (s *Server) missingMigrationVersions(ctx context.Context, expectedVersions []string) ([]string, error) {
	// See latestSchemaVersion: schema_migrations intentionally remains migration metadata.
	rows, err := s.pool.Query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	applied := map[string]struct{}{}
	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			return nil, err
		}
		applied[version] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	missing := []string{}
	for _, version := range expectedVersions {
		if _, ok := applied[version]; !ok {
			missing = append(missing, version)
		}
	}
	return missing, nil
}

func latestMigrationVersion(dir string) (string, error) {
	versions, err := migrationVersions(dir)
	if err != nil {
		return "", err
	}
	return versions[len(versions)-1], nil
}

func migrationVersions(dir string) ([]string, error) {
	candidates := []string{dir, filepath.Join("..", "..", dir)}
	var lastErr error
	for _, candidate := range candidates {
		version, err := migrationVersionsInDir(candidate)
		if err == nil {
			return version, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func migrationVersionsInDir(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	versions := []string{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		version, _, _ := strings.Cut(strings.TrimSuffix(entry.Name(), ".sql"), "_")
		versions = append(versions, version)
	}
	if len(versions) == 0 {
		return nil, fmt.Errorf("no migration files found in %s", dir)
	}
	sort.Strings(versions)
	return versions, nil
}

func traceVersion() string {
	if value := os.Getenv("TRACE_VERSION"); value != "" {
		return value
	}
	return "1.0"
}
