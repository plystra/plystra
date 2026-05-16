package capabilities

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	contractauthz "github.com/plystra/contracts/authz"
	"github.com/plystra/contracts/capability"
	"gopkg.in/yaml.v3"
)

type Manager struct {
	kernelVersion string
	configPath    string
	lockPath      string
	pool          *pgxpool.Pool
	client        *http.Client
	mu            sync.RWMutex
	states        map[string]string
	manifests     map[string]capability.Manifest
	services      map[string]capability.ServiceRegistration
	routes        map[string]capability.RouteRegistration
	processes     map[string]*exec.Cmd
	ordered       []capability.Manifest
	bootErr       error
}

type Options struct {
	KernelVersion string
	ConfigPath    string
	LockPath      string
	Pool          *pgxpool.Pool
}

func NewManager(opts Options) *Manager {
	return &Manager{
		kernelVersion: opts.KernelVersion,
		configPath:    opts.ConfigPath,
		lockPath:      opts.LockPath,
		pool:          opts.Pool,
		client:        &http.Client{Timeout: 5 * time.Second},
		states:        map[string]string{},
		manifests:     map[string]capability.Manifest{},
		services:      map[string]capability.ServiceRegistration{},
		routes:        map[string]capability.RouteRegistration{},
		processes:     map[string]*exec.Cmd{},
	}
}

func Boot(ctx context.Context, opts Options) (*Manager, error) {
	manager := NewManager(opts)
	if err := manager.Boot(ctx); err != nil {
		manager.bootErr = err
		_ = manager.Stop(context.Background())
		return manager, err
	}
	return manager, nil
}

func (m *Manager) Boot(ctx context.Context) error {
	if strings.TrimSpace(m.configPath) == "" {
		return nil
	}
	cfgData, err := os.ReadFile(m.configPath)
	if err != nil {
		return fmt.Errorf("load system capability config: %w", err)
	}
	cfg, err := capability.ParseConfig(cfgData)
	if err != nil {
		return err
	}
	lock, err := loadOrCreateLockfile(m.lockPath, cfg)
	if err != nil {
		return err
	}
	lockByID := map[string]capability.LockedCapability{}
	for _, locked := range lock.SystemCapabilities {
		lockByID[locked.ID] = locked
	}

	records := make([]configuredManifest, 0, len(cfg.SystemCapabilities))
	for _, configured := range cfg.SystemCapabilities {
		m.setState(configured.ID, capability.StateDiscovered)
		manifestPath := resolvePath(filepath.Dir(m.configPath), configured.Manifest)
		manifestData, err := os.ReadFile(manifestPath)
		if err != nil {
			return fmt.Errorf("load manifest for %s: %w", configured.ID, err)
		}
		manifest, err := capability.ParseManifest(manifestData)
		if err != nil {
			return fmt.Errorf("validate manifest for %s: %w", configured.ID, err)
		}
		if manifest.ID != configured.ID {
			return fmt.Errorf("configured capability %q loaded manifest %q", configured.ID, manifest.ID)
		}
		binaryPath := resolveExecutablePath(filepath.Dir(m.configPath), configured.Binary)
		locked, ok := lockByID[configured.ID]
		if !ok {
			return fmt.Errorf("lockfile is missing capability %q", configured.ID)
		}
		if locked.Version != manifest.Version {
			return fmt.Errorf("locked capability %q version %q does not match manifest %q", configured.ID, locked.Version, manifest.Version)
		}
		if err := verifyBinary(binaryPath, locked.Checksum); err != nil {
			return err
		}
		m.manifests[manifest.ID] = manifest
		m.setState(manifest.ID, capability.StateValidated)
		records = append(records, configuredManifest{config: configured, manifest: manifest, binaryPath: binaryPath, manifestPath: manifestPath})
	}

	manifests := make([]capability.Manifest, len(records))
	for i, record := range records {
		manifests[i] = record.manifest
	}
	ordered, err := capability.ResolveOrder(manifests)
	if err != nil {
		return err
	}
	m.ordered = ordered
	recordByID := map[string]configuredManifest{}
	for _, record := range records {
		recordByID[record.manifest.ID] = record
	}

	for _, manifest := range ordered {
		record := recordByID[manifest.ID]
		if err := m.applyMigrations(ctx, record); err != nil {
			m.setState(manifest.ID, capability.StateFailed)
			return err
		}
		m.setState(manifest.ID, capability.StateMigrated)
		if err := m.startCapability(ctx, record); err != nil {
			m.setState(manifest.ID, capability.StateFailed)
			return err
		}
		m.setState(manifest.ID, capability.StateReady)
	}
	return nil
}

func (m *Manager) Ready() error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.bootErr != nil {
		return m.bootErr
	}
	for _, id := range capability.RequiredSystemCapabilityOrder {
		if manifest, ok := m.manifests[id]; ok && manifest.Required && m.states[id] != capability.StateReady {
			return fmt.Errorf("required capability %s is %s", id, m.states[id])
		}
	}
	return nil
}

func (m *Manager) Services() []capability.ServiceRegistration {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]capability.ServiceRegistration, 0, len(m.services))
	for _, service := range m.services {
		out = append(out, service)
	}
	return out
}

func (m *Manager) States() map[string]string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := map[string]string{}
	for id, state := range m.states {
		out[id] = state
	}
	return out
}

func (m *Manager) Route(method, path string) (capability.RouteRegistration, capability.ServiceRegistration, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	route, ok := m.routes[routeKey(method, path)]
	if !ok {
		return capability.RouteRegistration{}, capability.ServiceRegistration{}, false
	}
	service, ok := m.services[route.Service]
	return route, service, ok
}

func (m *Manager) Proxy(w http.ResponseWriter, r *http.Request, route capability.RouteRegistration, service capability.ServiceRegistration, body []byte) error {
	if m == nil {
		return errors.New("capability manager is not configured")
	}
	targetPath := capabilityPath(route)
	if targetPath == "" {
		return fmt.Errorf("route %s %s is not proxyable", route.Method, route.Path)
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, "http://"+service.Address+targetPath, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", r.Header.Get("X-Request-ID"))
	req.Header.Set("X-Plystra-Internal-Call", "system-capability")
	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	for key, values := range resp.Header {
		if strings.EqualFold(key, "Content-Length") {
			continue
		}
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, err = io.Copy(w, resp.Body)
	return err
}

func (m *Manager) Authorize(ctx context.Context, explain bool, input contractauthz.CheckInput) (*contractauthz.Decision, error) {
	if m == nil {
		return nil, errors.New("capability manager is not configured")
	}
	path := "/api/v1/authz/check"
	operationPath := capability.PathAuthorizationCheck
	if explain {
		path = "/api/v1/authz/explain"
		operationPath = capability.PathAuthorizationExplain
	}
	route, service, ok := m.Route(http.MethodPost, path)
	if !ok {
		return nil, errors.New("authorization capability route is not registered")
	}
	if route.CapabilityID != capability.AuthorizationResource {
		return nil, fmt.Errorf("route %s is owned by unexpected capability %s", path, route.CapabilityID)
	}
	var decision contractauthz.Decision
	if err := postJSON(ctx, m.client, "http://"+service.Address+operationPath, input, &decision); err != nil {
		return nil, err
	}
	return &decision, nil
}

func (m *Manager) Stop(ctx context.Context) error {
	m.mu.Lock()
	processes := make(map[string]*exec.Cmd, len(m.processes))
	for id, cmd := range m.processes {
		processes[id] = cmd
	}
	m.mu.Unlock()
	var firstErr error
	for id, cmd := range processes {
		manifest := m.manifests[id]
		_ = postJSON(ctx, m.client, "http://"+manifest.Runtime.Address+capability.PathStop, capability.StopRequest{}, &capability.StopResponse{})
		if cmd.Process != nil {
			if err := cmd.Process.Kill(); err != nil && firstErr == nil {
				firstErr = err
			}
			_, _ = cmd.Process.Wait()
		}
		m.setState(id, capability.StateStopped)
	}
	return firstErr
}

type configuredManifest struct {
	config       capability.ConfiguredCapability
	manifest     capability.Manifest
	binaryPath   string
	manifestPath string
}

func (m *Manager) startCapability(ctx context.Context, record configuredManifest) error {
	manifest := record.manifest
	m.setState(manifest.ID, capability.StateStarting)
	binaryPath, err := filepath.Abs(record.binaryPath)
	if err != nil {
		return err
	}
	manifestPath, err := filepath.Abs(record.manifestPath)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, binaryPath)
	cmd.Dir = filepath.Dir(manifestPath)
	cmd.Env = append(os.Environ(),
		"PLYSTRA_CAPABILITY_ID="+manifest.ID,
		"PLYSTRA_CAPABILITY_ADDRESS="+manifest.Runtime.Address,
		"PLYSTRA_CAPABILITY_MANIFEST="+manifestPath,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start capability %s: %w", manifest.ID, err)
	}
	m.mu.Lock()
	m.processes[manifest.ID] = cmd
	m.mu.Unlock()

	if err := waitHealth(ctx, m.client, manifest); err != nil {
		return err
	}
	var desc capability.Description
	if err := getJSON(ctx, m.client, "http://"+manifest.Runtime.Address+capability.PathDescribe, &desc); err != nil {
		return fmt.Errorf("describe capability %s: %w", manifest.ID, err)
	}
	if desc.Manifest.ID != manifest.ID {
		return fmt.Errorf("capability %s described itself as %s", manifest.ID, desc.Manifest.ID)
	}
	if err := postJSON(ctx, m.client, "http://"+manifest.Runtime.Address+capability.PathPrepare, capability.PrepareRequest{KernelVersion: m.kernelVersion, Services: m.serviceMap()}, &capability.PrepareResponse{}); err != nil {
		return fmt.Errorf("prepare capability %s: %w", manifest.ID, err)
	}
	var startResp capability.StartResponse
	if err := postJSON(ctx, m.client, "http://"+manifest.Runtime.Address+capability.PathStart, capability.StartRequest{}, &startResp); err != nil {
		return fmt.Errorf("start lifecycle for capability %s: %w", manifest.ID, err)
	}
	if !startResp.Ready {
		return fmt.Errorf("capability %s did not become ready", manifest.ID)
	}
	m.register(manifest)
	m.setState(manifest.ID, capability.StateRegistered)
	return nil
}

func (m *Manager) applyMigrations(ctx context.Context, record configuredManifest) error {
	if m.pool == nil {
		return nil
	}
	if _, err := m.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS kernel_capability_migrations (
			id TEXT PRIMARY KEY,
			capability_id TEXT NOT NULL,
			capability_version TEXT NOT NULL,
			migration_id TEXT NOT NULL,
			checksum TEXT NOT NULL,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)
	`); err != nil {
		return fmt.Errorf("ensure capability migration table: %w", err)
	}
	dir := resolvePath(filepath.Dir(record.manifestPath), record.manifest.Provides.Migrations.Path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read capability migrations for %s: %w", record.manifest.ID, err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		sqlBytes, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(sqlBytes)
		checksum := "sha256:" + hex.EncodeToString(sum[:])
		migrationID := strings.TrimSuffix(entry.Name(), ".sql")
		id := record.manifest.ID + ":" + migrationID
		var existing string
		err = m.pool.QueryRow(ctx, `SELECT checksum FROM kernel_capability_migrations WHERE id = $1`, id).Scan(&existing)
		if err == nil {
			if existing != checksum {
				return fmt.Errorf("capability migration %s checksum mismatch", id)
			}
			continue
		}
		tx, err := m.pool.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(sqlBytes)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("apply capability migration %s: %w", id, err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO kernel_capability_migrations (id, capability_id, capability_version, migration_id, checksum)
			VALUES ($1, $2, $3, $4, $5)
		`, id, record.manifest.ID, record.manifest.Version, migrationID, checksum); err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) register(manifest capability.Manifest) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, service := range manifest.Provides.Services {
		m.services[service.Name] = capability.ServiceRegistration{
			Name:         service.Name,
			CapabilityID: manifest.ID,
			Protocol:     manifest.Runtime.Protocol,
			Address:      manifest.Runtime.Address,
			Version:      manifest.Version,
			Health:       "ready",
			RegisteredAt: time.Now().UTC(),
		}
	}
	for _, route := range manifest.Provides.Routes {
		m.routes[routeKey(route.Method, route.Path)] = capability.RouteRegistration{
			Method:       route.Method,
			Path:         route.Path,
			Service:      route.Service,
			Operation:    route.Operation,
			CapabilityID: manifest.ID,
		}
	}
}

func (m *Manager) serviceMap() map[string]capability.ServiceRegistration {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := map[string]capability.ServiceRegistration{}
	for name, service := range m.services {
		out[name] = service
	}
	return out
}

func (m *Manager) setState(id, state string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.states[id] = state
}

func waitHealth(ctx context.Context, client *http.Client, manifest capability.Manifest) error {
	deadline := time.Now().Add(20 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		var health capability.HealthResponse
		err := getJSON(ctx, client, "http://"+manifest.Runtime.Address+capability.PathHealth, &health)
		if err == nil && health.Status == "ready" {
			return nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	return fmt.Errorf("capability %s health check failed: %w", manifest.ID, lastErr)
}

func getJSON(ctx context.Context, client *http.Client, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("GET %s returned %d", url, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func postJSON(ctx context.Context, client *http.Client, url string, in any, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		payload, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("POST %s returned %d: %s", url, resp.StatusCode, strings.TrimSpace(string(payload)))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func loadOrCreateLockfile(path string, cfg capability.Config) (capability.Lockfile, error) {
	if strings.TrimSpace(path) != "" {
		data, err := os.ReadFile(path)
		if err == nil {
			return capability.ParseLockfile(data)
		}
		if !errors.Is(err, os.ErrNotExist) {
			return capability.Lockfile{}, err
		}
	}
	lock := capability.Lockfile{}
	base := "."
	if path != "" {
		base = filepath.Dir(path)
	}
	for _, item := range cfg.SystemCapabilities {
		binaryPath := resolveExecutablePath(base, item.Binary)
		sum, err := fileSHA256(binaryPath)
		if err != nil {
			return capability.Lockfile{}, err
		}
		manifestPath := resolvePath(base, item.Manifest)
		manifestData, err := os.ReadFile(manifestPath)
		if err != nil {
			return capability.Lockfile{}, err
		}
		manifest, err := capability.ParseManifest(manifestData)
		if err != nil {
			return capability.Lockfile{}, err
		}
		lock.SystemCapabilities = append(lock.SystemCapabilities, capability.LockedCapability{
			ID:       item.ID,
			Version:  manifest.Version,
			Source:   capability.SourceLocal,
			Path:     item.Binary,
			Checksum: sum,
		})
	}
	if strings.TrimSpace(path) != "" {
		data, err := yaml.Marshal(lock)
		if err != nil {
			return capability.Lockfile{}, err
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return capability.Lockfile{}, err
		}
	}
	return lock, nil
}

func verifyBinary(path, expected string) error {
	actual, err := fileSHA256(path)
	if err != nil {
		return err
	}
	if !strings.EqualFold(actual, expected) {
		return fmt.Errorf("checksum mismatch for %s: got %s, want %s", path, actual, expected)
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func resolvePath(base, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Clean(filepath.Join(base, path))
}

func resolveExecutablePath(base, path string) string {
	resolved := resolvePath(base, path)
	if _, err := os.Stat(resolved); err == nil {
		return resolved
	}
	if runtime.GOOS == "windows" && !strings.HasSuffix(strings.ToLower(resolved), ".exe") {
		if _, err := os.Stat(resolved + ".exe"); err == nil {
			return resolved + ".exe"
		}
	}
	if runtime.GOOS != "windows" && strings.HasSuffix(strings.ToLower(resolved), ".exe") {
		trimmed := strings.TrimSuffix(resolved, filepath.Ext(resolved))
		if _, err := os.Stat(trimmed); err == nil {
			return trimmed
		}
	}
	return resolved
}

func routeKey(method, path string) string {
	return strings.ToUpper(method) + " " + path
}

func capabilityPath(route capability.RouteRegistration) string {
	switch route.Operation {
	case "Check":
		return capability.PathAuthorizationCheck
	case "Explain":
		return capability.PathAuthorizationExplain
	case "Record":
		return capability.PathAuditRecord
	case "Query":
		return capability.PathAuditQuery
	default:
		return ""
	}
}
