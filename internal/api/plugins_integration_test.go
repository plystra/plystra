package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	coreent "github.com/plystra/core/ent"
	entplugin "github.com/plystra/core/ent/plugin"
	entpluginadminmenu "github.com/plystra/core/ent/pluginadminmenu"
	entpluginsettingsdefinition "github.com/plystra/core/ent/pluginsettingsdefinition"
	entproviderinstallation "github.com/plystra/core/ent/providerinstallation"
	"github.com/plystra/core/internal/plugins"
	"github.com/plystra/core/internal/store/entstore"
)

func TestAppModulesAreSeparatedFromReusablePluginListing(t *testing.T) {
	databaseURL := pluginTestDatabaseURL()
	if databaseURL == "" {
		t.Skip("set PLYSTRA_INTEGRATION_DATABASE_URL or PLYSTRA_DATABASE_URL to run plugin integration tests")
	}
	ctx := context.Background()
	store, err := entstore.Open(ctx, databaseURL)
	if err != nil {
		t.Fatalf("open ent store: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})

	suffix := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	reusableID := "test.reusable_" + suffix
	appModuleID := "app.sample.module_" + suffix
	t.Cleanup(func() {
		cleanupPluginIntegrationRows(context.Background(), store.Client(), t, reusableID, appModuleID)
	})
	createPluginRow(t, ctx, store.Client(), "plugin_listing_reusable_"+suffix, reusableID, plugins.Manifest{
		ID:               reusableID,
		Name:             "Reusable Test Plugin",
		Version:          "1.0.0",
		Type:             "plugin",
		Scope:            "public",
		Source:           "test",
		Status:           "enabled",
		ManifestVersion:  "1.0",
		PluginAPIVersion: "1.0",
		RequiresCore:     ">=0.0.1",
	})
	createPluginRow(t, ctx, store.Client(), "plugin_listing_app_module_"+suffix, appModuleID, plugins.Manifest{
		ID:               appModuleID,
		Name:             "Sample App Module",
		Version:          "1.0.0",
		Type:             "app_module",
		Scope:            "app",
		AppID:            "sample",
		TrustBundleID:    "sample.default",
		Source:           "test",
		Status:           "enabled",
		ManifestVersion:  "1.0",
		PluginAPIVersion: "1.0",
		RequiresCore:     ">=0.0.1",
		LocalCapabilities: []plugins.CapabilityDefinition{{
			ID:          "sample.operations.test" + suffix,
			Version:     "1.0.0",
			Level:       "declared",
			Description: "test-only local capability",
			Audit:       plugins.CapabilityAuditDefinition{Enforcement: "reported_event"},
			DataPlane:   plugins.CapabilityDataPlaneDefinition{Allowed: []string{"core_data_api"}},
		}},
	})

	server := NewServer(nil, store, "1.0.0-test")
	pluginsRec := pluginListRequest(server, "/api/v1/plugins")
	if pluginsRec.Code != http.StatusOK {
		t.Fatalf("plugins status = %d body=%s", pluginsRec.Code, pluginsRec.Body.String())
	}
	pluginKeys := pluginKeysFromListResponse(t, pluginsRec)
	if !pluginKeys[reusableID] {
		t.Fatalf("reusable plugin missing from /plugins listing: %#v", pluginKeys)
	}
	if pluginKeys[appModuleID] {
		t.Fatalf("app module leaked into /plugins listing: %#v", pluginKeys)
	}

	appModulesRec := pluginListRequest(server, "/api/v1/app-modules")
	if appModulesRec.Code != http.StatusOK {
		t.Fatalf("app-modules status = %d body=%s", appModulesRec.Code, appModulesRec.Body.String())
	}
	appModuleKeys := pluginKeysFromListResponse(t, appModulesRec)
	if !appModuleKeys[appModuleID] {
		t.Fatalf("app module missing from /app-modules listing: %#v", appModuleKeys)
	}
	if appModuleKeys[reusableID] {
		t.Fatalf("reusable plugin leaked into /app-modules listing: %#v", appModuleKeys)
	}

	appAsPluginRec := pluginListRequest(server, "/api/v1/plugins/"+appModuleID)
	if appAsPluginRec.Code != http.StatusNotFound {
		t.Fatalf("app module should be hidden from /plugins/{key}, got %d body=%s", appAsPluginRec.Code, appAsPluginRec.Body.String())
	}
	appModuleDetailRec := pluginListRequest(server, "/api/v1/app-modules/"+appModuleID)
	if appModuleDetailRec.Code != http.StatusOK {
		t.Fatalf("app module detail status = %d body=%s", appModuleDetailRec.Code, appModuleDetailRec.Body.String())
	}
}

func TestPluginManifestInstallPrunesStaleAppModuleMetadata(t *testing.T) {
	databaseURL := pluginTestDatabaseURL()
	if databaseURL == "" {
		t.Skip("set PLYSTRA_INTEGRATION_DATABASE_URL or PLYSTRA_DATABASE_URL to run plugin integration tests")
	}
	ctx := context.Background()
	store, err := entstore.Open(ctx, databaseURL)
	if err != nil {
		t.Fatalf("open ent store: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})

	suffix := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	appModuleID := "app.sample.converge_" + suffix
	pluginRowID := "plugin_" + safeIdentifier(appModuleID)
	t.Cleanup(func() {
		cleanupPluginManifestMetadataRows(context.Background(), store.Client(), t, appModuleID, pluginRowID)
	})

	server := NewServer(nil, store, "1.0.0-test")
	oldManifest := appModuleConvergenceManifest(appModuleID, suffix, "provider.endpoint", "Old Admin", "/apps/sample/old")
	installPluginManifestForTest(t, server, oldManifest)
	newManifest := appModuleConvergenceManifest(appModuleID, suffix, "runtime.endpoint", "New Admin", "/apps/sample/new")
	installPluginManifestForTest(t, server, newManifest)

	settingsRec := pluginListRequest(server, "/api/v1/app-modules/"+appModuleID+"/settings")
	if settingsRec.Code != http.StatusOK {
		t.Fatalf("settings status = %d body=%s", settingsRec.Code, settingsRec.Body.String())
	}
	settingKeys := pluginSettingsKeysFromListResponse(t, settingsRec)
	if settingKeys["provider.endpoint"] {
		t.Fatalf("stale provider.endpoint setting leaked after manifest update: %#v", settingKeys)
	}
	if !settingKeys["runtime.endpoint"] {
		t.Fatalf("runtime.endpoint setting missing after manifest update: %#v", settingKeys)
	}

	menusRec := pluginListRequest(server, "/api/v1/app-modules/"+appModuleID+"/admin-menus")
	if menusRec.Code != http.StatusOK {
		t.Fatalf("admin-menus status = %d body=%s", menusRec.Code, menusRec.Body.String())
	}
	menuLabels := pluginMenuLabelsFromListResponse(t, menusRec)
	if menuLabels["Old Admin"] {
		t.Fatalf("stale admin menu leaked after manifest update: %#v", menuLabels)
	}
	if !menuLabels["New Admin"] {
		t.Fatalf("new admin menu missing after manifest update: %#v", menuLabels)
	}

	staleSettings, err := store.Client().PluginSettingsDefinition.Query().
		Where(entpluginsettingsdefinition.PluginID(pluginRowID), entpluginsettingsdefinition.Key("provider.endpoint")).
		Count(ctx)
	if err != nil {
		t.Fatalf("count stale settings: %v", err)
	}
	if staleSettings != 0 {
		t.Fatalf("stale provider.endpoint setting definitions = %d, want 0", staleSettings)
	}
	staleMenus, err := store.Client().PluginAdminMenu.Query().
		Where(entpluginadminmenu.PluginID(pluginRowID), entpluginadminmenu.ID("pam_"+safeIdentifier(appModuleID+"_Old Admin"))).
		Count(ctx)
	if err != nil {
		t.Fatalf("count stale admin menus: %v", err)
	}
	if staleMenus != 0 {
		t.Fatalf("stale admin menus = %d, want 0", staleMenus)
	}
}

func TestPluginManifestInstallCreatesProviderInstallationForDirectDB(t *testing.T) {
	databaseURL := pluginTestDatabaseURL()
	if databaseURL == "" {
		t.Skip("set PLYSTRA_INTEGRATION_DATABASE_URL or PLYSTRA_DATABASE_URL to run plugin integration tests")
	}
	ctx := context.Background()
	store, err := entstore.Open(ctx, databaseURL)
	if err != nil {
		t.Fatalf("open ent store: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})

	suffix := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	appModuleID := "app.sample.directdb_" + suffix
	pluginRowID := "plugin_" + safeIdentifier(appModuleID)
	t.Cleanup(func() {
		if _, err := store.Client().ProviderInstallation.Delete().Where(entproviderinstallation.ProviderPluginID(appModuleID)).Exec(context.Background()); err != nil {
			t.Fatalf("cleanup provider installation: %v", err)
		}
		cleanupPluginManifestMetadataRows(context.Background(), store.Client(), t, appModuleID, pluginRowID)
	})

	server := NewServer(nil, store, "1.0.0-test")
	manifest := appModuleConvergenceManifest(appModuleID, suffix, "runtime.endpoint", "Admin", "/apps/sample/admin")
	manifest.LocalCapabilities[0].DataPlane.Allowed = []string{"direct_db"}
	manifest.Runtime.SchemaCompatibility = &plugins.SchemaCompatibilityDefinition{Min: 1, Preferred: 2, Max: 3}
	installPluginManifestForTest(t, server, manifest)

	installation, err := store.Client().ProviderInstallation.Query().
		Where(entproviderinstallation.ProviderPluginID(appModuleID)).
		Only(ctx)
	if err != nil {
		t.Fatalf("provider installation missing: %v", err)
	}
	if installation.SchemaName != "app_sample" {
		t.Fatalf("app module schema = %q, want app_sample", installation.SchemaName)
	}
	if installation.RuntimeSchemaMin != 1 || installation.RuntimeSchemaPreferred != 2 || installation.RuntimeSchemaMax != 3 {
		t.Fatalf("schema compatibility not recorded: %#v", installation)
	}
	if !installation.RlsRequired || !installation.ZeroDdlRuntime {
		t.Fatalf("provider installation must require RLS and zero-DDL runtime: %#v", installation)
	}
}

func pluginTestDatabaseURL() string {
	for _, key := range []string{"PLYSTRA_INTEGRATION_DATABASE_URL", "PLYSTRA_DATABASE_URL"} {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return value
		}
	}
	return ""
}

func cleanupPluginIntegrationRows(ctx context.Context, client *coreent.Client, t *testing.T, pluginKeys ...string) {
	t.Helper()
	if len(pluginKeys) == 0 {
		return
	}
	if _, err := client.Plugin.Delete().Where(entplugin.KeyIn(pluginKeys...)).Exec(ctx); err != nil {
		t.Fatalf("cleanup plugins: %v", err)
	}
}

func cleanupPluginManifestMetadataRows(ctx context.Context, client *coreent.Client, t *testing.T, pluginKey, pluginRowID string) {
	t.Helper()
	if _, err := client.PluginAdminMenu.Delete().Where(entpluginadminmenu.PluginID(pluginRowID)).Exec(ctx); err != nil {
		t.Fatalf("cleanup plugin admin menus: %v", err)
	}
	if _, err := client.PluginSettingsDefinition.Delete().Where(entpluginsettingsdefinition.PluginID(pluginRowID)).Exec(ctx); err != nil {
		t.Fatalf("cleanup plugin settings definitions: %v", err)
	}
	cleanupPluginIntegrationRows(ctx, client, t, pluginKey)
}

func appModuleConvergenceManifest(pluginID, suffix, endpointSettingKey, menuLabel, menuPath string) plugins.Manifest {
	return plugins.Manifest{
		ID:               pluginID,
		Name:             "Sample App Module Convergence Test",
		Version:          "1.0.0",
		Type:             "app_module",
		Scope:            "app",
		AppID:            "sample",
		TrustBundleID:    "sample.default",
		Source:           "test",
		Status:           "enabled",
		ManifestVersion:  "1.0",
		PluginAPIVersion: "1.0",
		RequiresCore:     ">=0.0.1",
		AdminMenus: []plugins.AdminMenuDefinition{{
			Label: menuLabel,
			Path:  menuPath,
		}},
		Settings: []plugins.SettingDefinition{{
			Key:       endpointSettingKey,
			ValueType: "string",
			Scope:     "instance",
			Default:   "https://sample-runtime.example",
		}},
		Runtime: plugins.ProviderRuntimeDefinition{
			Type:               "external",
			Protocol:           "http_json",
			Version:            "1.0.0",
			EndpointSettingKey: endpointSettingKey,
		},
		LocalCapabilities: []plugins.CapabilityDefinition{{
			ID:          "sample.convergence.test" + suffix,
			Version:     "1.0.0",
			Level:       "declared",
			Description: "test-only app-private capability",
			Audit:       plugins.CapabilityAuditDefinition{Enforcement: "reported_event"},
			DataPlane:   plugins.CapabilityDataPlaneDefinition{Allowed: []string{"core_data_api"}},
		}},
	}
}

func installPluginManifestForTest(t *testing.T, server *Server, manifest plugins.Manifest) {
	t.Helper()
	raw, err := json.Marshal(pluginInstallRequest{Manifest: manifest, Source: "test"})
	if err != nil {
		t.Fatalf("encode install request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/plugins/install", bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	server.handlePluginInstall(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("install manifest status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func pluginListRequest(server *Server, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	switch {
	case path == "/api/v1/plugins":
		server.handlePlugins(rec, req)
	case strings.HasPrefix(path, "/api/v1/plugins/"):
		server.handlePluginSubroutes(rec, req)
	case path == "/api/v1/app-modules":
		server.handleAppModules(rec, req)
	case strings.HasPrefix(path, "/api/v1/app-modules/"):
		server.handleAppModuleSubroutes(rec, req)
	default:
		rec.WriteHeader(http.StatusNotFound)
	}
	return rec
}

func pluginKeysFromListResponse(t *testing.T, rec *httptest.ResponseRecorder) map[string]bool {
	t.Helper()
	var payload struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	keys := map[string]bool{}
	for _, item := range payload.Data {
		keys[stringAny(item["key"])] = true
	}
	return keys
}

func pluginSettingsKeysFromListResponse(t *testing.T, rec *httptest.ResponseRecorder) map[string]bool {
	t.Helper()
	var payload struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode settings response: %v", err)
	}
	keys := map[string]bool{}
	for _, item := range payload.Data {
		keys[stringAny(item["key"])] = true
	}
	return keys
}

func pluginMenuLabelsFromListResponse(t *testing.T, rec *httptest.ResponseRecorder) map[string]bool {
	t.Helper()
	var payload struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode admin menus response: %v", err)
	}
	labels := map[string]bool{}
	for _, item := range payload.Data {
		labels[stringAny(item["label"])] = true
	}
	return labels
}
