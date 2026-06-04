package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	coreent "github.com/plystra/plystra/ent"
	entplugin "github.com/plystra/plystra/ent/plugin"
	"github.com/plystra/plystra/internal/plugins"
	"github.com/plystra/plystra/internal/store/entstore"
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
	appModuleID := "app.forge.module_" + suffix
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
		Name:             "Forge App Module",
		Version:          "1.0.0",
		Type:             "app_module",
		Scope:            "app",
		AppID:            "forge",
		Source:           "test",
		Status:           "enabled",
		ManifestVersion:  "1.0",
		PluginAPIVersion: "1.0",
		RequiresCore:     ">=0.0.1",
		LocalCapabilities: []plugins.CapabilityDefinition{{
			ID:          "forge.operations_" + suffix,
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
