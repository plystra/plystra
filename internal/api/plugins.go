package api

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"
	coreent "github.com/plystra/core/ent"
	entpermission "github.com/plystra/core/ent/permission"
	entplugin "github.com/plystra/core/ent/plugin"
	entpluginadminmenu "github.com/plystra/core/ent/pluginadminmenu"
	entresourcetype "github.com/plystra/core/ent/resourcetype"
)

type governedPluginKind string

const (
	governedPluginKindReusable  governedPluginKind = "reusable_plugin"
	governedPluginKindAppModule governedPluginKind = "app_module"
)

func (s *Server) handlePlugins(w http.ResponseWriter, r *http.Request) {
	s.handleGovernedPluginList(w, r, governedPluginKindReusable)
}

func (s *Server) handleAppModules(w http.ResponseWriter, r *http.Request) {
	s.handleGovernedPluginList(w, r, governedPluginKindAppModule)
}

func (s *Server) handleGovernedPluginList(w http.ResponseWriter, r *http.Request, kind governedPluginKind) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, r)
		return
	}
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	pluginRows, err := client.Plugin.Query().Order(entplugin.ByName()).All(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list plugins.", err.Error())
		return
	}
	rows := make([]map[string]any, 0, len(pluginRows))
	for _, pluginRow := range pluginRows {
		if !pluginRowMatchesKind(pluginRow, kind) {
			continue
		}
		row := pluginMap(pluginRow)
		resourceTypes, err := client.ResourceType.Query().Where(entresourcetype.Source("plugin:" + pluginRow.Key)).All(r.Context())
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list plugins.", err.Error())
			return
		}
		resourceKeys := make([]string, 0, len(resourceTypes))
		for _, resourceType := range resourceTypes {
			resourceKeys = append(resourceKeys, resourceType.Key)
		}
		row["resources_count"] = len(resourceTypes)
		if len(resourceKeys) > 0 {
			count, err := client.Permission.Query().Where(entpermission.ResourceIn(resourceKeys...)).Count(r.Context())
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list plugins.", err.Error())
				return
			}
			row["permissions_count"] = count
		} else {
			row["permissions_count"] = 0
		}
		count, err := client.PluginAdminMenu.Query().Where(entpluginadminmenu.PluginID(pluginRow.ID)).Count(r.Context())
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list plugins.", err.Error())
			return
		}
		row["admin_menus_count"] = count
		rows = append(rows, row)
	}
	writeList(w, r, http.StatusOK, rows, limitFrom(r, 50))
}

func (s *Server) handlePluginSubroutes(w http.ResponseWriter, r *http.Request) {
	s.handleGovernedPluginSubroutes(w, r, "/api/v1/plugins/", governedPluginKindReusable, "PLUGIN_NOT_FOUND", "Plugin was not found.")
}

func (s *Server) handleAppModuleSubroutes(w http.ResponseWriter, r *http.Request) {
	s.handleGovernedPluginSubroutes(w, r, "/api/v1/app-modules/", governedPluginKindAppModule, "APP_MODULE_NOT_FOUND", "App Module was not found.")
}

func (s *Server) handleGovernedPluginSubroutes(w http.ResponseWriter, r *http.Request, prefix string, kind governedPluginKind, notFoundCode, notFoundMessage string) {
	path := strings.TrimPrefix(r.URL.Path, prefix)
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	pluginKey := parts[0]
	switch {
	case len(parts) == 1:
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, r)
			return
		}
		row, err := s.loadGovernedPluginByKey(r.Context(), pluginKey, kind)
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, r, http.StatusNotFound, notFoundCode, notFoundMessage, nil)
			return
		}
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load plugin.", err.Error())
			return
		}
		writeData(w, r, http.StatusOK, row)
	case len(parts) == 2 && (parts[1] == "enable" || parts[1] == "disable" || parts[1] == "uninstall"):
		if !s.requireGovernedPluginKind(w, r, pluginKey, kind, notFoundCode, notFoundMessage) {
			return
		}
		s.handlePluginLifecycle(w, r, pluginKey, parts[1])
	case len(parts) == 2 && parts[1] == "settings":
		if !s.requireGovernedPluginKind(w, r, pluginKey, kind, notFoundCode, notFoundMessage) {
			return
		}
		s.handlePluginSettings(w, r, pluginKey)
	case len(parts) == 2 && parts[1] == "resources":
		if !s.requireGovernedPluginKind(w, r, pluginKey, kind, notFoundCode, notFoundMessage) {
			return
		}
		s.handlePluginResources(w, r, pluginKey)
	case len(parts) == 2 && parts[1] == "permissions":
		if !s.requireGovernedPluginKind(w, r, pluginKey, kind, notFoundCode, notFoundMessage) {
			return
		}
		s.handlePluginPermissions(w, r, pluginKey)
	case len(parts) == 2 && parts[1] == "audit-events":
		if !s.requireGovernedPluginKind(w, r, pluginKey, kind, notFoundCode, notFoundMessage) {
			return
		}
		s.handlePluginAuditEvents(w, r, pluginKey)
	case len(parts) == 2 && parts[1] == "admin-menus":
		if !s.requireGovernedPluginKind(w, r, pluginKey, kind, notFoundCode, notFoundMessage) {
			return
		}
		s.handlePluginAdminMenus(w, r, pluginKey)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) requireGovernedPluginKind(w http.ResponseWriter, r *http.Request, key string, kind governedPluginKind, notFoundCode, notFoundMessage string) bool {
	err := s.ensureGovernedPluginKind(r.Context(), key, kind)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, r, http.StatusNotFound, notFoundCode, notFoundMessage, nil)
		return false
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load plugin.", err.Error())
		return false
	}
	return true
}

func (s *Server) loadPluginByKey(ctx context.Context, key string) (map[string]any, error) {
	return s.loadGovernedPluginByKey(ctx, key, "")
}

func (s *Server) loadGovernedPluginByKey(ctx context.Context, key string, kind governedPluginKind) (map[string]any, error) {
	if s.ent == nil {
		return nil, errors.New("ent client is not configured")
	}
	row, err := s.ent.Plugin.Query().Where(entplugin.Key(key)).Only(ctx)
	if coreent.IsNotFound(err) {
		return nil, pgx.ErrNoRows
	}
	if err != nil {
		return nil, err
	}
	if kind != "" && !pluginRowMatchesKind(row, kind) {
		return nil, pgx.ErrNoRows
	}
	return pluginMap(row), nil
}

func (s *Server) ensureGovernedPluginKind(ctx context.Context, key string, kind governedPluginKind) error {
	if s.ent == nil {
		return errors.New("ent client is not configured")
	}
	row, err := s.ent.Plugin.Query().Where(entplugin.Key(key)).Only(ctx)
	if coreent.IsNotFound(err) {
		return pgx.ErrNoRows
	}
	if err != nil {
		return err
	}
	if !pluginRowMatchesKind(row, kind) {
		return pgx.ErrNoRows
	}
	return nil
}

func pluginRowMatchesKind(row *coreent.Plugin, kind governedPluginKind) bool {
	if kind == "" {
		return true
	}
	manifest := pluginManifestFromMap(row.Manifest)
	pluginType, pluginScope, _ := normalizedPluginGovernance(row, manifest)
	isAppModule := pluginType == "app_module" || pluginScope == "app"
	switch kind {
	case governedPluginKindAppModule:
		return isAppModule
	case governedPluginKindReusable:
		return !isAppModule
	default:
		return true
	}
}
