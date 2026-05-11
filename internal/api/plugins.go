package api

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"
	coreent "github.com/plystra/plystra/ent"
	entpermission "github.com/plystra/plystra/ent/permission"
	entplugin "github.com/plystra/plystra/ent/plugin"
	entpluginadminmenu "github.com/plystra/plystra/ent/pluginadminmenu"
	entresourcetype "github.com/plystra/plystra/ent/resourcetype"
)

func (s *Server) handlePlugins(w http.ResponseWriter, r *http.Request) {
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
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/plugins/")
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
		row, err := s.loadPluginByKey(r.Context(), pluginKey)
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, r, http.StatusNotFound, "PLUGIN_NOT_FOUND", "Plugin was not found.", nil)
			return
		}
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load plugin.", err.Error())
			return
		}
		writeData(w, r, http.StatusOK, row)
	case len(parts) == 2 && (parts[1] == "enable" || parts[1] == "disable" || parts[1] == "uninstall"):
		s.handlePluginLifecycle(w, r, pluginKey, parts[1])
	case len(parts) == 2 && parts[1] == "settings":
		s.handlePluginSettings(w, r, pluginKey)
	case len(parts) == 2 && parts[1] == "resources":
		s.handlePluginResources(w, r, pluginKey)
	case len(parts) == 2 && parts[1] == "permissions":
		s.handlePluginPermissions(w, r, pluginKey)
	case len(parts) == 2 && parts[1] == "audit-events":
		s.handlePluginAuditEvents(w, r, pluginKey)
	case len(parts) == 2 && parts[1] == "admin-menus":
		s.handlePluginAdminMenus(w, r, pluginKey)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) loadPluginByKey(ctx context.Context, key string) (map[string]any, error) {
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
	return pluginMap(row), nil
}
