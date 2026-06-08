package api

import (
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"
	coreent "github.com/plystra/core/ent"
	entauditeventtype "github.com/plystra/core/ent/auditeventtype"
	entpermission "github.com/plystra/core/ent/permission"
	entplugin "github.com/plystra/core/ent/plugin"
	entpluginadminmenu "github.com/plystra/core/ent/pluginadminmenu"
	entresourcetype "github.com/plystra/core/ent/resourcetype"
)

func (s *Server) handlePluginResources(w http.ResponseWriter, r *http.Request, pluginKey string) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, r)
		return
	}
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	rows, err := client.ResourceType.Query().
		Where(entresourcetype.Source("plugin:" + pluginKey)).
		Order(entresourcetype.ByKey()).
		All(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list plugin resources.", err.Error())
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, resourceTypeMap(row))
	}
	writeList(w, r, http.StatusOK, out, limitFrom(r, 50))
}

func (s *Server) handlePluginPermissions(w http.ResponseWriter, r *http.Request, pluginKey string) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, r)
		return
	}
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	resourceTypes, err := client.ResourceType.Query().Where(entresourcetype.Source("plugin:" + pluginKey)).All(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list plugin permissions.", err.Error())
		return
	}
	keys := make([]string, 0, len(resourceTypes))
	for _, resourceType := range resourceTypes {
		keys = append(keys, resourceType.Key)
	}
	if len(keys) == 0 {
		writeList(w, r, http.StatusOK, []map[string]any{}, limitFrom(r, 50))
		return
	}
	permissions, err := client.Permission.Query().
		Where(entpermission.ResourceIn(keys...)).
		Order(entpermission.ByResource(), entpermission.ByAction(), entpermission.ByScope()).
		All(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list plugin permissions.", err.Error())
		return
	}
	out := make([]map[string]any, 0, len(permissions))
	for _, permission := range permissions {
		out = append(out, permissionMap(permission))
	}
	writeList(w, r, http.StatusOK, out, limitFrom(r, 50))
}

func (s *Server) handlePluginAuditEvents(w http.ResponseWriter, r *http.Request, pluginKey string) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, r)
		return
	}
	pluginID, err := s.loadPluginID(r.Context(), pluginKey)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, r, http.StatusNotFound, "PLUGIN_NOT_FOUND", "Plugin was not found.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load plugin.", err.Error())
		return
	}
	rows, err := s.ent.AuditEventType.Query().
		Where(entauditeventtype.PluginID(pluginID)).
		Order(entauditeventtype.ByKey()).
		All(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list plugin audit events.", err.Error())
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, auditEventTypeMap(row))
	}
	writeList(w, r, http.StatusOK, out, limitFrom(r, 50))
}

func (s *Server) handlePluginAdminMenus(w http.ResponseWriter, r *http.Request, pluginKey string) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, r)
		return
	}
	pluginID, err := s.loadPluginID(r.Context(), pluginKey)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, r, http.StatusNotFound, "PLUGIN_NOT_FOUND", "Plugin was not found.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load plugin.", err.Error())
		return
	}
	rows, err := s.ent.PluginAdminMenu.Query().
		Where(entpluginadminmenu.PluginID(pluginID)).
		Order(entpluginadminmenu.BySortOrder(), entpluginadminmenu.ByLabel()).
		All(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list plugin admin menus.", err.Error())
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, pluginAdminMenuMap(row))
	}
	writeList(w, r, http.StatusOK, out, limitFrom(r, 50))
}

func (s *Server) handlePluginLifecycle(w http.ResponseWriter, r *http.Request, pluginKey, action string) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, r)
		return
	}
	status := map[string]string{
		"enable":    "enabled",
		"disable":   "disabled",
		"uninstall": "uninstalled",
	}[action]
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	pluginRow, err := client.Plugin.Query().Where(entplugin.Key(pluginKey)).Only(r.Context())
	if coreent.IsNotFound(err) {
		writeError(w, r, http.StatusNotFound, "PLUGIN_NOT_FOUND", "Plugin was not found.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load plugin.", err.Error())
		return
	}
	err = client.Plugin.UpdateOneID(pluginRow.ID).SetStatus(status).Exec(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to update plugin status.", err.Error())
		return
	}
	s.invalidateCapabilityProviderCacheForPlugin(r.Context(), pluginKey)
	row, err := s.loadPluginByKey(r.Context(), pluginKey)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load plugin.", err.Error())
		return
	}
	writeData(w, r, http.StatusOK, row)
}
