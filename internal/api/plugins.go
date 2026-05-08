package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	entauditeventtype "github.com/plystra/plystra/ent/auditeventtype"
	entpermission "github.com/plystra/plystra/ent/permission"
	entplugin "github.com/plystra/plystra/ent/plugin"
	entpluginadminmenu "github.com/plystra/plystra/ent/pluginadminmenu"
	entpluginsettingsdefinition "github.com/plystra/plystra/ent/pluginsettingsdefinition"
	entpluginsettingsvalue "github.com/plystra/plystra/ent/pluginsettingsvalue"
	entresourceaction "github.com/plystra/plystra/ent/resourceaction"
	entresourcemapping "github.com/plystra/plystra/ent/resourcemapping"
	entresourcetype "github.com/plystra/plystra/ent/resourcetype"

	"github.com/jackc/pgx/v5"
	coreent "github.com/plystra/plystra/ent"
	"github.com/plystra/plystra/internal/plugins"
)

func (s *Server) handlePluginManifestValidation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, r)
		return
	}
	var manifest plugins.Manifest
	if err := json.NewDecoder(r.Body).Decode(&manifest); err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Request body is invalid JSON.", err.Error())
		return
	}
	errors := plugins.ValidateManifestForCore(manifest, s.coreVersion)
	if errors == nil {
		errors = []string{}
	}
	writeData(w, r, http.StatusOK, map[string]any{
		"valid":  len(errors) == 0,
		"errors": errors,
	})
}

type pluginInstallRequest struct {
	Manifest plugins.Manifest `json:"manifest"`
	Source   string           `json:"source"`
}

func pluginManifestMap(manifest plugins.Manifest) (map[string]any, error) {
	raw, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Server) handlePluginInstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, r)
		return
	}
	var req pluginInstallRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Request body is invalid JSON.", err.Error())
		return
	}
	validationErrors := plugins.ValidateManifestForCore(req.Manifest, s.coreVersion)
	if len(validationErrors) > 0 {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Plugin manifest is invalid.", validationErrors)
		return
	}
	source := firstNonEmpty(req.Source, req.Manifest.Source, "local")
	status := firstNonEmpty(req.Manifest.Status, "installed")
	manifestMap, err := pluginManifestMap(req.Manifest)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to encode plugin manifest.", err.Error())
		return
	}
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	pluginID := "plugin_" + safeIdentifier(req.Manifest.ID)
	existing, err := client.Plugin.Query().Where(entplugin.Key(req.Manifest.ID)).Only(r.Context())
	if coreent.IsNotFound(err) {
		_, err = client.Plugin.Create().
			SetID(pluginID).
			SetKey(req.Manifest.ID).
			SetName(req.Manifest.Name).
			SetNillableDescription(optionalString(req.Manifest.Description)).
			SetVersion(req.Manifest.Version).
			SetSource(source).
			SetStatus(status).
			SetManifest(manifestMap).
			Save(r.Context())
	} else if err == nil {
		update := client.Plugin.UpdateOneID(existing.ID).
			SetName(req.Manifest.Name).
			SetVersion(req.Manifest.Version).
			SetSource(source).
			SetStatus(status).
			SetManifest(manifestMap)
		if req.Manifest.Description == "" {
			update.ClearDescription()
		} else {
			update.SetDescription(req.Manifest.Description)
		}
		err = update.Exec(r.Context())
		pluginID = existing.ID
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to install plugin metadata.", err.Error())
		return
	}
	if err := s.installPluginManifestMetadata(r.Context(), pluginID, req.Manifest); err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to install plugin declarations.", err.Error())
		return
	}
	row, err := s.loadPluginByKey(r.Context(), req.Manifest.ID)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load installed plugin.", err.Error())
		return
	}
	writeData(w, r, http.StatusCreated, row)
}

func (s *Server) installPluginManifestMetadata(ctx context.Context, pluginID string, manifest plugins.Manifest) error {
	if s.ent == nil {
		return errors.New("ent client is not configured")
	}
	metadata := map[string]any{"plugin": manifest.ID}
	for _, resource := range manifest.Resources {
		resourceTypeID := "rt_" + safeIdentifier(manifest.ID+"_"+resource.Key)
		existingRT, err := s.ent.ResourceType.Query().Where(entresourcetype.Key(resource.Key)).Only(ctx)
		if coreent.IsNotFound(err) {
			_, err = s.ent.ResourceType.Create().
				SetID(resourceTypeID).
				SetKey(resource.Key).
				SetDisplayName(resource.DisplayName).
				SetStatus("active").
				SetSource("plugin:" + manifest.ID).
				SetMetadata(metadata).
				Save(ctx)
		} else if err == nil {
			err = s.ent.ResourceType.UpdateOneID(existingRT.ID).
				SetDisplayName(resource.DisplayName).
				SetSource("plugin:" + manifest.ID).
				SetMetadata(metadata).
				Exec(ctx)
			resourceTypeID = existingRT.ID
		}
		if err != nil {
			return err
		}
		existingMapping, err := s.ent.ResourceMapping.Query().Where(entresourcemapping.ResourceTypeID(resourceTypeID)).Only(ctx)
		if coreent.IsNotFound(err) {
			_, err = s.ent.ResourceMapping.Create().
				SetID("rm_" + safeIdentifier(manifest.ID+"_"+resource.Key)).
				SetResourceTypeID(resourceTypeID).
				SetStorageKind("plugin_managed").
				SetIDField("id").
				SetSpaceField("space_id").
				SetGroupField("group_id").
				SetOwnerMemberField("owner_member_id").
				SetMetadataField("metadata").
				SetStatus("active").
				SetMetadata(metadata).
				Save(ctx)
		} else if err == nil {
			err = s.ent.ResourceMapping.UpdateOneID(existingMapping.ID).
				SetStorageKind("plugin_managed").
				ClearTableName().
				SetIDField("id").
				SetSpaceField("space_id").
				SetGroupField("group_id").
				SetOwnerMemberField("owner_member_id").
				ClearVisibilityField().
				SetMetadataField("metadata").
				SetStatus("active").
				SetMetadata(metadata).
				Exec(ctx)
		}
		if err != nil {
			return err
		}
		for _, action := range resource.Actions {
			existingAction, err := s.ent.ResourceAction.Query().Where(entresourceaction.ResourceTypeID(resourceTypeID), entresourceaction.Key(action.Key)).Only(ctx)
			if coreent.IsNotFound(err) {
				_, err = s.ent.ResourceAction.Create().
					SetID("ra_" + safeIdentifier(manifest.ID+"_"+resource.Key+"_"+action.Key)).
					SetResourceTypeID(resourceTypeID).
					SetKey(action.Key).
					SetDisplayName(titleFromKey(action.Key)).
					SetRiskLevel(firstNonEmpty(action.RiskLevel, "normal")).
					SetAuditDefault(true).
					SetMetadata(metadata).
					Save(ctx)
			} else if err == nil {
				err = s.ent.ResourceAction.UpdateOneID(existingAction.ID).
					SetDisplayName(titleFromKey(action.Key)).
					SetRiskLevel(firstNonEmpty(action.RiskLevel, "normal")).
					SetAuditDefault(true).
					SetMetadata(metadata).
					Exec(ctx)
			}
			if err != nil {
				return err
			}
		}
	}
	for _, permission := range manifest.Permissions {
		for _, scope := range permission.Scopes {
			existingPermission, err := s.ent.Permission.Query().Where(entpermission.Resource(permission.Resource), entpermission.Action(permission.Action), entpermission.Scope(scope)).Only(ctx)
			if coreent.IsNotFound(err) {
				_, err = s.ent.Permission.Create().
					SetID("perm_" + safeIdentifier(manifest.ID+"_"+permission.Resource+"_"+permission.Action+"_"+scope)).
					SetResource(permission.Resource).
					SetAction(permission.Action).
					SetScope(scope).
					Save(ctx)
			} else if err == nil {
				err = s.ent.Permission.UpdateOneID(existingPermission.ID).
					SetResource(permission.Resource).
					SetAction(permission.Action).
					SetScope(scope).
					Exec(ctx)
			}
			if err != nil {
				return err
			}
		}
	}
	for _, event := range manifest.AuditEvents {
		existingEvent, err := s.ent.AuditEventType.Query().Where(entauditeventtype.Key(event.Key)).Only(ctx)
		if coreent.IsNotFound(err) {
			_, err = s.ent.AuditEventType.Create().
				SetID("aet_" + safeIdentifier(manifest.ID+"_"+event.Key)).
				SetKey(event.Key).
				SetPluginID(pluginID).
				SetDisplayName(titleFromKey(event.Key)).
				SetRiskLevel(firstNonEmpty(event.RiskLevel, "normal")).
				SetDefaultAudit(true).
				SetMetadata(metadata).
				Save(ctx)
		} else if err == nil {
			err = s.ent.AuditEventType.UpdateOneID(existingEvent.ID).
				SetPluginID(pluginID).
				SetDisplayName(titleFromKey(event.Key)).
				SetRiskLevel(firstNonEmpty(event.RiskLevel, "normal")).
				SetDefaultAudit(true).
				SetMetadata(metadata).
				Exec(ctx)
		}
		if err != nil {
			return err
		}
	}
	for i, menu := range manifest.AdminMenus {
		menuID := "pam_" + safeIdentifier(manifest.ID+"_"+menu.Label)
		existingMenu, err := s.ent.PluginAdminMenu.Query().Where(entpluginadminmenu.ID(menuID)).Only(ctx)
		if coreent.IsNotFound(err) {
			_, err = s.ent.PluginAdminMenu.Create().
				SetID(menuID).
				SetPluginID(pluginID).
				SetLabel(menu.Label).
				SetPath(menu.Path).
				SetNillableRequiredPermission(optionalString(menu.RequiredPermission)).
				SetSortOrder(1000 + i).
				SetMetadata(metadata).
				Save(ctx)
		} else if err == nil {
			update := s.ent.PluginAdminMenu.UpdateOneID(existingMenu.ID).
				SetLabel(menu.Label).
				SetPath(menu.Path).
				SetSortOrder(1000 + i).
				SetMetadata(metadata)
			if menu.RequiredPermission == "" {
				update.ClearRequiredPermission()
			} else {
				update.SetRequiredPermission(menu.RequiredPermission)
			}
			err = update.Exec(ctx)
		}
		if err != nil {
			return err
		}
	}
	for _, setting := range manifest.Settings {
		scope := firstNonEmpty(setting.Scope, "space")
		existingSetting, err := s.ent.PluginSettingsDefinition.Query().Where(entpluginsettingsdefinition.PluginID(pluginID), entpluginsettingsdefinition.Key(setting.Key), entpluginsettingsdefinition.Scope(scope)).Only(ctx)
		if coreent.IsNotFound(err) {
			_, err = s.ent.PluginSettingsDefinition.Create().
				SetID("psd_" + safeIdentifier(manifest.ID+"_"+setting.Key+"_"+scope)).
				SetPluginID(pluginID).
				SetKey(setting.Key).
				SetValueType(firstNonEmpty(setting.ValueType, "string")).
				SetDefaultValue(map[string]any{}).
				SetNillableDescription(optionalString(setting.Description)).
				SetScope(scope).
				SetMetadata(metadata).
				Save(ctx)
		} else if err == nil {
			update := s.ent.PluginSettingsDefinition.UpdateOneID(existingSetting.ID).
				SetValueType(firstNonEmpty(setting.ValueType, "string")).
				SetMetadata(metadata)
			if setting.Description == "" {
				update.ClearDescription()
			} else {
				update.SetDescription(setting.Description)
			}
			err = update.Exec(ctx)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

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
	row, err := s.loadPluginByKey(r.Context(), pluginKey)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load plugin.", err.Error())
		return
	}
	writeData(w, r, http.StatusOK, row)
}

type pluginSettingsUpdateRequest struct {
	SpaceID  string         `json:"space_id"`
	Settings map[string]any `json:"settings"`
}

func (s *Server) handlePluginSettings(w http.ResponseWriter, r *http.Request, pluginKey string) {
	switch r.Method {
	case http.MethodGet:
		settings, err := s.loadPluginSettings(r.Context(), pluginKey, r.URL.Query().Get("space_id"))
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, r, http.StatusNotFound, "PLUGIN_NOT_FOUND", "Plugin was not found.", nil)
			return
		}
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load plugin settings.", err.Error())
			return
		}
		writeList(w, r, http.StatusOK, settings, limitFrom(r, 50))
	case http.MethodPatch:
		var req pluginSettingsUpdateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Request body is invalid JSON.", err.Error())
			return
		}
		if req.Settings == nil {
			writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "settings is required.", nil)
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
		for key, value := range req.Settings {
			client, ok := s.requireEnt(w, r)
			if !ok {
				return
			}
			exists, err := client.PluginSettingsDefinition.Query().Where(entpluginsettingsdefinition.PluginID(pluginID), entpluginsettingsdefinition.Key(key)).Exist(r.Context())
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to validate plugin setting.", err.Error())
				return
			}
			if !exists {
				writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Unknown plugin setting.", map[string]string{"key": key})
				return
			}
			valueMap := pluginSettingValueMap(value)
			existing, err := client.PluginSettingsValue.Query().Where(entpluginsettingsvalue.PluginID(pluginID), entpluginsettingsvalue.SpaceID(req.SpaceID), entpluginsettingsvalue.Key(key)).Only(r.Context())
			if coreent.IsNotFound(err) {
				_, err = client.PluginSettingsValue.Create().
					SetID("psv_" + safeIdentifier(pluginID+"_"+req.SpaceID+"_"+key)).
					SetPluginID(pluginID).
					SetSpaceID(req.SpaceID).
					SetKey(key).
					SetValue(valueMap).
					Save(r.Context())
			} else if err == nil {
				err = client.PluginSettingsValue.UpdateOneID(existing.ID).SetValue(valueMap).Exec(r.Context())
			}
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to update plugin setting.", err.Error())
				return
			}
		}
		settings, err := s.loadPluginSettings(r.Context(), pluginKey, req.SpaceID)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load plugin settings.", err.Error())
			return
		}
		writeList(w, r, http.StatusOK, settings, limitFrom(r, 50))
	default:
		writeMethodNotAllowed(w, r)
	}
}

func (s *Server) loadPluginSettings(ctx context.Context, pluginKey, spaceID string) ([]map[string]any, error) {
	pluginID, err := s.loadPluginID(ctx, pluginKey)
	if err != nil {
		return nil, err
	}
	definitions, err := s.ent.PluginSettingsDefinition.Query().
		Where(entpluginsettingsdefinition.PluginID(pluginID)).
		Order(entpluginsettingsdefinition.ByKey()).
		All(ctx)
	if err != nil {
		return nil, err
	}
	rows := make([]map[string]any, 0, len(definitions))
	for _, definition := range definitions {
		value := definition.DefaultValue
		settingValue, err := s.ent.PluginSettingsValue.Query().
			Where(entpluginsettingsvalue.PluginID(pluginID), entpluginsettingsvalue.Key(definition.Key), entpluginsettingsvalue.SpaceID(spaceID)).
			Only(ctx)
		if err != nil && !coreent.IsNotFound(err) {
			return nil, err
		}
		if settingValue != nil {
			value = settingValue.Value
		}
		rows = append(rows, pluginSettingsDefinitionMap(definition, value))
	}
	return rows, nil
}

func (s *Server) loadPluginID(ctx context.Context, pluginKey string) (string, error) {
	if s.ent == nil {
		return "", errors.New("ent client is not configured")
	}
	pluginRow, err := s.ent.Plugin.Query().Where(entplugin.Key(pluginKey)).Only(ctx)
	if coreent.IsNotFound(err) {
		return "", pgx.ErrNoRows
	}
	if err != nil {
		return "", err
	}
	return pluginRow.ID, nil
}
