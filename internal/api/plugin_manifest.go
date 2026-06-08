package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	coreent "github.com/plystra/core/ent"
	entauditeventtype "github.com/plystra/core/ent/auditeventtype"
	entpermission "github.com/plystra/core/ent/permission"
	entplugin "github.com/plystra/core/ent/plugin"
	entpluginadminmenu "github.com/plystra/core/ent/pluginadminmenu"
	entpluginsettingsdefinition "github.com/plystra/core/ent/pluginsettingsdefinition"
	entpluginsettingsvalue "github.com/plystra/core/ent/pluginsettingsvalue"
	entresourceaction "github.com/plystra/core/ent/resourceaction"
	entresourcemapping "github.com/plystra/core/ent/resourcemapping"
	entresourcetype "github.com/plystra/core/ent/resourcetype"
	"github.com/plystra/core/internal/plugins"
)

func (s *Server) handlePluginManifestValidation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, r)
		return
	}
	var manifest plugins.Manifest
	if !decodeJSON(w, r, &manifest) {
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
	if !decodeJSON(w, r, &req) {
		return
	}
	validationErrors := plugins.ValidateManifestForCore(req.Manifest, s.coreVersion)
	if len(validationErrors) > 0 {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Plugin manifest is invalid.", validationErrors)
		return
	}
	source := firstNonEmpty(req.Source, req.Manifest.Source, "local")
	status := firstNonEmpty(req.Manifest.Status, "installed")
	pluginType := firstNonEmpty(req.Manifest.Type, "plugin")
	pluginScope := firstNonEmpty(req.Manifest.Scope, "public")
	appID := strings.TrimSpace(req.Manifest.AppID)
	trustBundleID := strings.TrimSpace(req.Manifest.TrustBundleID)
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
			SetType(pluginType).
			SetScope(pluginScope).
			SetNillableAppID(optionalString(appID)).
			SetNillableTrustBundleID(optionalString(trustBundleID)).
			SetSource(source).
			SetStatus(status).
			SetManifest(manifestMap).
			Save(r.Context())
	} else if err == nil {
		update := client.Plugin.UpdateOneID(existing.ID).
			SetName(req.Manifest.Name).
			SetVersion(req.Manifest.Version).
			SetType(pluginType).
			SetScope(pluginScope).
			SetSource(source).
			SetStatus(status).
			SetManifest(manifestMap)
		if appID == "" {
			update.ClearAppID()
		} else {
			update.SetAppID(appID)
		}
		if trustBundleID == "" {
			update.ClearTrustBundleID()
		} else {
			update.SetTrustBundleID(trustBundleID)
		}
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
	s.invalidateCapabilityProviderCacheForPlugin(r.Context(), req.Manifest.ID)
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
	if err := s.prunePluginAdminMenus(ctx, pluginID, manifest); err != nil {
		return err
	}
	for _, setting := range manifest.Settings {
		scope := firstNonEmpty(setting.Scope, "space")
		defaultValue := pluginSettingDefaultValueMap(setting)
		if setting.Default != nil {
			if err := validatePluginSettingValue(pluginSettingDefinitionFromManifest(pluginID, setting, scope), defaultValue); err != nil {
				return err
			}
		} else if err := validateGovernedJSONValue("settings."+setting.Key+".default", defaultValue, governedJSONPolicy{MaxBytes: maxPluginSettingValueBytes, RejectSecrets: true}); err != nil {
			return err
		}
		existingSetting, err := s.ent.PluginSettingsDefinition.Query().Where(entpluginsettingsdefinition.PluginID(pluginID), entpluginsettingsdefinition.Key(setting.Key), entpluginsettingsdefinition.Scope(scope)).Only(ctx)
		if coreent.IsNotFound(err) {
			_, err = s.ent.PluginSettingsDefinition.Create().
				SetID("psd_" + safeIdentifier(manifest.ID+"_"+setting.Key+"_"+scope)).
				SetPluginID(pluginID).
				SetKey(setting.Key).
				SetValueType(firstNonEmpty(setting.ValueType, "string")).
				SetDefaultValue(defaultValue).
				SetNillableDescription(optionalString(setting.Description)).
				SetScope(scope).
				SetMetadata(metadata).
				Save(ctx)
		} else if err == nil {
			update := s.ent.PluginSettingsDefinition.UpdateOneID(existingSetting.ID).
				SetValueType(firstNonEmpty(setting.ValueType, "string")).
				SetDefaultValue(defaultValue).
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
	if err := s.prunePluginSettingsDefinitions(ctx, pluginID, manifest); err != nil {
		return err
	}
	return nil
}

func (s *Server) prunePluginAdminMenus(ctx context.Context, pluginID string, manifest plugins.Manifest) error {
	ids := make([]string, 0, len(manifest.AdminMenus))
	for _, menu := range manifest.AdminMenus {
		ids = append(ids, "pam_"+safeIdentifier(manifest.ID+"_"+menu.Label))
	}
	deleteQuery := s.ent.PluginAdminMenu.Delete().Where(entpluginadminmenu.PluginID(pluginID))
	if len(ids) > 0 {
		deleteQuery = deleteQuery.Where(entpluginadminmenu.IDNotIn(ids...))
	}
	_, err := deleteQuery.Exec(ctx)
	return err
}

func (s *Server) prunePluginSettingsDefinitions(ctx context.Context, pluginID string, manifest plugins.Manifest) error {
	current := map[string]bool{}
	keys := make([]string, 0, len(manifest.Settings))
	for _, setting := range manifest.Settings {
		scope := firstNonEmpty(setting.Scope, "space")
		current[setting.Key+"\x00"+scope] = true
		keys = append(keys, setting.Key)
	}
	valueDelete := s.ent.PluginSettingsValue.Delete().Where(entpluginsettingsvalue.PluginID(pluginID))
	if len(keys) > 0 {
		valueDelete = valueDelete.Where(entpluginsettingsvalue.KeyNotIn(keys...))
	}
	if _, err := valueDelete.Exec(ctx); err != nil {
		return err
	}
	rows, err := s.ent.PluginSettingsDefinition.Query().Where(entpluginsettingsdefinition.PluginID(pluginID)).All(ctx)
	if err != nil {
		return err
	}
	for _, row := range rows {
		if current[row.Key+"\x00"+row.Scope] {
			continue
		}
		if err := s.ent.PluginSettingsDefinition.DeleteOneID(row.ID).Exec(ctx); err != nil {
			return err
		}
	}
	return nil
}
