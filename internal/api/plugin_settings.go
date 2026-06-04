package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/jackc/pgx/v5"
	coreent "github.com/plystra/core/ent"
	entplugin "github.com/plystra/core/ent/plugin"
	entpluginsettingsdefinition "github.com/plystra/core/ent/pluginsettingsdefinition"
	entpluginsettingsvalue "github.com/plystra/core/ent/pluginsettingsvalue"
	"github.com/plystra/core/internal/plugins"
)

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
		if !decodeJSON(w, r, &req) {
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
			definition, valueSpaceID, err := s.resolvePluginSettingDefinition(r.Context(), pluginID, key, req.SpaceID)
			if err != nil {
				status := http.StatusBadRequest
				code := "VALIDATION_FAILED"
				if errors.Is(err, pgx.ErrNoRows) {
					status = http.StatusBadRequest
				}
				writeError(w, r, status, code, "Plugin setting is invalid.", map[string]string{"key": key, "error": err.Error()})
				return
			}
			valueMap := pluginSettingValueMap(value)
			if err := validatePluginSettingValue(definition, valueMap); err != nil {
				writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", err.Error(), nil)
				return
			}
			existing, err := client.PluginSettingsValue.Query().Where(entpluginsettingsvalue.PluginID(pluginID), entpluginsettingsvalue.SpaceID(valueSpaceID), entpluginsettingsvalue.Key(key)).Only(r.Context())
			if coreent.IsNotFound(err) {
				_, err = client.PluginSettingsValue.Create().
					SetID("psv_" + safeIdentifier(pluginID+"_"+valueSpaceID+"_"+key)).
					SetPluginID(pluginID).
					SetSpaceID(valueSpaceID).
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
		valueSpaceID := ""
		if definition.Scope == "space" {
			valueSpaceID = spaceID
		}
		settingValue, err := s.ent.PluginSettingsValue.Query().
			Where(entpluginsettingsvalue.PluginID(pluginID), entpluginsettingsvalue.Key(definition.Key), entpluginsettingsvalue.SpaceID(valueSpaceID)).
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

func (s *Server) resolvePluginSettingDefinition(ctx context.Context, pluginID, key, requestedSpaceID string) (*coreent.PluginSettingsDefinition, string, error) {
	if s.ent == nil {
		return nil, "", errors.New("ent client is not configured")
	}
	definitions, err := s.ent.PluginSettingsDefinition.Query().
		Where(entpluginsettingsdefinition.PluginID(pluginID), entpluginsettingsdefinition.Key(key)).
		All(ctx)
	if err != nil {
		return nil, "", err
	}
	if len(definitions) == 0 {
		return nil, "", pgx.ErrNoRows
	}
	targetScope := "instance"
	valueSpaceID := ""
	if requestedSpaceID != "" {
		targetScope = "space"
		valueSpaceID = requestedSpaceID
	}
	for _, definition := range definitions {
		if definition.Scope == targetScope {
			return definition, valueSpaceID, nil
		}
	}
	if targetScope == "space" {
		return nil, "", fmt.Errorf("setting %q is not declared for space scope", key)
	}
	return nil, "", fmt.Errorf("setting %q is not declared for instance scope", key)
}

func validatePluginSettingValue(definition *coreent.PluginSettingsDefinition, value map[string]any) error {
	if definition == nil {
		return errors.New("setting definition is required")
	}
	key := definition.Key
	if sensitiveConfigLikeKey(key) {
		return fmt.Errorf("settings.%s must not be a secret-like setting; declare secrets under plugin secrets", key)
	}
	if err := validatePluginSettingValueType(definition, value); err != nil {
		return err
	}
	return validateGovernedJSONValue("settings."+key, value, governedJSONPolicy{MaxBytes: maxPluginSettingValueBytes, RejectSecrets: true})
}

func pluginSettingDefinitionFromManifest(pluginID string, setting plugins.SettingDefinition, scope string) *coreent.PluginSettingsDefinition {
	return &coreent.PluginSettingsDefinition{
		PluginID:  pluginID,
		Key:       setting.Key,
		ValueType: firstNonEmpty(setting.ValueType, "string"),
		Scope:     firstNonEmpty(scope, "space"),
	}
}

func pluginSettingDefaultValueMap(setting plugins.SettingDefinition) map[string]any {
	if setting.Default == nil {
		return map[string]any{}
	}
	return pluginSettingValueMap(setting.Default)
}

func validatePluginSettingValueType(definition *coreent.PluginSettingsDefinition, value map[string]any) error {
	raw, ok := value["value"]
	if !ok {
		if definition.ValueType == "object" || definition.ValueType == "json" {
			return nil
		}
		return fmt.Errorf("settings.%s must be stored under value", definition.Key)
	}
	switch definition.ValueType {
	case "string":
		if _, ok := raw.(string); !ok {
			return fmt.Errorf("settings.%s must be a string", definition.Key)
		}
	case "integer":
		if !jsonScalarIsInteger(raw) {
			return fmt.Errorf("settings.%s must be an integer", definition.Key)
		}
	case "number":
		if !jsonScalarIsNumber(raw) {
			return fmt.Errorf("settings.%s must be a number", definition.Key)
		}
	case "boolean":
		if _, ok := raw.(bool); !ok {
			return fmt.Errorf("settings.%s must be a boolean", definition.Key)
		}
	case "string_array":
		values, ok := raw.([]any)
		if !ok {
			return fmt.Errorf("settings.%s must be an array of strings", definition.Key)
		}
		for i, item := range values {
			if _, ok := item.(string); !ok {
				return fmt.Errorf("settings.%s[%d] must be a string", definition.Key, i)
			}
		}
	case "array":
		if _, ok := raw.([]any); !ok {
			return fmt.Errorf("settings.%s must be an array", definition.Key)
		}
	case "object":
		if _, ok := raw.(map[string]any); !ok {
			return fmt.Errorf("settings.%s must be an object", definition.Key)
		}
	case "json":
		return nil
	default:
		return fmt.Errorf("settings.%s has unsupported setting type %q", definition.Key, definition.ValueType)
	}
	return nil
}

func jsonScalarIsNumber(value any) bool {
	switch value.(type) {
	case float64, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return true
	default:
		return false
	}
}

func jsonScalarIsInteger(value any) bool {
	switch typed := value.(type) {
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return true
	case float64:
		return typed == float64(int64(typed))
	default:
		return false
	}
}
