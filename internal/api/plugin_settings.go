package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"
	coreent "github.com/plystra/plystra/ent"
	entplugin "github.com/plystra/plystra/ent/plugin"
	entpluginsettingsdefinition "github.com/plystra/plystra/ent/pluginsettingsdefinition"
	entpluginsettingsvalue "github.com/plystra/plystra/ent/pluginsettingsvalue"
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
