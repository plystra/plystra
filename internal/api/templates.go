package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	entgroup "github.com/plystra/plystra/ent/group"
	entpermission "github.com/plystra/plystra/ent/permission"
	entplugin "github.com/plystra/plystra/ent/plugin"
	entrole "github.com/plystra/plystra/ent/role"
	entrolepermission "github.com/plystra/plystra/ent/rolepermission"
	entusermember "github.com/plystra/plystra/ent/usermember"

	coreent "github.com/plystra/plystra/ent"
	entspace "github.com/plystra/plystra/ent/space"
	"github.com/plystra/plystra/internal/plugins"
	"github.com/plystra/plystra/internal/templates"
)

func pluginSettingValueMap(value any) map[string]any {
	if value == nil {
		return map[string]any{}
	}
	if typed, ok := value.(map[string]any); ok {
		return typed
	}
	return map[string]any{"value": value}
}

type templateInstallRequest struct {
	SpaceID                  string `json:"space_id"`
	AllowMissingPlugins      bool   `json:"allow_missing_plugins"`
	AllowMissingCapabilities bool   `json:"allow_missing_capabilities"`
	InstalledByUserID        string `json:"installed_by_user_id"`
	InstalledByMemberID      string `json:"installed_by_member_id"`
	ActorUserID              string `json:"actor_user_id"`
	ActorMemberID            string `json:"actor_member_id"`
	ActorUserMemberID        string `json:"actor_user_member_id"`
	AllowExistingResources   bool   `json:"allow_existing_resources"`
}

func (s *Server) handleTemplates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, r)
		return
	}
	writeList(w, r, http.StatusOK, templates.Catalog(), limitFrom(r, 50))
}

func (s *Server) handleTemplateSubroutes(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/templates/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	tpl, ok := templates.ByID(parts[0])
	if !ok {
		writeError(w, r, http.StatusNotFound, "TEMPLATE_NOT_FOUND", "Template was not found.", nil)
		return
	}
	switch {
	case len(parts) == 1:
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, r)
			return
		}
		writeData(w, r, http.StatusOK, tpl)
	case len(parts) == 2 && parts[1] == "preview-install":
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, r)
			return
		}
		if err := s.validateTemplateCoreVersion(tpl); err != nil {
			writeError(w, r, http.StatusBadRequest, "INCOMPATIBLE_TEMPLATE", "Template is not compatible with this Core version.", err.Error())
			return
		}
		missing, err := s.missingTemplatePlugins(r.Context(), tpl)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to validate template plugins.", err.Error())
			return
		}
		missingCapabilities, providers, err := s.resolveTemplateCapabilities(r.Context(), tpl)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to resolve template capabilities.", err.Error())
			return
		}
		writeData(w, r, http.StatusOK, templates.Preview(tpl, missing, missingCapabilities, providers))
	case len(parts) == 2 && parts[1] == "install":
		s.handleTemplateInstall(w, r, tpl)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleTemplateInstall(w http.ResponseWriter, r *http.Request, tpl templates.Manifest) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, r)
		return
	}
	var req templateInstallRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.validateTemplateCoreVersion(tpl); err != nil {
		writeError(w, r, http.StatusBadRequest, "INCOMPATIBLE_TEMPLATE", "Template is not compatible with this Core version.", err.Error())
		return
	}
	missing, err := s.missingTemplatePlugins(r.Context(), tpl)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to validate template plugins.", err.Error())
		return
	}
	if len(missing) > 0 && !req.AllowMissingPlugins {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Template requires plugins that are not enabled.", map[string]any{"missing_plugins": missing})
		return
	}
	missingCapabilities, capabilityProviders, err := s.resolveTemplateCapabilities(r.Context(), tpl)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to resolve template capabilities.", err.Error())
		return
	}
	if len(missingCapabilities) > 0 && !req.AllowMissingCapabilities {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Template requires capabilities that are not provided by enabled plugins.", map[string]any{"missing_capabilities": missingCapabilities})
		return
	}
	applied, err := s.applyTemplateDefaults(r.Context(), tpl, req)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Failed to apply template defaults.", err.Error())
		return
	}
	snapshot, err := templates.ManifestMap(tpl)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to encode template manifest.", err.Error())
		return
	}
	installationID := "ti_" + safeIdentifier(tpl.ID+"_"+strconv.FormatInt(time.Now().UTC().UnixNano(), 10))
	installedByUserID := firstNonEmpty(req.InstalledByUserID, req.ActorUserID)
	installedByMemberID := firstNonEmpty(req.InstalledByMemberID, req.ActorMemberID)
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	_, err = client.TemplateInstallation.Create().
		SetID(installationID).
		SetTemplateID(tpl.ID).
		SetTemplateVersion(tpl.Version).
		SetNillableSpaceID(optionalString(req.SpaceID)).
		SetStatus("installed").
		SetManifestSnapshot(snapshot).
		SetNillableInstalledByUserID(optionalString(installedByUserID)).
		SetNillableInstalledByMemberID(optionalString(installedByMemberID)).
		Save(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to record template installation.", err.Error())
		return
	}
	if err := s.writeTemplateInstallAudit(r.Context(), tpl, req, installationID, applied, missing); err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to write template install audit log.", err.Error())
		return
	}
	writeData(w, r, http.StatusCreated, map[string]any{
		"installation_id": installationID,
		"status":          "installed",
		"template":        tpl,
		"preview":         templates.Preview(tpl, missing, missingCapabilities, capabilityProviders),
		"applied":         applied,
	})
}

func (s *Server) validateTemplateCoreVersion(tpl templates.Manifest) error {
	if !plugins.VersionSatisfies(s.coreVersion, tpl.RequiresCore) {
		return fmt.Errorf("requires_core %q is not satisfied by Core %q", tpl.RequiresCore, s.coreVersion)
	}
	return nil
}

func (s *Server) applyTemplateDefaults(ctx context.Context, tpl templates.Manifest, req templateInstallRequest) (map[string]any, error) {
	applied := map[string]any{
		"spaces":           []string{},
		"groups":           []string{},
		"roles":            []string{},
		"permissions":      []string{},
		"role_permissions": []string{},
	}
	targetSpaceID := req.SpaceID
	if targetSpaceID == "" && len(tpl.Spaces) > 0 {
		targetSpaceID = "space_" + safeIdentifier(tpl.ID+"_"+tpl.Spaces[0].Key)
	}
	if s.ent == nil {
		return nil, errors.New("ent client is not configured")
	}
	if req.SpaceID != "" {
		exists, err := s.ent.Space.Query().Where(entspace.ID(req.SpaceID), entspace.DeletedAtIsNil()).Exist(ctx)
		if err != nil {
			return nil, err
		}
		if !exists {
			return nil, fmt.Errorf("space %s was not found", req.SpaceID)
		}
		applied["spaces"] = append(applied["spaces"].([]string), req.SpaceID)
	} else {
		for _, space := range tpl.Spaces {
			spaceID := "space_" + safeIdentifier(tpl.ID+"_"+space.Key)
			name := firstNonEmpty(space.Name, titleFromKey(space.Key))
			existing, err := s.ent.Space.Query().Where(entspace.ID(spaceID)).Only(ctx)
			if coreent.IsNotFound(err) {
				_, err = s.ent.Space.Create().SetID(spaceID).SetName(name).SetStatus("active").Save(ctx)
			} else if err == nil {
				err = s.ent.Space.UpdateOneID(existing.ID).SetName(name).SetStatus("active").Exec(ctx)
			}
			if err != nil {
				return nil, err
			}
			applied["spaces"] = append(applied["spaces"].([]string), spaceID)
			if targetSpaceID == "" {
				targetSpaceID = spaceID
			}
		}
	}
	if targetSpaceID == "" {
		return nil, fmt.Errorf("space_id is required for templates that do not create a Space")
	}
	for _, group := range tpl.Groups {
		groupID := "group_" + safeIdentifier(targetSpaceID+"_"+group.Key)
		name := firstNonEmpty(group.Name, titleFromKey(group.Key))
		existing, err := s.ent.Group.Query().Where(entgroup.SpaceID(targetSpaceID), entgroup.Path(group.Key)).Only(ctx)
		if coreent.IsNotFound(err) {
			_, err = s.ent.Group.Create().
				SetID(groupID).
				SetSpaceID(targetSpaceID).
				SetName(name).
				SetDisplayName(name).
				SetPath(group.Key).
				SetDepth(pathDepth(group.Key)).
				SetStatus("active").
				Save(ctx)
		} else if err == nil {
			err = s.ent.Group.UpdateOneID(existing.ID).
				SetName(name).
				SetDisplayName(name).
				SetStatus("active").
				Exec(ctx)
			groupID = existing.ID
		}
		if err != nil {
			return nil, err
		}
		applied["groups"] = append(applied["groups"].([]string), groupID)
	}
	roleIDs := map[string]string{}
	for _, role := range tpl.Roles {
		roleID := "role_" + safeIdentifier(targetSpaceID+"_"+role.Key)
		existing, err := s.ent.Role.Query().Where(entrole.SpaceID(targetSpaceID), entrole.Key(role.Key)).Only(ctx)
		if coreent.IsNotFound(err) {
			_, err = s.ent.Role.Create().
				SetID(roleID).
				SetSpaceID(targetSpaceID).
				SetKey(role.Key).
				SetName(titleFromKey(role.Key)).
				Save(ctx)
		} else if err == nil {
			err = s.ent.Role.UpdateOneID(existing.ID).SetKey(role.Key).Exec(ctx)
			roleID = existing.ID
		}
		if err != nil {
			return nil, err
		}
		roleIDs[role.Key] = roleID
		applied["roles"] = append(applied["roles"].([]string), roleID)
	}
	for _, permission := range tpl.Permissions {
		roleID := roleIDs[permission.Role]
		if roleID == "" {
			return nil, fmt.Errorf("template permission references unknown role %q", permission.Role)
		}
		permissionID := "perm_" + safeIdentifier(permission.Resource+"_"+permission.Action+"_"+permission.Scope)
		existingPermission, err := s.ent.Permission.Query().Where(entpermission.Resource(permission.Resource), entpermission.Action(permission.Action), entpermission.Scope(permission.Scope)).Only(ctx)
		if coreent.IsNotFound(err) {
			_, err = s.ent.Permission.Create().
				SetID(permissionID).
				SetResource(permission.Resource).
				SetAction(permission.Action).
				SetScope(permission.Scope).
				Save(ctx)
		} else if err == nil {
			permissionID = existingPermission.ID
			err = s.ent.Permission.UpdateOneID(existingPermission.ID).
				SetResource(permission.Resource).
				SetAction(permission.Action).
				SetScope(permission.Scope).
				Exec(ctx)
		}
		if err != nil {
			return nil, err
		}
		rolePermissionID := "rp_" + safeIdentifier(roleID+"_"+permissionID)
		existingRolePermission, err := s.ent.RolePermission.Query().Where(entrolepermission.RoleID(roleID), entrolepermission.PermissionID(permissionID)).Only(ctx)
		if coreent.IsNotFound(err) {
			_, err = s.ent.RolePermission.Create().
				SetID(rolePermissionID).
				SetRoleID(roleID).
				SetPermissionID(permissionID).
				Save(ctx)
		} else if err == nil {
			rolePermissionID = existingRolePermission.ID
			err = s.ent.RolePermission.UpdateOneID(existingRolePermission.ID).ClearDeletedAt().Exec(ctx)
		}
		if err != nil {
			return nil, err
		}
		applied["permissions"] = append(applied["permissions"].([]string), permissionID)
		applied["role_permissions"] = append(applied["role_permissions"].([]string), rolePermissionID)
	}
	return applied, nil
}

func (s *Server) writeTemplateInstallAudit(ctx context.Context, tpl templates.Manifest, req templateInstallRequest, installationID string, applied map[string]any, missing []string) error {
	if s.ent == nil {
		return errors.New("ent client is not configured")
	}
	actorUserID := firstNonEmpty(req.ActorUserID, req.InstalledByUserID)
	actorMemberID := firstNonEmpty(req.ActorMemberID, req.InstalledByMemberID)
	actorUserMemberID := req.ActorUserMemberID
	spaceID := req.SpaceID
	if spaceID == "" {
		spaces, _ := applied["spaces"].([]string)
		if len(spaces) > 0 {
			spaceID = spaces[0]
		}
	}
	if actorUserMemberID == "" && actorUserID != "" && actorMemberID != "" {
		userMembers, err := s.ent.UserMember.Query().
			Where(
				entusermember.UserID(actorUserID),
				entusermember.MemberID(actorMemberID),
				entusermember.SpaceID(spaceID),
				entusermember.Status("active"),
				entusermember.DeletedAtIsNil(),
				entusermember.Or(entusermember.ExpiresAtIsNil(), entusermember.ExpiresAtGT(time.Now().UTC())),
			).
			All(ctx)
		if err == nil && len(userMembers) > 0 {
			sort.SliceStable(userMembers, func(i, j int) bool {
				if userMembers[i].IsPrimary != userMembers[j].IsPrimary {
					return userMembers[i].IsPrimary
				}
				return userMembers[i].CreatedAt.After(userMembers[j].CreatedAt)
			})
			actorUserMemberID = userMembers[0].ID
		}
	}
	if actorUserID == "" || actorMemberID == "" || actorUserMemberID == "" || spaceID == "" {
		return fmt.Errorf("actor_user_id, actor_member_id, actor_user_member_id, and space_id are required for template install audit")
	}
	trace := map[string]any{
		"trace_version":   "1.0",
		"decision":        "allow",
		"reason":          "template installed",
		"template":        tpl,
		"applied":         applied,
		"missing_plugins": missing,
		"request": map[string]any{
			"space_id":        req.SpaceID,
			"installation_id": installationID,
		},
	}
	if s.ent == nil {
		return errors.New("ent client is not configured")
	}
	_, err := s.ent.AuditLog.Create().
		SetID("audit_" + safeIdentifier(installationID)).
		SetSpaceID(spaceID).
		SetActorUserID(actorUserID).
		SetActorMemberID(actorMemberID).
		SetActorUserMemberID(actorUserMemberID).
		SetAction("template.install").
		SetResourceType("template").
		SetResourceID(tpl.ID).
		SetDecision("allow").
		SetTrace(trace).
		SetRequestID(installationID).
		Save(ctx)
	return err
}

func (s *Server) missingTemplatePlugins(ctx context.Context, tpl templates.Manifest) ([]string, error) {
	if s.ent == nil {
		return nil, errors.New("ent client is not configured")
	}
	missing := []string{}
	for _, key := range tpl.RequiredPlugins {
		pluginRow, err := s.ent.Plugin.Query().Where(entplugin.Key(key)).Only(ctx)
		if coreent.IsNotFound(err) {
			missing = append(missing, key)
			continue
		}
		if err != nil {
			return nil, err
		}
		if pluginRow.Status != "enabled" && pluginRow.Status != "installed" {
			missing = append(missing, key)
		}
	}
	return missing, nil
}

func (s *Server) resolveTemplateCapabilities(ctx context.Context, tpl templates.Manifest) ([]templates.CapabilityRequirement, map[string]string, error) {
	if s.ent == nil {
		return nil, nil, errors.New("ent client is not configured")
	}
	if len(tpl.RequiredCapabilities) == 0 {
		return nil, map[string]string{}, nil
	}
	pluginRows, err := s.ent.Plugin.Query().
		Where(entplugin.StatusIn("enabled", "installed")).
		All(ctx)
	if err != nil {
		return nil, nil, err
	}
	providers := map[string]string{}
	for _, requirement := range tpl.RequiredCapabilities {
		if requirement.Optional {
			continue
		}
		for _, pluginRow := range pluginRows {
			manifest, ok := pluginRow.Manifest["capabilities"].([]any)
			if !ok {
				continue
			}
			for _, raw := range manifest {
				item, ok := raw.(map[string]any)
				if !ok {
					continue
				}
				if stringAny(item["id"]) != requirement.ID {
					continue
				}
				if !capabilityLevelSatisfies(stringAny(item["level"]), requirement.MinLevel) {
					continue
				}
				version := stringAny(item["version"])
				if requirement.Version != "" && !plugins.VersionSatisfies(version, requirement.Version) {
					continue
				}
				providers[requirement.ID] = pluginRow.Key
			}
		}
	}
	missing := []templates.CapabilityRequirement{}
	for _, requirement := range tpl.RequiredCapabilities {
		if requirement.Optional {
			continue
		}
		if providers[requirement.ID] == "" {
			missing = append(missing, requirement)
		}
	}
	return missing, providers, nil
}

func capabilityLevelSatisfies(actual, required string) bool {
	if required == "" {
		required = "experimental"
	}
	return capabilityLevelRank(actual) >= capabilityLevelRank(required)
}

func capabilityLevelRank(level string) int {
	switch level {
	case "experimental":
		return 1
	case "standard":
		return 2
	case "enterprise":
		return 3
	default:
		return 0
	}
}

func stringAny(value any) string {
	if text, ok := value.(string); ok {
		return strings.TrimSpace(text)
	}
	return ""
}
