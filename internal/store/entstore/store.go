package entstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	entdialect "entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"

	coreent "github.com/plystra/plystra/ent"
	"github.com/plystra/plystra/ent/group"
	"github.com/plystra/plystra/ent/member"
	"github.com/plystra/plystra/ent/memberrole"
	"github.com/plystra/plystra/ent/permission"
	"github.com/plystra/plystra/ent/resource"
	"github.com/plystra/plystra/ent/resourceaction"
	"github.com/plystra/plystra/ent/resourcemapping"
	"github.com/plystra/plystra/ent/resourcetype"
	"github.com/plystra/plystra/ent/role"
	"github.com/plystra/plystra/ent/rolepermission"
	_ "github.com/plystra/plystra/ent/runtime"
	"github.com/plystra/plystra/ent/space"
	"github.com/plystra/plystra/ent/user"
	"github.com/plystra/plystra/ent/usermember"
	"github.com/plystra/plystra/internal/authz"
	"github.com/plystra/plystra/internal/resources"
)

var _ authz.Store = (*Store)(nil)
var _ resources.Store = (*Store)(nil)

type Store struct {
	client *coreent.Client
	db     *sql.DB
}

func Open(ctx context.Context, databaseURL string) (*Store, error) {
	cfg, err := pgx.ParseConfig(databaseURL)
	if err != nil {
		return nil, err
	}
	db := stdlib.OpenDB(*cfg)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	driver := entsql.OpenDB(entdialect.Postgres, db)
	return New(coreent.NewClient(coreent.Driver(driver)), db), nil
}

func New(client *coreent.Client, db *sql.DB) *Store {
	s := &Store{client: client, db: db}
	s.installHooks()
	return s
}

func (s *Store) Client() *coreent.Client {
	if s == nil {
		return nil
	}
	return s.client
}

func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	if s.client != nil {
		if err := s.client.Close(); err != nil {
			return err
		}
	}
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

func (s *Store) LoadAuthorizationContext(ctx context.Context, input authz.CheckInput) (authz.AuthorizationContext, error) {
	actorContext := input.NormalizedActor()
	actor, err := s.LoadActor(ctx, actorContext)
	if err != nil {
		return authz.AuthorizationContext{}, err
	}

	registry, registryErr := s.LoadResourceRegistration(ctx, input.ResourceType, input.Action)
	if registryErr != nil {
		return authz.AuthorizationContext{
			Actor:            actor,
			ResourceRegistry: registry,
			RegistryErr:      registryErr,
		}, nil
	}

	target, err := s.loadTargetSnapshot(ctx, input)
	if err != nil {
		return authz.AuthorizationContext{}, err
	}

	candidates, err := s.LoadPermissionCandidates(ctx, authz.CandidateQuery{
		MemberID:     actorContext.MemberID,
		ResourceType: input.ResourceType,
		Action:       input.Action,
	})
	if err != nil {
		return authz.AuthorizationContext{}, err
	}

	return authz.AuthorizationContext{
		Actor:              actor,
		ResourceRegistry:   registry,
		Target:             target,
		PermissionGrants:   candidates,
		PermissionFiltered: true,
	}, nil
}

func (s *Store) LoadActor(ctx context.Context, actor authz.ActorContext) (authz.ActorSnapshot, error) {
	u, err := s.client.User.Query().
		Where(user.ID(actor.UserID), user.DeletedAtIsNil()).
		Only(ctx)
	if isNotFound(err) {
		return authz.ActorSnapshot{}, authz.ErrNotFound
	}
	if err != nil {
		return authz.ActorSnapshot{}, err
	}

	um, err := s.client.UserMember.Query().
		Where(
			usermember.ID(actor.UserMemberID),
			usermember.UserID(actor.UserID),
			usermember.MemberID(actor.MemberID),
			usermember.SpaceID(actor.SpaceID),
			usermember.DeletedAtIsNil(),
		).
		Only(ctx)
	if isNotFound(err) {
		return authz.ActorSnapshot{}, authz.ErrNotFound
	}
	if err != nil {
		return authz.ActorSnapshot{}, err
	}

	m, err := s.client.Member.Query().
		Where(member.ID(actor.MemberID), member.DeletedAtIsNil()).
		Only(ctx)
	if isNotFound(err) {
		return authz.ActorSnapshot{}, authz.ErrNotFound
	}
	if err != nil {
		return authz.ActorSnapshot{}, err
	}

	sp, err := s.client.Space.Query().
		Where(space.ID(actor.SpaceID), space.DeletedAtIsNil()).
		Only(ctx)
	if isNotFound(err) {
		return authz.ActorSnapshot{}, authz.ErrNotFound
	}
	if err != nil {
		return authz.ActorSnapshot{}, err
	}

	return authz.ActorSnapshot{
		User: authz.UserSnapshot{
			ID:     u.ID,
			Email:  u.Email,
			Status: u.Status,
		},
		Member: authz.MemberSnapshot{
			ID:          m.ID,
			SpaceID:     m.SpaceID,
			DisplayName: m.DisplayName,
			Status:      m.Status,
		},
		UserMember: authz.UserMemberSnapshot{
			ID:           um.ID,
			UserID:       um.UserID,
			MemberID:     um.MemberID,
			SpaceID:      um.SpaceID,
			RelationType: um.RelationType,
			Status:       um.Status,
			IsPrimary:    um.IsPrimary,
			ExpiresAt:    um.ExpiresAt,
		},
		Space: authz.SpaceSnapshot{
			ID:     sp.ID,
			Name:   sp.Name,
			Status: sp.Status,
		},
	}, nil
}

func (s *Store) LoadResourceRegistration(ctx context.Context, resourceType, action string) (authz.ResourceRegistrySnapshot, error) {
	rt, err := s.client.ResourceType.Query().
		Where(resourcetype.Key(resourceType)).
		Only(ctx)
	if isNotFound(err) {
		return authz.ResourceRegistrySnapshot{}, authz.ErrResourceTypeNotFound
	}
	if err != nil {
		return authz.ResourceRegistrySnapshot{}, err
	}

	ra, err := s.client.ResourceAction.Query().
		Where(resourceaction.ResourceTypeID(rt.ID), resourceaction.Key(action)).
		Only(ctx)
	if isNotFound(err) {
		return authz.ResourceRegistrySnapshot{}, authz.ErrResourceActionNotFound
	}
	if err != nil {
		return authz.ResourceRegistrySnapshot{}, err
	}

	rm, err := s.client.ResourceMapping.Query().
		Where(resourcemapping.ResourceTypeID(rt.ID)).
		Only(ctx)
	if err != nil {
		return authz.ResourceRegistrySnapshot{}, err
	}

	return authz.ResourceRegistrySnapshot{
		ResourceType: mapResourceType(rt),
		Action:       mapResourceAction(ra),
		Mapping:      mapResourceMapping(rm),
	}, nil
}

func (s *Store) LoadTarget(ctx context.Context, resourceType, resourceID string) (authz.TargetSnapshot, error) {
	res, err := s.client.Resource.Query().
		Where(resource.ID(resourceID), resource.ResourceType(resourceType), resource.DeletedAtIsNil()).
		Only(ctx)
	if isNotFound(err) {
		return authz.TargetSnapshot{}, authz.ErrNotFound
	}
	if err != nil {
		return authz.TargetSnapshot{}, err
	}

	target := authz.TargetSnapshot{Resource: mapResource(res)}
	if res.GroupID != nil {
		g, err := s.client.Group.Query().
			Where(group.ID(*res.GroupID), group.DeletedAtIsNil()).
			Only(ctx)
		if isNotFound(err) {
			return target, nil
		}
		if err != nil {
			return authz.TargetSnapshot{}, err
		}
		target.Group = &authz.GroupSnapshot{
			ID:      g.ID,
			SpaceID: g.SpaceID,
			Path:    g.Path,
			Status:  g.Status,
		}
	}

	return target, nil
}

func (s *Store) loadTargetSnapshot(ctx context.Context, input authz.CheckInput) (authz.TargetSnapshot, error) {
	if input.Target != nil {
		target := *input.Target
		if target.Resource.ID == "" {
			target.Resource.ID = input.ResourceID
		}
		if target.Resource.Type == "" {
			target.Resource.Type = input.ResourceType
		}
		return target, nil
	}
	return s.LoadTarget(ctx, input.ResourceType, input.ResourceID)
}

func (s *Store) LoadPermissionCandidates(ctx context.Context, query authz.CandidateQuery) ([]authz.PermissionCandidate, error) {
	grants, err := s.client.MemberRole.Query().
		Where(
			memberrole.MemberID(query.MemberID),
			memberrole.Status(authz.StatusActive),
			memberrole.DeletedAtIsNil(),
		).
		All(ctx)
	if err != nil {
		return nil, err
	}
	if len(grants) == 0 {
		return nil, nil
	}

	roleIDs := uniqueStringsFrom(grants, func(grant *coreent.MemberRole) string { return grant.RoleID })
	perms, err := s.client.Permission.Query().
		Where(
			permission.Resource(query.ResourceType),
			permission.Action(query.Action),
			permission.Status(authz.StatusActive),
			permission.DeletedAtIsNil(),
		).
		All(ctx)
	if err != nil {
		return nil, err
	}
	if len(perms) == 0 {
		return nil, nil
	}
	permissionIDs := uniqueStringsFrom(perms, func(perm *coreent.Permission) string { return perm.ID })

	rolePerms, err := s.client.RolePermission.Query().
		Where(
			rolepermission.RoleIDIn(roleIDs...),
			rolepermission.PermissionIDIn(permissionIDs...),
			rolepermission.DeletedAtIsNil(),
		).
		All(ctx)
	if err != nil {
		return nil, err
	}
	if len(rolePerms) == 0 {
		return nil, nil
	}

	roles, err := s.client.Role.Query().
		Where(
			role.IDIn(uniqueStringsFrom(rolePerms, func(rp *coreent.RolePermission) string { return rp.RoleID })...),
			role.Status(authz.StatusActive),
			role.DeletedAtIsNil(),
		).
		All(ctx)
	if err != nil {
		return nil, err
	}

	rolesByID := mapRoles(roles)
	permsByID := mapPermissions(perms)
	grantsByRole := mapMemberRoles(grants)
	anchors, err := s.loadAnchorGroups(ctx, grants)
	if err != nil {
		return nil, err
	}

	var candidates []authz.PermissionCandidate
	for _, rp := range rolePerms {
		roleSnapshot, ok := rolesByID[rp.RoleID]
		if !ok {
			continue
		}
		permissionSnapshot, ok := permsByID[rp.PermissionID]
		if !ok {
			continue
		}
		for _, grant := range grantsByRole[rp.RoleID] {
			candidates = append(candidates, authz.PermissionCandidate{
				Role:              roleSnapshot,
				Permission:        permissionSnapshot,
				ScopeAnchor:       anchors[derefString(grant.ScopeAnchorGroupID)],
				MemberRoleSpaceID: grant.SpaceID,
			})
		}
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		left, right := candidates[i], candidates[j]
		if left.Role.Key != right.Role.Key {
			return left.Role.Key < right.Role.Key
		}
		if left.Permission.Resource != right.Permission.Resource {
			return left.Permission.Resource < right.Permission.Resource
		}
		if left.Permission.Action != right.Permission.Action {
			return left.Permission.Action < right.Permission.Action
		}
		return left.Permission.Scope < right.Permission.Scope
	})

	return candidates, nil
}

func (s *Store) WriteAuditLog(ctx context.Context, decision authz.Decision) error {
	if !shouldWriteAudit(decision) {
		return nil
	}
	rawTrace, err := decision.MarshalTraceJSON()
	if err != nil {
		return err
	}
	trace := map[string]any{}
	if err := json.Unmarshal(rawTrace, &trace); err != nil {
		return fmt.Errorf("decode audit trace snapshot: %w", err)
	}

	var denyCode *string
	if decision.DenyCode != nil {
		value := string(*decision.DenyCode)
		denyCode = &value
	}
	requestID := nilIfEmpty(decision.Audit.RequestID)

	return s.client.AuditLog.Create().
		SetID(firstNonEmpty(decision.Audit.ID, newID("audit"))).
		SetSpaceID(decision.Audit.SpaceID).
		SetNillableActorUserID(nilIfEmpty(decision.Audit.ActorUserID)).
		SetNillableActorMemberID(nilIfEmpty(decision.Audit.ActorMemberID)).
		SetNillableActorUserMemberID(nilIfEmpty(decision.Audit.ActorUserMemberID)).
		SetAction(decision.Audit.Action).
		SetResourceType(decision.Audit.ResourceType).
		SetResourceID(decision.Audit.ResourceID).
		SetDecision(decision.Audit.Decision).
		SetNillableDenyCode(denyCode).
		SetTrace(trace).
		SetNillableRequestID(requestID).
		SetNillableIPAddress(nilIfEmpty(decision.Request.IP)).
		SetNillableUserAgent(nilIfEmpty(decision.Request.UserAgent)).
		Exec(ctx)
}

func shouldWriteAudit(decision authz.Decision) bool {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("AUDIT_WRITE_MODE")))
	if mode == "" {
		mode = "always"
	}
	switch mode {
	case "always":
		return true
	case "deny_only":
		return decision.Decision == authz.DecisionDeny
	case "manual", "disabled_for_dev":
		return false
	default:
		return true
	}
}

func (s *Store) UpsertResourceType(ctx context.Context, input resources.RegisterResourceTypeInput) (*resources.ResourceType, error) {
	existing, err := s.client.ResourceType.Query().Where(resourcetype.Key(input.Key)).Only(ctx)
	if err != nil && !isNotFound(err) {
		return nil, err
	}
	if isNotFound(err) {
		created, err := s.client.ResourceType.Create().
			SetID(newID("rt")).
			SetKey(input.Key).
			SetDisplayName(input.DisplayName).
			SetNillableDescription(nilIfEmpty(input.Description)).
			SetSource(input.Source).
			SetMetadata(nonNilMap(input.Metadata)).
			Save(ctx)
		if err != nil {
			return nil, err
		}
		out := mapResourceType(created)
		return &out, nil
	}

	builder := s.client.ResourceType.UpdateOneID(existing.ID).
		SetDisplayName(input.DisplayName).
		SetSource(input.Source).
		SetMetadata(nonNilMap(input.Metadata))
	if input.Description == "" {
		builder.ClearDescription()
	} else {
		builder.SetDescription(input.Description)
	}
	updated, err := builder.Save(ctx)
	if err != nil {
		return nil, err
	}
	out := mapResourceType(updated)
	return &out, nil
}

func (s *Store) UpsertResourceAction(ctx context.Context, input resources.RegisterResourceActionInput) (*resources.ResourceAction, error) {
	rt, err := s.client.ResourceType.Query().Where(resourcetype.Key(input.ResourceTypeKey)).Only(ctx)
	if isNotFound(err) {
		return nil, authz.ErrResourceTypeNotFound
	}
	if err != nil {
		return nil, err
	}

	existing, err := s.client.ResourceAction.Query().
		Where(resourceaction.ResourceTypeID(rt.ID), resourceaction.Key(input.Key)).
		Only(ctx)
	if err != nil && !isNotFound(err) {
		return nil, err
	}
	if isNotFound(err) {
		created, err := s.client.ResourceAction.Create().
			SetID(newID("ra")).
			SetResourceTypeID(rt.ID).
			SetKey(input.Key).
			SetDisplayName(input.DisplayName).
			SetNillableDescription(nilIfEmpty(input.Description)).
			SetRiskLevel(input.RiskLevel).
			SetAuditDefault(input.AuditDefault).
			SetMetadata(nonNilMap(input.Metadata)).
			Save(ctx)
		if err != nil {
			return nil, err
		}
		out := mapResourceAction(created)
		return &out, nil
	}

	builder := s.client.ResourceAction.UpdateOneID(existing.ID).
		SetDisplayName(input.DisplayName).
		SetRiskLevel(input.RiskLevel).
		SetAuditDefault(input.AuditDefault).
		SetMetadata(nonNilMap(input.Metadata))
	if input.Description == "" {
		builder.ClearDescription()
	} else {
		builder.SetDescription(input.Description)
	}
	updated, err := builder.Save(ctx)
	if err != nil {
		return nil, err
	}
	out := mapResourceAction(updated)
	return &out, nil
}

func (s *Store) UpsertResourceMapping(ctx context.Context, input resources.RegisterResourceMappingInput) (*resources.ResourceMapping, error) {
	rt, err := s.client.ResourceType.Query().Where(resourcetype.Key(input.ResourceTypeKey)).Only(ctx)
	if isNotFound(err) {
		return nil, authz.ErrResourceTypeNotFound
	}
	if err != nil {
		return nil, err
	}

	existing, err := s.client.ResourceMapping.Query().
		Where(resourcemapping.ResourceTypeID(rt.ID)).
		Only(ctx)
	if err != nil && !isNotFound(err) {
		return nil, err
	}
	if isNotFound(err) {
		created, err := s.client.ResourceMapping.Create().
			SetID(newID("rm")).
			SetResourceTypeID(rt.ID).
			SetStorageKind(input.StorageKind).
			SetNillableTableName(nilIfEmpty(input.TableName)).
			SetIDField(input.IDField).
			SetSpaceField(input.SpaceField).
			SetNillableGroupField(nilIfEmpty(input.GroupField)).
			SetNillableOwnerMemberField(nilIfEmpty(input.OwnerMemberField)).
			SetNillableVisibilityField(nilIfEmpty(input.VisibilityField)).
			SetNillableMetadataField(nilIfEmpty(input.MetadataField)).
			SetMetadata(nonNilMap(input.Metadata)).
			Save(ctx)
		if err != nil {
			return nil, err
		}
		out := mapResourceMapping(created)
		return &out, nil
	}

	builder := s.client.ResourceMapping.UpdateOneID(existing.ID).
		SetStorageKind(input.StorageKind).
		SetIDField(input.IDField).
		SetSpaceField(input.SpaceField).
		SetMetadata(nonNilMap(input.Metadata))
	setNullableString(builder.SetTableName, builder.ClearTableName, input.TableName)
	setNullableString(builder.SetGroupField, builder.ClearGroupField, input.GroupField)
	setNullableString(builder.SetOwnerMemberField, builder.ClearOwnerMemberField, input.OwnerMemberField)
	setNullableString(builder.SetVisibilityField, builder.ClearVisibilityField, input.VisibilityField)
	setNullableString(builder.SetMetadataField, builder.ClearMetadataField, input.MetadataField)

	updated, err := builder.Save(ctx)
	if err != nil {
		return nil, err
	}
	out := mapResourceMapping(updated)
	return &out, nil
}

func (s *Store) GetResourceType(ctx context.Context, key string) (*resources.ResourceType, error) {
	rt, err := s.client.ResourceType.Query().Where(resourcetype.Key(key)).Only(ctx)
	if isNotFound(err) {
		return nil, authz.ErrResourceTypeNotFound
	}
	if err != nil {
		return nil, err
	}
	out := mapResourceType(rt)
	return &out, nil
}

func (s *Store) ListResourceActions(ctx context.Context, resourceTypeKey string) ([]resources.ResourceAction, error) {
	rt, err := s.client.ResourceType.Query().Where(resourcetype.Key(resourceTypeKey)).Only(ctx)
	if isNotFound(err) {
		return nil, authz.ErrResourceTypeNotFound
	}
	if err != nil {
		return nil, err
	}

	actions, err := s.client.ResourceAction.Query().
		Where(resourceaction.ResourceTypeID(rt.ID)).
		Order(coreent.Asc(resourceaction.FieldKey)).
		All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]resources.ResourceAction, 0, len(actions))
	for _, action := range actions {
		out = append(out, mapResourceAction(action))
	}
	return out, nil
}

func (s *Store) GetResourceMapping(ctx context.Context, resourceTypeKey string) (*resources.ResourceMapping, error) {
	rt, err := s.client.ResourceType.Query().Where(resourcetype.Key(resourceTypeKey)).Only(ctx)
	if isNotFound(err) {
		return nil, authz.ErrResourceTypeNotFound
	}
	if err != nil {
		return nil, err
	}
	rm, err := s.client.ResourceMapping.Query().Where(resourcemapping.ResourceTypeID(rt.ID)).Only(ctx)
	if isNotFound(err) {
		return nil, authz.ErrResourceTypeNotFound
	}
	if err != nil {
		return nil, err
	}
	out := mapResourceMapping(rm)
	return &out, nil
}

func (s *Store) loadAnchorGroups(ctx context.Context, grants []*coreent.MemberRole) (map[string]*authz.GroupSnapshot, error) {
	anchorIDs := uniqueStringsFrom(grants, func(grant *coreent.MemberRole) string {
		return derefString(grant.ScopeAnchorGroupID)
	})
	if len(anchorIDs) == 0 {
		return map[string]*authz.GroupSnapshot{}, nil
	}
	groups, err := s.client.Group.Query().
		Where(group.IDIn(anchorIDs...), group.DeletedAtIsNil()).
		All(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]*authz.GroupSnapshot, len(groups))
	for _, g := range groups {
		value := authz.GroupSnapshot{
			ID:      g.ID,
			SpaceID: g.SpaceID,
			Path:    g.Path,
			Status:  g.Status,
		}
		out[g.ID] = &value
	}
	return out, nil
}

func mapResourceType(rt *coreent.ResourceType) authz.ResourceTypeSnapshot {
	return authz.ResourceTypeSnapshot{
		ID:          rt.ID,
		Key:         rt.Key,
		DisplayName: rt.DisplayName,
		Description: derefString(rt.Description),
		Status:      rt.Status,
		Source:      rt.Source,
		Metadata:    nonNilMap(rt.Metadata),
	}
}

func mapResourceAction(ra *coreent.ResourceAction) authz.ResourceActionSnapshot {
	return authz.ResourceActionSnapshot{
		ID:             ra.ID,
		ResourceTypeID: ra.ResourceTypeID,
		Key:            ra.Key,
		DisplayName:    ra.DisplayName,
		Description:    derefString(ra.Description),
		RiskLevel:      ra.RiskLevel,
		AuditDefault:   ra.AuditDefault,
		Metadata:       nonNilMap(ra.Metadata),
	}
}

func mapResourceMapping(rm *coreent.ResourceMapping) authz.ResourceMappingSnapshot {
	return authz.ResourceMappingSnapshot{
		ID:               rm.ID,
		ResourceTypeID:   rm.ResourceTypeID,
		StorageKind:      rm.StorageKind,
		TableName:        derefString(rm.TableName),
		IDField:          rm.IDField,
		SpaceField:       rm.SpaceField,
		GroupField:       derefString(rm.GroupField),
		OwnerMemberField: derefString(rm.OwnerMemberField),
		VisibilityField:  derefString(rm.VisibilityField),
		MetadataField:    derefString(rm.MetadataField),
		Status:           rm.Status,
		Metadata:         nonNilMap(rm.Metadata),
	}
}

func mapResource(res *coreent.Resource) authz.ResourceSnapshot {
	return authz.ResourceSnapshot{
		ID:            res.ID,
		Type:          res.ResourceType,
		SpaceID:       res.SpaceID,
		GroupID:       derefString(res.GroupID),
		OwnerMemberID: derefString(res.OwnerMemberID),
		DisplayName:   derefString(res.DisplayName),
		Visibility:    res.Visibility,
		Status:        res.Status,
		Metadata:      nonNilMap(res.Metadata),
	}
}

func mapRoles(roles []*coreent.Role) map[string]authz.RoleSnapshot {
	out := make(map[string]authz.RoleSnapshot, len(roles))
	for _, role := range roles {
		out[role.ID] = authz.RoleSnapshot{
			ID:      role.ID,
			Key:     role.Key,
			SpaceID: role.SpaceID,
		}
	}
	return out
}

func mapPermissions(perms []*coreent.Permission) map[string]authz.PermissionSnapshot {
	out := make(map[string]authz.PermissionSnapshot, len(perms))
	for _, perm := range perms {
		out[perm.ID] = authz.PermissionSnapshot{
			ID:       perm.ID,
			Resource: perm.Resource,
			Action:   perm.Action,
			Scope:    authz.Scope(perm.Scope),
		}
	}
	return out
}

func mapMemberRoles(grants []*coreent.MemberRole) map[string][]*coreent.MemberRole {
	out := make(map[string][]*coreent.MemberRole)
	for _, grant := range grants {
		out[grant.RoleID] = append(out[grant.RoleID], grant)
	}
	return out
}

func uniqueStringsFrom[T any](values []T, pick func(T) string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, value := range values {
		item := pick(value)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

func isNotFound(err error) bool {
	return coreent.IsNotFound(err)
}

func derefString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func nilIfEmpty(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func nonNilMap(value map[string]any) map[string]any {
	if value == nil {
		return map[string]any{}
	}
	return value
}

func setNullableString[T any](set func(string) T, clear func() T, value string) {
	if value == "" {
		clear()
		return
	}
	set(value)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func newID(prefix string) string {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return prefix + "_" + strconv.FormatInt(time.Now().UTC().UnixNano(), 10)
	}
	return prefix + "_" + hex.EncodeToString(buf[:])
}
