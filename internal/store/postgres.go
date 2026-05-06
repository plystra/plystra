package store

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/plystra/plystra/internal/authz"
	"github.com/plystra/plystra/internal/resources"
)

var _ authz.Store = (*PostgresStore)(nil)
var _ resources.Store = (*PostgresStore)(nil)

type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

func OpenPostgres(ctx context.Context, databaseURL string) (*PostgresStore, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}

	return NewPostgresStore(pool), nil
}

func (s *PostgresStore) Close() {
	if s != nil && s.pool != nil {
		s.pool.Close()
	}
}

func (s *PostgresStore) LoadActor(ctx context.Context, actor authz.ActorContext) (authz.ActorSnapshot, error) {
	var out authz.ActorSnapshot
	var space authz.SpaceSnapshot
	var expiresAt pgtype.Timestamptz

	err := s.pool.QueryRow(ctx, loadActorSQL, actor.UserID, actor.UserMemberID, actor.MemberID, actor.SpaceID).Scan(
		&out.User.ID,
		&out.User.Email,
		&out.User.Status,
		&out.UserMember.ID,
		&out.UserMember.UserID,
		&out.UserMember.MemberID,
		&out.UserMember.SpaceID,
		&out.UserMember.RelationType,
		&out.UserMember.Status,
		&out.UserMember.IsPrimary,
		&expiresAt,
		&out.Member.ID,
		&out.Member.SpaceID,
		&out.Member.DisplayName,
		&out.Member.Status,
		&space.ID,
		&space.Name,
		&space.Status,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, authz.ErrNotFound
	}
	if err != nil {
		return out, err
	}

	if expiresAt.Valid {
		t := expiresAt.Time
		out.UserMember.ExpiresAt = &t
	}
	out.Space = space

	return out, nil
}

func (s *PostgresStore) LoadTarget(ctx context.Context, resourceType, resourceID string) (authz.TargetSnapshot, error) {
	var out authz.TargetSnapshot
	var metadata []byte
	var groupID pgtype.Text
	var groupSpaceID pgtype.Text
	var groupPath pgtype.Text
	var groupStatus pgtype.Text

	err := s.pool.QueryRow(ctx, loadTargetSQL, resourceType, resourceID).Scan(
		&out.Resource.ID,
		&out.Resource.Type,
		&out.Resource.SpaceID,
		&out.Resource.GroupID,
		&out.Resource.OwnerMemberID,
		&out.Resource.DisplayName,
		&out.Resource.Visibility,
		&out.Resource.Status,
		&metadata,
		&groupID,
		&groupSpaceID,
		&groupPath,
		&groupStatus,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, authz.ErrNotFound
	}
	if err != nil {
		return out, err
	}

	if len(metadata) > 0 {
		if err := json.Unmarshal(metadata, &out.Resource.Metadata); err != nil {
			return out, fmt.Errorf("decode resource metadata: %w", err)
		}
	}
	if groupID.Valid {
		out.Group = &authz.GroupSnapshot{
			ID:      groupID.String,
			SpaceID: groupSpaceID.String,
			Path:    groupPath.String,
			Status:  groupStatus.String,
		}
	}

	return out, nil
}

func (s *PostgresStore) LoadResourceRegistration(ctx context.Context, resourceType, action string) (authz.ResourceRegistrySnapshot, error) {
	var out authz.ResourceRegistrySnapshot
	var resourceTypeMetadata []byte
	var actionMetadata []byte
	var mappingMetadata []byte

	err := s.pool.QueryRow(ctx, loadResourceRegistrationSQL, resourceType, action).Scan(
		&out.ResourceType.ID,
		&out.ResourceType.Key,
		&out.ResourceType.DisplayName,
		&out.ResourceType.Description,
		&out.ResourceType.Status,
		&out.ResourceType.Source,
		&resourceTypeMetadata,
		&out.Action.ID,
		&out.Action.ResourceTypeID,
		&out.Action.Key,
		&out.Action.DisplayName,
		&out.Action.Description,
		&out.Action.RiskLevel,
		&out.Action.AuditDefault,
		&actionMetadata,
		&out.Mapping.ID,
		&out.Mapping.ResourceTypeID,
		&out.Mapping.StorageKind,
		&out.Mapping.TableName,
		&out.Mapping.IDField,
		&out.Mapping.SpaceField,
		&out.Mapping.GroupField,
		&out.Mapping.OwnerMemberField,
		&out.Mapping.VisibilityField,
		&out.Mapping.MetadataField,
		&out.Mapping.Status,
		&mappingMetadata,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		var exists bool
		if existsErr := s.pool.QueryRow(ctx, resourceTypeExistsSQL, resourceType).Scan(&exists); existsErr != nil {
			return out, existsErr
		}
		if !exists {
			return out, authz.ErrResourceTypeNotFound
		}
		return out, authz.ErrResourceActionNotFound
	}
	if err != nil {
		return out, err
	}

	if err := decodeJSONMap(resourceTypeMetadata, &out.ResourceType.Metadata); err != nil {
		return out, fmt.Errorf("decode resource type metadata: %w", err)
	}
	if err := decodeJSONMap(actionMetadata, &out.Action.Metadata); err != nil {
		return out, fmt.Errorf("decode resource action metadata: %w", err)
	}
	if err := decodeJSONMap(mappingMetadata, &out.Mapping.Metadata); err != nil {
		return out, fmt.Errorf("decode resource mapping metadata: %w", err)
	}

	return out, nil
}

func (s *PostgresStore) LoadPermissionCandidates(ctx context.Context, query authz.CandidateQuery) ([]authz.PermissionCandidate, error) {
	rows, err := s.pool.Query(ctx, loadCandidatesSQL, query.MemberID, query.ResourceType, query.Action)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var candidates []authz.PermissionCandidate
	for rows.Next() {
		var candidate authz.PermissionCandidate
		var scope string
		var anchorID pgtype.Text
		var anchorSpaceID pgtype.Text
		var anchorPath pgtype.Text
		var anchorStatus pgtype.Text

		if err := rows.Scan(
			&candidate.Role.ID,
			&candidate.Role.Key,
			&candidate.Role.SpaceID,
			&candidate.Permission.ID,
			&candidate.Permission.Resource,
			&candidate.Permission.Action,
			&scope,
			&candidate.MemberRoleSpaceID,
			&anchorID,
			&anchorSpaceID,
			&anchorPath,
			&anchorStatus,
		); err != nil {
			return nil, err
		}

		candidate.Permission.Scope = authz.Scope(scope)
		if anchorID.Valid {
			candidate.ScopeAnchor = &authz.GroupSnapshot{
				ID:      anchorID.String,
				SpaceID: anchorSpaceID.String,
				Path:    anchorPath.String,
				Status:  anchorStatus.String,
			}
		}
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return candidates, nil
}

func (s *PostgresStore) WriteAuditLog(ctx context.Context, decision authz.Decision) error {
	if !shouldWriteAudit(decision) {
		return nil
	}
	trace, err := decision.MarshalTraceJSON()
	if err != nil {
		return err
	}

	var denyCode any
	if decision.DenyCode != nil {
		denyCode = string(*decision.DenyCode)
	}

	_, err = s.pool.Exec(ctx, insertAuditLogSQL,
		firstNonEmpty(decision.Audit.ID, newAuditID()),
		decision.Audit.SpaceID,
		decision.Audit.ActorUserID,
		decision.Audit.ActorMemberID,
		decision.Audit.ActorUserMemberID,
		decision.Audit.Action,
		decision.Audit.ResourceType,
		decision.Audit.ResourceID,
		decision.Audit.Decision,
		denyCode,
		string(trace),
		decision.Audit.RequestID,
		decision.Request.IP,
		decision.Request.UserAgent,
	)

	return err
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
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

func (s *PostgresStore) UpsertResourceType(ctx context.Context, input resources.RegisterResourceTypeInput) (*resources.ResourceType, error) {
	metadata, err := json.Marshal(input.Metadata)
	if err != nil {
		return nil, err
	}

	var out resources.ResourceType
	var rawMetadata []byte
	err = s.pool.QueryRow(ctx, upsertResourceTypeSQL,
		newID("rt"),
		input.Key,
		input.DisplayName,
		input.Description,
		input.Source,
		string(metadata),
	).Scan(
		&out.ID,
		&out.Key,
		&out.DisplayName,
		&out.Description,
		&out.Status,
		&out.Source,
		&rawMetadata,
	)
	if err != nil {
		return nil, err
	}
	if err := decodeJSONMap(rawMetadata, &out.Metadata); err != nil {
		return nil, err
	}

	return &out, nil
}

func (s *PostgresStore) UpsertResourceAction(ctx context.Context, input resources.RegisterResourceActionInput) (*resources.ResourceAction, error) {
	metadata, err := json.Marshal(input.Metadata)
	if err != nil {
		return nil, err
	}

	var out resources.ResourceAction
	var rawMetadata []byte
	err = s.pool.QueryRow(ctx, upsertResourceActionSQL,
		input.ResourceTypeKey,
		newID("ra"),
		input.Key,
		input.DisplayName,
		input.Description,
		input.RiskLevel,
		input.AuditDefault,
		string(metadata),
	).Scan(
		&out.ID,
		&out.ResourceTypeID,
		&out.Key,
		&out.DisplayName,
		&out.Description,
		&out.RiskLevel,
		&out.AuditDefault,
		&rawMetadata,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, authz.ErrResourceTypeNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := decodeJSONMap(rawMetadata, &out.Metadata); err != nil {
		return nil, err
	}

	return &out, nil
}

func (s *PostgresStore) UpsertResourceMapping(ctx context.Context, input resources.RegisterResourceMappingInput) (*resources.ResourceMapping, error) {
	metadata, err := json.Marshal(input.Metadata)
	if err != nil {
		return nil, err
	}

	var out resources.ResourceMapping
	var rawMetadata []byte
	err = s.pool.QueryRow(ctx, upsertResourceMappingSQL,
		input.ResourceTypeKey,
		newID("rm"),
		input.StorageKind,
		input.TableName,
		input.IDField,
		input.SpaceField,
		input.GroupField,
		input.OwnerMemberField,
		input.VisibilityField,
		input.MetadataField,
		string(metadata),
	).Scan(
		&out.ID,
		&out.ResourceTypeID,
		&out.StorageKind,
		&out.TableName,
		&out.IDField,
		&out.SpaceField,
		&out.GroupField,
		&out.OwnerMemberField,
		&out.VisibilityField,
		&out.MetadataField,
		&out.Status,
		&rawMetadata,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, authz.ErrResourceTypeNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := decodeJSONMap(rawMetadata, &out.Metadata); err != nil {
		return nil, err
	}

	return &out, nil
}

func (s *PostgresStore) GetResourceType(ctx context.Context, key string) (*resources.ResourceType, error) {
	var out resources.ResourceType
	var rawMetadata []byte
	err := s.pool.QueryRow(ctx, getResourceTypeSQL, key).Scan(
		&out.ID,
		&out.Key,
		&out.DisplayName,
		&out.Description,
		&out.Status,
		&out.Source,
		&rawMetadata,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, authz.ErrResourceTypeNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := decodeJSONMap(rawMetadata, &out.Metadata); err != nil {
		return nil, err
	}
	return &out, nil
}

func (s *PostgresStore) ListResourceActions(ctx context.Context, resourceTypeKey string) ([]resources.ResourceAction, error) {
	rows, err := s.pool.Query(ctx, listResourceActionsSQL, resourceTypeKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var actions []resources.ResourceAction
	for rows.Next() {
		var action resources.ResourceAction
		var rawMetadata []byte
		if err := rows.Scan(
			&action.ID,
			&action.ResourceTypeID,
			&action.Key,
			&action.DisplayName,
			&action.Description,
			&action.RiskLevel,
			&action.AuditDefault,
			&rawMetadata,
		); err != nil {
			return nil, err
		}
		if err := decodeJSONMap(rawMetadata, &action.Metadata); err != nil {
			return nil, err
		}
		actions = append(actions, action)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return actions, nil
}

func (s *PostgresStore) GetResourceMapping(ctx context.Context, resourceTypeKey string) (*resources.ResourceMapping, error) {
	var out resources.ResourceMapping
	var rawMetadata []byte
	err := s.pool.QueryRow(ctx, getResourceMappingSQL, resourceTypeKey).Scan(
		&out.ID,
		&out.ResourceTypeID,
		&out.StorageKind,
		&out.TableName,
		&out.IDField,
		&out.SpaceField,
		&out.GroupField,
		&out.OwnerMemberField,
		&out.VisibilityField,
		&out.MetadataField,
		&out.Status,
		&rawMetadata,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, authz.ErrResourceTypeNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := decodeJSONMap(rawMetadata, &out.Metadata); err != nil {
		return nil, err
	}
	return &out, nil
}

func newAuditID() string {
	return newID("audit")
}

func newID(prefix string) string {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return fmt.Sprintf("%s_%d", prefix, time.Now().UTC().UnixNano())
	}

	return fmt.Sprintf("%s_%s_%x", prefix, time.Now().UTC().Format("20060102T150405Z"), buf)
}

func decodeJSONMap(raw []byte, target *map[string]any) error {
	if len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, target)
}
