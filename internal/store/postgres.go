package store

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/plystra/plystra/internal/authz"
)

var _ authz.Store = (*PostgresStore)(nil)

type PostgresStore struct {
	pool *pgxpool.Pool
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

	return &PostgresStore{pool: pool}, nil
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
	trace, err := decision.MarshalTraceJSON()
	if err != nil {
		return err
	}

	var denyCode any
	if decision.DenyCode != nil {
		denyCode = string(*decision.DenyCode)
	}

	_, err = s.pool.Exec(ctx, insertAuditLogSQL,
		newAuditID(),
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
	)

	return err
}

func newAuditID() string {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return fmt.Sprintf("audit_%d", time.Now().UTC().UnixNano())
	}

	return fmt.Sprintf("audit_%s_%x", time.Now().UTC().Format("20060102T150405Z"), buf)
}
