package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	entgroup "github.com/plystra/plystra/ent/group"
	entmember "github.com/plystra/plystra/ent/member"
	entresource "github.com/plystra/plystra/ent/resource"
	entresourcemapping "github.com/plystra/plystra/ent/resourcemapping"

	"github.com/jackc/pgx/v5"
	coreent "github.com/plystra/plystra/ent"
	entspace "github.com/plystra/plystra/ent/space"
	"github.com/plystra/plystra/internal/authz"
)

func (s *Server) authorizeTarget(w http.ResponseWriter, r *http.Request, actor authz.ActorContext, resourceType, resourceID, action string, target authz.TargetSnapshot) (*authz.Decision, bool) {
	decision, err := authz.Check(r.Context(), s.authzStore, authz.CheckInput{
		Actor:        actor,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Action:       action,
		Target:       &target,
		RequestID:    requestIDFrom(r),
		IP:           remoteIPFrom(r),
		UserAgent:    r.UserAgent(),
	})
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Authorization check failed.", err.Error())
		return nil, false
	}
	if !decision.IsAllowed() {
		writeError(w, r, http.StatusForbidden, "AUTHORIZATION_DENIED", "The action is not allowed.", decision)
		return decision, false
	}
	return decision, true
}

func (s *Server) requireInternalResourceMapping(ctx context.Context, resourceType string) error {
	rt, err := s.loadResourceTypeEntityByKey(ctx, resourceType)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrAPINotFound
		}
		return err
	}
	mapping, err := s.ent.ResourceMapping.Query().Where(entresourcemapping.ResourceTypeID(rt.ID)).Only(ctx)
	if coreent.IsNotFound(err) {
		return ErrAPINotFound
	}
	if err != nil {
		return err
	}
	if mapping.StorageKind != "internal_table" || derefString(mapping.TableName) != "resources" {
		return ErrAPIUnsupportedMapping
	}
	return nil
}

var ErrAPINotFound = errors.New("api resource not found")
var ErrAPIUnsupportedMapping = errors.New("unsupported resource mapping")

func (s *Server) writeMappingError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrAPINotFound):
		writeError(w, r, http.StatusNotFound, "RESOURCE_TYPE_NOT_FOUND", "Resource type mapping was not found.", nil)
	case errors.Is(err, ErrAPIUnsupportedMapping):
		writeError(w, r, http.StatusBadRequest, "UNSUPPORTED_RESOURCE_MAPPING", "Data Console mutations currently support internal resources table mappings only.", nil)
	default:
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to validate resource mapping.", err.Error())
	}
}

func (s *Server) resourceExists(ctx context.Context, resourceType, resourceID string) (bool, error) {
	if s.ent == nil {
		return false, errors.New("ent client is not configured")
	}
	return s.ent.Resource.Query().Where(entresource.ResourceType(resourceType), entresource.ID(resourceID), entresource.DeletedAtIsNil()).Exist(ctx)
}

func (s *Server) validateResourceRefs(ctx context.Context, spaceID, groupID, ownerMemberID string) error {
	if groupID != "" {
		if _, err := s.loadGroupSnapshot(ctx, spaceID, groupID); err != nil {
			return err
		}
	}
	if ownerMemberID != "" {
		if err := s.validateMemberInSpace(ctx, spaceID, ownerMemberID); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) validateMemberInSpace(ctx context.Context, spaceID, memberID string) error {
	if memberID == "" {
		return nil
	}
	if s.ent == nil {
		return errors.New("ent client is not configured")
	}
	exists, err := s.ent.Member.Query().Where(entmember.ID(memberID), entmember.SpaceID(spaceID), entmember.DeletedAtIsNil()).Exist(ctx)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("member %s is not in space %s", memberID, spaceID)
	}
	return nil
}

func (s *Server) proposedResourceTarget(ctx context.Context, resourceType, resourceID, spaceID, groupID, ownerMemberID, displayName, visibility, status string, metadata map[string]any) (authz.TargetSnapshot, error) {
	group, err := s.loadGroupSnapshot(ctx, spaceID, groupID)
	if err != nil {
		return authz.TargetSnapshot{}, err
	}
	return authz.TargetSnapshot{
		Resource: authz.ResourceSnapshot{
			ID:            resourceID,
			Type:          resourceType,
			SpaceID:       spaceID,
			GroupID:       groupID,
			OwnerMemberID: ownerMemberID,
			DisplayName:   displayName,
			Visibility:    visibility,
			Status:        status,
			Metadata:      nonNilMap(metadata),
		},
		Group: group,
	}, nil
}

func (s *Server) loadGroupSnapshot(ctx context.Context, spaceID, groupID string) (*authz.GroupSnapshot, error) {
	if groupID == "" {
		return nil, nil
	}
	if s.ent == nil {
		return nil, errors.New("ent client is not configured")
	}
	row, err := s.ent.Group.Query().Where(entgroup.ID(groupID), entgroup.SpaceID(spaceID), entgroup.DeletedAtIsNil()).Only(ctx)
	if coreent.IsNotFound(err) {
		return nil, pgx.ErrNoRows
	}
	if err != nil {
		return nil, err
	}
	return &authz.GroupSnapshot{
		ID:      row.ID,
		SpaceID: row.SpaceID,
		Path:    row.Path,
		Status:  row.Status,
	}, nil
}

func (s *Server) loadResourceTarget(ctx context.Context, resourceType, resourceID string) (authz.TargetSnapshot, error) {
	if s.ent == nil {
		return authz.TargetSnapshot{}, errors.New("ent client is not configured")
	}
	row, err := s.ent.Resource.Query().Where(entresource.ResourceType(resourceType), entresource.ID(resourceID), entresource.DeletedAtIsNil()).Only(ctx)
	if coreent.IsNotFound(err) {
		return authz.TargetSnapshot{}, pgx.ErrNoRows
	}
	if err != nil {
		return authz.TargetSnapshot{}, err
	}
	target := authz.TargetSnapshot{
		Resource: authz.ResourceSnapshot{
			ID:            row.ID,
			Type:          row.ResourceType,
			SpaceID:       row.SpaceID,
			GroupID:       derefString(row.GroupID),
			OwnerMemberID: derefString(row.OwnerMemberID),
			DisplayName:   derefString(row.DisplayName),
			Visibility:    row.Visibility,
			Status:        row.Status,
			Metadata:      nonNilMap(row.Metadata),
		},
	}
	group, err := s.loadGroupSnapshot(ctx, target.Resource.SpaceID, target.Resource.GroupID)
	if err != nil {
		return authz.TargetSnapshot{}, err
	}
	target.Group = group
	return target, nil
}

func (s *Server) loadResourceRow(ctx context.Context, resourceType, resourceID string) (map[string]any, error) {
	if s.ent == nil {
		return nil, errors.New("ent client is not configured")
	}
	row, err := s.ent.Resource.Query().Where(entresource.ResourceType(resourceType), entresource.ID(resourceID)).Only(ctx)
	if coreent.IsNotFound(err) {
		return nil, pgx.ErrNoRows
	}
	if err != nil {
		return nil, err
	}
	return s.resourceMapWithRefs(ctx, row)
}

func (s *Server) resourceMapWithRefs(ctx context.Context, row *coreent.Resource) (map[string]any, error) {
	spaceName := ""
	if row.SpaceID != "" {
		spaceRecord, err := s.ent.Space.Query().Where(entspace.ID(row.SpaceID), entspace.DeletedAtIsNil()).Only(ctx)
		if err != nil && !coreent.IsNotFound(err) {
			return nil, err
		}
		if spaceRecord != nil {
			spaceName = spaceRecord.Name
		}
	}
	groupPath := ""
	if groupID := derefString(row.GroupID); groupID != "" {
		groupRecord, err := s.ent.Group.Query().Where(entgroup.ID(groupID), entgroup.DeletedAtIsNil()).Only(ctx)
		if err != nil && !coreent.IsNotFound(err) {
			return nil, err
		}
		if groupRecord != nil {
			groupPath = groupRecord.Path
		}
	}
	ownerMemberDisplayName := ""
	if memberID := derefString(row.OwnerMemberID); memberID != "" {
		memberRecord, err := s.ent.Member.Query().Where(entmember.ID(memberID), entmember.DeletedAtIsNil()).Only(ctx)
		if err != nil && !coreent.IsNotFound(err) {
			return nil, err
		}
		if memberRecord != nil {
			ownerMemberDisplayName = memberRecord.DisplayName
		}
	}
	return resourceMap(row, spaceName, groupPath, ownerMemberDisplayName), nil
}
