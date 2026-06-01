package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	entusermember "github.com/plystra/plystra/ent/usermember"

	"github.com/jackc/pgx/v5"
	coreent "github.com/plystra/plystra/ent"
	entmember "github.com/plystra/plystra/ent/member"
	entuser "github.com/plystra/plystra/ent/user"
	"github.com/plystra/plystra/internal/authz"
)

type userMemberMutationRequest struct {
	Actor            authz.ActorContext `json:"actor"`
	ID               string             `json:"id"`
	UserID           string             `json:"user_id"`
	MemberID         string             `json:"member_id"`
	RelationType     string             `json:"relation_type"`
	Status           *string            `json:"status"`
	IsPrimary        *bool              `json:"is_primary"`
	ExpiresAt        *time.Time         `json:"expires_at"`
	LinkedByMemberID *string            `json:"linked_by_member_id"`
	LinkedAt         *time.Time         `json:"linked_at"`
	RevokedReason    *string            `json:"revoked_reason"`
	Metadata         map[string]any     `json:"metadata"`
}

func (s *Server) handleSpaceUserMembers(w http.ResponseWriter, r *http.Request, spaceID string, parts []string) {
	if len(parts) == 0 {
		switch r.Method {
		case http.MethodPost:
			var req userMemberMutationRequest
			if !decodeJSON(w, r, &req) {
				return
			}
			if req.UserID == "" || req.MemberID == "" || req.RelationType == "" {
				writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "user_id, member_id, and relation_type are required.", nil)
				return
			}
			if req.ID == "" {
				req.ID = newEntityID("um")
			}
			if err := s.validateUserMemberRefs(r.Context(), spaceID, req.UserID, req.MemberID, derefString(req.LinkedByMemberID)); err != nil {
				writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "UserMember references are invalid.", err.Error())
				return
			}
			linkedAt := req.LinkedAt
			if linkedAt == nil {
				now := time.Now().UTC()
				linkedAt = &now
			}
			client, ok := s.requireEnt(w, r)
			if !ok {
				return
			}
			_, err := client.UserMember.Create().
				SetID(req.ID).
				SetUserID(req.UserID).
				SetMemberID(req.MemberID).
				SetSpaceID(spaceID).
				SetRelationType(req.RelationType).
				SetStatus(firstNonEmpty(derefString(req.Status), "active")).
				SetIsPrimary(boolValue(req.IsPrimary, false)).
				SetNillableExpiresAt(req.ExpiresAt).
				SetNillableLinkedByMemberID(optionalString(derefString(req.LinkedByMemberID))).
				SetNillableLinkedAt(linkedAt).
				SetMetadata(nonNilMap(req.Metadata)).
				Save(r.Context())
			if err != nil {
				writeError(w, r, http.StatusConflict, "USER_MEMBER_CREATE_FAILED", "Failed to create UserMember.", err.Error())
				return
			}
			row, err := s.loadUserMemberInSpace(r.Context(), spaceID, req.ID)
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load created UserMember.", err.Error())
				return
			}
			s.recordMutationAudit(r.Context(), r, req.Actor, spaceID, "user_member.created", "user_member", req.ID, row)
			writeData(w, r, http.StatusCreated, row)
		case http.MethodGet:
			limit := limitFrom(r, 50)
			client, ok := s.requireEnt(w, r)
			if !ok {
				return
			}
			query := client.UserMember.Query().
				Where(entusermember.SpaceID(spaceID), entusermember.DeletedAtIsNil())
			values := r.URL.Query()
			if userID := strings.TrimSpace(values.Get("user_id")); userID != "" {
				query = query.Where(entusermember.UserID(userID))
			}
			if memberID := strings.TrimSpace(values.Get("member_id")); memberID != "" {
				query = query.Where(entusermember.MemberID(memberID))
			}
			if status := strings.TrimSpace(values.Get("status")); status != "" {
				query = query.Where(entusermember.Status(status))
			}
			if relationType := strings.TrimSpace(values.Get("relation_type")); relationType != "" {
				query = query.Where(entusermember.RelationType(relationType))
			}
			userMembers, err := query.Limit(limit).All(r.Context())
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list UserMembers.", err.Error())
				return
			}
			rows := make([]map[string]any, 0, len(userMembers))
			for _, userMember := range userMembers {
				row, err := s.userMemberMapWithRefs(r.Context(), userMember)
				if err != nil {
					writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list UserMembers.", err.Error())
					return
				}
				rows = append(rows, row)
			}
			sort.SliceStable(rows, func(i, j int) bool {
				leftEmail, _ := rows[i]["email"].(string)
				rightEmail, _ := rows[j]["email"].(string)
				if leftEmail != rightEmail {
					return leftEmail < rightEmail
				}
				leftMember, _ := rows[i]["member_display_name"].(string)
				rightMember, _ := rows[j]["member_display_name"].(string)
				return leftMember < rightMember
			})
			writeList(w, r, http.StatusOK, rows, limit)
		default:
			writeMethodNotAllowed(w, r)
		}
		return
	}
	userMemberID := parts[0]
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			row, err := s.loadUserMemberInSpace(r.Context(), spaceID, userMemberID)
			if errors.Is(err, pgx.ErrNoRows) {
				writeError(w, r, http.StatusNotFound, "USER_MEMBER_NOT_FOUND", "UserMember was not found.", nil)
				return
			}
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load UserMember.", err.Error())
				return
			}
			writeData(w, r, http.StatusOK, row)
		case http.MethodPatch:
			s.handleUserMemberUpdate(w, r, spaceID, userMemberID)
		default:
			writeMethodNotAllowed(w, r)
		}
		return
	}
	if len(parts) == 2 && parts[1] == "revoke" {
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, r)
			return
		}
		var req userMemberMutationRequest
		if !decodeOptionalJSON(w, r, &req) {
			return
		}
		client, ok := s.requireEnt(w, r)
		if !ok {
			return
		}
		update := client.UserMember.UpdateOneID(userMemberID).
			SetStatus("revoked").
			SetRevokedAt(time.Now().UTC())
		if reason := derefString(req.RevokedReason); reason != "" {
			update.SetRevokedReason(reason)
		} else {
			update.ClearRevokedReason()
		}
		err := update.Exec(r.Context())
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to revoke UserMember.", err.Error())
			return
		}
		row, err := s.loadUserMemberInSpace(r.Context(), spaceID, userMemberID)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load revoked UserMember.", err.Error())
			return
		}
		s.recordMutationAudit(r.Context(), r, req.Actor, spaceID, "user_member.revoked", "user_member", userMemberID, row)
		writeData(w, r, http.StatusOK, row)
		return
	}
	http.NotFound(w, r)
}

func (s *Server) handleUserMemberUpdate(w http.ResponseWriter, r *http.Request, spaceID, userMemberID string) {
	var req userMemberMutationRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	current, err := s.loadUserMemberInSpace(r.Context(), spaceID, userMemberID)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, r, http.StatusNotFound, "USER_MEMBER_NOT_FOUND", "UserMember was not found.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load UserMember.", err.Error())
		return
	}
	userID := firstNonEmpty(req.UserID, stringFromMap(current, "user_id"))
	memberID := firstNonEmpty(req.MemberID, stringFromMap(current, "member_id"))
	linkedBy := nullableFromRequest(req.LinkedByMemberID, stringFromMap(current, "linked_by_member_id"))
	if err := s.validateUserMemberRefs(r.Context(), spaceID, userID, memberID, linkedBy); err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "UserMember references are invalid.", err.Error())
		return
	}
	metadata := mapFromAny(current["metadata"])
	if req.Metadata != nil {
		metadata = req.Metadata
	}
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	update := client.UserMember.UpdateOneID(userMemberID).
		SetUserID(userID).
		SetMemberID(memberID).
		SetRelationType(firstNonEmpty(req.RelationType, stringFromMap(current, "relation_type"))).
		SetStatus(firstNonEmpty(derefString(req.Status), stringFromMap(current, "status"), "active")).
		SetIsPrimary(boolValue(req.IsPrimary, boolFromMap(current, "is_primary", false))).
		SetMetadata(nonNilMap(metadata))
	if req.ExpiresAt != nil {
		update.SetExpiresAt(*req.ExpiresAt)
	}
	if linkedBy == "" {
		update.ClearLinkedByMemberID()
	} else {
		update.SetLinkedByMemberID(linkedBy)
	}
	if req.LinkedAt != nil {
		update.SetLinkedAt(*req.LinkedAt)
	}
	err = update.Exec(r.Context())
	if err != nil {
		writeError(w, r, http.StatusConflict, "USER_MEMBER_UPDATE_FAILED", "Failed to update UserMember.", err.Error())
		return
	}
	row, err := s.loadUserMemberInSpace(r.Context(), spaceID, userMemberID)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load updated UserMember.", err.Error())
		return
	}
	s.recordMutationAudit(r.Context(), r, req.Actor, spaceID, "user_member.updated", "user_member", userMemberID, row)
	writeData(w, r, http.StatusOK, row)
}

func (s *Server) loadUserMemberInSpace(ctx context.Context, spaceID, userMemberID string) (map[string]any, error) {
	if s.ent == nil {
		return nil, errors.New("ent client is not configured")
	}
	row, err := s.ent.UserMember.Query().Where(entusermember.ID(userMemberID), entusermember.SpaceID(spaceID), entusermember.DeletedAtIsNil()).Only(ctx)
	if coreent.IsNotFound(err) {
		return nil, pgx.ErrNoRows
	}
	if err != nil {
		return nil, err
	}
	return s.userMemberMapWithRefs(ctx, row)
}

func (s *Server) validateUserMemberRefs(ctx context.Context, spaceID, userID, memberID, linkedByMemberID string) error {
	if s.ent == nil {
		return errors.New("ent client is not configured")
	}
	userExists, err := s.ent.User.Query().Where(entuser.ID(userID), entuser.DeletedAtIsNil()).Exist(ctx)
	if err != nil {
		return err
	}
	if !userExists {
		return fmt.Errorf("user %s does not exist", userID)
	}
	if err := s.validateMemberInSpace(ctx, spaceID, memberID); err != nil {
		return err
	}
	if linkedByMemberID != "" {
		if err := s.validateMemberInSpace(ctx, spaceID, linkedByMemberID); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) userMemberMapWithRefs(ctx context.Context, row *coreent.UserMember) (map[string]any, error) {
	userRecord, err := s.ent.User.Query().Where(entuser.ID(row.UserID), entuser.DeletedAtIsNil()).Only(ctx)
	if coreent.IsNotFound(err) {
		return userMemberMap(row, "", ""), nil
	}
	if err != nil {
		return nil, err
	}
	memberRecord, err := s.ent.Member.Query().Where(entmember.ID(row.MemberID), entmember.DeletedAtIsNil()).Only(ctx)
	if coreent.IsNotFound(err) {
		return userMemberMap(row, userRecord.Email, ""), nil
	}
	if err != nil {
		return nil, err
	}
	return userMemberMap(row, userRecord.Email, memberRecord.DisplayName), nil
}
