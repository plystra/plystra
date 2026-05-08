package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	entmember "github.com/plystra/plystra/ent/member"

	"github.com/jackc/pgx/v5"
	coreent "github.com/plystra/plystra/ent"
	"github.com/plystra/plystra/internal/authz"
)

type memberMutationRequest struct {
	Actor       authz.ActorContext `json:"actor"`
	ID          string             `json:"id"`
	DisplayName string             `json:"display_name"`
	MemberType  *string            `json:"member_type"`
	Status      *string            `json:"status"`
	Metadata    map[string]any     `json:"metadata"`
}

func (s *Server) handleSpaceMembers(w http.ResponseWriter, r *http.Request, spaceID string, parts []string) {
	if len(parts) == 0 {
		switch r.Method {
		case http.MethodPost:
			var req memberMutationRequest
			if !decodeJSON(w, r, &req) {
				return
			}
			if strings.TrimSpace(req.DisplayName) == "" {
				writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "display_name is required.", nil)
				return
			}
			if req.ID == "" {
				req.ID = newEntityID("member")
			}
			client, ok := s.requireEnt(w, r)
			if !ok {
				return
			}
			_, err := client.Member.Create().
				SetID(req.ID).
				SetSpaceID(spaceID).
				SetDisplayName(req.DisplayName).
				SetMemberType(firstNonEmpty(derefString(req.MemberType), "human")).
				SetStatus(firstNonEmpty(derefString(req.Status), "active")).
				SetMetadata(nonNilMap(req.Metadata)).
				Save(r.Context())
			if err != nil {
				writeError(w, r, http.StatusConflict, "MEMBER_CREATE_FAILED", "Failed to create Member.", err.Error())
				return
			}
			row, err := s.loadMemberInSpace(r.Context(), spaceID, req.ID)
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load created Member.", err.Error())
				return
			}
			s.recordMutationAudit(r.Context(), r, req.Actor, spaceID, "member.created", "member", req.ID, row)
			writeData(w, r, http.StatusCreated, row)
		case http.MethodGet:
			limit := limitFrom(r, 50)
			client, ok := s.requireEnt(w, r)
			if !ok {
				return
			}
			members, err := client.Member.Query().
				Where(entmember.SpaceID(spaceID), entmember.DeletedAtIsNil()).
				Order(entmember.ByDisplayName()).
				Limit(limit).
				All(r.Context())
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list Members.", err.Error())
				return
			}
			rows := make([]map[string]any, 0, len(members))
			for _, member := range members {
				rows = append(rows, memberMap(member))
			}
			writeList(w, r, http.StatusOK, rows, limit)
		default:
			writeMethodNotAllowed(w, r)
		}
		return
	}
	memberID := parts[0]
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			row, err := s.loadMemberInSpace(r.Context(), spaceID, memberID)
			if errors.Is(err, pgx.ErrNoRows) {
				writeError(w, r, http.StatusNotFound, "MEMBER_NOT_FOUND", "Member was not found.", nil)
				return
			}
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load Member.", err.Error())
				return
			}
			writeData(w, r, http.StatusOK, row)
		case http.MethodPatch:
			s.handleMemberUpdate(w, r, spaceID, memberID)
		default:
			writeMethodNotAllowed(w, r)
		}
		return
	}
	if len(parts) == 2 && parts[1] == "disable" {
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, r)
			return
		}
		var req memberMutationRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		row, err := s.updateScopedStatus(r.Context(), "members", memberID, spaceID, "disabled")
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to disable Member.", err.Error())
			return
		}
		s.recordMutationAudit(r.Context(), r, req.Actor, spaceID, "member.disabled", "member", memberID, row)
		writeData(w, r, http.StatusOK, row)
		return
	}
	http.NotFound(w, r)
}

func (s *Server) handleMemberUpdate(w http.ResponseWriter, r *http.Request, spaceID, memberID string) {
	var req memberMutationRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	current, err := s.loadMemberInSpace(r.Context(), spaceID, memberID)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, r, http.StatusNotFound, "MEMBER_NOT_FOUND", "Member was not found.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load Member.", err.Error())
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
	err = client.Member.UpdateOneID(memberID).
		SetDisplayName(firstNonEmpty(req.DisplayName, stringFromMap(current, "display_name"))).
		SetMemberType(firstNonEmpty(derefString(req.MemberType), stringFromMap(current, "member_type"), "human")).
		SetStatus(firstNonEmpty(derefString(req.Status), stringFromMap(current, "status"), "active")).
		SetMetadata(nonNilMap(metadata)).
		Exec(r.Context())
	if err != nil {
		writeError(w, r, http.StatusConflict, "MEMBER_UPDATE_FAILED", "Failed to update Member.", err.Error())
		return
	}
	row, err := s.loadMemberInSpace(r.Context(), spaceID, memberID)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load updated Member.", err.Error())
		return
	}
	s.recordMutationAudit(r.Context(), r, req.Actor, spaceID, "member.updated", "member", memberID, row)
	writeData(w, r, http.StatusOK, row)
}

func (s *Server) loadMemberInSpace(ctx context.Context, spaceID, memberID string) (map[string]any, error) {
	if s.ent == nil {
		return nil, errors.New("ent client is not configured")
	}
	row, err := s.ent.Member.Query().Where(entmember.ID(memberID), entmember.SpaceID(spaceID), entmember.DeletedAtIsNil()).Only(ctx)
	if coreent.IsNotFound(err) {
		return nil, pgx.ErrNoRows
	}
	if err != nil {
		return nil, err
	}
	return memberMap(row), nil
}
