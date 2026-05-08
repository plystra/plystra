package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	entuser "github.com/plystra/plystra/ent/user"

	"github.com/jackc/pgx/v5"
	coreent "github.com/plystra/plystra/ent"
	"github.com/plystra/plystra/internal/authz"
)

type userMutationRequest struct {
	Actor        authz.ActorContext `json:"actor"`
	AuditSpaceID string             `json:"audit_space_id"`
	ID           string             `json:"id"`
	Email        string             `json:"email"`
	Username     *string            `json:"username"`
	Phone        *string            `json:"phone"`
	PasswordHash *string            `json:"password_hash"`
	Status       *string            `json:"status"`
	Metadata     map[string]any     `json:"metadata"`
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		client, ok := s.requireEnt(w, r)
		if !ok {
			return
		}
		var req userMutationRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		if strings.TrimSpace(req.Email) == "" {
			writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "email is required.", nil)
			return
		}
		if req.ID == "" {
			req.ID = newEntityID("user")
		}
		status := firstNonEmpty(derefString(req.Status), "active")
		_, err := client.User.Create().
			SetID(req.ID).
			SetEmail(req.Email).
			SetNillableUsername(optionalString(derefString(req.Username))).
			SetNillablePhone(optionalString(derefString(req.Phone))).
			SetNillablePasswordHash(optionalString(derefString(req.PasswordHash))).
			SetStatus(status).
			SetMetadata(nonNilMap(req.Metadata)).
			Save(r.Context())
		if err != nil {
			writeError(w, r, http.StatusConflict, "USER_CREATE_FAILED", "Failed to create User.", err.Error())
			return
		}
		row, err := s.loadUser(r.Context(), req.ID)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load created User.", err.Error())
			return
		}
		response := userResponse(row)
		s.recordMutationAudit(r.Context(), r, req.Actor, req.AuditSpaceID, "user.created", "user", req.ID, response)
		writeData(w, r, http.StatusCreated, response)
	case http.MethodGet:
		limit := limitFrom(r, 50)
		client, ok := s.requireEnt(w, r)
		if !ok {
			return
		}
		users, err := client.User.Query().
			Where(entuser.DeletedAtIsNil()).
			Order(entuser.ByEmail()).
			Limit(limit).
			All(r.Context())
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list Users.", err.Error())
			return
		}
		rows := make([]map[string]any, 0, len(users))
		for _, user := range users {
			rows = append(rows, userResponse(userMap(user)))
		}
		writeList(w, r, http.StatusOK, rows, limit)
	default:
		writeMethodNotAllowed(w, r)
	}
}

func (s *Server) handleUserSubroutes(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/users/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	userID := parts[0]
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			row, err := s.loadUser(r.Context(), userID)
			if errors.Is(err, pgx.ErrNoRows) {
				writeError(w, r, http.StatusNotFound, "USER_NOT_FOUND", "User was not found.", nil)
				return
			}
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load User.", err.Error())
				return
			}
			writeData(w, r, http.StatusOK, userResponse(row))
		case http.MethodPatch:
			var req userMutationRequest
			if !decodeJSON(w, r, &req) {
				return
			}
			current, err := s.loadUser(r.Context(), userID)
			if errors.Is(err, pgx.ErrNoRows) {
				writeError(w, r, http.StatusNotFound, "USER_NOT_FOUND", "User was not found.", nil)
				return
			}
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load User.", err.Error())
				return
			}
			email := firstNonEmpty(req.Email, stringFromMap(current, "email"))
			status := firstNonEmpty(derefString(req.Status), stringFromMap(current, "status"), "active")
			metadata := mapFromAny(current["metadata"])
			if req.Metadata != nil {
				metadata = req.Metadata
			}
			username := nullableFromRequest(req.Username, stringFromMap(current, "username"))
			phone := nullableFromRequest(req.Phone, stringFromMap(current, "phone"))
			passwordHash := nullableFromRequest(req.PasswordHash, stringFromMap(current, "password_hash"))
			client, ok := s.requireEnt(w, r)
			if !ok {
				return
			}
			update := client.User.UpdateOneID(userID).
				SetEmail(email).
				SetStatus(status).
				SetMetadata(nonNilMap(metadata))
			if username == "" {
				update.ClearUsername()
			} else {
				update.SetUsername(username)
			}
			if phone == "" {
				update.ClearPhone()
			} else {
				update.SetPhone(phone)
			}
			if passwordHash == "" {
				update.ClearPasswordHash()
			} else {
				update.SetPasswordHash(passwordHash)
			}
			err = update.Exec(r.Context())
			if err != nil {
				writeError(w, r, http.StatusConflict, "USER_UPDATE_FAILED", "Failed to update User.", err.Error())
				return
			}
			row, err := s.loadUser(r.Context(), userID)
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load updated User.", err.Error())
				return
			}
			response := userResponse(row)
			s.recordMutationAudit(r.Context(), r, req.Actor, req.AuditSpaceID, "user.updated", "user", userID, response)
			writeData(w, r, http.StatusOK, response)
		default:
			writeMethodNotAllowed(w, r)
		}
		return
	}
	if len(parts) == 2 && (parts[1] == "disable" || parts[1] == "restore") {
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, r)
			return
		}
		var req userMutationRequest
		if r.Body != nil {
			_ = json.NewDecoder(r.Body).Decode(&req)
		}
		status := "disabled"
		action := "user.disabled"
		if parts[1] == "restore" {
			status = "active"
			action = "user.restored"
		}
		row, err := s.updateStatus(r.Context(), "users", userID, status)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to update User status.", err.Error())
			return
		}
		response := userResponse(row)
		s.recordMutationAudit(r.Context(), r, req.Actor, req.AuditSpaceID, action, "user", userID, response)
		writeData(w, r, http.StatusOK, response)
		return
	}
	http.NotFound(w, r)
}

func (s *Server) loadUser(ctx context.Context, id string) (map[string]any, error) {
	if s.ent == nil {
		return nil, errors.New("ent client is not configured")
	}
	row, err := s.ent.User.Query().Where(entuser.ID(id), entuser.DeletedAtIsNil()).Only(ctx)
	if coreent.IsNotFound(err) {
		return nil, pgx.ErrNoRows
	}
	if err != nil {
		return nil, err
	}
	return userPersistenceMap(row), nil
}

func userResponse(row map[string]any) map[string]any {
	if row == nil {
		return nil
	}
	response := make(map[string]any, len(row))
	for key, value := range row {
		if key == "password_hash" {
			continue
		}
		response[key] = value
	}
	return response
}
