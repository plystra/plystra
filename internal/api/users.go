package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	entsession "github.com/plystra/core/ent/session"
	entuser "github.com/plystra/core/ent/user"

	"github.com/jackc/pgx/v5"
	coreent "github.com/plystra/core/ent"
	"github.com/plystra/core/internal/authz"
)

type userMutationRequest struct {
	Actor        authz.ActorContext `json:"actor"`
	AuditSpaceID string             `json:"audit_space_id"`
	ID           string             `json:"id"`
	Email        string             `json:"email"`
	Username     *string            `json:"username"`
	Phone        *string            `json:"phone"`
	Password     *string            `json:"password"`
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
		req.Email = normalizeEmail(req.Email)
		if req.Email == "" {
			writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "email is required.", nil)
			return
		}
		if req.ID == "" {
			req.ID = newEntityID("user")
		}
		status := firstNonEmpty(derefString(req.Status), "active")
		passwordHash, ok := s.passwordHashFromRequest(w, r, req, "")
		if !ok {
			return
		}
		create := client.User.Create().
			SetID(req.ID).
			SetEmail(req.Email).
			SetNillableUsername(optionalString(derefString(req.Username))).
			SetNillablePhone(optionalString(derefString(req.Phone))).
			SetNillablePasswordHash(optionalString(passwordHash)).
			SetStatus(status).
			SetMetadata(nonNilMap(req.Metadata))
		if passwordHash != "" {
			now := time.Now().UTC()
			create.SetPasswordChangedAt(now)
		}
		_, err := create.Save(r.Context())
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
			email := firstNonEmpty(normalizeEmail(req.Email), stringFromMap(current, "email"))
			status := firstNonEmpty(derefString(req.Status), stringFromMap(current, "status"), "active")
			metadata := mapFromAny(current["metadata"])
			if req.Metadata != nil {
				metadata = req.Metadata
			}
			username := nullableFromRequest(req.Username, stringFromMap(current, "username"))
			phone := nullableFromRequest(req.Phone, stringFromMap(current, "phone"))
			passwordHash, ok := s.passwordHashFromRequest(w, r, req, stringFromMap(current, "password_hash"))
			if !ok {
				return
			}
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
			passwordChanged := req.Password != nil && passwordHash != stringFromMap(current, "password_hash")
			if passwordChanged {
				update.SetPasswordChangedAt(time.Now().UTC())
			}
			err = update.Exec(r.Context())
			if err != nil {
				writeError(w, r, http.StatusConflict, "USER_UPDATE_FAILED", "Failed to update User.", err.Error())
				return
			}
			if passwordChanged {
				if err := s.revokeUserSessions(r.Context(), userID); err != nil {
					writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to revoke existing sessions after password change.", err.Error())
					return
				}
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
		if !decodeOptionalJSON(w, r, &req) {
			return
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

func (s *Server) passwordHashFromRequest(w http.ResponseWriter, r *http.Request, req userMutationRequest, currentHash string) (string, bool) {
	if req.Password != nil {
		password := derefString(req.Password)
		if message, ok := validatePlaintextPassword(password); !ok {
			writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", message, nil)
			return "", false
		}
		hash, err := hashPassword(password)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to hash password.", err.Error())
			return "", false
		}
		return hash, true
	}
	return currentHash, true
}

func (s *Server) revokeUserSessions(ctx context.Context, userID string) error {
	if s.ent == nil {
		return errors.New("ent client is not configured")
	}
	_, err := s.ent.Session.Update().
		Where(entsession.UserID(userID), entsession.RevokedAtIsNil()).
		SetRevokedAt(time.Now().UTC()).
		Save(ctx)
	return err
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
