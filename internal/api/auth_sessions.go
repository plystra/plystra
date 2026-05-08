package api

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	coreent "github.com/plystra/plystra/ent"
	entmember "github.com/plystra/plystra/ent/member"
	entsession "github.com/plystra/plystra/ent/session"
	entspace "github.com/plystra/plystra/ent/space"
	entusermember "github.com/plystra/plystra/ent/usermember"

	"github.com/jackc/pgx/v5"
	entuser "github.com/plystra/plystra/ent/user"
)

func (s *Server) sessionFromRequest(ctx context.Context, r *http.Request) (sessionRecord, error) {
	token := bearerToken(r)
	if token == "" {
		return sessionRecord{}, pgx.ErrNoRows
	}
	if s.ent == nil {
		return sessionRecord{}, errors.New("ent client is not configured")
	}
	record, err := s.ent.Session.Query().
		Where(
			entsession.AccessTokenHash(tokenHash(token)),
			entsession.RevokedAtIsNil(),
			entsession.ExpiresAtGT(time.Now().UTC()),
		).
		Only(ctx)
	if coreent.IsNotFound(err) {
		return sessionRecord{}, pgx.ErrNoRows
	}
	if err != nil {
		return sessionRecord{}, err
	}
	return sessionRecordFromEnt(record), nil
}

func (s *Server) sessionByRefreshToken(ctx context.Context, token string) (sessionRecord, error) {
	if s.ent == nil {
		return sessionRecord{}, errors.New("ent client is not configured")
	}
	record, err := s.ent.Session.Query().
		Where(
			entsession.RefreshTokenHash(tokenHash(token)),
			entsession.RevokedAtIsNil(),
			entsession.RefreshExpiresAtGT(time.Now().UTC()),
		).
		Only(ctx)
	if coreent.IsNotFound(err) {
		return sessionRecord{}, pgx.ErrNoRows
	}
	if err != nil {
		return sessionRecord{}, err
	}
	return sessionRecordFromEnt(record), nil
}

func (s *Server) defaultActorForUser(ctx context.Context, userID string) (map[string]any, []map[string]any, error) {
	available, err := s.availableActorBindings(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	if len(available) == 0 {
		return nil, nil, pgx.ErrNoRows
	}
	return actorMapFromBinding(available[0]), available, nil
}

func (s *Server) actorForSession(ctx context.Context, session sessionRecord) (map[string]any, []map[string]any, error) {
	available, err := s.availableActorBindings(ctx, session.UserID)
	if err != nil {
		return nil, nil, err
	}
	for _, binding := range available {
		if binding["user_member_id"] == session.ActiveUserMemberID {
			return actorMapFromBinding(binding), available, nil
		}
	}
	if len(available) == 0 {
		return nil, nil, pgx.ErrNoRows
	}
	return actorMapFromBinding(available[0]), available, nil
}

func (s *Server) actorBindingForUser(ctx context.Context, userID, memberID, userMemberID string) (map[string]any, error) {
	bindings, err := s.availableActorBindingsFiltered(ctx, userID, memberID, userMemberID)
	if err != nil {
		return nil, err
	}
	if len(bindings) == 0 {
		return nil, pgx.ErrNoRows
	}
	return bindings[0], nil
}

func (s *Server) availableActorBindings(ctx context.Context, userID string) ([]map[string]any, error) {
	return s.availableActorBindingsFiltered(ctx, userID, "", "")
}

func (s *Server) availableActorBindingsFiltered(ctx context.Context, userID, memberID, userMemberID string) ([]map[string]any, error) {
	if s.ent == nil {
		return nil, errors.New("ent client is not configured")
	}
	now := time.Now().UTC()
	q := s.ent.UserMember.Query().
		Where(
			entusermember.UserID(userID),
			entusermember.Status("active"),
			entusermember.DeletedAtIsNil(),
			entusermember.RevokedAtIsNil(),
			entusermember.Or(entusermember.ExpiresAtIsNil(), entusermember.ExpiresAtGT(now)),
		)
	if memberID != "" {
		q = q.Where(entusermember.MemberID(memberID))
	}
	if userMemberID != "" {
		q = q.Where(entusermember.ID(userMemberID))
	}
	userRecord, err := s.ent.User.Query().
		Where(entuser.ID(userID), entuser.DeletedAtIsNil()).
		Only(ctx)
	if coreent.IsNotFound(err) {
		return []map[string]any{}, nil
	}
	if err != nil {
		return nil, err
	}
	userMembers, err := q.All(ctx)
	if err != nil {
		return nil, err
	}
	bindings := make([]map[string]any, 0, len(userMembers))
	for _, userMember := range userMembers {
		memberRecord, err := s.ent.Member.Query().
			Where(
				entmember.ID(userMember.MemberID),
				entmember.Status("active"),
				entmember.DeletedAtIsNil(),
			).
			Only(ctx)
		if coreent.IsNotFound(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		spaceRecord, err := s.ent.Space.Query().
			Where(
				entspace.ID(userMember.SpaceID),
				entspace.Status("active"),
				entspace.DeletedAtIsNil(),
			).
			Only(ctx)
		if coreent.IsNotFound(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		bindings = append(bindings, map[string]any{
			"user_member_id":      userMember.ID,
			"user_id":             userMember.UserID,
			"user_email":          userRecord.Email,
			"member_id":           userMember.MemberID,
			"member_display_name": memberRecord.DisplayName,
			"space_id":            userMember.SpaceID,
			"space_name":          spaceRecord.Name,
			"relation_type":       userMember.RelationType,
			"is_primary":          userMember.IsPrimary,
		})
	}
	sort.SliceStable(bindings, func(i, j int) bool {
		leftPrimary, _ := bindings[i]["is_primary"].(bool)
		rightPrimary, _ := bindings[j]["is_primary"].(bool)
		if leftPrimary != rightPrimary {
			return leftPrimary
		}
		leftSpace, _ := bindings[i]["space_name"].(string)
		rightSpace, _ := bindings[j]["space_name"].(string)
		if leftSpace != rightSpace {
			return leftSpace < rightSpace
		}
		leftMember, _ := bindings[i]["member_display_name"].(string)
		rightMember, _ := bindings[j]["member_display_name"].(string)
		return leftMember < rightMember
	})
	return bindings, nil
}

func (s *Server) requireEnt(w http.ResponseWriter, r *http.Request) (*coreent.Client, bool) {
	if s.ent == nil {
		writeError(w, r, http.StatusServiceUnavailable, "NOT_READY", "Ent client is not configured.", nil)
		return nil, false
	}
	return s.ent, true
}

func sessionRecordFromEnt(record *coreent.Session) sessionRecord {
	return sessionRecord{
		ID:                 record.ID,
		UserID:             record.UserID,
		ActiveSpaceID:      derefString(record.ActiveSpaceID),
		ActiveMemberID:     derefString(record.ActiveMemberID),
		ActiveUserMemberID: derefString(record.ActiveUserMemberID),
		ExpiresAt:          record.ExpiresAt,
		RefreshExpiresAt:   record.RefreshExpiresAt,
	}
}

func optionalString(value string) *string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return &value
}

func actorMapFromBinding(binding map[string]any) map[string]any {
	return map[string]any{
		"user_id":        binding["user_id"],
		"member_id":      binding["member_id"],
		"user_member_id": binding["user_member_id"],
		"space_id":       binding["space_id"],
	}
}

func stringMapValue(values map[string]any, key string) string {
	value, _ := values[key].(string)
	return value
}

func bearerToken(r *http.Request) string {
	value := r.Header.Get("Authorization")
	if value == "" {
		return ""
	}
	parts := strings.SplitN(value, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func newToken(prefix string) string {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return prefix + hex.EncodeToString([]byte(strconv.FormatInt(time.Now().UTC().UnixNano(), 10)))
	}
	if prefix == "" {
		return hex.EncodeToString(buf[:])
	}
	return prefix + "_" + hex.EncodeToString(buf[:])
}

func tokenHash(token string) string {
	if secret := sessionTokenSecret(); secret != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		_, _ = mac.Write([]byte(token))
		return hex.EncodeToString(mac.Sum(nil))
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func sessionTokenSecret() string {
	return firstEnv("PLYSTRA_SESSION_SECRET", "SESSION_SECRET", "JWT_SECRET", "PLYSTRA_JWT_SECRET")
}
