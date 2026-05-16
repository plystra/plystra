package identity

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	StatusActive = "active"

	RelationLogin     = "login"
	RelationDelegate  = "delegate"
	RelationExternal  = "external"
	RelationService   = "service"
	RelationTemporary = "temporary"

	MemberTypeHuman   = "human"
	MemberTypeService = "service"
)

var (
	ErrInvalidIdentity = errors.New("invalid identity")
	ErrInactiveActor   = errors.New("inactive actor")
	ErrExpiredBinding  = errors.New("expired user-member binding")
)

type User struct {
	ID       string
	Email    string
	Username string
	Status   string
}

type Space struct {
	ID     string
	Name   string
	Slug   string
	Type   string
	Status string
}

type Member struct {
	ID          string
	SpaceID     string
	DisplayName string
	MemberType  string
	Status      string
}

type UserMember struct {
	ID           string
	UserID       string
	MemberID     string
	SpaceID      string
	RelationType string
	Status       string
	IsPrimary    bool
	ExpiresAt    *time.Time
}

type ActingIdentity struct {
	User       User
	Member     Member
	UserMember UserMember
	Space      Space
}

func ValidateActingIdentity(identity ActingIdentity, now time.Time) error {
	if identity.User.ID == "" || identity.Member.ID == "" || identity.UserMember.ID == "" || identity.Space.ID == "" {
		return fmt.Errorf("%w: User, Member, UserMember, and Space IDs are required", ErrInvalidIdentity)
	}
	if identity.UserMember.UserID != identity.User.ID {
		return fmt.Errorf("%w: UserMember.user_id must match User.id", ErrInvalidIdentity)
	}
	if identity.UserMember.MemberID != identity.Member.ID {
		return fmt.Errorf("%w: UserMember.member_id must match Member.id", ErrInvalidIdentity)
	}
	if identity.Member.SpaceID != identity.Space.ID || identity.UserMember.SpaceID != identity.Space.ID {
		return fmt.Errorf("%w: Member, UserMember, and Space must share the same space_id", ErrInvalidIdentity)
	}
	if identity.User.Status != StatusActive || identity.Member.Status != StatusActive || identity.UserMember.Status != StatusActive || identity.Space.Status != StatusActive {
		return ErrInactiveActor
	}
	if identity.UserMember.ExpiresAt != nil && identity.UserMember.ExpiresAt.Before(now.UTC()) {
		return ErrExpiredBinding
	}
	return nil
}

func DefaultSpaceID(appID string) string {
	appID = strings.TrimSpace(appID)
	if appID == "" {
		appID = "app"
	}
	return "space_default_" + safeToken(appID)
}

func safeToken(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := strings.Trim(b.String(), "_")
	if out == "" {
		return "app"
	}
	return out
}
