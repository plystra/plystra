package admin

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

const (
	LevelInstanceSuper = "instance_super_admin"
	LevelInstance      = "instance_admin"
	LevelSpace         = "space_admin"
	LevelGroup         = "group_admin"
	StatusActive       = "active"
)

var permissionTokenPattern = regexp.MustCompile(`^(?:[a-z0-9_-]+|\*)$`)

type Requirement struct {
	PermissionKey string
	SpaceID       string
	GroupID       string
	EntityKind    string
	EntityID      string
}

type Grant struct {
	UserID        string
	MemberID      string
	SpaceID       string
	GroupID       string
	Level         string
	PermissionKey string
	Status        string
	ExpiresAt     *time.Time
	RevokedAt     *time.Time
}

type GroupCoverageResolver interface {
	GroupCovers(grantGroupID, targetGroupID string) (bool, error)
}

func GrantAllows(grant Grant, requirement Requirement, resolver GroupCoverageResolver, now time.Time) (bool, error) {
	grant = grant.Normalized()
	requirement = requirement.Normalized()
	if !grant.Active(now) {
		return false, nil
	}
	if grant.Level == LevelInstanceSuper {
		return true, nil
	}
	if !PermissionMatches(grant.PermissionKey, requirement.PermissionKey) {
		return false, nil
	}
	switch grant.Level {
	case LevelInstance:
		return true, nil
	case LevelSpace:
		return grant.SpaceID != "" && requirement.SpaceID != "" && grant.SpaceID == requirement.SpaceID, nil
	case LevelGroup:
		if grant.GroupID == "" || requirement.GroupID == "" {
			return false, nil
		}
		if resolver == nil {
			return grant.GroupID == requirement.GroupID, nil
		}
		return resolver.GroupCovers(grant.GroupID, requirement.GroupID)
	default:
		return false, fmt.Errorf("unknown admin level %q", grant.Level)
	}
}

func (grant Grant) Normalized() Grant {
	grant.PermissionKey = strings.ToLower(strings.TrimSpace(grant.PermissionKey))
	grant.Level = strings.TrimSpace(grant.Level)
	grant.Status = strings.TrimSpace(grant.Status)
	grant.SpaceID = strings.TrimSpace(grant.SpaceID)
	grant.GroupID = strings.TrimSpace(grant.GroupID)
	return grant
}

func (grant Grant) Active(now time.Time) bool {
	grant = grant.Normalized()
	if grant.Status != StatusActive || grant.RevokedAt != nil {
		return false
	}
	return grant.ExpiresAt == nil || grant.ExpiresAt.After(now.UTC())
}

func (requirement Requirement) Normalized() Requirement {
	requirement.PermissionKey = strings.ToLower(strings.TrimSpace(requirement.PermissionKey))
	requirement.SpaceID = strings.TrimSpace(requirement.SpaceID)
	requirement.GroupID = strings.TrimSpace(requirement.GroupID)
	return requirement
}

func PermissionMatches(grantKey, requiredKey string) bool {
	grantKey = strings.ToLower(strings.TrimSpace(grantKey))
	requiredKey = strings.ToLower(strings.TrimSpace(requiredKey))
	if grantKey == "*" || grantKey == requiredKey {
		return true
	}
	requiredDomain, requiredAction, ok := strings.Cut(requiredKey, ":")
	if !ok {
		return false
	}
	if grantKey == requiredDomain+":*" || grantKey == requiredDomain+":manage" {
		return true
	}
	return requiredAction == "read" && grantKey == requiredDomain+":manage"
}

func ValidPermissionKey(key string) bool {
	key = strings.TrimSpace(key)
	if key != strings.ToLower(key) {
		return false
	}
	if key == "*" {
		return true
	}
	domain, action, ok := strings.Cut(key, ":")
	return ok && domain != "*" && tokenValid(domain) && tokenValid(action)
}

func tokenValid(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || strings.Contains(value, "*") {
		return value == "*"
	}
	return permissionTokenPattern.MatchString(value)
}
