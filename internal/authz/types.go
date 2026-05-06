package authz

import (
	"context"
	"errors"
	"fmt"
	"time"
)

const (
	StatusActive = "active"

	DecisionAllow = "allow"
	DecisionDeny  = "deny"
)

var ErrNotFound = errors.New("not found")
var ErrResourceTypeNotFound = errors.New("resource type not found")
var ErrResourceActionNotFound = errors.New("resource action not found")

type Scope string

const (
	ScopeSelf      Scope = "self"
	ScopeGroup     Scope = "group"
	ScopeGroupTree Scope = "group_tree"
	ScopeSpace     Scope = "space"
	ScopeGlobal    Scope = "global"
)

type CheckInput struct {
	Actor             ActorContext    `json:"actor"`
	ActorUserID       string          `json:"actor_user_id"`
	ActorMemberID     string          `json:"actor_member_id"`
	ActorUserMemberID string          `json:"actor_user_member_id"`
	SpaceID           string          `json:"space_id"`
	ResourceType      string          `json:"resource_type"`
	ResourceID        string          `json:"resource_id"`
	Target            *TargetSnapshot `json:"target,omitempty"`
	Action            string          `json:"action"`
	Explain           bool            `json:"explain"`
	RequestID         string          `json:"request_id,omitempty"`
	IP                string          `json:"ip,omitempty"`
	UserAgent         string          `json:"user_agent,omitempty"`
}

func (in CheckInput) Validate() error {
	actor := in.NormalizedActor()
	missing := map[string]string{
		"actor_user_id":        actor.UserID,
		"actor_member_id":      actor.MemberID,
		"actor_user_member_id": actor.UserMemberID,
		"space_id":             actor.SpaceID,
		"resource_type":        in.ResourceType,
		"resource_id":          in.ResourceID,
		"action":               in.Action,
	}

	for field, value := range missing {
		if value == "" {
			return fmt.Errorf("%s is required", field)
		}
	}

	return nil
}

func (in CheckInput) NormalizedActor() ActorContext {
	actor := in.Actor
	if actor.UserID == "" {
		actor.UserID = in.ActorUserID
	}
	if actor.MemberID == "" {
		actor.MemberID = in.ActorMemberID
	}
	if actor.UserMemberID == "" {
		actor.UserMemberID = in.ActorUserMemberID
	}
	if actor.SpaceID == "" {
		actor.SpaceID = in.SpaceID
	}
	return actor
}

type ActorContext struct {
	UserID       string `json:"user_id"`
	MemberID     string `json:"member_id"`
	UserMemberID string `json:"user_member_id"`
	SpaceID      string `json:"space_id"`
}

type CandidateQuery struct {
	MemberID     string
	ResourceType string
	Action       string
}

type Store interface {
	LoadActor(ctx context.Context, actor ActorContext) (ActorSnapshot, error)
	LoadResourceRegistration(ctx context.Context, resourceType, action string) (ResourceRegistrySnapshot, error)
	LoadTarget(ctx context.Context, resourceType, resourceID string) (TargetSnapshot, error)
	LoadPermissionCandidates(ctx context.Context, query CandidateQuery) ([]PermissionCandidate, error)
	WriteAuditLog(ctx context.Context, decision Decision) error
}

type ActorSnapshot struct {
	User       UserSnapshot       `json:"user"`
	Member     MemberSnapshot     `json:"member"`
	UserMember UserMemberSnapshot `json:"user_member"`
	Space      SpaceSnapshot      `json:"-"`
}

type UserSnapshot struct {
	ID     string `json:"id"`
	Email  string `json:"email"`
	Status string `json:"status"`
}

type MemberSnapshot struct {
	ID          string `json:"id"`
	SpaceID     string `json:"space_id"`
	DisplayName string `json:"display_name"`
	Status      string `json:"status"`
}

type UserMemberSnapshot struct {
	ID           string     `json:"id"`
	UserID       string     `json:"user_id"`
	MemberID     string     `json:"member_id"`
	SpaceID      string     `json:"space_id"`
	RelationType string     `json:"relation_type"`
	Status       string     `json:"status"`
	IsPrimary    bool       `json:"is_primary"`
	ExpiresAt    *time.Time `json:"expires_at"`
}

type SpaceSnapshot struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

type TargetSnapshot struct {
	Resource ResourceSnapshot `json:"resource"`
	Group    *GroupSnapshot   `json:"group"`
}

type ResourceSnapshot struct {
	ID            string         `json:"id"`
	Type          string         `json:"type"`
	SpaceID       string         `json:"space_id"`
	GroupID       string         `json:"group_id"`
	OwnerMemberID string         `json:"owner_member_id"`
	DisplayName   string         `json:"display_name,omitempty"`
	Visibility    string         `json:"visibility,omitempty"`
	Status        string         `json:"status,omitempty"`
	Metadata      map[string]any `json:"metadata,omitempty"`
}

type GroupSnapshot struct {
	ID      string `json:"id"`
	SpaceID string `json:"space_id"`
	Path    string `json:"path"`
	Status  string `json:"status"`
}

type RoleSnapshot struct {
	ID      string `json:"id"`
	Key     string `json:"key"`
	SpaceID string `json:"-"`
}

type PermissionSnapshot struct {
	ID       string `json:"id"`
	Resource string `json:"resource"`
	Action   string `json:"action"`
	Scope    Scope  `json:"scope"`
}

type PermissionCandidate struct {
	Role              RoleSnapshot       `json:"role"`
	Permission        PermissionSnapshot `json:"permission"`
	ScopeAnchor       *GroupSnapshot     `json:"scope_anchor"`
	ScopeCheck        ScopeCheck         `json:"scope_check"`
	MemberRoleSpaceID string             `json:"-"`
}

type ScopeCheck struct {
	Covered  bool      `json:"covered"`
	Rule     string    `json:"rule"`
	Reason   string    `json:"reason"`
	DenyCode *DenyCode `json:"deny_code,omitempty"`
}

type AuditContext struct {
	ActorUserID       string    `json:"actor_user_id"`
	ActorMemberID     string    `json:"actor_member_id"`
	ActorUserMemberID string    `json:"actor_user_member_id"`
	SpaceID           string    `json:"space_id"`
	Action            string    `json:"action"`
	ResourceType      string    `json:"resource_type"`
	ResourceID        string    `json:"resource_id"`
	Decision          string    `json:"decision"`
	DenyCode          *DenyCode `json:"deny_code"`
	RequestID         string    `json:"request_id,omitempty"`
}

type ResourceRegistrySnapshot struct {
	ResourceType ResourceTypeSnapshot    `json:"resource_type"`
	Action       ResourceActionSnapshot  `json:"action"`
	Mapping      ResourceMappingSnapshot `json:"mapping"`
}

type ResourceTypeSnapshot struct {
	ID          string         `json:"id"`
	Key         string         `json:"key"`
	DisplayName string         `json:"display_name"`
	Description string         `json:"description,omitempty"`
	Status      string         `json:"status"`
	Source      string         `json:"source"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

type ResourceActionSnapshot struct {
	ID             string         `json:"id"`
	ResourceTypeID string         `json:"resource_type_id"`
	Key            string         `json:"key"`
	DisplayName    string         `json:"display_name"`
	Description    string         `json:"description,omitempty"`
	RiskLevel      string         `json:"risk_level"`
	AuditDefault   bool           `json:"audit_default"`
	Metadata       map[string]any `json:"metadata,omitempty"`
}

type ResourceMappingSnapshot struct {
	ID               string         `json:"id"`
	ResourceTypeID   string         `json:"resource_type_id"`
	StorageKind      string         `json:"storage_kind"`
	TableName        string         `json:"table_name,omitempty"`
	IDField          string         `json:"id_field"`
	SpaceField       string         `json:"space_field"`
	GroupField       string         `json:"group_field,omitempty"`
	OwnerMemberField string         `json:"owner_member_field,omitempty"`
	VisibilityField  string         `json:"visibility_field,omitempty"`
	MetadataField    string         `json:"metadata_field,omitempty"`
	Status           string         `json:"status"`
	Metadata         map[string]any `json:"metadata,omitempty"`
}

type RequestMetadata struct {
	RequestID string `json:"request_id,omitempty"`
	IP        string `json:"ip,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
}

type Decision struct {
	Decision          string                   `json:"decision"`
	DenyCode          *DenyCode                `json:"deny_code"`
	Actor             ActorSnapshot            `json:"actor"`
	Space             SpaceSnapshot            `json:"space"`
	Target            TargetSnapshot           `json:"target"`
	ResourceRegistry  ResourceRegistrySnapshot `json:"resource_registry"`
	MatchedCandidates []PermissionCandidate    `json:"matched_candidates"`
	Request           RequestMetadata          `json:"request,omitempty"`
	Reason            string                   `json:"reason"`
	Audit             AuditContext             `json:"audit"`
}

func (d Decision) IsAllowed() bool {
	return d.Decision == DecisionAllow
}
