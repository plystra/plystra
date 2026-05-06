package resources

import "github.com/plystra/plystra/internal/authz"

const (
	DefaultSource      = "core"
	DefaultStatus      = authz.StatusActive
	DefaultStorageKind = "internal_table"
	DefaultRiskLevel   = "normal"
)

type RegisterResourceTypeInput struct {
	Key         string
	DisplayName string
	Description string
	Source      string
	Metadata    map[string]any
}

type RegisterResourceActionInput struct {
	ResourceTypeKey string
	Key             string
	DisplayName     string
	Description     string
	RiskLevel       string
	AuditDefault    bool
	Metadata        map[string]any
}

type RegisterResourceMappingInput struct {
	ResourceTypeKey  string
	StorageKind      string
	TableName        string
	IDField          string
	SpaceField       string
	GroupField       string
	OwnerMemberField string
	VisibilityField  string
	MetadataField    string
	Metadata         map[string]any
}

type ResourceType = authz.ResourceTypeSnapshot
type ResourceAction = authz.ResourceActionSnapshot
type ResourceMapping = authz.ResourceMappingSnapshot
