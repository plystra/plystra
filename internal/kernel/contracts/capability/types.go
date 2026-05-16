package capability

import "time"

const (
	KindSystemCapability = "system_capability"

	RuntimeBuiltin    = "builtin"
	RuntimeProcess    = "process"
	ProtocolInProcess = "in_process"
	ProtocolHTTP      = "http"
	ProtocolGRPC      = "grpc"

	SourceLocal = "local"

	StabilityExperimental = "experimental"

	StateDiscovered = "discovered"
	StateValidated  = "validated"
	StateMigrated   = "migrated"
	StateRegistered = "registered"
	StateStarting   = "starting"
	StateReady      = "ready"
	StateDegraded   = "degraded"
	StateFailed     = "failed"
	StateStopped    = "stopped"
)

const (
	AuditExplainable      = "audit.explainable"
	IdentityBusiness      = "identity.business"
	ResourceRegistry      = "resource.registry"
	AuthorizationResource = "authorization.resource"
	AdminControlPlane     = "admin.control_plane"
)

const (
	ServiceAudit                  = "audit.service"
	ServiceIdentity               = "identity.service"
	ServiceResourceRegistry       = "resource.registry"
	ServiceAuthorization          = "authorization.service"
	ServiceAuthorizationChecker   = "authorization.checker"
	ServiceAuthorizationExplainer = "authorization.explainer"
	ServiceAdmin                  = "admin.service"
)

var RequiredSystemCapabilityOrder = []string{
	AuditExplainable,
	IdentityBusiness,
	ResourceRegistry,
	AuthorizationResource,
	AdminControlPlane,
}

type Manifest struct {
	ID         string   `json:"id" yaml:"id"`
	Kind       string   `json:"kind" yaml:"kind"`
	Name       string   `json:"name" yaml:"name"`
	Version    string   `json:"version" yaml:"version"`
	Runtime    Runtime  `json:"runtime" yaml:"runtime"`
	Requires   Requires `json:"requires" yaml:"requires"`
	Provides   Provides `json:"provides" yaml:"provides"`
	Privileged bool     `json:"privileged" yaml:"privileged"`
	Required   bool     `json:"required" yaml:"required"`
	Stability  string   `json:"stability" yaml:"stability"`
}

type Runtime struct {
	Type     string `json:"type" yaml:"type"`
	Protocol string `json:"protocol" yaml:"protocol"`
	Socket   string `json:"socket" yaml:"socket"`
	Address  string `json:"address" yaml:"address"`
}

type Requires struct {
	Kernel       string   `json:"kernel" yaml:"kernel"`
	Capabilities []string `json:"capabilities" yaml:"capabilities"`
}

type Provides struct {
	Services   []ServiceRef `json:"services" yaml:"services"`
	Routes     []RouteRef   `json:"routes" yaml:"routes"`
	Migrations MigrationRef `json:"migrations" yaml:"migrations"`
	Events     EventsRef    `json:"events" yaml:"events"`
}

type ServiceRef struct {
	Name string `json:"name" yaml:"name"`
}

type RouteRef struct {
	Method    string `json:"method" yaml:"method"`
	Path      string `json:"path" yaml:"path"`
	Service   string `json:"service" yaml:"service"`
	Operation string `json:"operation" yaml:"operation"`
}

type MigrationRef struct {
	Namespace string `json:"namespace" yaml:"namespace"`
	Path      string `json:"path" yaml:"path"`
}

type EventsRef struct {
	Publishes  []string `json:"publishes" yaml:"publishes"`
	Subscribes []string `json:"subscribes" yaml:"subscribes"`
}

type Config struct {
	SystemCapabilities []ConfiguredCapability `json:"system_capabilities" yaml:"system_capabilities"`
}

type ConfiguredCapability struct {
	ID       string `json:"id" yaml:"id"`
	Source   string `json:"source" yaml:"source"`
	Binary   string `json:"binary" yaml:"binary"`
	Manifest string `json:"manifest" yaml:"manifest"`
	Required bool   `json:"required" yaml:"required"`
}

type Lockfile struct {
	SystemCapabilities []LockedCapability `json:"system_capabilities" yaml:"system_capabilities"`
}

type LockedCapability struct {
	ID       string `json:"id" yaml:"id"`
	Version  string `json:"version" yaml:"version"`
	Source   string `json:"source" yaml:"source"`
	Path     string `json:"path" yaml:"path"`
	Checksum string `json:"checksum" yaml:"checksum"`
}

type ServiceRegistration struct {
	Name         string    `json:"name"`
	CapabilityID string    `json:"capability_id"`
	Protocol     string    `json:"protocol"`
	Address      string    `json:"address"`
	Version      string    `json:"version"`
	Health       string    `json:"health"`
	RegisteredAt time.Time `json:"registered_at"`
}

type RouteRegistration struct {
	Method       string `json:"method"`
	Path         string `json:"path"`
	Service      string `json:"service"`
	Operation    string `json:"operation"`
	CapabilityID string `json:"capability_id"`
}

type Description struct {
	Manifest Manifest              `json:"manifest"`
	Services []ServiceRegistration `json:"services,omitempty"`
	Routes   []RouteRegistration   `json:"routes,omitempty"`
}

type PrepareRequest struct {
	KernelVersion string                         `json:"kernel_version"`
	Config        map[string]any                 `json:"config,omitempty"`
	Services      map[string]ServiceRegistration `json:"services,omitempty"`
}

type PrepareResponse struct {
	Accepted bool   `json:"accepted"`
	Message  string `json:"message,omitempty"`
}

type StartRequest struct{}

type StartResponse struct {
	Ready bool   `json:"ready"`
	State string `json:"state"`
}

type HealthResponse struct {
	Status       string `json:"status"`
	CapabilityID string `json:"capability_id"`
	Version      string `json:"version"`
}

type StopRequest struct{}

type StopResponse struct {
	Stopped bool `json:"stopped"`
}
