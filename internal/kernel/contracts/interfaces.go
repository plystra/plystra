package contracts

import (
	"context"
	"net/http"

	kadmin "github.com/plystra/plystra/internal/kernel/contracts/admin"
	kauthz "github.com/plystra/plystra/internal/kernel/contracts/authz"
	kcap "github.com/plystra/plystra/internal/kernel/contracts/capability"
)

type ServiceRegistration = kcap.ServiceRegistration

type SystemCapability interface {
	ID() string
	Manifest() kcap.Manifest
	Init(context.Context, KernelContext) error
	Register(context.Context, Registry) error
	Start(context.Context) error
	Ready(context.Context) error
	Stop(context.Context) error
	Health(context.Context) HealthStatus
}

type KernelContext struct {
	KernelVersion string
}

type Registry interface {
	Services() ServiceRegistry
	Routes() RouteRegistry
	Migrations() MigrationRegistry
	Events() EventRegistry
}

type ServiceRegistry interface {
	Provide(name string, service any) error
	Require(name string) (any, error)
	List() []kcap.ServiceRegistration
}

type RouteRegistry interface {
	Register(Route) error
	List() []kcap.RouteRegistration
}

type MigrationRegistry interface {
	Register(capabilityID string, migrations []Migration) error
	List() []MigrationRegistration
}

type EventRegistry interface {
	Emit(context.Context, SystemEvent)
	Events() []SystemEvent
}

type Route struct {
	Method       string
	Path         string
	Service      string
	Operation    string
	CapabilityID string
	Handler      http.Handler
}

type Migration struct {
	ID        string
	Namespace string
	Path      string
	Checksum  string
}

type MigrationRegistration struct {
	CapabilityID string
	Migration    Migration
}

type SystemEvent struct {
	Type         string
	CapabilityID string
	Message      string
}

type HealthStatus struct {
	Status  string
	Message string
}

const (
	ServiceAudit            = kcap.ServiceAudit
	ServiceIdentity         = kcap.ServiceIdentity
	ServiceResourceRegistry = kcap.ServiceResourceRegistry
	ServiceAuthorization    = kcap.ServiceAuthorization
	ServiceAdmin            = kcap.ServiceAdmin
)

type AuditService interface {
	RecordAuthorizationDecision(context.Context, kauthz.Decision) error
}

type IdentityService interface {
	ResolveActor(context.Context, kauthz.ActorContext) (kauthz.ActorSnapshot, error)
	ValidateActor(context.Context, kauthz.ActorContext) error
}

type ResourceRegistryService interface {
	LoadResourceRegistration(context.Context, string, string) (kauthz.ResourceRegistrySnapshot, error)
	LoadTarget(context.Context, string, string) (kauthz.TargetSnapshot, error)
}

type AuthorizationService interface {
	Check(context.Context, kauthz.CheckInput) (*kauthz.Decision, error)
	Explain(context.Context, kauthz.CheckInput) (*kauthz.Decision, error)
}

type AdminControlPlane interface {
	AuthorizeAdminAction(context.Context, kadmin.Requirement) (bool, error)
}
