package resource_registry

import (
	"context"

	"github.com/plystra/core/internal/authz"
	"github.com/plystra/core/internal/kernel/contracts"
	kcap "github.com/plystra/core/internal/kernel/contracts/capability"
	"github.com/plystra/core/internal/resources"
)

const ID = kcap.ResourceRegistry

type Capability struct {
	service *Service
}

func NewCapability(resourceStore resources.Store, authzStore authz.Store) *Capability {
	return &Capability{service: NewService(resourceStore, authzStore)}
}

func (c *Capability) ID() string { return ID }

func (c *Capability) Manifest() kcap.Manifest {
	return kcap.Manifest{
		ID:      ID,
		Kind:    kcap.KindSystemCapability,
		Name:    "Resource Registry",
		Version: "0.0.1",
		Runtime: kcap.Runtime{Type: kcap.RuntimeBuiltin, Protocol: kcap.ProtocolInProcess, Address: "builtin"},
		Requires: kcap.Requires{
			Kernel:       ">=0.1.0",
			Capabilities: []string{kcap.AuditExplainable},
		},
		Provides: kcap.Provides{
			Services: []kcap.ServiceRef{{Name: kcap.ServiceResourceRegistry}},
			Routes: []kcap.RouteRef{
				{Method: "GET", Path: "/api/v1/resource-types", Service: kcap.ServiceResourceRegistry, Operation: "ListResourceTypes"},
				{Method: "POST", Path: "/api/v1/resource-types", Service: kcap.ServiceResourceRegistry, Operation: "RegisterResourceType"},
				{Method: "GET", Path: "/api/v1/resources", Service: kcap.ServiceResourceRegistry, Operation: "ListResources"},
			},
			Migrations: kcap.MigrationRef{Namespace: "sys_resource", Path: "internal/system/resource_registry/migrations"},
			Events:     kcap.EventsRef{Publishes: []string{"resource.registry_updated"}},
		},
		Privileged: true,
		Required:   true,
		Stability:  kcap.StabilityExperimental,
	}
}

func (c *Capability) Init(context.Context, contracts.KernelContext) error { return nil }

func (c *Capability) Register(_ context.Context, reg contracts.Registry) error {
	if err := reg.Services().Provide(kcap.ServiceResourceRegistry, c.service); err != nil {
		return err
	}
	if err := RegisterRoutes(reg.Routes()); err != nil {
		return err
	}
	return reg.Migrations().Register(ID, []contracts.Migration{{ID: "root_atlas_resource_registry", Namespace: "sys_resource", Path: "migrations"}})
}

func (c *Capability) Start(context.Context) error { return nil }

func (c *Capability) Ready(context.Context) error { return c.service.Ready() }

func (c *Capability) Stop(context.Context) error { return nil }

func (c *Capability) Health(ctx context.Context) contracts.HealthStatus {
	if err := c.Ready(ctx); err != nil {
		return contracts.HealthStatus{Status: kcap.StateFailed, Message: err.Error()}
	}
	return contracts.HealthStatus{Status: kcap.StateReady}
}
