package authz

import (
	"context"

	coreauthz "github.com/plystra/plystra/internal/authz"
	"github.com/plystra/plystra/internal/kernel/contracts"
	kcap "github.com/plystra/plystra/internal/kernel/contracts/capability"
	"github.com/plystra/plystra/internal/kernel/registry"
)

const ID = kcap.AuthorizationResource

type Capability struct {
	store   coreauthz.Store
	service *Service
}

func NewCapability(store coreauthz.Store) *Capability {
	return &Capability{store: store}
}

func (c *Capability) ID() string { return ID }

func (c *Capability) Manifest() kcap.Manifest {
	return kcap.Manifest{
		ID:      ID,
		Kind:    kcap.KindSystemCapability,
		Name:    "Resource Authorization",
		Version: "1.0.0-rc121",
		Runtime: kcap.Runtime{Type: kcap.RuntimeBuiltin, Protocol: kcap.ProtocolInProcess, Address: "builtin"},
		Requires: kcap.Requires{
			Kernel: ">=0.1.0",
			Capabilities: []string{
				kcap.IdentityBusiness,
				kcap.ResourceRegistry,
				kcap.AuditExplainable,
			},
		},
		Provides: kcap.Provides{
			Services: []kcap.ServiceRef{{Name: kcap.ServiceAuthorization}},
			Routes: []kcap.RouteRef{
				{Method: "POST", Path: "/api/v1/authz/check", Service: kcap.ServiceAuthorization, Operation: "Check"},
				{Method: "POST", Path: "/api/v1/authz/explain", Service: kcap.ServiceAuthorization, Operation: "Explain"},
			},
			Migrations: kcap.MigrationRef{Namespace: "sys_authz", Path: "internal/system/authz/migrations"},
			Events:     kcap.EventsRef{Publishes: []string{"authorization.decision_recorded"}},
		},
		Privileged: true,
		Required:   true,
		Stability:  kcap.StabilityExperimental,
	}
}

func (c *Capability) Init(context.Context, contracts.KernelContext) error { return nil }

func (c *Capability) Register(_ context.Context, reg contracts.Registry) error {
	identity, err := registry.Require[contracts.IdentityService](reg.Services(), contracts.ServiceIdentity)
	if err != nil {
		return err
	}
	resources, err := registry.Require[contracts.ResourceRegistryService](reg.Services(), contracts.ServiceResourceRegistry)
	if err != nil {
		return err
	}
	audit, err := registry.Require[contracts.AuditService](reg.Services(), contracts.ServiceAudit)
	if err != nil {
		return err
	}
	c.service = NewService(c.store, identity, resources, audit)
	if err := reg.Services().Provide(kcap.ServiceAuthorization, c.service); err != nil {
		return err
	}
	if err := RegisterRoutes(reg.Routes()); err != nil {
		return err
	}
	return reg.Migrations().Register(ID, []contracts.Migration{{ID: "root_atlas_authz", Namespace: "sys_authz", Path: "migrations"}})
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
