package admin

import (
	"context"

	"github.com/plystra/core/internal/kernel/contracts"
	kcap "github.com/plystra/core/internal/kernel/contracts/capability"
	"github.com/plystra/core/internal/kernel/registry"
)

const ID = kcap.AdminControlPlane

type Capability struct {
	service *Service
}

func NewCapability() *Capability {
	return &Capability{}
}

func (c *Capability) ID() string { return ID }

func (c *Capability) Manifest() kcap.Manifest {
	return kcap.Manifest{
		ID:      ID,
		Kind:    kcap.KindSystemCapability,
		Name:    "Admin Control Plane",
		Version: "0.0.1",
		Runtime: kcap.Runtime{Type: kcap.RuntimeBuiltin, Protocol: kcap.ProtocolInProcess, Address: "builtin"},
		Requires: kcap.Requires{
			Kernel: ">=0.1.0",
			Capabilities: []string{
				kcap.IdentityBusiness,
				kcap.AuthorizationResource,
				kcap.AuditExplainable,
			},
		},
		Provides: kcap.Provides{
			Services: []kcap.ServiceRef{{Name: kcap.ServiceAdmin}},
			Routes: []kcap.RouteRef{
				{Method: "GET", Path: "/api/v1/admin/me", Service: kcap.ServiceAdmin, Operation: "AdminMe"},
				{Method: "GET", Path: "/api/v1/admin/grants", Service: kcap.ServiceAdmin, Operation: "ListGrants"},
				{Method: "POST", Path: "/api/v1/admin/grants", Service: kcap.ServiceAdmin, Operation: "GrantAdmin"},
			},
			Migrations: kcap.MigrationRef{Namespace: "sys_admin", Path: "internal/system/admin/migrations"},
			Events:     kcap.EventsRef{Publishes: []string{"admin.action_authorized"}},
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
	authorization, err := registry.Require[contracts.AuthorizationService](reg.Services(), contracts.ServiceAuthorization)
	if err != nil {
		return err
	}
	audit, err := registry.Require[contracts.AuditService](reg.Services(), contracts.ServiceAudit)
	if err != nil {
		return err
	}
	c.service = NewService(identity, authorization, audit)
	if err := reg.Services().Provide(kcap.ServiceAdmin, c.service); err != nil {
		return err
	}
	if err := RegisterRoutes(reg.Routes()); err != nil {
		return err
	}
	return reg.Migrations().Register(ID, []contracts.Migration{{ID: "root_atlas_admin", Namespace: "sys_admin", Path: "migrations"}})
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
