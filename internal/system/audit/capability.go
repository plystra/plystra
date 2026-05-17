package audit

import (
	"context"

	"github.com/plystra/plystra/internal/authz"
	"github.com/plystra/plystra/internal/kernel/contracts"
	kcap "github.com/plystra/plystra/internal/kernel/contracts/capability"
)

const ID = kcap.AuditExplainable

type Capability struct {
	service *Service
}

func NewCapability(store authz.Store) *Capability {
	return &Capability{service: NewService(store)}
}

func (c *Capability) ID() string {
	return ID
}

func (c *Capability) Manifest() kcap.Manifest {
	return kcap.Manifest{
		ID:      ID,
		Kind:    kcap.KindSystemCapability,
		Name:    "Explainable Audit",
		Version: "1.0.0-rc121",
		Runtime: kcap.Runtime{Type: kcap.RuntimeBuiltin, Protocol: kcap.ProtocolInProcess, Address: "builtin"},
		Requires: kcap.Requires{
			Kernel: ">=0.1.0",
		},
		Provides: kcap.Provides{
			Services: []kcap.ServiceRef{{Name: kcap.ServiceAudit}},
			Routes: []kcap.RouteRef{
				{Method: "GET", Path: "/api/v1/audit/logs", Service: kcap.ServiceAudit, Operation: "Query"},
				{Method: "GET", Path: "/api/v1/audit/logs/{audit_log_id}", Service: kcap.ServiceAudit, Operation: "Get"},
			},
			Migrations: kcap.MigrationRef{Namespace: "sys_audit", Path: "internal/system/audit/migrations"},
			Events:     kcap.EventsRef{Publishes: []string{"audit.event_recorded"}},
		},
		Privileged: true,
		Required:   true,
		Stability:  kcap.StabilityExperimental,
	}
}

func (c *Capability) Init(context.Context, contracts.KernelContext) error { return nil }

func (c *Capability) Register(_ context.Context, reg contracts.Registry) error {
	if err := reg.Services().Provide(kcap.ServiceAudit, c.service); err != nil {
		return err
	}
	if err := RegisterRoutes(reg.Routes()); err != nil {
		return err
	}
	return reg.Migrations().Register(ID, []contracts.Migration{{ID: "root_atlas_audit", Namespace: "sys_audit", Path: "migrations"}})
}

func (c *Capability) Start(context.Context) error { return nil }

func (c *Capability) Ready(context.Context) error { return c.service.Ready() }

func (c *Capability) Stop(context.Context) error { return nil }

func (c *Capability) Health(context.Context) contracts.HealthStatus {
	if err := c.Ready(context.Background()); err != nil {
		return contracts.HealthStatus{Status: kcap.StateFailed, Message: err.Error()}
	}
	return contracts.HealthStatus{Status: kcap.StateReady}
}
