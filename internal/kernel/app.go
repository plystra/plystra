package kernel

import (
	"context"

	"github.com/plystra/core/internal/kernel/contracts"
	"github.com/plystra/core/internal/kernel/events"
	"github.com/plystra/core/internal/kernel/lifecycle"
	"github.com/plystra/core/internal/kernel/registry"
)

type App struct {
	Registry  *registry.Registry
	Lifecycle *lifecycle.Manager
}

type Options struct {
	KernelVersion string
	Capabilities  []contracts.SystemCapability
}

func Boot(ctx context.Context, opts Options) (*App, error) {
	reg := registry.New()
	manager := lifecycle.New(opts.KernelVersion, reg)
	app := &App{Registry: reg, Lifecycle: manager}

	for _, capability := range opts.Capabilities {
		if err := manager.Register(capability); err != nil {
			return nil, err
		}
		reg.Events().Emit(ctx, contracts.SystemEvent{Type: events.CapabilityLoaded, CapabilityID: capability.ID()})
	}
	if err := manager.Boot(ctx); err != nil {
		reg.Events().Emit(ctx, contracts.SystemEvent{Type: events.CapabilityFailed, Message: err.Error()})
		return app, err
	}
	reg.Events().Emit(ctx, contracts.SystemEvent{Type: events.KernelStarted})
	return app, nil
}

func (a *App) Ready() error {
	if a == nil || a.Lifecycle == nil {
		return nil
	}
	return a.Lifecycle.Ready()
}

func (a *App) Stop(ctx context.Context) error {
	if a == nil || a.Lifecycle == nil {
		return nil
	}
	return a.Lifecycle.Stop(ctx)
}

func (a *App) States() map[string]string {
	if a == nil || a.Lifecycle == nil {
		return map[string]string{}
	}
	return a.Lifecycle.States()
}

func (a *App) Services() []contracts.ServiceRegistration {
	if a == nil || a.Lifecycle == nil {
		return nil
	}
	return a.Lifecycle.Services()
}

func (a *App) AuthorizationService() (contracts.AuthorizationService, bool) {
	if a == nil || a.Lifecycle == nil {
		return nil, false
	}
	raw, err := a.Lifecycle.Service(contracts.ServiceAuthorization)
	if err != nil {
		return nil, false
	}
	service, ok := raw.(contracts.AuthorizationService)
	return service, ok
}
