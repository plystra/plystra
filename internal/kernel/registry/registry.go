package registry

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/plystra/core/internal/kernel/contracts"
	kcap "github.com/plystra/core/internal/kernel/contracts/capability"
)

type Registry struct {
	services   *ServiceRegistry
	routes     *RouteRegistry
	migrations *MigrationRegistry
	events     *EventRegistry
}

func New() *Registry {
	return &Registry{
		services:   NewServiceRegistry(),
		routes:     NewRouteRegistry(),
		migrations: NewMigrationRegistry(),
		events:     NewEventRegistry(),
	}
}

func (r *Registry) Services() contracts.ServiceRegistry {
	return r.services
}

func (r *Registry) Routes() contracts.RouteRegistry {
	return r.routes
}

func (r *Registry) Migrations() contracts.MigrationRegistry {
	return r.migrations
}

func (r *Registry) Events() contracts.EventRegistry {
	return r.events
}

type ServiceRegistry struct {
	mu       sync.RWMutex
	services map[string]any
	meta     map[string]kcap.ServiceRegistration
}

func NewServiceRegistry() *ServiceRegistry {
	return &ServiceRegistry{services: map[string]any{}, meta: map[string]kcap.ServiceRegistration{}}
}

func (r *ServiceRegistry) Provide(name string, service any) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("service name is required")
	}
	if service == nil {
		return fmt.Errorf("service %s is nil", name)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.services[name]; exists {
		return fmt.Errorf("service %s is already registered", name)
	}
	r.services[name] = service
	r.meta[name] = kcap.ServiceRegistration{Name: name, Protocol: "in-process", Address: "builtin", Health: kcap.StateReady, RegisteredAt: time.Now().UTC()}
	return nil
}

func (r *ServiceRegistry) Require(name string) (any, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	service, ok := r.services[name]
	if !ok {
		return nil, fmt.Errorf("service %s is not registered", name)
	}
	return service, nil
}

func (r *ServiceRegistry) SetCapability(name, capabilityID, version string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	meta := r.meta[name]
	meta.CapabilityID = capabilityID
	meta.Version = version
	r.meta[name] = meta
}

func (r *ServiceRegistry) List() []kcap.ServiceRegistration {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]kcap.ServiceRegistration, 0, len(r.meta))
	for _, item := range r.meta {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

type RouteRegistry struct {
	mu     sync.RWMutex
	routes map[string]contracts.Route
}

func NewRouteRegistry() *RouteRegistry {
	return &RouteRegistry{routes: map[string]contracts.Route{}}
}

func (r *RouteRegistry) Register(route contracts.Route) error {
	route.Method = strings.ToUpper(strings.TrimSpace(route.Method))
	route.Path = strings.TrimSpace(route.Path)
	if route.Method == "" || route.Path == "" || route.Service == "" || route.Operation == "" || route.CapabilityID == "" {
		return fmt.Errorf("route requires method, path, service, operation, and capability_id")
	}
	if route.Path[0] != '/' {
		return fmt.Errorf("route path %q must start with /", route.Path)
	}
	switch route.Method {
	case http.MethodGet, http.MethodPost, http.MethodPatch, http.MethodDelete:
	default:
		return fmt.Errorf("route method %q is not supported", route.Method)
	}
	key := route.Method + " " + route.Path
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.routes[key]; exists {
		return fmt.Errorf("route %s is already registered", key)
	}
	r.routes[key] = route
	return nil
}

func (r *RouteRegistry) List() []kcap.RouteRegistration {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]kcap.RouteRegistration, 0, len(r.routes))
	for _, route := range r.routes {
		out = append(out, kcap.RouteRegistration{
			Method:       route.Method,
			Path:         route.Path,
			Service:      route.Service,
			Operation:    route.Operation,
			CapabilityID: route.CapabilityID,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path == out[j].Path {
			return out[i].Method < out[j].Method
		}
		return out[i].Path < out[j].Path
	})
	return out
}

type MigrationRegistry struct {
	mu         sync.RWMutex
	migrations []contracts.MigrationRegistration
}

func NewMigrationRegistry() *MigrationRegistry {
	return &MigrationRegistry{}
}

func (r *MigrationRegistry) Register(capabilityID string, migrations []contracts.Migration) error {
	capabilityID = strings.TrimSpace(capabilityID)
	if capabilityID == "" {
		return fmt.Errorf("capability_id is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, migration := range migrations {
		if migration.ID == "" || migration.Namespace == "" {
			return fmt.Errorf("migration id and namespace are required for %s", capabilityID)
		}
		r.migrations = append(r.migrations, contracts.MigrationRegistration{CapabilityID: capabilityID, Migration: migration})
	}
	return nil
}

func (r *MigrationRegistry) List() []contracts.MigrationRegistration {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]contracts.MigrationRegistration, len(r.migrations))
	copy(out, r.migrations)
	return out
}

type EventRegistry struct {
	mu     sync.RWMutex
	events []contracts.SystemEvent
}

func NewEventRegistry() *EventRegistry {
	return &EventRegistry{}
}

func (r *EventRegistry) Emit(_ context.Context, event contracts.SystemEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
}

func (r *EventRegistry) Events() []contracts.SystemEvent {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]contracts.SystemEvent, len(r.events))
	copy(out, r.events)
	return out
}

func Require[T any](services contracts.ServiceRegistry, name string) (T, error) {
	var zero T
	raw, err := services.Require(name)
	if err != nil {
		return zero, err
	}
	typed, ok := raw.(T)
	if !ok {
		return zero, fmt.Errorf("service %s has unexpected type %T", name, raw)
	}
	return typed, nil
}
