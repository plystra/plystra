package lifecycle

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/plystra/core/internal/kernel/contracts"
	kcap "github.com/plystra/core/internal/kernel/contracts/capability"
	"github.com/plystra/core/internal/kernel/registry"
)

type Manager struct {
	kernelVersion string
	registry      *registry.Registry
	mu            sync.RWMutex
	capabilities  map[string]contracts.SystemCapability
	manifests     map[string]kcap.Manifest
	states        map[string]string
	ordered       []contracts.SystemCapability
	bootErr       error
}

func New(kernelVersion string, reg *registry.Registry) *Manager {
	return &Manager{
		kernelVersion: kernelVersion,
		registry:      reg,
		capabilities:  map[string]contracts.SystemCapability{},
		manifests:     map[string]kcap.Manifest{},
		states:        map[string]string{},
	}
}

func (m *Manager) Register(capability contracts.SystemCapability) error {
	if capability == nil {
		return fmt.Errorf("capability is nil")
	}
	id := capability.ID()
	if id == "" {
		return fmt.Errorf("capability id is required")
	}
	manifest := capability.Manifest()
	if manifest.ID != id {
		return fmt.Errorf("capability %s manifest id is %s", id, manifest.ID)
	}
	if err := kcap.ValidateManifest(manifest); err != nil {
		return fmt.Errorf("validate capability %s: %w", id, err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.capabilities[id]; exists {
		return fmt.Errorf("capability %s is already registered", id)
	}
	m.capabilities[id] = capability
	m.manifests[id] = manifest
	m.states[id] = kcap.StateDiscovered
	return nil
}

func (m *Manager) Boot(ctx context.Context) error {
	if err := m.resolveOrder(); err != nil {
		m.bootErr = err
		return err
	}
	for _, capability := range m.ordered {
		id := capability.ID()
		m.setState(id, kcap.StateValidated)
		if err := capability.Init(ctx, contracts.KernelContext{KernelVersion: m.kernelVersion}); err != nil {
			m.setState(id, kcap.StateFailed)
			m.bootErr = err
			return fmt.Errorf("init capability %s: %w", id, err)
		}
		m.setState(id, kcap.StateMigrated)
		if err := capability.Register(ctx, m.registry); err != nil {
			m.setState(id, kcap.StateFailed)
			m.bootErr = err
			return fmt.Errorf("register capability %s: %w", id, err)
		}
		m.markServiceMetadata(capability.Manifest())
		m.setState(id, kcap.StateRegistered)
		if err := capability.Start(ctx); err != nil {
			m.setState(id, kcap.StateFailed)
			m.bootErr = err
			return fmt.Errorf("start capability %s: %w", id, err)
		}
		if err := capability.Ready(ctx); err != nil {
			m.setState(id, kcap.StateFailed)
			m.bootErr = err
			return fmt.Errorf("capability %s is not ready: %w", id, err)
		}
		m.setState(id, kcap.StateReady)
		m.registry.Events().Emit(ctx, contracts.SystemEvent{Type: "capability.ready", CapabilityID: id})
	}
	return nil
}

func (m *Manager) Ready() error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.bootErr != nil {
		return m.bootErr
	}
	for _, id := range kcap.RequiredSystemCapabilityOrder {
		manifest, ok := m.manifests[id]
		if !ok {
			return fmt.Errorf("required capability %s is missing", id)
		}
		if manifest.Required && m.states[id] != kcap.StateReady {
			return fmt.Errorf("required capability %s is %s", id, m.states[id])
		}
	}
	return nil
}

func (m *Manager) Stop(ctx context.Context) error {
	m.mu.RLock()
	ordered := make([]contracts.SystemCapability, len(m.ordered))
	copy(ordered, m.ordered)
	m.mu.RUnlock()
	var firstErr error
	for i := len(ordered) - 1; i >= 0; i-- {
		capability := ordered[i]
		if err := capability.Stop(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
		m.setState(capability.ID(), kcap.StateStopped)
	}
	return firstErr
}

func (m *Manager) States() map[string]string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := map[string]string{}
	for id, state := range m.states {
		out[id] = state
	}
	return out
}

func (m *Manager) Services() []kcap.ServiceRegistration {
	return m.registry.Services().List()
}

func (m *Manager) Service(name string) (any, error) {
	return m.registry.Services().Require(name)
}

func (m *Manager) resolveOrder() error {
	m.mu.RLock()
	manifests := make([]kcap.Manifest, 0, len(m.manifests))
	for _, manifest := range m.manifests {
		manifests = append(manifests, manifest)
	}
	capabilitiesByID := make(map[string]contracts.SystemCapability, len(m.capabilities))
	for id, capability := range m.capabilities {
		capabilitiesByID[id] = capability
	}
	m.mu.RUnlock()

	orderedManifests, err := kcap.ResolveOrder(manifests)
	if err != nil {
		return err
	}
	ordered := make([]contracts.SystemCapability, 0, len(orderedManifests))
	for _, manifest := range orderedManifests {
		ordered = append(ordered, capabilitiesByID[manifest.ID])
	}
	m.mu.Lock()
	m.ordered = ordered
	m.mu.Unlock()
	return nil
}

func (m *Manager) markServiceMetadata(manifest kcap.Manifest) {
	services, ok := m.registry.Services().(*registry.ServiceRegistry)
	if !ok {
		return
	}
	for _, service := range manifest.Provides.Services {
		services.SetCapability(service.Name, manifest.ID, manifest.Version)
	}
}

func (m *Manager) setState(id, state string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.states[id] = state
}

func (m *Manager) CapabilityIDs() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ids := make([]string, 0, len(m.capabilities))
	for id := range m.capabilities {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
