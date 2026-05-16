package kernel

import (
	"context"
	"testing"

	"github.com/plystra/plystra/internal/authz"
	kcap "github.com/plystra/plystra/internal/kernel/contracts/capability"
	"github.com/plystra/plystra/internal/resources"
	"github.com/plystra/plystra/internal/system"
)

func TestBootRegistersBuiltInSystemCapabilities(t *testing.T) {
	store := &testSystemStore{}
	app, err := Boot(context.Background(), Options{KernelVersion: "1.0.0-rc104", Capabilities: system.BuiltInCapabilities(store, store)})
	if err != nil {
		t.Fatalf("Boot() error = %v", err)
	}
	if err := app.Ready(); err != nil {
		t.Fatalf("Ready() error = %v", err)
	}

	states := app.States()
	for _, id := range kcap.RequiredSystemCapabilityOrder {
		if states[id] != kcap.StateReady {
			t.Fatalf("state[%s] = %q, want ready; all states=%#v", id, states[id], states)
		}
	}

	services := map[string]string{}
	for _, service := range app.Services() {
		services[service.Name] = service.CapabilityID
	}
	expected := map[string]string{
		kcap.ServiceAudit:            kcap.AuditExplainable,
		kcap.ServiceIdentity:         kcap.IdentityBusiness,
		kcap.ServiceResourceRegistry: kcap.ResourceRegistry,
		kcap.ServiceAuthorization:    kcap.AuthorizationResource,
		kcap.ServiceAdmin:            kcap.AdminControlPlane,
	}
	for name, capabilityID := range expected {
		if services[name] != capabilityID {
			t.Fatalf("service %s capability = %q, want %q; all services=%#v", name, services[name], capabilityID, services)
		}
	}

	if _, ok := app.AuthorizationService(); !ok {
		t.Fatalf("authorization service was not registered")
	}
}

var _ authz.Store = (*testSystemStore)(nil)
var _ resources.Store = (*testSystemStore)(nil)

type testSystemStore struct{}

func (s *testSystemStore) LoadActor(context.Context, authz.ActorContext) (authz.ActorSnapshot, error) {
	return authz.ActorSnapshot{}, authz.ErrNotFound
}

func (s *testSystemStore) LoadResourceRegistration(context.Context, string, string) (authz.ResourceRegistrySnapshot, error) {
	return authz.ResourceRegistrySnapshot{}, authz.ErrResourceTypeNotFound
}

func (s *testSystemStore) LoadTarget(context.Context, string, string) (authz.TargetSnapshot, error) {
	return authz.TargetSnapshot{}, authz.ErrNotFound
}

func (s *testSystemStore) LoadPermissionCandidates(context.Context, authz.CandidateQuery) ([]authz.PermissionCandidate, error) {
	return nil, nil
}

func (s *testSystemStore) WriteAuditLog(context.Context, authz.Decision) error {
	return nil
}

func (s *testSystemStore) UpsertResourceType(context.Context, resources.RegisterResourceTypeInput) (*resources.ResourceType, error) {
	return nil, nil
}

func (s *testSystemStore) UpsertResourceAction(context.Context, resources.RegisterResourceActionInput) (*resources.ResourceAction, error) {
	return nil, nil
}

func (s *testSystemStore) UpsertResourceMapping(context.Context, resources.RegisterResourceMappingInput) (*resources.ResourceMapping, error) {
	return nil, nil
}

func (s *testSystemStore) GetResourceType(context.Context, string) (*resources.ResourceType, error) {
	return nil, nil
}

func (s *testSystemStore) ListResourceActions(context.Context, string) ([]resources.ResourceAction, error) {
	return nil, nil
}

func (s *testSystemStore) GetResourceMapping(context.Context, string) (*resources.ResourceMapping, error) {
	return nil, nil
}
