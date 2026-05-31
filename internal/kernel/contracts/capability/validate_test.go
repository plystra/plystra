package capability

import "testing"

func TestResolveOrderUsesSystemDependencyGraph(t *testing.T) {
	manifests := []Manifest{
		testManifest(AdminControlPlane, "sys_admin", []string{IdentityBusiness, AuthorizationResource, AuditExplainable}),
		testManifest(AuthorizationResource, "sys_authz", []string{IdentityBusiness, ResourceRegistry, AuditExplainable}),
		testManifest(ResourceRegistry, "sys_resource", nil),
		testManifest(IdentityBusiness, "sys_identity", nil),
		testManifest(AuditExplainable, "sys_audit", nil),
	}
	ordered, err := ResolveOrder(manifests)
	if err != nil {
		t.Fatalf("ResolveOrder error = %v", err)
	}
	got := make([]string, len(ordered))
	for i, item := range ordered {
		got[i] = item.ID
	}
	want := RequiredSystemCapabilityOrder
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %#v, want %#v", got, want)
		}
	}
}

func TestValidateManifestRejectsWrongNamespace(t *testing.T) {
	manifest := testManifest(AuthorizationResource, "sys_identity", nil)
	if err := ValidateManifest(manifest); err == nil {
		t.Fatalf("ValidateManifest accepted wrong migration namespace")
	}
}

func testManifest(id, namespace string, deps []string) Manifest {
	return Manifest{
		ID:       id,
		Kind:     KindSystemCapability,
		Name:     id,
		Version:  "0.0.1",
		Runtime:  Runtime{Type: RuntimeBuiltin, Protocol: ProtocolInProcess, Address: "builtin"},
		Requires: Requires{Kernel: ">=0.1.0", Capabilities: deps},
		Provides: Provides{
			Services:   []ServiceRef{{Name: id + ".service"}},
			Migrations: MigrationRef{Namespace: namespace, Path: "migrations/"},
		},
		Privileged: true,
		Required:   true,
		Stability:  StabilityExperimental,
	}
}
