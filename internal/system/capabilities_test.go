package system_test

import (
	"slices"
	"testing"

	"github.com/plystra/plystra/internal/kernel/contracts/capability"
	systemadmin "github.com/plystra/plystra/internal/system/admin"
	systemaudit "github.com/plystra/plystra/internal/system/audit"
	systemauthz "github.com/plystra/plystra/internal/system/authz"
	systemidentity "github.com/plystra/plystra/internal/system/identity"
	systemresource "github.com/plystra/plystra/internal/system/resource_registry"
)

func TestBuiltInSystemCapabilityManifests(t *testing.T) {
	manifests := []capability.Manifest{
		systemaudit.NewCapability(nil).Manifest(),
		systemidentity.NewCapability(nil).Manifest(),
		systemresource.NewCapability(nil, nil).Manifest(),
		systemauthz.NewCapability(nil).Manifest(),
		systemadmin.NewCapability().Manifest(),
	}

	for _, manifest := range manifests {
		if err := capability.ValidateManifest(manifest); err != nil {
			t.Fatalf("ValidateManifest(%s) error = %v", manifest.ID, err)
		}
		if manifest.Runtime.Type != capability.RuntimeBuiltin || manifest.Runtime.Protocol != capability.ProtocolInProcess {
			t.Fatalf("%s runtime = %#v, want built-in in-process", manifest.ID, manifest.Runtime)
		}
		if !manifest.Privileged || !manifest.Required {
			t.Fatalf("%s must be privileged and required", manifest.ID)
		}
	}

	ordered, err := capability.ResolveOrder(manifests)
	if err != nil {
		t.Fatalf("ResolveOrder() error = %v", err)
	}
	got := make([]string, len(ordered))
	for i, manifest := range ordered {
		got[i] = manifest.ID
	}
	if !slices.Equal(got, capability.RequiredSystemCapabilityOrder) {
		t.Fatalf("order = %#v, want %#v", got, capability.RequiredSystemCapabilityOrder)
	}
}
