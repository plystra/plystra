package api

import (
	"context"
	"strings"
	"testing"

	"github.com/plystra/core/internal/templates"
)

func TestApplyTemplateDefaultsRequiresExistingSpaceID(t *testing.T) {
	server := &Server{}
	_, err := server.applyTemplateDefaults(context.Background(), templates.Manifest{
		ID:           "internal-admin",
		Version:      "0.0.1",
		RequiresCore: ">=0.0.1 <0.1.0",
		Spaces:       []templates.Space{{Key: "default", Name: "Default Workspace"}},
	}, templateInstallRequest{})
	if err == nil {
		t.Fatalf("template install without space_id should be rejected")
	}
	if !strings.Contains(err.Error(), "space_id is required") || !strings.Contains(err.Error(), "create_space must use provisioning/action gateway") {
		t.Fatalf("unexpected error: %v", err)
	}
}
