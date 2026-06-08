package api

import (
	"strings"
	"testing"
	"time"

	"github.com/plystra/core/internal/authz"
)

func TestProviderRequestContextTTLClamp(t *testing.T) {
	if got := providerRequestContextTTL(0); got != providerRequestContextMaxTTL {
		t.Fatalf("default TTL = %s, want %s", got, providerRequestContextMaxTTL)
	}
	if got := providerRequestContextTTL(1); got != providerRequestContextMinTTL {
		t.Fatalf("minimum TTL = %s, want %s", got, providerRequestContextMinTTL)
	}
	if got := providerRequestContextTTL(int((10 * time.Minute).Milliseconds())); got != providerRequestContextMaxTTL {
		t.Fatalf("maximum TTL = %s, want %s", got, providerRequestContextMaxTTL)
	}
	if got := providerRequestContextTTL(30000); got != 30*time.Second {
		t.Fatalf("configured TTL = %s, want 30s", got)
	}
}

func TestValidateProviderRequestContextRequest(t *testing.T) {
	valid := providerRequestContextRequest{
		ProviderPluginID: "plystra.email",
		SpaceID:          "space_1",
		Actor: authz.ActorContext{
			UserID:       "user_1",
			MemberID:     "member_1",
			UserMemberID: "um_1",
		},
		Capability:        "workflow.approval",
		Operation:         "create_request",
		CapabilityGrantID: "grant_1",
	}
	if err := validateProviderRequestContextRequest(valid); err != nil {
		t.Fatalf("valid request failed: %v", err)
	}
	missingActor := valid
	missingActor.Actor.MemberID = ""
	if err := validateProviderRequestContextRequest(missingActor); err == nil || !strings.Contains(err.Error(), "actor.member_id") {
		t.Fatalf("missing actor should fail, got %v", err)
	}
	withSecretMetadata := valid
	withSecretMetadata.Metadata = map[string]any{"api_token": "do-not-store"}
	if err := validateProviderRequestContextRequest(withSecretMetadata); err == nil || !strings.Contains(err.Error(), "secret-like key") {
		t.Fatalf("secret-like metadata should fail, got %v", err)
	}
	missingBinding := valid
	missingBinding.CapabilityGrantID = ""
	if err := validateProviderRequestContextRequest(missingBinding); err == nil || !strings.Contains(err.Error(), "capability_grant_id or action_execution_id") {
		t.Fatalf("missing authorization binding should fail, got %v", err)
	}
	doubleBinding := valid
	doubleBinding.ActionExecutionID = "act_1"
	if err := validateProviderRequestContextRequest(doubleBinding); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("double authorization binding should fail, got %v", err)
	}
	grantWithoutCapability := valid
	grantWithoutCapability.Capability = ""
	if err := validateProviderRequestContextRequest(grantWithoutCapability); err == nil || !strings.Contains(err.Error(), "capability and operation are required") {
		t.Fatalf("grant binding without capability should fail, got %v", err)
	}
	actionWithCapability := valid
	actionWithCapability.CapabilityGrantID = ""
	actionWithCapability.ActionExecutionID = "act_1"
	if err := validateProviderRequestContextRequest(actionWithCapability); err == nil || !strings.Contains(err.Error(), "must be omitted") {
		t.Fatalf("action binding with explicit capability should fail, got %v", err)
	}
	actionOnly := valid
	actionOnly.Capability = ""
	actionOnly.Operation = ""
	actionOnly.CapabilityGrantID = ""
	actionOnly.ActionExecutionID = "act_1"
	if err := validateProviderRequestContextRequest(actionOnly); err != nil {
		t.Fatalf("valid action binding request failed: %v", err)
	}
}
