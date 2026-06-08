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
}
