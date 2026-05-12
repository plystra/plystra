package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHashPasswordUsesArgon2ID(t *testing.T) {
	encoded, err := hashPassword("new-user-password")
	if err != nil {
		t.Fatalf("hashPassword error: %v", err)
	}
	if !verifyPassword("new-user-password", encoded) {
		t.Fatalf("argon2id password did not verify")
	}
	if passwordNeedsRehash(encoded) {
		t.Fatalf("fresh argon2id password unexpectedly needs rehash")
	}
}

func TestVerifyPasswordRejectsNonArgon2IDHash(t *testing.T) {
	if verifyPassword("anything", "pbkdf2_sha256$120000$valid_salt$00000000000000000000000000000000") {
		t.Fatalf("PBKDF2 hash verified")
	}
}

func TestLoginAttemptLimiterLocksAndResets(t *testing.T) {
	now := time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC)
	limiter := &loginAttemptLimiter{
		records: map[string]loginAttemptRecord{},
		limit:   2,
		window:  time.Minute,
		lockout: 5 * time.Minute,
		now: func() time.Time {
			return now
		},
	}
	keys := []string{"email:alice@example.com", "ip:203.0.113.10"}

	if retry := limiter.recordFailure(keys); retry != 0 {
		t.Fatalf("first failure retry = %s, want no lock", retry)
	}
	if retry := limiter.recordFailure(keys); retry <= 0 {
		t.Fatalf("second failure did not lock")
	}
	if retry := limiter.retryAfter(keys); retry <= 0 {
		t.Fatalf("retryAfter did not report active lock")
	}
	limiter.reset(keys)
	if retry := limiter.retryAfter(keys); retry != 0 {
		t.Fatalf("retryAfter after reset = %s, want 0", retry)
	}
}

func TestLoginThrottleKeysUseNormalizedEmailAndRemoteIP(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	req.RemoteAddr = "203.0.113.10:1234"
	keys := loginThrottleKeys(" Alice@Example.COM ", req)
	if len(keys) != 2 {
		t.Fatalf("keys = %#v", keys)
	}
	if keys[0] != "email:alice@example.com" {
		t.Fatalf("email key = %q", keys[0])
	}
	if keys[1] != "ip:203.0.113.10" {
		t.Fatalf("ip key = %q", keys[1])
	}
}

func TestTokenHashLookupAcceptsPreviousSessionSecret(t *testing.T) {
	t.Setenv("PLYSTRA_SESSION_SECRET", "old-session-secret-at-least-32-characters")
	oldHash := tokenHash("ply_at_test_token")

	t.Setenv("PLYSTRA_SESSION_SECRET", "new-session-secret-at-least-32-characters")
	t.Setenv("PLYSTRA_SESSION_SECRET_PREVIOUS", "old-session-secret-at-least-32-characters")
	hashes := tokenHashesForLookup("ply_at_test_token")
	if len(hashes) != 2 {
		t.Fatalf("hash count = %d, want primary and previous", len(hashes))
	}
	if hashes[0] == oldHash {
		t.Fatalf("primary hash unexpectedly used previous secret first")
	}
	if hashes[1] != oldHash {
		t.Fatalf("previous secret hash not present")
	}
}

func TestValidatePlaintextPasswordPolicy(t *testing.T) {
	if message, ok := validatePlaintextPassword("short"); ok || message == "" {
		t.Fatalf("short password accepted: ok=%v message=%q", ok, message)
	}
	if message, ok := validatePlaintextPassword("long-enough-password"); !ok || message != "" {
		t.Fatalf("valid password rejected: ok=%v message=%q", ok, message)
	}
}
