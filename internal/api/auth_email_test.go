package api

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAuthEmailValidation(t *testing.T) {
	t.Setenv("PLYSTRA_PUBLIC_APP_URL", "https://app.example.com")
	if err := validateEmailAddress("alice@example.com"); err != nil {
		t.Fatalf("valid email rejected: %v", err)
	}
	if err := validateEmailAddress("alice@example.com\r\nbcc@example.com"); err == nil {
		t.Fatalf("header-injection email accepted")
	}
	if err := validateRedirectURL("https://app.example.com/auth/callback"); err != nil {
		t.Fatalf("valid redirect rejected: %v", err)
	}
	if err := validateRedirectURL("http://app.example.com/auth/callback"); err == nil {
		t.Fatalf("non-https redirect accepted")
	}
}

func TestAuthChallengeSecretHashUsesSessionSecret(t *testing.T) {
	t.Setenv("PLYSTRA_SESSION_SECRET", "auth-challenge-secret-at-least-32-characters")
	left := challengeSecretHash("alice@example.com:auth.email_verification:123456")
	right := challengeSecretHash("alice@example.com:auth.email_verification:123456")
	other := challengeSecretHash("alice@example.com:auth.email_verification:654321")
	if left == "" || left != right {
		t.Fatalf("challenge hash is not stable")
	}
	if left == other || strings.Contains(left, "123456") {
		t.Fatalf("challenge hash leaked or failed to vary")
	}
}

func TestMagicLinkURLUsesHTTPSRedirect(t *testing.T) {
	t.Setenv("PLYSTRA_PUBLIC_APP_URL", "https://app.example.com")
	got := magicLinkURL("ply_ml_token", "https://app.example.com/auth/callback?next=%2Fconsole")
	if !strings.HasPrefix(got, "https://app.example.com/auth/callback?") {
		t.Fatalf("magic link URL = %s", got)
	}
	if !strings.Contains(got, "token=ply_ml_token") {
		t.Fatalf("magic link URL missing token: %s", got)
	}
}

func TestMagicLinkURLFallsBackForUnsafeRedirect(t *testing.T) {
	t.Setenv("PLYSTRA_PUBLIC_APP_URL", "https://console.example.com")
	got := magicLinkURL("ply_ml_token", "http://attacker.example.com/callback")
	if !strings.HasPrefix(got, "https://console.example.com/auth/consume?") {
		t.Fatalf("magic link fallback URL = %s", got)
	}
}

func TestMagicLinkURLFallsBackForUnconfiguredHTTPSRedirect(t *testing.T) {
	t.Setenv("PLYSTRA_PUBLIC_APP_URL", "https://console.example.com")
	got := magicLinkURL("ply_ml_token", "https://attacker.example.com/callback")
	if !strings.HasPrefix(got, "https://console.example.com/auth/consume?") {
		t.Fatalf("magic link fallback URL = %s", got)
	}
}

func TestValidateRedirectURLRequiresAllowedOrigin(t *testing.T) {
	t.Setenv("PLYSTRA_PUBLIC_APP_URL", "https://app.example.com")
	if err := validateRedirectURL("https://app.example.com/auth/callback"); err != nil {
		t.Fatalf("allowed redirect rejected: %v", err)
	}
	if err := validateRedirectURL("https://attacker.example.com/auth/callback"); err == nil {
		t.Fatalf("unconfigured redirect origin accepted")
	}
}

func TestValidateRedirectURLAllowsConfiguredOrigin(t *testing.T) {
	t.Setenv("PLYSTRA_PUBLIC_APP_URL", "https://app.example.com")
	t.Setenv("PLYSTRA_AUTH_ALLOWED_REDIRECT_ORIGINS", "https://console.example.com")
	if err := validateRedirectURL("https://console.example.com/auth/callback"); err != nil {
		t.Fatalf("configured redirect rejected: %v", err)
	}
}

func TestValidateAuthChallengeMetadataRejectsLineBreaks(t *testing.T) {
	if err := validateAuthChallengeMetadata(map[string]any{"next": "/console\r\nx"}); err == nil {
		t.Fatalf("metadata line break accepted")
	}
}

func TestMagicLinkURLUsesServerPublicURLFallback(t *testing.T) {
	t.Setenv("SERVER_PUBLIC_URL", "https://core.example.com")
	got := magicLinkURL("ply_ml_token", "")
	if !strings.HasPrefix(got, "https://core.example.com/auth/consume?") {
		t.Fatalf("magic link fallback URL = %s", got)
	}
}

func TestExposeChallengeIDHiddenInProduction(t *testing.T) {
	t.Setenv("SERVER_MODE", "production")
	if got := exposeChallengeID("authchal_test"); got != "" {
		t.Fatalf("production challenge id = %q, want hidden", got)
	}
}

func TestEmailCodeChallengeHashSeparatesLookupSecretFromDeliveredCode(t *testing.T) {
	t.Setenv("PLYSTRA_SESSION_SECRET", "auth-challenge-secret-at-least-32-characters")
	challengeID := "authchal_test"
	code := "123456"
	tokenHashValue := tokenHash(firstNonEmpty("", challengeID))
	codeHashValue := challengeSecretHash("alice@example.com:" + authChallengeEmailVerification + ":" + code)
	if tokenHashValue == "" || codeHashValue == "" {
		t.Fatalf("hashes must be populated")
	}
	if tokenHashValue == codeHashValue {
		t.Fatalf("email code challenge reused code hash as token hash")
	}
}

func TestNewNumericCodeHasFixedDigits(t *testing.T) {
	for i := 0; i < 100; i++ {
		code, err := newNumericCode(6)
		if err != nil {
			t.Fatalf("newNumericCode error: %v", err)
		}
		if !validEmailCode(code) {
			t.Fatalf("invalid numeric code %q", code)
		}
	}
}

func TestBuildAuthEmailUsesCapabilityContractShape(t *testing.T) {
	t.Setenv("PLYSTRA_AUTH_EMAIL_FROM", "no-reply@example.com")
	msg := buildAuthEmail(authChallengeEmailVerification, authDeliveryEmailCode, "alice@example.com", "123456", "", time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC), "authchal_test")
	if msg.Purpose != authChallengeEmailVerification {
		t.Fatalf("purpose = %s", msg.Purpose)
	}
	if msg.From.Address != "no-reply@example.com" {
		t.Fatalf("from = %#v", msg.From)
	}
	if len(msg.To) != 1 || msg.To[0].Address != "alice@example.com" {
		t.Fatalf("to = %#v", msg.To)
	}
	if !strings.Contains(msg.Text, "123456") || !strings.Contains(msg.HTML, "123456") {
		t.Fatalf("verification code missing from body")
	}
	if msg.Headers["X-Plystra-Auth-Challenge"] != "authchal_test" {
		t.Fatalf("challenge header missing: %#v", msg.Headers)
	}
}

func TestChallengeThrottleKeysAreScoped(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/v1/auth/email-code", nil)
	req.RemoteAddr = "203.0.113.10:1234"
	keys := challengeThrottleKeys("Alice@Example.com", req, "email_code")
	if len(keys) != 2 {
		t.Fatalf("keys = %#v", keys)
	}
	if keys[0] != "email_code:email:alice@example.com" {
		t.Fatalf("email key = %q", keys[0])
	}
	if keys[1] != "email_code:ip:203.0.113.10" {
		t.Fatalf("ip key = %q", keys[1])
	}
}

func TestAuthLimiterRecordsEmailSendAttempts(t *testing.T) {
	limiter := newLoginAttemptLimiterFromEnv()
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	limiter.now = func() time.Time { return now }
	keys := []string{"email_code:email:alice@example.com"}
	if retry := limiter.recordAttempt(keys, 2); retry != 0 {
		t.Fatalf("first send retry = %s, want none", retry)
	}
	if retry := limiter.recordAttempt(keys, 2); retry <= 0 {
		t.Fatalf("second send retry = %s, want lockout", retry)
	}
}
