package main

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestValidateProductionConfigRejectsWildcardCORS(t *testing.T) {
	setValidProductionEnv(t)
	t.Setenv("CORS_ALLOWED_ORIGINS", "*")

	err := validateProductionConfig()
	if err == nil || !strings.Contains(err.Error(), "CORS_ALLOWED_ORIGINS") {
		t.Fatalf("validateProductionConfig error = %v, want CORS wildcard rejection", err)
	}
}

func TestValidateProductionConfigRequiresCanonicalSessionSecret(t *testing.T) {
	setValidProductionEnv(t)
	t.Setenv("PLYSTRA_SESSION_SECRET", "")

	if err := validateProductionConfig(); err == nil || !strings.Contains(err.Error(), "PLYSTRA_SESSION_SECRET") {
		t.Fatalf("validateProductionConfig error = %v, want PLYSTRA_SESSION_SECRET rejection", err)
	}
}

func TestValidateProductionConfigRejectsUnsafePreviousSessionSecret(t *testing.T) {
	setValidProductionEnv(t)
	t.Setenv("PLYSTRA_SESSION_SECRET_PREVIOUS", defaultSessionSecret)

	err := validateProductionConfig()
	if err == nil || !strings.Contains(err.Error(), "PLYSTRA_SESSION_SECRET_PREVIOUS") {
		t.Fatalf("validateProductionConfig error = %v, want previous secret rejection", err)
	}
}

func TestValidateProductionConfigRejectsUnsafeAPIKeySecret(t *testing.T) {
	setValidProductionEnv(t)
	t.Setenv("PLYSTRA_API_KEY_SECRET", defaultAPIKeySecret)

	err := validateProductionConfig()
	if err == nil || !strings.Contains(err.Error(), "PLYSTRA_API_KEY_SECRET") {
		t.Fatalf("validateProductionConfig error = %v, want API key secret rejection", err)
	}
}

func TestValidateProductionConfigRejectsSharedAPIKeySecret(t *testing.T) {
	setValidProductionEnv(t)
	t.Setenv("PLYSTRA_API_KEY_SECRET", "production-session-secret-at-least-32-characters")

	err := validateProductionConfig()
	if err == nil || !strings.Contains(err.Error(), "distinct") {
		t.Fatalf("validateProductionConfig error = %v, want distinct API key secret rejection", err)
	}
}

func TestValidateProductionConfigRejectsUnsafePreviousAPIKeySecret(t *testing.T) {
	setValidProductionEnv(t)
	t.Setenv("PLYSTRA_API_KEY_SECRET_PREVIOUS", defaultAPIKeySecret)

	err := validateProductionConfig()
	if err == nil || !strings.Contains(err.Error(), "PLYSTRA_API_KEY_SECRET_PREVIOUS") {
		t.Fatalf("validateProductionConfig error = %v, want previous API key secret rejection", err)
	}
}

func TestValidateProductionConfigRequiresRegistrationTokenWhenEnabled(t *testing.T) {
	setValidProductionEnv(t)
	t.Setenv("PLYSTRA_AUTH_REGISTRATION_ENABLED", "true")

	err := validateProductionConfig()
	if err == nil || !strings.Contains(err.Error(), "PLYSTRA_AUTH_REGISTRATION_TOKEN") {
		t.Fatalf("validateProductionConfig error = %v, want registration token rejection", err)
	}
}

func TestValidateProductionConfigAllowsPublicUserOnlyRegistrationWithoutToken(t *testing.T) {
	setValidProductionEnv(t)
	t.Setenv("PLYSTRA_AUTH_REGISTRATION_ENABLED", "true")
	t.Setenv("PLYSTRA_AUTH_REGISTRATION_TOKEN", "")
	t.Setenv("PLYSTRA_AUTH_PUBLIC_USER_REGISTRATION_ENABLED", "true")

	if err := validateProductionConfig(); err != nil {
		t.Fatalf("validateProductionConfig error = %v, want public user-only registration without token to pass", err)
	}
}

func TestValidateProductionConfigRequiresBootstrapRegistrationTokenWhenEnabled(t *testing.T) {
	setValidProductionEnv(t)
	t.Setenv("PLYSTRA_BOOTSTRAP_REGISTRATION_ENABLED", "true")

	err := validateProductionConfig()
	if err == nil || !strings.Contains(err.Error(), "PLYSTRA_BOOTSTRAP_REGISTRATION_TOKEN") {
		t.Fatalf("validateProductionConfig error = %v, want bootstrap registration token rejection", err)
	}
}

func TestValidateProductionConfigRequiresEmailCapability(t *testing.T) {
	setValidProductionEnv(t)
	t.Setenv("PLYSTRA_EMAIL_CAPABILITY_URL", "")

	err := validateProductionConfig()
	if err == nil || !strings.Contains(err.Error(), "PLYSTRA_EMAIL_CAPABILITY_URL") {
		t.Fatalf("validateProductionConfig error = %v, want email capability URL rejection", err)
	}
}

func TestValidateProductionConfigRejectsEmailLogMode(t *testing.T) {
	setValidProductionEnv(t)
	t.Setenv("PLYSTRA_EMAIL_DELIVERY_MODE", "log")

	err := validateProductionConfig()
	if err == nil || !strings.Contains(err.Error(), "PLYSTRA_EMAIL_DELIVERY_MODE") {
		t.Fatalf("validateProductionConfig error = %v, want email log mode rejection", err)
	}
}

func TestValidateProductionConfigRejectsUnsafeRedirectOrigin(t *testing.T) {
	setValidProductionEnv(t)
	t.Setenv("PLYSTRA_AUTH_ALLOWED_REDIRECT_ORIGINS", "http://console.example.com")

	err := validateProductionConfig()
	if err == nil || !strings.Contains(err.Error(), "PLYSTRA_AUTH_ALLOWED_REDIRECT_ORIGINS") {
		t.Fatalf("validateProductionConfig error = %v, want redirect origin rejection", err)
	}
}

func TestNewHTTPServerUsesProductionTimeouts(t *testing.T) {
	t.Setenv("HTTP_READ_HEADER_TIMEOUT", "7s")
	t.Setenv("HTTP_READ_TIMEOUT", "31s")
	t.Setenv("HTTP_WRITE_TIMEOUT", "61s")
	t.Setenv("HTTP_IDLE_TIMEOUT", "121s")

	server, err := newHTTPServer(":0", http.NewServeMux())
	if err != nil {
		t.Fatalf("newHTTPServer error = %v", err)
	}
	if server.ReadHeaderTimeout != 7*time.Second {
		t.Fatalf("ReadHeaderTimeout = %s", server.ReadHeaderTimeout)
	}
	if server.ReadTimeout != 31*time.Second {
		t.Fatalf("ReadTimeout = %s", server.ReadTimeout)
	}
	if server.WriteTimeout != 61*time.Second {
		t.Fatalf("WriteTimeout = %s", server.WriteTimeout)
	}
	if server.IdleTimeout != 121*time.Second {
		t.Fatalf("IdleTimeout = %s", server.IdleTimeout)
	}
}

func TestNewHTTPServerRejectsInvalidTimeout(t *testing.T) {
	t.Setenv("HTTP_READ_HEADER_TIMEOUT", "not-a-duration")

	if _, err := newHTTPServer(":0", http.NewServeMux()); err == nil {
		t.Fatalf("newHTTPServer accepted invalid timeout")
	}
}

func setValidProductionEnv(t *testing.T) {
	t.Helper()
	t.Setenv("SERVER_MODE", "production")
	t.Setenv("DATABASE_URL", "postgres://prod_user:prod_password@db.example.com:5432/plystra?sslmode=require")
	t.Setenv("PLYSTRA_SESSION_SECRET", "production-session-secret-at-least-32-characters")
	t.Setenv("PLYSTRA_API_KEY_SECRET", "production-api-key-secret-at-least-32-characters")
	t.Setenv("CORS_ALLOWED_ORIGINS", "https://console.example.com")
	t.Setenv("SERVER_PUBLIC_URL", "https://plystra.example.com")
	t.Setenv("PLYSTRA_EMAIL_CAPABILITY_URL", "https://email-capability.example.com/contract/v1/email/send")
	t.Setenv("PLYSTRA_EMAIL_CAPABILITY_TOKEN", "production-email-capability-token-at-least-32-characters")
	t.Setenv("PLYSTRA_AUTH_EMAIL_FROM", "no-reply@example.com")
}
