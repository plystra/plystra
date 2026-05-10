package main

import (
	"strings"
	"testing"
)

func TestValidateProductionConfigRejectsWildcardCORS(t *testing.T) {
	setValidProductionEnv(t)
	t.Setenv("CORS_ALLOWED_ORIGINS", "*")

	err := validateProductionConfig()
	if err == nil || !strings.Contains(err.Error(), "CORS_ALLOWED_ORIGINS") {
		t.Fatalf("validateProductionConfig error = %v, want CORS wildcard rejection", err)
	}
}

func TestValidateProductionConfigAcceptsSessionSecretAlias(t *testing.T) {
	setValidProductionEnv(t)
	t.Setenv("JWT_SECRET", defaultJWTSecret)

	if err := validateProductionConfig(); err != nil {
		t.Fatalf("validateProductionConfig rejected PLYSTRA_SESSION_SECRET alias: %v", err)
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

func setValidProductionEnv(t *testing.T) {
	t.Helper()
	t.Setenv("SERVER_MODE", "production")
	t.Setenv("DATABASE_URL", "postgres://prod_user:prod_password@db.example.com:5432/plystra?sslmode=require")
	t.Setenv("PLYSTRA_SESSION_SECRET", "production-session-secret-at-least-32-characters")
	t.Setenv("CORS_ALLOWED_ORIGINS", "https://console.example.com")
	t.Setenv("SERVER_PUBLIC_URL", "https://plystra.example.com")
}
