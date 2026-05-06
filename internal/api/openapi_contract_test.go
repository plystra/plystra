package api

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenAPIDocumentsReleaseRoutesAndEnvelope(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "openapi", "plystra.v1.0.0.json"))
	if err != nil {
		t.Fatalf("read OpenAPI: %v", err)
	}
	var doc struct {
		Paths      map[string]any `json:"paths"`
		Components struct {
			Schemas map[string]struct {
				Properties map[string]any `json:"properties"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode OpenAPI: %v", err)
	}

	requiredPaths := []string{
		"/api/v1/health",
		"/api/v1/ready",
		"/api/v1/version",
		"/system/health",
		"/api/v1/authz/check",
		"/api/v1/authz/explain",
		"/api/v1/users",
		"/api/v1/spaces",
		"/api/v1/spaces/{space_id}/groups",
		"/api/v1/spaces/{space_id}/members",
		"/api/v1/spaces/{space_id}/user-members",
		"/api/v1/spaces/{space_id}/roles",
		"/api/v1/permissions",
		"/api/v1/spaces/{space_id}/member-roles",
		"/api/v1/role-permissions",
		"/api/v1/resource-types",
		"/api/v1/resources",
		"/api/v1/spaces/{space_id}/resources",
		"/api/v1/audit-logs",
		"/api/v1/spaces/{space_id}/audit-logs",
	}
	for _, path := range requiredPaths {
		if _, ok := doc.Paths[path]; !ok {
			t.Fatalf("OpenAPI path %s is missing", path)
		}
	}

	envelope := doc.Components.Schemas["Envelope"].Properties
	if _, ok := envelope["request_id"]; !ok {
		t.Fatalf("Envelope.request_id is missing")
	}
	if _, ok := envelope["meta"]; !ok {
		t.Fatalf("Envelope.meta is missing")
	}
	errEnvelope := doc.Components.Schemas["ErrorEnvelope"].Properties
	if _, ok := errEnvelope["request_id"]; !ok {
		t.Fatalf("ErrorEnvelope.request_id is missing")
	}
	if _, ok := errEnvelope["meta"]; !ok {
		t.Fatalf("ErrorEnvelope.meta is missing")
	}
}
