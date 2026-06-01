package api

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestOpenAPIDocumentsReleaseRoutesAndEnvelope(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "openapi", "plystra.v0.0.1.json"))
	if err != nil {
		t.Fatalf("read OpenAPI: %v", err)
	}
	var doc struct {
		Paths      map[string]any `json:"paths"`
		Components struct {
			Schemas map[string]struct {
				Properties map[string]any `json:"properties"`
			} `json:"schemas"`
			SecuritySchemes map[string]any `json:"securitySchemes"`
		} `json:"components"`
		Tags      []map[string]any `json:"tags"`
		TagGroups []struct {
			Name string   `json:"name"`
			Tags []string `json:"tags"`
		} `json:"x-tagGroups"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode OpenAPI: %v", err)
	}

	requiredPaths := []string{
		"/api/v1/health",
		"/api/v1/ready",
		"/api/v1/version",
		"/api/v1/auth/register",
		"/api/v1/auth/login",
		"/api/v1/admin/me",
		"/api/v1/admin/grants",
		"/api/v1/api-keys",
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
		"/api/v1/spaces/{space_id}/role-permissions",
		"/api/v1/resource-types",
		"/api/v1/resources",
		"/api/v1/spaces/{space_id}/resources",
		"/api/v1/spaces/{space_id}/data/models",
		"/api/v1/spaces/{space_id}/data/records/batch",
		"/api/v1/spaces/{space_id}/data/models/{model_key}/records",
		"/api/v1/app-data/{model_key}/{record_id}",
		"/api/v1/audit/logs",
		"/api/v1/spaces/{space_id}/audit-logs",
	}
	for _, path := range requiredPaths {
		if _, ok := doc.Paths[path]; !ok {
			t.Fatalf("OpenAPI path %s is missing", path)
		}
	}

	envelopeFound := false
	for name, schema := range doc.Components.Schemas {
		if _, hasData := schema.Properties["data"]; hasData {
			if _, hasRequestID := schema.Properties["request_id"]; !hasRequestID {
				continue
			}
			envelopeFound = true
			if _, ok := schema.Properties["meta"]; ok {
				t.Fatalf("%s.meta must not be documented", name)
			}
		}
	}
	if !envelopeFound {
		t.Fatalf("OpenAPI response envelope schemas are missing")
	}
	errEnvelope := doc.Components.Schemas["ApiOpenAPIErrorEnvelope"].Properties
	if _, ok := errEnvelope["request_id"]; !ok {
		t.Fatalf("ErrorEnvelope.request_id is missing")
	}
	if _, ok := errEnvelope["meta"]; ok {
		t.Fatalf("ErrorEnvelope.meta must not be documented")
	}
	if _, ok := doc.Components.SecuritySchemes["BearerAuth"]; !ok {
		t.Fatalf("OpenAPI BearerAuth security scheme is missing")
	}
	if _, ok := doc.Components.SecuritySchemes["ApiKeyAuth"]; !ok {
		t.Fatalf("OpenAPI ApiKeyAuth security scheme is missing")
	}
	if len(doc.Tags) == 0 {
		t.Fatalf("OpenAPI tags are missing")
	}
	if len(doc.TagGroups) == 0 {
		t.Fatalf("OpenAPI x-tagGroups are missing")
	}

	requestBodyPaths := map[string]string{
		"POST /api/v1/auth/register":                            "/api/v1/auth/register",
		"POST /api/v1/auth/login":                               "/api/v1/auth/login",
		"POST /api/v1/authz/check":                              "/api/v1/authz/check",
		"POST /api/v1/users":                                    "/api/v1/users",
		"PATCH /api/v1/users/{user_id}":                         "/api/v1/users/{user_id}",
		"POST /api/v1/api-keys":                                 "/api/v1/api-keys",
		"POST /api/v1/admin/grants":                             "/api/v1/admin/grants",
		"POST /api/v1/resource-types":                           "/api/v1/resource-types",
		"POST /api/v1/plugins/install":                          "/api/v1/plugins/install",
		"POST /api/v1/templates/{template_id}/install":          "/api/v1/templates/{template_id}/install",
		"POST /api/v1/spaces/{space_id}/data/records/batch":     "/api/v1/spaces/{space_id}/data/records/batch",
		"PATCH /api/v1/data/rows/{resource_type}/{resource_id}": "/api/v1/data/rows/{resource_type}/{resource_id}",
	}
	for label, path := range requestBodyPaths {
		method := label[:4]
		if method == "PATC" {
			method = "patch"
		} else {
			method = "post"
		}
		op, ok := doc.Paths[path].(map[string]any)
		if !ok {
			t.Fatalf("OpenAPI path %s is not an object", path)
		}
		methodDoc, ok := op[method].(map[string]any)
		if !ok {
			t.Fatalf("OpenAPI operation %s is missing", label)
		}
		if _, ok := methodDoc["requestBody"]; !ok {
			t.Fatalf("OpenAPI operation %s is missing requestBody", label)
		}
	}
}

func TestOpenAPIArtifactIsGenerated(t *testing.T) {
	spec, err := GenerateOpenAPI(OpenAPIVersion)
	if err != nil {
		t.Fatalf("generate OpenAPI: %v", err)
	}
	generated, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		t.Fatalf("marshal generated OpenAPI: %v", err)
	}
	generated = append(generated, '\n')
	committed, err := os.ReadFile(filepath.Join("..", "..", "openapi", "plystra.v0.0.1.json"))
	if err != nil {
		t.Fatalf("read OpenAPI: %v", err)
	}
	if !reflect.DeepEqual(generated, committed) {
		t.Fatalf("OpenAPI JSON is stale; run go run ./cmd/plystra-openapi -out openapi")
	}
}
