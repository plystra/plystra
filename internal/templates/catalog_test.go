package templates

import "testing"

func TestCatalogIncludesAuthReadySaaSWithEmailCapability(t *testing.T) {
	tpl, ok := ByID("auth-ready-saas")
	if !ok {
		t.Fatalf("auth-ready-saas template is missing")
	}
	if len(tpl.RequiredCapabilities) != 1 {
		t.Fatalf("RequiredCapabilities length = %d, want 1", len(tpl.RequiredCapabilities))
	}
	req := tpl.RequiredCapabilities[0]
	if req.ID != "email.transactional" || req.MinLevel != "standard" {
		t.Fatalf("unexpected capability requirement: %#v", req)
	}
	if len(tpl.RequiredPlugins) != 1 || tpl.RequiredPlugins[0] != "plystra.auth_complete" {
		t.Fatalf("unexpected required plugins: %#v", tpl.RequiredPlugins)
	}
}
