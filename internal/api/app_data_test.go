package api

import (
	"strings"
	"testing"

	coreent "github.com/plystra/plystra/ent"
)

func TestAppDataMutationPolicyViolation(t *testing.T) {
	if got := appDataMutationPolicyViolation(&coreent.AppDataModel{}, "update", false); got != "" {
		t.Fatalf("model without policy should not be blocked: %q", got)
	}
	model := &coreent.AppDataModel{Metadata: map[string]any{"mutation_policy": appDataMutationPolicyServiceAppendOnly}}
	if got := appDataMutationPolicyViolation(model, "create", true); got != "" {
		t.Fatalf("service append-only create should be allowed: %q", got)
	}
	if got := appDataMutationPolicyViolation(model, "create", false); !strings.Contains(got, "service API key") {
		t.Fatalf("user create should require service key, got %q", got)
	}
	if got := appDataMutationPolicyViolation(model, "update", true); !strings.Contains(got, "only permits create") {
		t.Fatalf("update should be blocked, got %q", got)
	}
	unknown := &coreent.AppDataModel{Metadata: map[string]any{"mutation_policy": "locked"}}
	if got := appDataMutationPolicyViolation(unknown, "create", true); !strings.Contains(got, "not supported") {
		t.Fatalf("unknown policy should be blocked, got %q", got)
	}
}

func TestAppDataBatchOperationServiceAuthorized(t *testing.T) {
	appendOnly := &coreent.AppDataModel{Metadata: map[string]any{"mutation_policy": appDataMutationPolicyServiceAppendOnly}}
	normal := &coreent.AppDataModel{}

	if !appDataBatchOperationServiceAuthorized(normal, appDataRecordBatchOperation{Operation: "update"}, appDataBatchServiceAuthorization{PrimaryManage: true}) {
		t.Fatal("primary service authorization should allow any batch operation")
	}
	if !appDataBatchOperationServiceAuthorized(appendOnly, appDataRecordBatchOperation{Operation: "CREATE"}, appDataBatchServiceAuthorization{SecondaryAppendOnlyCreate: true}) {
		t.Fatal("secondary service authorization should allow append-only creates")
	}
	if appDataBatchOperationServiceAuthorized(appendOnly, appDataRecordBatchOperation{Operation: "update"}, appDataBatchServiceAuthorization{SecondaryAppendOnlyCreate: true}) {
		t.Fatal("secondary service authorization must not allow append-only updates")
	}
	if appDataBatchOperationServiceAuthorized(normal, appDataRecordBatchOperation{Operation: "create"}, appDataBatchServiceAuthorization{SecondaryAppendOnlyCreate: true}) {
		t.Fatal("secondary service authorization must not allow normal model creates")
	}
}
