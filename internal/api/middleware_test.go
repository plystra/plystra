package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestResponseEnvelopeRequestIDCompatibility(t *testing.T) {
	handler := requestMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeData(w, r, http.StatusOK, map[string]any{"ok": true})
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	req.Header.Set("X-Request-ID", "req_test_envelope")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["request_id"] != "req_test_envelope" {
		t.Fatalf("request_id = %v", body["request_id"])
	}
	meta, ok := body["meta"].(map[string]any)
	if !ok {
		t.Fatalf("meta missing or wrong type: %T", body["meta"])
	}
	if meta["request_id"] != body["request_id"] {
		t.Fatalf("meta.request_id = %v, want %v", meta["request_id"], body["request_id"])
	}
}

func TestErrorEnvelopeIncludesMetaRequestID(t *testing.T) {
	handler := requestMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "bad request", nil)
	}))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users", nil)
	req.Header.Set("X-Request-ID", "req_test_error")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["request_id"] != "req_test_error" {
		t.Fatalf("request_id = %v", body["request_id"])
	}
	meta := body["meta"].(map[string]any)
	if meta["request_id"] != body["request_id"] {
		t.Fatalf("meta.request_id = %v, want %v", meta["request_id"], body["request_id"])
	}
}

func TestRecoveryHidesPanicDetailsInProduction(t *testing.T) {
	t.Setenv("SERVER_MODE", "production")
	handler := requestMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("secret panic detail")
	}))
	req := httptest.NewRequest(http.MethodGet, "/panic", nil)
	req.Header.Set("X-Request-ID", "req_test_panic")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	var body struct {
		Error struct {
			Details any `json:"details"`
		} `json:"error"`
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.RequestID != "req_test_panic" {
		t.Fatalf("request_id = %s", body.RequestID)
	}
	if body.Error.Details != nil {
		t.Fatalf("panic details leaked in production: %v", body.Error.Details)
	}
}

func TestStructuredLogContainsReleaseFields(t *testing.T) {
	t.Setenv("LOG_FORMAT", "json")
	oldStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = writer
	defer func() { os.Stdout = oldStdout }()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	req = req.WithContext(context.WithValue(req.Context(), requestIDKey, "req_test_log"))
	req.RemoteAddr = "192.0.2.10:1234"
	req.Header.Set("User-Agent", "plystra-test")
	logHTTPRequest(req, http.Header{}, http.StatusOK, 42, 3*time.Millisecond, "")
	_ = writer.Close()

	var entry map[string]any
	if err := json.NewDecoder(reader).Decode(&entry); err != nil {
		t.Fatalf("decode log entry: %v", err)
	}
	for _, field := range []string{"timestamp", "level", "request_id", "method", "path", "status", "latency_ms", "remote_ip", "user_agent"} {
		if _, ok := entry[field]; !ok {
			t.Fatalf("log field %s missing in %#v", field, entry)
		}
	}
	if entry["request_id"] != "req_test_log" {
		t.Fatalf("request_id = %v", entry["request_id"])
	}
}
