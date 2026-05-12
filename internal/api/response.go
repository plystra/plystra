package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/plystra/plystra/internal/authz"
)

func writeData(w http.ResponseWriter, r *http.Request, status int, data any) {
	requestID := requestIDFrom(r)
	writeJSON(w, status, map[string]any{
		"data":       data,
		"request_id": requestID,
	})
}

func writeList(w http.ResponseWriter, r *http.Request, status int, data any, limit int) {
	requestID := requestIDFrom(r)
	writeJSON(w, status, map[string]any{
		"data": data,
		"pagination": map[string]any{
			"limit":    limit,
			"cursor":   nil,
			"has_more": false,
		},
		"request_id": requestID,
	})
}

func writeError(w http.ResponseWriter, r *http.Request, status int, code, message string, details any) {
	requestID := requestIDFrom(r)
	w.Header().Set("X-Plystra-Error-Code", code)
	errPayload := map[string]any{
		"code":       code,
		"message":    message,
		"details":    details,
		"request_id": requestID,
	}
	if decision, ok := authzDecisionFromDetails(details); ok {
		if decision.DenyCode != nil {
			errPayload["deny_code"] = string(*decision.DenyCode)
		}
		if decision.TraceID != "" {
			errPayload["trace_id"] = decision.TraceID
		}
		if decision.Audit.ID != "" {
			errPayload["audit_log_id"] = decision.Audit.ID
		}
		w.Header().Set("X-Plystra-Trace-ID", decision.TraceID)
		if decision.Audit.ID != "" {
			w.Header().Set("X-Plystra-Audit-Log-ID", decision.Audit.ID)
		}
	}
	writeJSON(w, status, map[string]any{
		"error":      errPayload,
		"request_id": requestID,
	})
}

func authzDecisionFromDetails(details any) (*authz.Decision, bool) {
	switch typed := details.(type) {
	case *authz.Decision:
		if typed == nil {
			return nil, false
		}
		return typed, true
	case authz.Decision:
		return &typed, true
	default:
		return nil, false
	}
}

func writeMethodNotAllowed(w http.ResponseWriter, r *http.Request) {
	writeError(w, r, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "HTTP method is not allowed for this endpoint.", nil)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func limitFrom(r *http.Request, fallback int) int {
	if raw := r.URL.Query().Get("limit"); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err == nil && limit > 0 && limit <= 200 {
			return limit
		}
	}
	return fallback
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func derefString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func nonNilMap(value map[string]any) map[string]any {
	if value == nil {
		return map[string]any{}
	}
	return value
}

func decodeJSON(w http.ResponseWriter, r *http.Request, out any) bool {
	if err := json.NewDecoder(r.Body).Decode(out); err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Request body is invalid JSON.", err.Error())
		return false
	}
	return true
}
