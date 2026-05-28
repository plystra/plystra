package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type contextKey string

const (
	requestIDKey       contextKey = "request_id"
	adminPrincipalKey  contextKey = "admin_principal"
	maxRequestIDLength            = 128
	defaultCORSOrigins            = "http://localhost:3000,http://localhost:5173,http://localhost:8080,http://127.0.0.1:3000,http://127.0.0.1:5173,http://127.0.0.1:8080"
)

func (s *Server) requestMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		setSecurityHeaders(w.Header())
		origin := allowedCORSOrigin(r)
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
		}
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Request-ID, X-Plystra-Metrics-Token, X-Plystra-API-Key")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
		requestID := normalizeRequestID(r.Header.Get(requestIDHeader()))
		if requestID == "" {
			requestID = newRequestID()
		}
		w.Header().Set(requestIDHeader(), requestID)
		ctxReq := r.WithContext(context.WithValue(r.Context(), requestIDKey, requestID))
		defer func() {
			if recovered := recover(); recovered != nil {
				if !recorder.wrote {
					writeError(recorder, ctxReq, http.StatusInternalServerError, "INTERNAL_ERROR", "Request handling failed.", safePanicDetails(recovered))
				}
				logHTTPRequest(ctxReq, recorder.Header(), recorder.status, recorder.bytes, time.Since(start), "INTERNAL_ERROR")
				return
			}
			logHTTPRequest(ctxReq, recorder.Header(), recorder.status, recorder.bytes, time.Since(start), w.Header().Get("X-Plystra-Error-Code"))
		}()
		if r.Method == http.MethodOptions {
			recorder.WriteHeader(http.StatusNoContent)
			return
		}
		if !publicRoute(ctxReq) {
			requirement := adminRequirementFor(ctxReq.Method, ctxReq.URL.Path, ctxReq.URL.Query().Get("space_id"))
			principal, allowed, err := s.adminCredentialAllowed(ctxReq.Context(), ctxReq, requirement)
			if errors.Is(err, pgx.ErrNoRows) {
				writeError(recorder, ctxReq, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED", "A valid access token or API key is required.", nil)
				return
			}
			if err != nil {
				writeError(recorder, ctxReq, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to evaluate admin permissions.", err.Error())
				return
			}
			if !allowed {
				writeError(recorder, ctxReq, http.StatusForbidden, "ADMIN_PERMISSION_REQUIRED", "The current user does not have the required admin permission.", map[string]any{"permission": requirement.PermissionKey})
				return
			}
			ctxReq = ctxReq.WithContext(context.WithValue(ctxReq.Context(), adminPrincipalKey, principal))
		}
		next.ServeHTTP(recorder, ctxReq)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
	wrote  bool
}

func (r *statusRecorder) WriteHeader(status int) {
	if r.wrote {
		return
	}
	r.status = status
	r.wrote = true
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Write(data []byte) (int, error) {
	if !r.wrote {
		r.WriteHeader(r.status)
	}
	n, err := r.ResponseWriter.Write(data)
	r.bytes += n
	return n, err
}

func requestIDHeader() string {
	if value := os.Getenv("REQUEST_ID_HEADER"); value != "" {
		return value
	}
	return "X-Request-ID"
}

func allowedCORSOrigin(r *http.Request) string {
	configured := os.Getenv("CORS_ALLOWED_ORIGINS")
	if configured == "" {
		configured = defaultCORSOrigins
	}
	origin := r.Header.Get("Origin")
	for _, allowed := range strings.Split(configured, ",") {
		allowed = strings.TrimSpace(allowed)
		if allowed == "*" {
			return "*"
		}
		if origin != "" && allowed == origin {
			return origin
		}
	}
	return ""
}

func setSecurityHeaders(headers http.Header) {
	headers.Set("X-Content-Type-Options", "nosniff")
	headers.Set("X-Frame-Options", "DENY")
	headers.Set("Referrer-Policy", "no-referrer")
	headers.Set("Cache-Control", "no-store")
}

func normalizeRequestID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxRequestIDLength {
		return ""
	}
	for _, char := range value {
		if char < 33 || char > 126 || char == '"' || char == '\'' || char == '\\' {
			return ""
		}
	}
	return value
}

func publicRoute(r *http.Request) bool {
	if r.Method == http.MethodOptions {
		return true
	}
	path := r.URL.Path
	if r.Method == http.MethodGet {
		switch path {
		case "/api/v1/health", "/api/v1/ready", "/api/v1/version", "/metrics":
			return true
		}
	}
	if r.Method == http.MethodPost {
		switch path {
		case "/api/v1/auth/register", "/api/v1/auth/login", "/api/v1/auth/refresh", "/api/v1/auth/logout":
			return true
		case "/api/v1/actor/switch-member":
			return true
		}
	}
	return r.Method == http.MethodGet && path == "/api/v1/actor/context"
}

func (s *Server) metricsAuthorized(r *http.Request) bool {
	configured := firstEnv("METRICS_TOKEN", "PLYSTRA_METRICS_TOKEN")
	if configured != "" {
		for _, provided := range []string{
			strings.TrimSpace(r.Header.Get("X-Plystra-Metrics-Token")),
			strings.TrimSpace(r.Header.Get("X-Metrics-Token")),
			bearerToken(r),
		} {
			if constantTimeStringEqual(provided, configured) {
				return true
			}
		}
		return false
	}
	_, allowed, err := s.adminCredentialAllowed(r.Context(), r, adminRequirement{PermissionKey: "metrics:read"})
	return err == nil && allowed
}

func constantTimeStringEqual(left, right string) bool {
	if left == "" || right == "" || len(left) != len(right) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func featureEnabled(key string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "on", "enabled":
		return true
	default:
		return false
	}
}

func logHTTPRequest(r *http.Request, headers http.Header, status, bytes int, latency time.Duration, errorCode string) {
	remoteIP := remoteIPFrom(r)
	if strings.EqualFold(os.Getenv("LOG_FORMAT"), "text") {
		fmt.Fprintf(os.Stdout, "timestamp=%s level=info request_id=%s method=%s path=%s status=%d latency_ms=%d remote_ip=%s user_agent=%q error_code=%s\n",
			time.Now().UTC().Format(time.RFC3339), requestIDFrom(r), r.Method, r.URL.Path, status, latency.Milliseconds(), remoteIP, r.UserAgent(), errorCode)
		return
	}
	entry := map[string]any{
		"timestamp":   time.Now().UTC().Format(time.RFC3339Nano),
		"level":       "info",
		"request_id":  requestIDFrom(r),
		"method":      r.Method,
		"path":        r.URL.Path,
		"status":      status,
		"status_code": status,
		"latency_ms":  latency.Milliseconds(),
		"remote_ip":   remoteIP,
		"user_agent":  r.UserAgent(),
		"bytes":       bytes,
	}
	if errorCode != "" {
		entry["error_code"] = errorCode
	}
	if traceID := headers.Get("X-Plystra-Trace-ID"); traceID != "" {
		entry["trace_id"] = traceID
	}
	if auditLogID := headers.Get("X-Plystra-Audit-Log-ID"); auditLogID != "" {
		entry["audit_log_id"] = auditLogID
	}
	_ = json.NewEncoder(os.Stdout).Encode(entry)
}

func remoteIPFrom(r *http.Request) string {
	remoteIP := directRemoteIP(r.RemoteAddr)
	if remoteIP == "" {
		remoteIP = strings.TrimSpace(r.RemoteAddr)
	}
	if trustedProxyIP(remoteIP, os.Getenv("TRUSTED_PROXIES")) {
		if forwarded := forwardedClientIP(r.Header.Get("X-Forwarded-For")); forwarded != "" {
			return forwarded
		}
		if realIP := validHeaderIP(r.Header.Get("X-Real-IP")); realIP != "" {
			return realIP
		}
	}
	return remoteIP
}

func directRemoteIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	host = strings.TrimSpace(host)
	if net.ParseIP(host) == nil {
		return ""
	}
	return host
}

func trustedProxyIP(remoteIP, configured string) bool {
	ip := net.ParseIP(strings.TrimSpace(remoteIP))
	if ip == nil || strings.TrimSpace(configured) == "" {
		return false
	}
	for _, entry := range strings.Split(configured, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if _, network, err := net.ParseCIDR(entry); err == nil {
			if network.Contains(ip) {
				return true
			}
			continue
		}
		if trustedIP := net.ParseIP(entry); trustedIP != nil && trustedIP.Equal(ip) {
			return true
		}
	}
	return false
}

func forwardedClientIP(value string) string {
	for _, part := range strings.Split(value, ",") {
		if ip := validHeaderIP(part); ip != "" {
			return ip
		}
	}
	return ""
}

func validHeaderIP(value string) string {
	value = strings.TrimSpace(value)
	if net.ParseIP(value) == nil {
		return ""
	}
	return value
}

func safePanicDetails(recovered any) any {
	if strings.EqualFold(firstEnv("SERVER_MODE", "PLYSTRA_ENV"), "production") {
		return nil
	}
	return fmt.Sprint(recovered)
}

func firstEnv(keys ...string) string {
	for _, key := range keys {
		if value := os.Getenv(key); value != "" {
			return value
		}
	}
	return ""
}

func requestIDFrom(r *http.Request) string {
	if value, ok := r.Context().Value(requestIDKey).(string); ok {
		return value
	}
	return newRequestID()
}
