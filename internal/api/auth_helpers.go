package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	minPasswordLength     = 12
	maxPasswordByteLength = 1024
)

const dummyPasswordHash = "argon2id$v=19$m=65536,t=3,p=2$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func normalizeEmail(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func validatePlaintextPassword(password string) (string, bool) {
	if strings.TrimSpace(password) == "" {
		return "password must not be empty.", false
	}
	if len(password) < intEnv("PLYSTRA_PASSWORD_MIN_LENGTH", minPasswordLength) {
		return "password must be at least " + strconv.Itoa(intEnv("PLYSTRA_PASSWORD_MIN_LENGTH", minPasswordLength)) + " characters.", false
	}
	if len(password) > maxPasswordByteLength {
		return "password is too long.", false
	}
	return "", true
}

func consumePasswordCheck(password string) {
	_ = verifyPassword(password, dummyPasswordHash)
}

func (s *Server) recordLoginFailure(w http.ResponseWriter, r *http.Request, throttleKeys []string) {
	retryAfter := s.authLimiter.recordFailure(throttleKeys)
	if retryAfter > 0 {
		writeAuthRateLimited(w, r, retryAfter)
		return
	}
	writeError(w, r, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED", "Email or password is incorrect.", nil)
}

func writeAuthRateLimited(w http.ResponseWriter, r *http.Request, retryAfter time.Duration) {
	seconds := int(retryAfter.Seconds())
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	writeError(w, r, http.StatusTooManyRequests, "AUTH_RATE_LIMITED", "Too many failed login attempts. Try again later.", map[string]any{
		"retry_after_seconds": seconds,
	})
}
