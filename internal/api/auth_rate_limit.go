package api

import (
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultLoginFailureLimit   = 8
	defaultLoginFailureWindow  = 15 * time.Minute
	defaultLoginFailureLockout = 15 * time.Minute
)

type loginAttemptLimiter struct {
	mu      sync.Mutex
	records map[string]loginAttemptRecord
	limit   int
	window  time.Duration
	lockout time.Duration
	now     func() time.Time
}

type loginAttemptRecord struct {
	Failures    int
	WindowStart time.Time
	LockedUntil time.Time
	LastSeen    time.Time
}

func newLoginAttemptLimiterFromEnv() *loginAttemptLimiter {
	return &loginAttemptLimiter{
		records: map[string]loginAttemptRecord{},
		limit:   intEnv("PLYSTRA_AUTH_LOGIN_MAX_FAILURES", defaultLoginFailureLimit),
		window:  durationEnv("PLYSTRA_AUTH_LOGIN_WINDOW", defaultLoginFailureWindow),
		lockout: durationEnv("PLYSTRA_AUTH_LOGIN_LOCKOUT", defaultLoginFailureLockout),
		now:     time.Now,
	}
}

func (l *loginAttemptLimiter) retryAfter(keys []string) time.Duration {
	if l == nil {
		return 0
	}
	now := l.now().UTC()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneLocked(now)
	var longest time.Duration
	for _, key := range keys {
		record, ok := l.records[key]
		if !ok || !record.LockedUntil.After(now) {
			continue
		}
		remaining := record.LockedUntil.Sub(now)
		if remaining > longest {
			longest = remaining
		}
	}
	return longest
}

func (l *loginAttemptLimiter) recordFailure(keys []string) time.Duration {
	return l.recordAttempt(keys, l.limit)
}

func (l *loginAttemptLimiter) recordAttempt(keys []string, limit int) time.Duration {
	if l == nil {
		return 0
	}
	if limit < 1 {
		limit = l.limit
	}
	now := l.now().UTC()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneLocked(now)
	var longest time.Duration
	for _, key := range keys {
		record := l.records[key]
		if record.WindowStart.IsZero() || now.Sub(record.WindowStart) > l.window {
			record = loginAttemptRecord{WindowStart: now}
		}
		record.Failures++
		record.LastSeen = now
		if record.Failures >= limit {
			record.LockedUntil = now.Add(l.lockout)
		}
		l.records[key] = record
		if record.LockedUntil.After(now) {
			remaining := record.LockedUntil.Sub(now)
			if remaining > longest {
				longest = remaining
			}
		}
	}
	return longest
}

func (l *loginAttemptLimiter) reset(keys []string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, key := range keys {
		delete(l.records, key)
	}
}

func (l *loginAttemptLimiter) pruneLocked(now time.Time) {
	for key, record := range l.records {
		if !record.LockedUntil.IsZero() && record.LockedUntil.Before(now) {
			delete(l.records, key)
			continue
		}
		if record.LockedUntil.IsZero() && now.Sub(record.LastSeen) > 2*l.window {
			delete(l.records, key)
		}
	}
}

func loginThrottleKeys(email string, r *http.Request) []string {
	normalizedEmail := normalizeEmail(email)
	ip := remoteIPFrom(r)
	keys := make([]string, 0, 2)
	if normalizedEmail != "" {
		keys = append(keys, "email:"+normalizedEmail)
	}
	if strings.TrimSpace(ip) != "" {
		keys = append(keys, "ip:"+strings.TrimSpace(ip))
	}
	return keys
}

func intEnv(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1 {
		return fallback
	}
	return parsed
}

func durationEnv(key string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err == nil && parsed > 0 {
		return parsed
	}
	minutes, err := strconv.Atoi(value)
	if err != nil || minutes < 1 {
		return fallback
	}
	return time.Duration(minutes) * time.Minute
}
