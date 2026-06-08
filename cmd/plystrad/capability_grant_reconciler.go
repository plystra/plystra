package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/plystra/core/internal/api"
)

const (
	defaultCapabilityGrantReconcilerInterval = 30 * time.Second
	defaultCapabilityGrantReconcilerBatch    = 100
)

func startCapabilityGrantReconciler(ctx context.Context, server *api.Server) {
	if !capabilityGrantReconcilerEnabled() {
		return
	}
	interval, err := durationFromEnv("PLYSTRA_CAPABILITY_GRANT_RECONCILE_INTERVAL", defaultCapabilityGrantReconcilerInterval)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid capability grant reconciler interval: %v\n", err)
		return
	}
	batch := intFromEnv("PLYSTRA_CAPABILITY_GRANT_RECONCILE_BATCH", defaultCapabilityGrantReconcilerBatch)
	go runCapabilityGrantReconciler(ctx, server, interval, batch)
}

func runCapabilityGrantReconciler(ctx context.Context, server *api.Server, interval time.Duration, batch int) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	reconcileOnce := func() {
		runCtx, cancel := context.WithTimeout(ctx, interval)
		defer cancel()
		result, err := server.ReconcileCapabilityGrantOutcomes(runCtx, time.Now().UTC(), batch)
		if err != nil {
			fmt.Fprintf(os.Stderr, "capability grant reconciler: %v\n", err)
			return
		}
		if result.Marked > 0 {
			fmt.Fprintf(os.Stderr, "capability grant reconciler marked %d missing outcome(s)\n", result.Marked)
		}
	}
	reconcileOnce()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			reconcileOnce()
		}
	}
}

func capabilityGrantReconcilerEnabled() bool {
	value := strings.TrimSpace(os.Getenv("PLYSTRA_CAPABILITY_GRANT_RECONCILER_ENABLED"))
	if value == "" {
		return true
	}
	switch strings.ToLower(value) {
	case "0", "false", "no", "off", "disabled":
		return false
	default:
		return true
	}
}

func intFromEnv(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}
