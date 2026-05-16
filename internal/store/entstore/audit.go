package entstore

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/plystra/plystra/internal/authz"
	systemaudit "github.com/plystra/system-audit"
)

func (s *Store) WriteAuditLog(ctx context.Context, decision authz.Decision) error {
	if !shouldWriteAudit(decision) {
		return nil
	}
	rawTrace, err := decision.MarshalTraceJSON()
	if err != nil {
		return err
	}
	trace := map[string]any{}
	if err := json.Unmarshal(rawTrace, &trace); err != nil {
		return fmt.Errorf("decode audit trace snapshot: %w", err)
	}
	if err := systemaudit.RejectSensitiveFields(trace); err != nil {
		return fmt.Errorf("validate audit trace snapshot: %w", err)
	}

	var denyCode *string
	if decision.DenyCode != nil {
		value := string(*decision.DenyCode)
		denyCode = &value
	}
	requestID := nilIfEmpty(decision.Audit.RequestID)

	return s.client.AuditLog.Create().
		SetID(firstNonEmpty(decision.Audit.ID, newID("audit"))).
		SetSpaceID(decision.Audit.SpaceID).
		SetNillableActorUserID(nilIfEmpty(decision.Audit.ActorUserID)).
		SetNillableActorMemberID(nilIfEmpty(decision.Audit.ActorMemberID)).
		SetNillableActorUserMemberID(nilIfEmpty(decision.Audit.ActorUserMemberID)).
		SetAction(decision.Audit.Action).
		SetResourceType(decision.Audit.ResourceType).
		SetResourceID(decision.Audit.ResourceID).
		SetDecision(decision.Audit.Decision).
		SetNillableDenyCode(denyCode).
		SetTrace(trace).
		SetNillableRequestID(requestID).
		SetNillableIPAddress(nilIfEmpty(decision.Request.IP)).
		SetNillableUserAgent(nilIfEmpty(decision.Request.UserAgent)).
		Exec(ctx)
}

func shouldWriteAudit(decision authz.Decision) bool {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("AUDIT_WRITE_MODE")))
	if mode == "" {
		mode = "always"
	}
	switch mode {
	case "always":
		return true
	case "deny_only":
		return decision.Decision == authz.DecisionDeny
	case "manual", "disabled_for_dev":
		return false
	default:
		return true
	}
}
