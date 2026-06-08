package api

import (
	"context"
	"fmt"
	"time"

	coreent "github.com/plystra/core/ent"
	entcapabilitygrant "github.com/plystra/core/ent/capabilitygrant"
)

const defaultCapabilityGrantReconcileBatchLimit = 100

type CapabilityGrantReconcileResult struct {
	Scanned int
	Marked  int
}

func (s *Server) ReconcileCapabilityGrantOutcomes(ctx context.Context, now time.Time, limit int) (CapabilityGrantReconcileResult, error) {
	if s == nil || s.ent == nil {
		return CapabilityGrantReconcileResult{}, fmt.Errorf("ent client is not configured")
	}
	if limit <= 0 {
		limit = defaultCapabilityGrantReconcileBatchLimit
	}
	now = now.UTC()
	rows, err := s.ent.CapabilityGrant.Query().
		Where(
			entcapabilitygrant.Status("active"),
			entcapabilitygrant.OutcomeStatus("pending"),
			entcapabilitygrant.ExpectedOutcomeByLTE(now),
		).
		Order(entcapabilitygrant.ByExpectedOutcomeBy()).
		Limit(limit).
		All(ctx)
	if err != nil {
		return CapabilityGrantReconcileResult{}, err
	}
	result := CapabilityGrantReconcileResult{Scanned: len(rows)}
	for _, row := range rows {
		updated, marked, err := s.markCapabilityGrantOutcomeMissing(ctx, row, now)
		if err != nil {
			return result, err
		}
		if !marked {
			continue
		}
		result.Marked++
		s.recordCapabilityGrantSystemAudit(ctx, updated, "capability.outcome.missing", "Capability outcome receipt missing after expected outcome window")
	}
	return result, nil
}

func (s *Server) markCapabilityGrantOutcomeMissing(ctx context.Context, row *coreent.CapabilityGrant, now time.Time) (*coreent.CapabilityGrant, bool, error) {
	if row == nil {
		return nil, false, nil
	}
	metadata := nonNilMap(row.Metadata)
	metadata["outcome"] = map[string]any{
		"status":              "missing",
		"outcome_event_id":    "missing_" + row.ID,
		"finished_at":         now.UTC().Format(time.RFC3339),
		"expected_outcome_by": row.ExpectedOutcomeBy.UTC().Format(time.RFC3339),
		"reconciled_by":       "core_capability_grant_reconciler",
	}
	updated, err := s.ent.CapabilityGrant.Update().
		Where(
			entcapabilitygrant.ID(row.ID),
			entcapabilitygrant.Status("active"),
			entcapabilitygrant.OutcomeStatus("pending"),
			entcapabilitygrant.ExpectedOutcomeByLTE(now.UTC()),
		).
		SetStatus("expired").
		SetOutcomeStatus("missing").
		SetMetadata(metadata).
		Save(ctx)
	if err != nil {
		return nil, false, err
	}
	if updated == 0 {
		return row, false, nil
	}
	fresh, err := s.ent.CapabilityGrant.Query().Where(entcapabilitygrant.ID(row.ID)).Only(ctx)
	if err != nil {
		return nil, false, err
	}
	return fresh, true, nil
}

func (s *Server) recordCapabilityGrantSystemAudit(ctx context.Context, row *coreent.CapabilityGrant, action, reason string) {
	if row == nil || s.ent == nil {
		return
	}
	actor := authzActorFromCapabilityGrant(row)
	trace := map[string]any{
		"trace_version":       traceVersion(),
		"decision":            "allow",
		"reason":              reason,
		"capability":          row.Capability,
		"operation":           row.Operation,
		"caller_plugin":       row.CallerPluginID,
		"target":              row.TargetProviderID,
		"grant_id":            row.ID,
		"outcome_status":      row.OutcomeStatus,
		"expected_outcome_by": row.ExpectedOutcomeBy.UTC().Format(time.RFC3339),
		"created_at":          time.Now().UTC().Format(time.RFC3339),
	}
	_, _ = s.ent.AuditLog.Create().
		SetID(newEntityID("audit")).
		SetSpaceID(row.SpaceID).
		SetNillableActorUserID(optionalString(actor.UserID)).
		SetNillableActorMemberID(optionalString(actor.MemberID)).
		SetNillableActorUserMemberID(optionalString(actor.UserMemberID)).
		SetAction(action).
		SetResourceType("capability_grant").
		SetResourceID(row.ID).
		SetDecision("allow").
		SetTrace(trace).
		Save(ctx)
}
