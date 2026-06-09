package api

import (
	"context"
	"fmt"
	"time"

	coreent "github.com/plystra/core/ent"
	entactionexecution "github.com/plystra/core/ent/actionexecution"
)

const defaultActionExecutionReconcileBatchLimit = 100

type ActionExecutionReconcileResult struct {
	Scanned int
	Marked  int
}

func (s *Server) ReconcileActionExecutions(ctx context.Context, now time.Time, limit int) (ActionExecutionReconcileResult, error) {
	if s == nil || s.ent == nil {
		return ActionExecutionReconcileResult{}, fmt.Errorf("ent client is not configured")
	}
	if limit <= 0 {
		limit = defaultActionExecutionReconcileBatchLimit
	}
	now = now.UTC()
	rows, err := s.ent.ActionExecution.Query().
		Where(
			entactionexecution.StatusIn("running", "pending"),
			entactionexecution.TimeoutAtLTE(now),
		).
		Order(entactionexecution.ByTimeoutAt()).
		Limit(limit).
		All(ctx)
	if err != nil {
		return ActionExecutionReconcileResult{}, err
	}
	result := ActionExecutionReconcileResult{Scanned: len(rows)}
	for _, row := range rows {
		updated, marked, err := s.markActionExecutionResultUnknown(ctx, row, now)
		if err != nil {
			return result, err
		}
		if !marked {
			continue
		}
		result.Marked++
		s.recordActionExecutionSystemAudit(ctx, updated, "action_execution.result_unknown", "Action execution timed out before provider reported a terminal result")
	}
	return result, nil
}

func (s *Server) markActionExecutionResultUnknown(ctx context.Context, row *coreent.ActionExecution, now time.Time) (*coreent.ActionExecution, bool, error) {
	if row == nil {
		return nil, false, nil
	}
	metadata := nonNilMap(row.Metadata)
	metadata["result_unknown_reconciliation"] = map[string]any{
		"status":        "result_unknown",
		"timeout_at":    row.TimeoutAt.UTC().Format(time.RFC3339),
		"completed_at":  now.UTC().Format(time.RFC3339),
		"reconciled_by": "core_action_execution_reconciler",
	}
	updated, err := s.ent.ActionExecution.Update().
		Where(
			entactionexecution.ID(row.ID),
			entactionexecution.StatusIn("running", "pending"),
			entactionexecution.TimeoutAtLTE(now.UTC()),
		).
		SetStatus("result_unknown").
		SetCompletedAt(now.UTC()).
		SetErrorCode("ACTION_EXECUTION_TIMEOUT").
		SetErrorMessage("Action execution timed out before the provider reported a terminal result.").
		SetMetadata(metadata).
		Save(ctx)
	if err != nil {
		return nil, false, err
	}
	if updated == 0 {
		return row, false, nil
	}
	fresh, err := s.ent.ActionExecution.Query().Where(entactionexecution.ID(row.ID)).Only(ctx)
	if err != nil {
		return nil, false, err
	}
	return fresh, true, nil
}

func (s *Server) recordActionExecutionSystemAudit(ctx context.Context, row *coreent.ActionExecution, action, reason string) {
	if row == nil || s.ent == nil {
		return
	}
	actor := capabilityGrantPrincipal{
		UserID:       derefString(row.PrincipalUserID),
		MemberID:     derefString(row.PrincipalMemberID),
		UserMemberID: derefString(row.PrincipalUserMemberID),
	}
	trace := map[string]any{
		"trace_version":       traceVersion(),
		"decision":            "allow",
		"reason":              reason,
		"capability":          row.Capability,
		"operation":           row.Operation,
		"action_execution_id": row.ID,
		"executor_plugin":     row.ExecutorPluginID,
		"provider_plugin":     row.ProviderPluginID,
		"status":              row.Status,
		"timeout_at":          row.TimeoutAt.UTC().Format(time.RFC3339),
		"completed_at":        optionalTime(row.CompletedAt),
		"created_at":          time.Now().UTC().Format(time.RFC3339),
	}
	_, _ = s.ent.AuditLog.Create().
		SetID(newEntityID("audit")).
		SetSpaceID(row.SpaceID).
		SetNillableActorUserID(optionalString(actor.UserID)).
		SetNillableActorMemberID(optionalString(actor.MemberID)).
		SetNillableActorUserMemberID(optionalString(actor.UserMemberID)).
		SetAction(action).
		SetResourceType("action_execution").
		SetResourceID(row.ID).
		SetDecision("allow").
		SetTrace(trace).
		Save(ctx)
}
