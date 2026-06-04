package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	coreent "github.com/plystra/core/ent"
	entcapabilitygrant "github.com/plystra/core/ent/capabilitygrant"
)

// capabilityGrantSubtreeLimit bounds how many descendant grants a single
// parent_grant_id revocation will traverse, protecting Core against an
// adversarially deep or wide lineage tree.
const capabilityGrantSubtreeLimit = 5000

// capabilityGrantRevokeRequest revokes one or more capability grants.
//
// Revocation is the defining property of a revocable mediated grant: because B
// introspects every grant before executing, a Core-side revocation is
// effectively immediate. Per technical-architecture.en.md §II.12 / §II.15
// rule 16, grants are revocable by exactly one of: grant_id, member_id,
// parent_grant_id (the grant and its descendant lineage), or a stale provider
// binding_epoch.
type capabilityGrantRevokeRequest struct {
	SpaceID          string `json:"space_id"`
	GrantID          string `json:"grant_id,omitempty"`
	MemberID         string `json:"member_id,omitempty"`
	ParentGrantID    string `json:"parent_grant_id,omitempty"`
	BindingEpoch     int    `json:"binding_epoch,omitempty"`
	TargetProviderID string `json:"target_provider_id,omitempty"`
	Reason           string `json:"reason,omitempty"`
}

func (req *capabilityGrantRevokeRequest) normalize() {
	req.SpaceID = strings.TrimSpace(req.SpaceID)
	req.GrantID = strings.TrimSpace(req.GrantID)
	req.MemberID = strings.TrimSpace(req.MemberID)
	req.ParentGrantID = strings.TrimSpace(req.ParentGrantID)
	req.TargetProviderID = strings.TrimSpace(req.TargetProviderID)
	req.Reason = strings.TrimSpace(req.Reason)
}

// selector returns which revocation axis the request uses, enforcing that
// exactly one selector is present. binding_epoch additionally requires a
// target_provider_id because the epoch is a per-provider-binding counter.
func (req capabilityGrantRevokeRequest) selector() (string, error) {
	chosen := ""
	count := 0
	if req.GrantID != "" {
		chosen = "grant_id"
		count++
	}
	if req.MemberID != "" {
		chosen = "member_id"
		count++
	}
	if req.ParentGrantID != "" {
		chosen = "parent_grant_id"
		count++
	}
	if req.BindingEpoch != 0 {
		chosen = "binding_epoch"
		count++
	}
	if req.BindingEpoch < 0 {
		return "", errors.New("binding_epoch must be a positive epoch")
	}
	switch {
	case count == 0:
		return "", errors.New("exactly one of grant_id, member_id, parent_grant_id, or binding_epoch is required")
	case count > 1:
		return "", errors.New("only one of grant_id, member_id, parent_grant_id, or binding_epoch may be set")
	}
	if chosen == "binding_epoch" && req.TargetProviderID == "" {
		return "", errors.New("target_provider_id is required when revoking by binding_epoch")
	}
	return chosen, nil
}

func defaultRevocationReason(selector string) string {
	switch selector {
	case "member_id":
		return "principal_revoked"
	case "parent_grant_id":
		return "parent_grant_revoked"
	case "binding_epoch":
		return "binding_epoch_superseded"
	default:
		return "manual_revocation"
	}
}

// grantIsRevocable reports whether a grant can still be revoked. Already
// revoked, expired, or superseded grants are skipped so revocation is
// idempotent.
func grantIsRevocable(row *coreent.CapabilityGrant) bool {
	if row == nil || row.RevokedAt != nil {
		return false
	}
	return row.Status == "active" || row.Status == "used"
}

func grantIDs(rows []*coreent.CapabilityGrant) []string {
	ids := make([]string, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row.ID)
	}
	return ids
}

func (s *Server) handleGrantRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, r)
		return
	}
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	var req capabilityGrantRevokeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.normalize()
	if req.SpaceID == "" {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "space_id is required.", nil)
		return
	}
	selector, err := req.selector()
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", err.Error(), nil)
		return
	}
	if ok := s.requireCapabilityGrantPermission(w, r, "capabilities:manage", req.SpaceID); !ok {
		return
	}
	candidates, found, err := s.collectGrantsToRevoke(r.Context(), client, req, selector)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to resolve grants to revoke.", err.Error())
		return
	}
	if !found {
		writeError(w, r, http.StatusNotFound, "CAPABILITY_GRANT_NOT_FOUND", "No capability grant matched the revocation selector.", map[string]any{"selector": selector})
		return
	}
	reason := firstNonEmpty(req.Reason, defaultRevocationReason(selector))
	now := time.Now().UTC()
	ids := grantIDs(candidates)
	if len(ids) > 0 {
		if _, err := client.CapabilityGrant.Update().
			Where(entcapabilitygrant.IDIn(ids...), entcapabilitygrant.RevokedAtIsNil()).
			SetStatus("revoked").
			SetRevokedAt(now).
			SetRevokedReason(reason).
			Save(r.Context()); err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to revoke capability grants.", err.Error())
			return
		}
		for _, row := range candidates {
			row.Status = "revoked"
			revokedAt := now
			revokedReason := reason
			row.RevokedAt = &revokedAt
			row.RevokedReason = &revokedReason
			s.recordCapabilityGrantAudit(r, row, "capability.grant.revoked", reason)
		}
	}
	writeData(w, r, http.StatusOK, map[string]any{
		"selector":      selector,
		"space_id":      req.SpaceID,
		"reason":        reason,
		"revoked_count": len(ids),
		"grant_ids":     ids,
	})
}

// collectGrantsToRevoke resolves the revocable grant rows for a selector,
// always scoped to req.SpaceID so a space-scoped credential can never revoke
// grants in another Space. The boolean return reports whether the selector
// referenced an existing grant (false yields a 404 for grant_id /
// parent_grant_id selectors).
func (s *Server) collectGrantsToRevoke(ctx context.Context, client *coreent.Client, req capabilityGrantRevokeRequest, selector string) ([]*coreent.CapabilityGrant, bool, error) {
	switch selector {
	case "grant_id":
		row, err := client.CapabilityGrant.Query().
			Where(entcapabilitygrant.ID(req.GrantID), entcapabilitygrant.SpaceID(req.SpaceID)).
			Only(ctx)
		if coreent.IsNotFound(err) {
			return nil, false, nil
		}
		if err != nil {
			return nil, false, err
		}
		if grantIsRevocable(row) {
			return []*coreent.CapabilityGrant{row}, true, nil
		}
		return nil, true, nil
	case "member_id":
		rows, err := client.CapabilityGrant.Query().
			Where(
				entcapabilitygrant.SpaceID(req.SpaceID),
				entcapabilitygrant.PrincipalMemberID(req.MemberID),
				entcapabilitygrant.RevokedAtIsNil(),
				entcapabilitygrant.StatusIn("active", "used"),
			).
			All(ctx)
		return rows, true, err
	case "binding_epoch":
		rows, err := client.CapabilityGrant.Query().
			Where(
				entcapabilitygrant.SpaceID(req.SpaceID),
				entcapabilitygrant.TargetProviderID(req.TargetProviderID),
				entcapabilitygrant.BindingEpochLT(req.BindingEpoch),
				entcapabilitygrant.RevokedAtIsNil(),
				entcapabilitygrant.StatusIn("active", "used"),
			).
			All(ctx)
		return rows, true, err
	case "parent_grant_id":
		return s.collectGrantSubtree(ctx, client, req.SpaceID, req.ParentGrantID)
	}
	return nil, false, nil
}

// collectGrantSubtree returns the revocable grants in the lineage subtree
// rooted at rootGrantID (inclusive). Core owns the parent_grant_id lineage, so
// revoking a parent cancels the whole delegation chain it spawned.
func (s *Server) collectGrantSubtree(ctx context.Context, client *coreent.Client, spaceID, rootGrantID string) ([]*coreent.CapabilityGrant, bool, error) {
	root, err := client.CapabilityGrant.Query().
		Where(entcapabilitygrant.ID(rootGrantID), entcapabilitygrant.SpaceID(spaceID)).
		Only(ctx)
	if coreent.IsNotFound(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	collected := map[string]struct{}{root.ID: {}}
	ordered := []*coreent.CapabilityGrant{root}
	frontier := []string{root.ID}
	for len(frontier) > 0 {
		children, err := client.CapabilityGrant.Query().
			Where(entcapabilitygrant.SpaceID(spaceID), entcapabilitygrant.ParentGrantIDIn(frontier...)).
			All(ctx)
		if err != nil {
			return nil, true, err
		}
		next := frontier[:0:0]
		for _, child := range children {
			if _, seen := collected[child.ID]; seen {
				continue
			}
			collected[child.ID] = struct{}{}
			ordered = append(ordered, child)
			next = append(next, child.ID)
		}
		frontier = next
		if len(collected) >= capabilityGrantSubtreeLimit {
			break
		}
	}
	revocable := make([]*coreent.CapabilityGrant, 0, len(ordered))
	for _, row := range ordered {
		if grantIsRevocable(row) {
			revocable = append(revocable, row)
		}
	}
	return revocable, true, nil
}

// capabilityGrantReconcileRequest scans a Space for hanging mediated grants.
type capabilityGrantReconcileRequest struct {
	SpaceID string `json:"space_id"`
}

// handleGrantReconcile implements the C1b reconciler from
// technical-architecture.en.md §II.6 / §V.2. It marks grants past their
// expected_outcome_by window (with no outcome receipt) as `missing` — the only
// signal — while leaving timing-normal `pending` grants untouched. It also
// lapses active grants whose TTL has elapsed to `expired` so the ledger
// reflects reality.
func (s *Server) handleGrantReconcile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, r)
		return
	}
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	var req capabilityGrantReconcileRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.SpaceID = strings.TrimSpace(req.SpaceID)
	if req.SpaceID == "" {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "space_id is required.", nil)
		return
	}
	if ok := s.requireCapabilityGrantPermission(w, r, "capabilities:manage", req.SpaceID); !ok {
		return
	}
	now := time.Now().UTC()

	missingRows, err := client.CapabilityGrant.Query().
		Where(
			entcapabilitygrant.SpaceID(req.SpaceID),
			entcapabilitygrant.OutcomeStatus("pending"),
			entcapabilitygrant.ExpectedOutcomeByLT(now),
			entcapabilitygrant.RevokedAtIsNil(),
		).
		All(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to scan hanging capability grants.", err.Error())
		return
	}
	missingIDs := grantIDs(missingRows)
	if len(missingIDs) > 0 {
		if _, err := client.CapabilityGrant.Update().
			Where(entcapabilitygrant.IDIn(missingIDs...), entcapabilitygrant.OutcomeStatus("pending")).
			SetOutcomeStatus("missing").
			Save(r.Context()); err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to mark missing capability outcomes.", err.Error())
			return
		}
		for _, row := range missingRows {
			row.OutcomeStatus = "missing"
			s.recordCapabilityGrantAudit(r, row, "capability.outcome.missing", "outcome receipt missing after expected window")
		}
	}

	expiredRows, err := client.CapabilityGrant.Query().
		Where(
			entcapabilitygrant.SpaceID(req.SpaceID),
			entcapabilitygrant.Status("active"),
			entcapabilitygrant.ExpiresAtLT(now),
			entcapabilitygrant.RevokedAtIsNil(),
		).
		All(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to scan expired capability grants.", err.Error())
		return
	}
	expiredIDs := grantIDs(expiredRows)
	if len(expiredIDs) > 0 {
		if _, err := client.CapabilityGrant.Update().
			Where(entcapabilitygrant.IDIn(expiredIDs...), entcapabilitygrant.Status("active")).
			SetStatus("expired").
			Save(r.Context()); err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to lapse expired capability grants.", err.Error())
			return
		}
	}

	writeData(w, r, http.StatusOK, map[string]any{
		"space_id":          req.SpaceID,
		"marked_missing":    len(missingIDs),
		"missing_grant_ids": missingIDs,
		"expired":           len(expiredIDs),
		"expired_grant_ids": expiredIDs,
	})
}
