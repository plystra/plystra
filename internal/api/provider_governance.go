package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	coreent "github.com/plystra/core/ent"
	entproviderinstallation "github.com/plystra/core/ent/providerinstallation"
	entprovidermigrationrevision "github.com/plystra/core/ent/providermigrationrevision"
	entprovidermigrationstep "github.com/plystra/core/ent/providermigrationstep"
	"github.com/plystra/core/internal/plugins"
)

const maxProviderMigrationSteps = 200

type providerMigrationRevisionRequest struct {
	ProviderPluginID     string                         `json:"provider_plugin_id"`
	Revision             string                         `json:"revision"`
	BundleHash           string                         `json:"bundle_hash"`
	FromSchemaVersion    int                            `json:"from_schema_version"`
	ToSchemaVersion      int                            `json:"to_schema_version"`
	Destructive          bool                           `json:"destructive"`
	RLSBypass            bool                           `json:"rls_bypass"`
	RequiresManualReview bool                           `json:"requires_manual_review"`
	Metadata             map[string]any                 `json:"metadata"`
	Steps                []providerMigrationStepRequest `json:"steps"`
}

type providerMigrationStepRequest struct {
	StatementHash       string         `json:"statement_hash"`
	StatementKind       string         `json:"statement_kind"`
	Destructive         bool           `json:"destructive"`
	Backfill            bool           `json:"backfill"`
	TenantScopeReviewed bool           `json:"tenant_scope_reviewed"`
	RLSBypass           bool           `json:"rls_bypass"`
	Precondition        string         `json:"precondition"`
	RecoveryAction      string         `json:"recovery_action"`
	Metadata            map[string]any `json:"metadata"`
}

type providerMigrationReviewRequest struct {
	Approved bool           `json:"approved"`
	Notes    string         `json:"notes"`
	Metadata map[string]any `json:"metadata"`
}

func (s *Server) handleProviderInstallations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, r)
		return
	}
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	query := client.ProviderInstallation.Query().Order(entproviderinstallation.ByProviderPluginID())
	if providerID := strings.TrimSpace(r.URL.Query().Get("provider_plugin_id")); providerID != "" {
		query = query.Where(entproviderinstallation.ProviderPluginID(providerID))
	}
	if status := strings.TrimSpace(r.URL.Query().Get("status")); status != "" {
		query = query.Where(entproviderinstallation.Status(status))
	}
	if appID := strings.TrimSpace(r.URL.Query().Get("app_id")); appID != "" {
		query = query.Where(entproviderinstallation.AppID(appID))
	}
	rows, err := query.Limit(limitFrom(r, 50)).All(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list provider installations.", err.Error())
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, providerInstallationMap(row))
	}
	writeList(w, r, http.StatusOK, out, limitFrom(r, 50))
}

func (s *Server) handleProviderInstallationSubroutes(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/provider-installations/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 1 && parts[0] != "" && r.Method == http.MethodGet {
		s.getProviderInstallation(w, r, parts[0])
		return
	}
	http.NotFound(w, r)
}

func (s *Server) getProviderInstallation(w http.ResponseWriter, r *http.Request, installationID string) {
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	row, err := client.ProviderInstallation.Query().Where(entproviderinstallation.ID(installationID)).Only(r.Context())
	if coreent.IsNotFound(err) {
		writeError(w, r, http.StatusNotFound, "PROVIDER_INSTALLATION_NOT_FOUND", "Provider installation was not found.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load provider installation.", err.Error())
		return
	}
	writeData(w, r, http.StatusOK, providerInstallationMap(row))
}

func (s *Server) handleProviderMigrationRevisions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listProviderMigrationRevisions(w, r)
	case http.MethodPost:
		s.createProviderMigrationRevision(w, r)
	default:
		writeMethodNotAllowed(w, r)
	}
}

func (s *Server) handleProviderMigrationRevisionSubroutes(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/provider-migration-revisions/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 1 && parts[0] != "" && r.Method == http.MethodGet {
		s.getProviderMigrationRevision(w, r, parts[0])
		return
	}
	if len(parts) == 2 && parts[0] != "" && parts[1] == "review" {
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, r)
			return
		}
		s.reviewProviderMigrationRevision(w, r, parts[0])
		return
	}
	http.NotFound(w, r)
}

func (s *Server) listProviderMigrationRevisions(w http.ResponseWriter, r *http.Request) {
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	query := client.ProviderMigrationRevision.Query().Order(entprovidermigrationrevision.ByCreatedAt())
	if providerID := strings.TrimSpace(r.URL.Query().Get("provider_plugin_id")); providerID != "" {
		query = query.Where(entprovidermigrationrevision.ProviderPluginID(providerID))
	}
	if installationID := strings.TrimSpace(r.URL.Query().Get("installation_id")); installationID != "" {
		query = query.Where(entprovidermigrationrevision.InstallationID(installationID))
	}
	if status := strings.TrimSpace(r.URL.Query().Get("status")); status != "" {
		query = query.Where(entprovidermigrationrevision.Status(status))
	}
	rows, err := query.Limit(limitFrom(r, 50)).All(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list provider migration revisions.", err.Error())
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, providerMigrationRevisionMap(row, nil))
	}
	writeList(w, r, http.StatusOK, out, limitFrom(r, 50))
}

func (s *Server) getProviderMigrationRevision(w http.ResponseWriter, r *http.Request, revisionID string) {
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	row, err := client.ProviderMigrationRevision.Query().Where(entprovidermigrationrevision.ID(revisionID)).Only(r.Context())
	if coreent.IsNotFound(err) {
		writeError(w, r, http.StatusNotFound, "PROVIDER_MIGRATION_REVISION_NOT_FOUND", "Provider migration revision was not found.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load provider migration revision.", err.Error())
		return
	}
	steps, err := client.ProviderMigrationStep.Query().
		Where(entprovidermigrationstep.RevisionID(row.ID)).
		Order(entprovidermigrationstep.ByStepIndex()).
		All(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load provider migration steps.", err.Error())
		return
	}
	writeData(w, r, http.StatusOK, providerMigrationRevisionMap(row, steps))
}

func (s *Server) createProviderMigrationRevision(w http.ResponseWriter, r *http.Request) {
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	var req providerMigrationRevisionRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.normalize()
	if err := validateProviderMigrationRevisionRequest(req); err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Provider migration revision is invalid.", err.Error())
		return
	}
	installation, err := client.ProviderInstallation.Query().
		Where(entproviderinstallation.ProviderPluginID(req.ProviderPluginID), entproviderinstallation.DeletedAtIsNil()).
		Only(r.Context())
	if coreent.IsNotFound(err) {
		writeError(w, r, http.StatusNotFound, "PROVIDER_INSTALLATION_NOT_FOUND", "Provider installation was not found for this plugin.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load provider installation.", err.Error())
		return
	}
	if installation.Status == "disabled" || installation.Status == "uninstalled" {
		writeError(w, r, http.StatusConflict, "PROVIDER_INSTALLATION_INACTIVE", "Provider installation is not active for migration planning.", map[string]any{
			"provider_plugin_id": installation.ProviderPluginID,
			"status":             installation.Status,
		})
		return
	}
	revisionID := "pmrev_" + safeIdentifier(req.ProviderPluginID+"_"+req.Revision)
	existing, err := client.ProviderMigrationRevision.Query().
		Where(entprovidermigrationrevision.ProviderPluginID(req.ProviderPluginID), entprovidermigrationrevision.Revision(req.Revision)).
		Only(r.Context())
	if err == nil {
		if !providerMigrationRevisionReplayMatches(existing, req, installation) {
			writeError(w, r, http.StatusConflict, "PROVIDER_MIGRATION_REVISION_CONFLICT", "Existing provider migration revision does not match this plan.", map[string]any{
				"revision_id":        existing.ID,
				"provider_plugin_id": existing.ProviderPluginID,
				"revision":           existing.Revision,
				"status":             existing.Status,
			})
			return
		}
		steps, err := client.ProviderMigrationStep.Query().Where(entprovidermigrationstep.RevisionID(existing.ID)).Order(entprovidermigrationstep.ByStepIndex()).All(r.Context())
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load provider migration steps.", err.Error())
			return
		}
		writeData(w, r, http.StatusOK, providerMigrationRevisionMap(existing, steps))
		return
	}
	if err != nil && !coreent.IsNotFound(err) {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to check provider migration idempotency.", err.Error())
		return
	}
	tx, err := client.Tx(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to start provider migration transaction.", err.Error())
		return
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	revisionStatus := "planned"
	stepReviewRequired := providerMigrationStepsRequireReview(req.Steps)
	if req.RequiresManualReview || req.Destructive || req.RLSBypass || stepReviewRequired {
		revisionStatus = "review_required"
	}
	row, err := tx.ProviderMigrationRevision.Create().
		SetID(revisionID).
		SetProviderPluginID(req.ProviderPluginID).
		SetInstallationID(installation.ID).
		SetRevision(req.Revision).
		SetBundleHash(req.BundleHash).
		SetSchemaName(installation.SchemaName).
		SetFromSchemaVersion(req.FromSchemaVersion).
		SetToSchemaVersion(req.ToSchemaVersion).
		SetStatus(revisionStatus).
		SetDestructive(req.Destructive).
		SetRlsBypass(req.RLSBypass).
		SetRequiresManualReview(req.RequiresManualReview || req.Destructive || req.RLSBypass || stepReviewRequired).
		SetMetadata(nonNilMap(req.Metadata)).
		Save(r.Context())
	if err != nil {
		writeError(w, r, http.StatusConflict, "PROVIDER_MIGRATION_REVISION_CREATE_FAILED", "Failed to create provider migration revision.", err.Error())
		return
	}
	steps := make([]*coreent.ProviderMigrationStep, 0, len(req.Steps))
	for i, step := range req.Steps {
		status := "planned"
		if step.Destructive || step.Backfill || step.RLSBypass {
			status = "review_required"
		}
		created, err := tx.ProviderMigrationStep.Create().
			SetID("pmstep_" + safeIdentifier(row.ID+"_"+fmt.Sprintf("%04d", i+1))).
			SetRevisionID(row.ID).
			SetProviderPluginID(req.ProviderPluginID).
			SetStepIndex(i + 1).
			SetStatementHash(step.StatementHash).
			SetStatementKind(step.StatementKind).
			SetStatus(status).
			SetDestructive(step.Destructive).
			SetBackfill(step.Backfill).
			SetTenantScopeReviewed(step.TenantScopeReviewed).
			SetRlsBypass(step.RLSBypass).
			SetNillablePrecondition(optionalString(step.Precondition)).
			SetNillableRecoveryAction(optionalString(step.RecoveryAction)).
			SetMetadata(nonNilMap(step.Metadata)).
			Save(r.Context())
		if err != nil {
			writeError(w, r, http.StatusConflict, "PROVIDER_MIGRATION_STEP_CREATE_FAILED", "Failed to create provider migration step.", err.Error())
			return
		}
		steps = append(steps, created)
	}
	if err := tx.Commit(); err != nil {
		writeError(w, r, http.StatusConflict, "PROVIDER_MIGRATION_REVISION_CREATE_FAILED", "Failed to commit provider migration revision.", err.Error())
		return
	}
	committed = true
	writeData(w, r, http.StatusCreated, providerMigrationRevisionMap(row, steps))
}

func providerMigrationStepsRequireReview(steps []providerMigrationStepRequest) bool {
	for _, step := range steps {
		if step.Destructive || step.Backfill || step.RLSBypass {
			return true
		}
	}
	return false
}

func (s *Server) reviewProviderMigrationRevision(w http.ResponseWriter, r *http.Request, revisionID string) {
	client, ok := s.requireEnt(w, r)
	if !ok {
		return
	}
	var req providerMigrationReviewRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Notes = strings.TrimSpace(req.Notes)
	if len(req.Notes) > 2048 {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "review notes must be 2048 characters or fewer.", nil)
		return
	}
	if err := validateGovernedMetadata("provider_migration_review.metadata", nonNilMap(req.Metadata)); err != nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "Provider migration review metadata is invalid.", err.Error())
		return
	}
	row, err := client.ProviderMigrationRevision.Query().Where(entprovidermigrationrevision.ID(revisionID)).Only(r.Context())
	if coreent.IsNotFound(err) {
		writeError(w, r, http.StatusNotFound, "PROVIDER_MIGRATION_REVISION_NOT_FOUND", "Provider migration revision was not found.", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load provider migration revision.", err.Error())
		return
	}
	principal, _ := adminPrincipalFrom(r)
	status := "rejected"
	if req.Approved {
		status = "approved"
	}
	metadata := nonNilMap(row.Metadata)
	review := nonNilMap(req.Metadata)
	if req.Notes != "" {
		review["notes"] = req.Notes
	}
	review["approved"] = req.Approved
	review["reviewed_at"] = time.Now().UTC().Format(time.RFC3339)
	metadata["review"] = review
	update := client.ProviderMigrationRevision.UpdateOneID(row.ID).
		SetStatus(status).
		SetReviewedAt(time.Now().UTC()).
		SetMetadata(metadata)
	if principal.CredentialType == "session" && principal.Session.UserID != "" {
		update.SetReviewedByUserID(principal.Session.UserID)
	}
	updated, err := update.Save(r.Context())
	if err != nil {
		writeError(w, r, http.StatusConflict, "PROVIDER_MIGRATION_REVISION_REVIEW_FAILED", "Failed to review provider migration revision.", err.Error())
		return
	}
	writeData(w, r, http.StatusOK, providerMigrationRevisionMap(updated, nil))
}

func (req *providerMigrationRevisionRequest) normalize() {
	req.ProviderPluginID = strings.TrimSpace(req.ProviderPluginID)
	req.Revision = strings.TrimSpace(req.Revision)
	req.BundleHash = strings.TrimSpace(req.BundleHash)
	for i := range req.Steps {
		req.Steps[i].StatementHash = strings.TrimSpace(req.Steps[i].StatementHash)
		req.Steps[i].StatementKind = strings.TrimSpace(req.Steps[i].StatementKind)
		req.Steps[i].Precondition = strings.TrimSpace(req.Steps[i].Precondition)
		req.Steps[i].RecoveryAction = strings.TrimSpace(req.Steps[i].RecoveryAction)
	}
}

func validateProviderMigrationRevisionRequest(req providerMigrationRevisionRequest) error {
	switch {
	case req.ProviderPluginID == "":
		return errors.New("provider_plugin_id is required")
	case req.Revision == "":
		return errors.New("revision is required")
	case !validProviderMigrationRevisionKey(req.Revision):
		return errors.New("revision must contain only letters, numbers, dot, underscore, or dash")
	case !validMigrationHash(req.BundleHash):
		return errors.New("bundle_hash must be a sha256 hex or h1-prefixed hash")
	case req.FromSchemaVersion < 0 || req.ToSchemaVersion < 0:
		return errors.New("schema versions must be non-negative")
	case req.ToSchemaVersion < req.FromSchemaVersion:
		return errors.New("to_schema_version must be greater than or equal to from_schema_version")
	case len(req.Steps) == 0:
		return errors.New("steps must not be empty")
	case len(req.Steps) > maxProviderMigrationSteps:
		return fmt.Errorf("steps must contain %d entries or fewer", maxProviderMigrationSteps)
	}
	if req.Destructive || req.RLSBypass {
		req.RequiresManualReview = true
	}
	if err := validateGovernedMetadata("provider_migration_revision.metadata", nonNilMap(req.Metadata)); err != nil {
		return err
	}
	statementHashes := map[string]struct{}{}
	for i, step := range req.Steps {
		if !validMigrationHash(step.StatementHash) {
			return fmt.Errorf("steps[%d].statement_hash must be a sha256 hex or h1-prefixed hash", i)
		}
		if _, ok := statementHashes[step.StatementHash]; ok {
			return fmt.Errorf("steps[%d].statement_hash duplicates another step", i)
		}
		statementHashes[step.StatementHash] = struct{}{}
		if !validProviderStatementKind(step.StatementKind) {
			return fmt.Errorf("steps[%d].statement_kind is invalid", i)
		}
		if (step.Destructive || step.Backfill || step.RLSBypass) && !step.TenantScopeReviewed {
			return fmt.Errorf("steps[%d].tenant_scope_reviewed is required for destructive, backfill, or rls_bypass steps", i)
		}
		if len(step.Precondition) > 2048 || len(step.RecoveryAction) > 2048 {
			return fmt.Errorf("steps[%d].precondition and recovery_action must be 2048 characters or fewer", i)
		}
		if providerMigrationMetadataContainsRawSQL(step.Metadata) {
			return fmt.Errorf("steps[%d].metadata must not contain raw SQL text; submit statement_hash, kind, precondition, and recovery_action only", i)
		}
		if err := validateGovernedMetadata(fmt.Sprintf("provider_migration_steps[%d].metadata", i), nonNilMap(step.Metadata)); err != nil {
			return err
		}
	}
	return nil
}

func providerMigrationMetadataContainsRawSQL(metadata map[string]any) bool {
	for key := range nonNilMap(metadata) {
		normalized := strings.ToLower(strings.TrimSpace(key))
		normalized = strings.ReplaceAll(normalized, "-", "_")
		normalized = strings.ReplaceAll(normalized, ".", "_")
		switch normalized {
		case "sql", "statement", "query", "ddl", "dml", "raw_sql", "statement_text":
			return true
		}
	}
	return false
}

func validProviderMigrationRevisionKey(value string) bool {
	if len(value) > 120 {
		return false
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '.' || r == '_' || r == '-':
		default:
			return false
		}
	}
	return true
}

func validMigrationHash(value string) bool {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "h1:") {
		return len(value) > 8 && !strings.ContainsAny(value, " \t\r\n")
	}
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'f':
		case r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
}

func validProviderStatementKind(kind string) bool {
	switch strings.TrimSpace(kind) {
	case "create_schema", "create_table", "alter_table", "drop_table", "create_index", "drop_index", "enable_rls", "create_policy", "alter_policy", "create_trigger", "grant_privileges", "revoke_privileges", "backfill", "other":
		return true
	default:
		return false
	}
}

func providerMigrationRevisionReplayMatches(row *coreent.ProviderMigrationRevision, req providerMigrationRevisionRequest, installation *coreent.ProviderInstallation) bool {
	if row == nil || installation == nil {
		return false
	}
	return row.ProviderPluginID == req.ProviderPluginID &&
		row.InstallationID == installation.ID &&
		row.Revision == req.Revision &&
		row.BundleHash == req.BundleHash &&
		row.SchemaName == installation.SchemaName &&
		row.FromSchemaVersion == req.FromSchemaVersion &&
		row.ToSchemaVersion == req.ToSchemaVersion &&
		row.Destructive == req.Destructive &&
		row.RlsBypass == req.RLSBypass
}

func (s *Server) ensureProviderInstallationForManifest(ctx context.Context, pluginID string, manifest plugins.Manifest, row *coreent.Plugin) error {
	if s.ent == nil {
		return errors.New("ent client is not configured")
	}
	if pluginID == "" {
		pluginID = "plugin_" + safeIdentifier(manifest.ID)
	}
	pluginType, pluginScope, appID, trustBundleID := normalizedPluginGovernance(row, manifest)
	if !manifestNeedsProviderInstallation(manifest) {
		existing, err := s.ent.ProviderInstallation.Query().Where(entproviderinstallation.ProviderPluginID(manifest.ID)).Only(ctx)
		if coreent.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return err
		}
		metadata := nonNilMap(existing.Metadata)
		metadata["disabled_reason"] = "manifest_no_direct_db_data_plane"
		return s.ent.ProviderInstallation.UpdateOneID(existing.ID).
			SetStatus("disabled").
			SetMetadata(metadata).
			Exec(ctx)
	}
	schemaName, migratorRole, runtimeRole := providerDatabaseIdentifiers(manifest.ID, pluginType, appID)
	compatMin, compatMax, compatPreferred := providerRuntimeSchemaCompatibility(manifest.Runtime)
	metadata := providerInstallationMetadata(manifest, pluginType == "app_module")
	existing, err := s.ent.ProviderInstallation.Query().Where(entproviderinstallation.ProviderPluginID(manifest.ID)).Only(ctx)
	if coreent.IsNotFound(err) {
		return s.ent.ProviderInstallation.Create().
			SetID("pinst_" + safeIdentifier(manifest.ID)).
			SetProviderPluginID(manifest.ID).
			SetPluginType(pluginType).
			SetPluginScope(pluginScope).
			SetNillableAppID(optionalString(appID)).
			SetNillableTrustBundleID(optionalString(trustBundleID)).
			SetSchemaName(schemaName).
			SetMigratorRole(migratorRole).
			SetRuntimeRole(runtimeRole).
			SetRuntimeSchemaMin(compatMin).
			SetRuntimeSchemaMax(compatMax).
			SetRuntimeSchemaPreferred(compatPreferred).
			SetRlsRequired(true).
			SetZeroDdlRuntime(true).
			SetMutationJournalRequired(manifestMutationJournalRequired(manifest)).
			SetStatus("planned").
			SetMetadata(metadata).
			Exec(ctx)
	}
	if err != nil {
		return err
	}
	update := s.ent.ProviderInstallation.UpdateOneID(existing.ID).
		SetPluginType(pluginType).
		SetPluginScope(pluginScope).
		SetSchemaName(schemaName).
		SetMigratorRole(migratorRole).
		SetRuntimeRole(runtimeRole).
		SetRuntimeSchemaMin(compatMin).
		SetRuntimeSchemaMax(compatMax).
		SetRuntimeSchemaPreferred(compatPreferred).
		SetRlsRequired(true).
		SetZeroDdlRuntime(true).
		SetMutationJournalRequired(manifestMutationJournalRequired(manifest)).
		SetStatus(firstNonEmpty(existing.Status, "planned")).
		SetMetadata(metadata)
	if appID == "" {
		update.ClearAppID()
	} else {
		update.SetAppID(appID)
	}
	if trustBundleID == "" {
		update.ClearTrustBundleID()
	} else {
		update.SetTrustBundleID(trustBundleID)
	}
	return update.Exec(ctx)
}

func manifestNeedsProviderInstallation(manifest plugins.Manifest) bool {
	for _, capability := range manifestProvidedCapabilities(manifest) {
		for _, plane := range capability.DataPlane.Allowed {
			if plane == "direct_db" || plane == "direct_db_with_mutation_journal" {
				return true
			}
		}
	}
	return false
}

func manifestMutationJournalRequired(manifest plugins.Manifest) bool {
	for _, capability := range manifestProvidedCapabilities(manifest) {
		if capability.Audit.Enforcement == "observed_mutation" {
			return true
		}
		for _, plane := range capability.DataPlane.Allowed {
			if plane == "direct_db_with_mutation_journal" {
				return true
			}
		}
	}
	return false
}

func providerRuntimeSchemaCompatibility(runtime plugins.ProviderRuntimeDefinition) (int, int, int) {
	if runtime.SchemaCompatibility == nil {
		return 0, 0, 0
	}
	return runtime.SchemaCompatibility.Min, runtime.SchemaCompatibility.Max, runtime.SchemaCompatibility.Preferred
}

func providerDatabaseIdentifiers(pluginID, pluginType, appID string) (string, string, string) {
	if pluginType == "app_module" && strings.TrimSpace(appID) != "" {
		schemaName := postgresIdentifier("app", appID)
		roleBase := postgresIdentifier(schemaName, pluginID)
		return schemaName, postgresIdentifier(roleBase, "migrator_owner"), postgresIdentifier(roleBase, "runtime")
	}
	schemaName := postgresIdentifier("plg", pluginID)
	return schemaName, postgresIdentifier(schemaName, "migrator_owner"), postgresIdentifier(schemaName, "runtime")
}

func postgresIdentifier(parts ...string) string {
	raw := safeIdentifier(strings.Join(parts, "_"))
	if raw == "" {
		raw = "plystra"
	}
	if len(raw) <= 63 {
		return raw
	}
	sum := sha256.Sum256([]byte(raw))
	suffix := hex.EncodeToString(sum[:])[:12]
	head := strings.Trim(raw[:50], "_")
	if head == "" {
		head = "plystra"
	}
	return head + "_" + suffix
}

func providerInstallationMetadata(manifest plugins.Manifest, appSchemaShared bool) map[string]any {
	planes := map[string]bool{}
	for _, capability := range manifestProvidedCapabilities(manifest) {
		for _, plane := range capability.DataPlane.Allowed {
			planes[plane] = true
		}
	}
	dataPlanes := make([]any, 0, len(planes))
	for plane := range planes {
		dataPlanes = append(dataPlanes, plane)
	}
	return map[string]any{
		"source":                   "manifest_install",
		"plugin_version":           manifest.Version,
		"runtime_type":             manifest.Runtime.Type,
		"runtime_protocol":         manifest.Runtime.Protocol,
		"runtime_version":          manifest.Runtime.Version,
		"allowed_data_planes":      dataPlanes,
		"app_module_schema_shared": appSchemaShared,
	}
}

func providerInstallationMap(row *coreent.ProviderInstallation) map[string]any {
	return map[string]any{
		"id":                        row.ID,
		"provider_plugin_id":        row.ProviderPluginID,
		"plugin_type":               row.PluginType,
		"plugin_scope":              row.PluginScope,
		"app_id":                    derefString(row.AppID),
		"trust_bundle_id":           derefString(row.TrustBundleID),
		"schema_name":               row.SchemaName,
		"migrator_role":             row.MigratorRole,
		"runtime_role":              row.RuntimeRole,
		"schema_version":            row.SchemaVersion,
		"runtime_schema_min":        row.RuntimeSchemaMin,
		"runtime_schema_max":        row.RuntimeSchemaMax,
		"runtime_schema_preferred":  row.RuntimeSchemaPreferred,
		"rls_required":              row.RlsRequired,
		"zero_ddl_runtime":          row.ZeroDdlRuntime,
		"mutation_journal_required": row.MutationJournalRequired,
		"status":                    row.Status,
		"metadata":                  nonNilMap(row.Metadata),
		"created_at":                formatTime(row.CreatedAt),
		"updated_at":                formatTime(row.UpdatedAt),
		"deleted_at":                optionalTime(row.DeletedAt),
	}
}

func providerMigrationRevisionMap(row *coreent.ProviderMigrationRevision, steps []*coreent.ProviderMigrationStep) map[string]any {
	out := map[string]any{
		"id":                     row.ID,
		"provider_plugin_id":     row.ProviderPluginID,
		"installation_id":        row.InstallationID,
		"revision":               row.Revision,
		"bundle_hash":            row.BundleHash,
		"schema_name":            row.SchemaName,
		"from_schema_version":    row.FromSchemaVersion,
		"to_schema_version":      row.ToSchemaVersion,
		"status":                 row.Status,
		"destructive":            row.Destructive,
		"rls_bypass":             row.RlsBypass,
		"requires_manual_review": row.RequiresManualReview,
		"reviewed_by_user_id":    derefString(row.ReviewedByUserID),
		"reviewed_at":            optionalTime(row.ReviewedAt),
		"started_at":             optionalTime(row.StartedAt),
		"finished_at":            optionalTime(row.FinishedAt),
		"last_error":             derefString(row.LastError),
		"metadata":               nonNilMap(row.Metadata),
		"created_at":             formatTime(row.CreatedAt),
		"updated_at":             formatTime(row.UpdatedAt),
	}
	if steps != nil {
		mapped := make([]map[string]any, 0, len(steps))
		for _, step := range steps {
			mapped = append(mapped, providerMigrationStepMap(step))
		}
		out["steps"] = mapped
	}
	return out
}

func providerMigrationStepMap(row *coreent.ProviderMigrationStep) map[string]any {
	return map[string]any{
		"id":                    row.ID,
		"revision_id":           row.RevisionID,
		"provider_plugin_id":    row.ProviderPluginID,
		"step_index":            row.StepIndex,
		"statement_hash":        row.StatementHash,
		"statement_kind":        row.StatementKind,
		"status":                row.Status,
		"destructive":           row.Destructive,
		"backfill":              row.Backfill,
		"tenant_scope_reviewed": row.TenantScopeReviewed,
		"rls_bypass":            row.RlsBypass,
		"precondition":          derefString(row.Precondition),
		"recovery_action":       derefString(row.RecoveryAction),
		"started_at":            optionalTime(row.StartedAt),
		"finished_at":           optionalTime(row.FinishedAt),
		"error":                 derefString(row.Error),
		"metadata":              nonNilMap(row.Metadata),
		"created_at":            formatTime(row.CreatedAt),
		"updated_at":            formatTime(row.UpdatedAt),
	}
}
