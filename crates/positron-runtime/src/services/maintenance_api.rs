use std::fmt::Write;

use positron_api::maintenance::{
    MaintenanceStatusRequest, MaintenanceStatusResponse, MaintenanceTaskStatus,
};
use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
use positron_kernel::{MaintenanceScope, MaintenanceTaskClass, MaintenanceTaskPhase};

use crate::ServiceHandle;

impl ServiceHandle {
    /// Authenticates a system administrator before decoding the bounded
    /// inspection request. The response is derived solely from the runtime's
    /// one coordinator and contains no credentials or immutable input bytes.
    pub(crate) fn maintenance_status(
        &self,
        bearer: &str,
        body: &[u8],
    ) -> Result<MaintenanceStatusResponse, (u16, &'static str)> {
        self.instance
            .attribute(
                PresentedCredential::parse(bearer).map_err(|_| (401, "authentication_rejected"))?,
                RequestedIntent::SystemAdministration,
                CompatibilityHints::none(),
            )
            .map_err(|_| (401, "authentication_rejected"))?;
        MaintenanceStatusRequest::decode(body).map_err(|_| (400, "invalid_request"))?;
        let statuses = self
            .instance
            .maintenance_coordinator()
            .lock()
            .map_err(|_| (503, "administration_unavailable"))?
            .statuses()
            .map_err(|_| (503, "administration_unavailable"))?;
        let mut response = MaintenanceStatusResponse {
            tasks: Vec::with_capacity(statuses.len()),
            queued: 0,
            running: 0,
            deferred: 0,
            terminal: 0,
        };
        for status in statuses {
            let phase = phase_name(status.phase());
            match status.phase() {
                MaintenanceTaskPhase::Queued => response.queued += 1,
                MaintenanceTaskPhase::Running => response.running += 1,
                MaintenanceTaskPhase::Deferred => response.deferred += 1,
                MaintenanceTaskPhase::Cancelled
                | MaintenanceTaskPhase::Succeeded
                | MaintenanceTaskPhase::Failed => response.terminal += 1,
            }
            response.tasks.push(MaintenanceTaskStatus {
                identity: hex(status.task().identity().to_bytes()),
                class: class_name(status.task().class()).to_owned(),
                scope: scope_name(status.task().scope()),
                phase: phase.to_owned(),
                submitted_at_unix_seconds: status.submitted_at(),
                checkpoint_sequence: status.checkpoint().map(|checkpoint| checkpoint.sequence()),
                pause_until_unix_seconds: status.pause_until(),
                cancellation_requested: status.cancellation_requested(),
            });
        }
        response
            .validate()
            .map_err(|_| (503, "administration_unavailable"))?;
        Ok(response)
    }
}

fn hex(bytes: [u8; 16]) -> String {
    let mut rendered = String::with_capacity(32);
    for byte in bytes {
        let _ = write!(rendered, "{byte:02x}");
    }
    rendered
}

fn scope_name(scope: MaintenanceScope) -> String {
    match scope {
        MaintenanceScope::System => "system".to_owned(),
        MaintenanceScope::Tenant(tenant) => format!("tenant:{}", tenant.to_canonical_text()),
        MaintenanceScope::Segment {
            tenant,
            signal,
            shard,
        } => format!(
            "segment:{}:{}:{}",
            tenant.to_canonical_text(),
            signal.as_str(),
            shard.value()
        ),
    }
}

const fn phase_name(phase: MaintenanceTaskPhase) -> &'static str {
    match phase {
        MaintenanceTaskPhase::Queued => "queued",
        MaintenanceTaskPhase::Running => "running",
        MaintenanceTaskPhase::Deferred => "deferred",
        MaintenanceTaskPhase::Cancelled => "cancelled",
        MaintenanceTaskPhase::Succeeded => "succeeded",
        MaintenanceTaskPhase::Failed => "failed",
    }
}

const fn class_name(class: MaintenanceTaskClass) -> &'static str {
    match class {
        MaintenanceTaskClass::ActiveSegmentRoll => "active_segment_roll",
        MaintenanceTaskClass::Compaction => "compaction",
        MaintenanceTaskClass::RetentionPublication => "retention_publication",
        MaintenanceTaskClass::RetentionReclamation => "retention_reclamation",
        MaintenanceTaskClass::CatalogReclamation => "catalog_reclamation",
        MaintenanceTaskClass::OrphanReclamation => "orphan_reclamation",
        MaintenanceTaskClass::IntegrityScrub => "integrity_scrub",
        MaintenanceTaskClass::QuarantineFollowUp => "quarantine_follow_up",
        MaintenanceTaskClass::SchemaStatistics => "schema_statistics",
        MaintenanceTaskClass::SchemaPromotion => "schema_promotion",
        MaintenanceTaskClass::SchemaDemotion => "schema_demotion",
        MaintenanceTaskClass::GovernanceAuditCheckpoint => "governance_audit_checkpoint",
        MaintenanceTaskClass::KeyRewrap => "key_rewrap",
        MaintenanceTaskClass::EnvelopeVerification => "envelope_verification",
        MaintenanceTaskClass::Migration => "migration",
        MaintenanceTaskClass::RepositoryVerification => "repository_verification",
        MaintenanceTaskClass::RepositoryCleanup => "repository_cleanup",
        MaintenanceTaskClass::BackupSnapshot => "backup_snapshot",
        MaintenanceTaskClass::DurableExport => "durable_export",
        MaintenanceTaskClass::SnapshotLeaseExpiry => "snapshot_lease_expiry",
        MaintenanceTaskClass::CompletedOperationExpiry => "completed_operation_expiry",
        MaintenanceTaskClass::TenantPurge => "tenant_purge",
    }
}
