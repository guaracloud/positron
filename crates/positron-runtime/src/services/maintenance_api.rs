use std::fmt::Write;

use sha2::{Digest, Sha256};

use positron_api::maintenance::{
    MaintenanceExplainRequest, MaintenanceExplainResponse, MaintenanceRunRequest,
    MaintenanceRunResponse, MaintenanceStatusRequest, MaintenanceStatusResponse,
    MaintenanceTaskStatus,
};
use positron_domain::{
    identity::{PrincipalId, TenantId},
    routing::{SignalKind, VirtualShardId},
};
use positron_governance::{
    AuthorizedContext, CompatibilityHints, Identity, PresentedCredential, RequestedIntent,
};
use positron_kernel::{
    ActiveSegmentLedger, Catalog, LedgerFailure, LedgerFailureCode, MaintenanceScope,
    MaintenanceTaskClass, MaintenanceTaskId, MaintenanceTaskPhase, SegmentScope,
};

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
        self.authorize_system_administration(bearer)?;
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
            match status.phase() {
                MaintenanceTaskPhase::Queued => response.queued += 1,
                MaintenanceTaskPhase::Running => response.running += 1,
                MaintenanceTaskPhase::Deferred => response.deferred += 1,
                MaintenanceTaskPhase::Cancelled
                | MaintenanceTaskPhase::Succeeded
                | MaintenanceTaskPhase::Failed => response.terminal += 1,
            }
            response.tasks.push(task_status(status));
        }
        response
            .validate()
            .map_err(|_| (503, "administration_unavailable"))?;
        Ok(response)
    }

    pub(crate) fn explain_maintenance_task(
        &self,
        bearer: &str,
        body: &[u8],
    ) -> Result<MaintenanceExplainResponse, (u16, &'static str)> {
        self.authorize_system_administration(bearer)?;
        let request =
            MaintenanceExplainRequest::decode(body).map_err(|_| (400, "invalid_request"))?;
        let identity = task_identity(&request.identity).ok_or((400, "invalid_request"))?;
        let status = self
            .instance
            .maintenance_coordinator()
            .lock()
            .map_err(|_| (503, "administration_unavailable"))?
            .status(identity)
            .map_err(|_| (404, "task_unavailable"))?;
        Ok(MaintenanceExplainResponse {
            task: task_status(status),
        })
    }

    /// Submits only the kernel-produced Compaction descriptor for one explicit
    /// sealed signal scope. Callers provide no source objects, retention
    /// bounds, reservations, preconditions, or task descriptor fields.
    pub(crate) fn run_maintenance(
        &self,
        bearer: &str,
        body: &[u8],
    ) -> Result<MaintenanceRunResponse, (u16, &'static str)> {
        let actor = self.authorize_system_administration(bearer)?;
        let request = MaintenanceRunRequest::decode(body).map_err(|_| (400, "invalid_request"))?;
        let tenant =
            TenantId::parse_canonical(request.tenant()).map_err(|_| (400, "invalid_request"))?;
        let signal = signal(request.signal()).ok_or((400, "invalid_request"))?;
        let shard = VirtualShardId::new(request.shard()).map_err(|_| (400, "invalid_request"))?;
        let idempotency = PrincipalId::parse_canonical(request.idempotency_key())
            .map_err(|_| (400, "invalid_request"))?;
        let task_identity = maintenance_task_id(actor.principal_id(), idempotency)?;
        let _catalog_operation = self
            .catalog_operation()
            .map_err(|_| (503, "administration_unavailable"))?;
        let instance = &self.instance;
        let catalog = Catalog::open(
            &instance._authority,
            instance.instance,
            instance
                .key
                .catalog_secret(instance.instance)
                .map_err(|_| (503, "administration_unavailable"))?,
        )
        .map_err(|_| (503, "administration_unavailable"))?;
        let snapshot = catalog
            .pin()
            .map_err(|_| (503, "administration_unavailable"))?;
        let identity =
            Identity::open(&snapshot).map_err(|_| (503, "administration_unavailable"))?;
        let scope = SegmentScope::new(tenant, signal, shard);
        let expected_scope = MaintenanceScope::segment(tenant, signal, shard);
        if !snapshot
            .reachable_ledger_scopes(tenant, signal)
            .map_err(|_| (503, "administration_unavailable"))?
            .into_iter()
            .any(|candidate| candidate == scope)
        {
            return Err((404, "source_unavailable"));
        }
        let coordinator = instance
            .maintenance_coordinator()
            .lock()
            .map_err(|_| (503, "administration_unavailable"))?;
        match coordinator.status(task_identity) {
            Ok(status)
                if status.task().class() == MaintenanceTaskClass::Compaction
                    && status.task().scope() == expected_scope =>
            {
                return Ok(MaintenanceRunResponse {
                    task: task_status(status),
                });
            },
            Ok(_) => return Err((409, "idempotency_conflict")),
            Err(positron_kernel::MaintenanceFailure::UnknownTask) => {},
            Err(_) => return Err((503, "administration_unavailable")),
        }
        let key = super::tenant_segment_key(instance, &identity, scope)
            .map_err(|_| (503, "administration_unavailable"))?;
        let ledger = ActiveSegmentLedger::open_for_maintenance_with_retention_time(
            &instance._authority,
            &instance.retention_time,
            &catalog,
            scope,
            key,
        )
        .map_err(|_| (503, "administration_unavailable"))?;
        let bucket = ledger.sealed_compaction_bucket().map_err(source_failure)?;
        let task = ledger
            .prepare_compaction_task(bucket, task_identity)
            .map_err(|_| (503, "administration_unavailable"))?;
        let now = instance
            .retention_time
            .governance_now_seconds()
            .map_err(|_| (503, "administration_unavailable"))?;
        let submitted = task
            .submit_and_persist(&coordinator, &catalog, now)
            .map_err(|_| (503, "administration_unavailable"))?;
        let status = coordinator
            .status(submitted.identity())
            .map_err(|_| (503, "administration_unavailable"))?;
        drop(coordinator);
        drop(ledger);
        drop(catalog);
        drop(_catalog_operation);
        self.notify_maintenance_worker();
        Ok(MaintenanceRunResponse {
            task: task_status(status),
        })
    }

    fn authorize_system_administration(
        &self,
        bearer: &str,
    ) -> Result<AuthorizedContext, (u16, &'static str)> {
        self.instance
            .attribute(
                PresentedCredential::parse(bearer).map_err(|_| (401, "authentication_rejected"))?,
                RequestedIntent::SystemAdministration,
                CompatibilityHints::none(),
            )
            .map_err(|_| (401, "authentication_rejected"))
    }
}

fn signal(value: &str) -> Option<SignalKind> {
    match value {
        "logs" => Some(SignalKind::Logs),
        "traces" => Some(SignalKind::Traces),
        _ => None,
    }
}

fn source_failure(failure: LedgerFailure) -> (u16, &'static str) {
    match failure.code() {
        LedgerFailureCode::InvalidInput | LedgerFailureCode::PhysicalScopeMismatch => {
            (404, "source_unavailable")
        },
        _ => (503, "administration_unavailable"),
    }
}

fn maintenance_task_id(
    principal: PrincipalId,
    idempotency: PrincipalId,
) -> Result<MaintenanceTaskId, (u16, &'static str)> {
    let mut digest = Sha256::new();
    digest.update(b"positron-maintenance-run-v1");
    digest.update(principal.to_bytes());
    digest.update(idempotency.to_bytes());
    let digest: [u8; 32] = digest.finalize().into();
    let mut identity = [0_u8; 16];
    identity.copy_from_slice(
        digest
            .get(..16)
            .ok_or((503, "administration_unavailable"))?,
    );
    MaintenanceTaskId::new(identity).map_err(|_| (503, "administration_unavailable"))
}

fn task_status(status: positron_kernel::MaintenanceTaskStatus) -> MaintenanceTaskStatus {
    MaintenanceTaskStatus {
        identity: hex(status.task().identity().to_bytes()),
        class: class_name(status.task().class()).to_owned(),
        scope: scope_name(status.task().scope()),
        phase: phase_name(status.phase()).to_owned(),
        submitted_at_unix_seconds: status.submitted_at(),
        checkpoint_sequence: status.checkpoint().map(|checkpoint| checkpoint.sequence()),
        pause_until_unix_seconds: status.pause_until(),
        cancellation_requested: status.cancellation_requested(),
    }
}

fn task_identity(value: &str) -> Option<positron_kernel::MaintenanceTaskId> {
    let mut bytes = [0_u8; 16];
    for (slot, pair) in bytes.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let high = hex_value(*pair.first()?)?;
        let low = hex_value(*pair.get(1)?)?;
        *slot = (high << 4) | low;
    }
    positron_kernel::MaintenanceTaskId::new(bytes).ok()
}

const fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use positron_api::maintenance::MaintenanceRunRequest;
    use positron_domain::routing::SignalKind;
    use positron_kernel::{ActiveSegmentLedger, MaintenanceTaskPhase};
    use prost::Message;

    use super::super::ServiceHandle;
    use super::super::tests::schema_maintenance::{Fixture, open_catalog, request};

    #[test]
    fn authenticated_run_prepares_one_sealed_compaction_task_and_replays_after_reopen()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let (initialized, ingest, _, administrator) = fixture.initialized_with_admin()?;
        let services = ServiceHandle::new(Arc::clone(&initialized))?;
        services.ingest_otlp_logs(&ingest, request("run-api-sealed-source").encode_to_vec())?;
        let catalog = open_catalog(&initialized)?;
        let scope = catalog
            .pin()?
            .reachable_ledger_scopes(initialized.default_tenant_id(), SignalKind::Logs)?
            .into_iter()
            .next()
            .ok_or("log scope")?;
        ActiveSegmentLedger::open_for_maintenance_with_retention_time(
            &initialized._authority,
            &initialized.retention_time,
            &catalog,
            scope,
            initialized.tenant_segment_key_for_test(scope)?,
        )?
        .seal()?;
        drop(catalog);
        let request = MaintenanceRunRequest::new(
            "compaction".to_owned(),
            initialized.default_tenant_id().to_canonical_text(),
            "logs".to_owned(),
            scope.shard_id().value(),
            "00000000-0000-0000-0000-000000000001".to_owned(),
        );
        let body = request.encode()?;
        let first = services
            .run_maintenance(&administrator, &body)
            .map_err(|failure| format!("first run: {failure:?}"))?;
        assert_eq!(first.task.class, "compaction");
        assert_eq!(first.task.phase, "queued");
        let replay = services
            .run_maintenance(&administrator, &body)
            .map_err(|failure| format!("replayed run: {failure:?}"))?;
        assert_eq!(replay, first, "retry attaches to the durable task");
        let identity = super::task_identity(&first.task.identity).ok_or("task identity")?;
        drop(services);
        drop(initialized);

        let reopened = fixture.reopen()?;
        let _restored_services = ServiceHandle::new(Arc::clone(&reopened))?;
        assert_eq!(
            reopened
                .maintenance_coordinator()
                .lock()
                .map_err(|_| "maintenance coordinator")?
                .status(identity)
                .map_err(|failure| format!("restored task: {failure:?}"))?
                .phase(),
            MaintenanceTaskPhase::Queued,
            "the acknowledged run remains durably queued after reopen"
        );
        Ok(())
    }

    #[test]
    fn maintenance_run_rejects_unauthenticated_requests_before_decoding()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let (initialized, _, _, _) = fixture.initialized_with_admin()?;
        let services = ServiceHandle::new(initialized)?;
        assert_eq!(
            services.run_maintenance("not-a-credential", br#"{\"unknown\":true}"#),
            Err((401, "authentication_rejected")),
            "authentication precedes decoding"
        );
        Ok(())
    }
}
