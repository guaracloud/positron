use positron_domain::identity::TenantId;
use positron_domain::routing::SignalKind;
use positron_domain::time::UnixNanoseconds;
use positron_kernel::{ActiveSegmentLedger, IngestTime};

use super::{LogStoreFailure, codec};

const NANOS_PER_SECOND: i64 = 1_000_000_000;
const MAX_RETENTION_SECONDS: u64 = i64::MAX as u64 / NANOS_PER_SECOND as u64;

/// Tenant-and-signal retention duration expressed in whole seconds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogRetentionPolicy {
    configured: positron_governance::RetentionPolicySnapshot,
}

impl LogRetentionPolicy {
    /// Reads the immutable tenant Log policy from one authenticated Catalog
    /// snapshot. No caller-supplied duration can authorize deletion.
    pub fn from_catalog(
        snapshot: &positron_kernel::CatalogSnapshot,
    ) -> Result<Self, LogStoreFailure> {
        let configured = positron_governance::RetentionPolicySnapshot::open(snapshot)
            .map_err(|_| LogStoreFailure::corrupt_policy())?;
        if configured.retention_seconds().get() > MAX_RETENTION_SECONDS {
            return Err(LogStoreFailure::invalid_input());
        }
        Ok(Self { configured })
    }

    #[must_use]
    pub const fn retention_seconds(self) -> u64 {
        self.configured.retention_seconds().get()
    }

    /// Derives the fixed compaction boundary owned by this tenant Log Store.
    pub fn bucket(
        self,
        tenant: TenantId,
        ingest_time: IngestTime,
    ) -> Result<LogRetentionBucket, LogStoreFailure> {
        if tenant != self.configured.tenant() {
            return Err(LogStoreFailure::physical_scope_mismatch());
        }
        let duration = self.configured.retention_seconds();
        positron_kernel::RetentionBucket::for_ingest_time(
            tenant,
            SignalKind::Logs,
            ingest_time,
            duration,
        )
        .map(LogRetentionBucket)
        .map_err(map_kernel_failure)
    }
}

/// Fixed tenant-and-Log-Store ingest-time interval used by later compaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogRetentionBucket(positron_kernel::RetentionBucket);

impl LogRetentionBucket {
    #[must_use]
    pub const fn tenant(self) -> TenantId {
        self.0.tenant()
    }

    #[must_use]
    pub const fn signal_kind(self) -> SignalKind {
        SignalKind::Logs
    }

    #[must_use]
    pub const fn start(self) -> UnixNanoseconds {
        self.0.start()
    }

    #[must_use]
    pub const fn end_exclusive(self) -> UnixNanoseconds {
        self.0.end_exclusive()
    }
}

/// Result of one bounded Log Store retention pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogRetentionOutcome {
    evaluated_at: UnixNanoseconds,
    expired_segments: usize,
    reclaimed_segments: usize,
    clock_provenance: positron_kernel::RetentionCutoffProvenance,
}

impl LogRetentionOutcome {
    #[must_use]
    pub const fn evaluated_at(self) -> UnixNanoseconds {
        self.evaluated_at
    }

    #[must_use]
    pub const fn expired_segments(self) -> usize {
        self.expired_segments
    }

    #[must_use]
    pub const fn reclaimed_segments(self) -> usize {
        self.reclaimed_segments
    }

    #[must_use]
    pub const fn clock_provenance(self) -> positron_kernel::RetentionCutoffProvenance {
        self.clock_provenance
    }
}

pub(super) fn enforce_retention<'kernel, 'catalog>(
    ledger: &ActiveSegmentLedger<'kernel, 'catalog>,
    tenant: TenantId,
    policy: LogRetentionPolicy,
    cancellation: &dyn super::ScanCancellation,
    observer: &dyn super::ScanObserver,
) -> Result<LogRetentionOutcome, LogStoreFailure> {
    if ledger.scope().tenant_id() != tenant
        || ledger.scope().signal_kind() != positron_domain::routing::SignalKind::Logs
        || policy.configured.tenant() != tenant
        || policy.configured.signal_kind() != positron_domain::routing::SignalKind::Logs
        || policy.configured.instance() != ledger.catalog_instance().to_bytes()
    {
        return Err(LogStoreFailure::physical_scope_mismatch());
    }
    let current = ledger
        .current_catalog_snapshot()
        .map_err(map_kernel_failure)?;
    policy
        .configured
        .validate_current(&current)
        .map_err(|_| LogStoreFailure::corrupt_policy())?;
    let retention_seconds = policy.configured.retention_seconds();
    super::check_scan_cancellation(cancellation)?;
    let evaluation = ledger
        .begin_retention_with_policy(retention_seconds, policy.configured.governance_object())
        .map_err(map_kernel_failure)?;
    let active_segment = ledger.active_segment_id().map_err(map_kernel_failure)?;
    for block in evaluation.blocks() {
        if block.segment_id() == active_segment {
            continue;
        }
        super::check_scan_cancellation(cancellation)?;
        observer
            .observe_scanned_bytes(
                u64::try_from(block.payload().len())
                    .map_err(|_| LogStoreFailure::limit_exceeded())?,
            )
            .map_err(LogStoreFailure::observation)?;
        codec::validate_retention_block_observed(tenant, block, cancellation, observer)?;
    }
    super::check_scan_cancellation(cancellation)?;
    let reclamation = evaluation.commit().map_err(map_kernel_failure)?;
    Ok(LogRetentionOutcome {
        evaluated_at: reclamation.evaluated_at(),
        expired_segments: reclamation.logically_retired_segments(),
        reclaimed_segments: reclamation.physically_reclaimed_segments(),
        clock_provenance: positron_kernel::RetentionCutoffProvenance::PersistedRetentionFrontier,
    })
}

fn map_kernel_failure(failure: positron_kernel::LedgerFailure) -> LogStoreFailure {
    LogStoreFailure::kernel(failure)
}
