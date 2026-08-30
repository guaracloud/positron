use positron_domain::identity::TenantId;
use positron_domain::routing::SignalKind;
use positron_domain::time::UnixNanoseconds;
use positron_kernel::{ActiveSegmentLedger, IngestTime, LifecycleClock, LifecycleClockSource};

use super::{LogStoreFailure, codec};

const NANOS_PER_SECOND: i64 = 1_000_000_000;
const MAX_RETENTION_SECONDS: u64 = i64::MAX as u64 / NANOS_PER_SECOND as u64;

/// Tenant-and-signal retention duration expressed in whole seconds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogRetentionPolicy {
    retention_seconds: u64,
}

impl LogRetentionPolicy {
    /// Creates a positive bounded retention duration.
    pub fn new(retention_seconds: u64) -> Result<Self, LogStoreFailure> {
        if retention_seconds == 0 || retention_seconds > MAX_RETENTION_SECONDS {
            return Err(LogStoreFailure::invalid_input());
        }
        Ok(Self { retention_seconds })
    }

    #[must_use]
    pub const fn retention_seconds(self) -> u64 {
        self.retention_seconds
    }

    /// Derives the fixed compaction boundary owned by this tenant Log Store.
    pub fn bucket(
        self,
        tenant: TenantId,
        ingest_time: IngestTime,
    ) -> Result<LogRetentionBucket, LogStoreFailure> {
        let duration = std::num::NonZeroU64::new(self.retention_seconds)
            .ok_or_else(LogStoreFailure::invalid_input)?;
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

pub(super) fn enforce_retention<'kernel, 'catalog, S: LifecycleClockSource>(
    ledger: &ActiveSegmentLedger<'kernel, 'catalog>,
    clock: &LifecycleClock<S>,
    tenant: TenantId,
    policy: LogRetentionPolicy,
    cancellation: &dyn super::ScanCancellation,
    observer: &dyn super::ScanObserver,
) -> Result<LogRetentionOutcome, LogStoreFailure> {
    if ledger.scope().tenant_id() != tenant
        || ledger.scope().signal_kind() != positron_domain::routing::SignalKind::Logs
    {
        return Err(LogStoreFailure::physical_scope_mismatch());
    }
    let retention_seconds = std::num::NonZeroU64::new(policy.retention_seconds)
        .ok_or_else(LogStoreFailure::invalid_input)?;
    super::check_scan_cancellation(cancellation)?;
    let cutoff = clock
        .retention_cutoff(retention_seconds)
        .map_err(|failure| match failure {
            positron_kernel::LifecycleClockFailure::Unavailable => {
                LogStoreFailure::clock_unavailable()
            },
            positron_kernel::LifecycleClockFailure::OutOfRange => LogStoreFailure::limit_exceeded(),
        })?;
    let evaluated_at = cutoff.evaluated_at();
    let clock_provenance = cutoff.provenance();
    let snapshot = ledger.snapshot().map_err(map_kernel_failure)?;
    let active_segment = ledger.active_segment_id().map_err(map_kernel_failure)?;
    let mut evidence = Vec::new();
    evidence
        .try_reserve_exact(snapshot.blocks().len())
        .map_err(|_| LogStoreFailure::resource_exhausted())?;
    for block in snapshot.blocks() {
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
        let latest = codec::block_retention_range_observed(
            tenant,
            &snapshot,
            block.payload(),
            cancellation,
            observer,
        )?
        .ok_or_else(LogStoreFailure::malformed_block)?;
        evidence.push(
            snapshot
                .retention_evidence(block, latest, retention_seconds)
                .map_err(map_kernel_failure)?,
        );
    }
    super::check_scan_cancellation(cancellation)?;
    drop(snapshot);
    let reclamation = ledger
        .retire_expired_sealed_segments(cutoff, &evidence)
        .map_err(map_kernel_failure)?;
    Ok(LogRetentionOutcome {
        evaluated_at,
        expired_segments: reclamation.logically_retired_segments(),
        reclaimed_segments: reclamation.physically_reclaimed_segments(),
        clock_provenance,
    })
}

fn map_kernel_failure(failure: positron_kernel::LedgerFailure) -> LogStoreFailure {
    LogStoreFailure::kernel(failure)
}
