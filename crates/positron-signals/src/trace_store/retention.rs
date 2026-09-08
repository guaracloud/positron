use positron_domain::identity::TenantId;
use positron_domain::routing::SignalKind;
use positron_domain::time::UnixNanoseconds;
use positron_kernel::{ActiveSegmentLedger, CatalogLogRetentionPolicy, IngestTime};

use super::{TraceStoreFailure, codec};

/// Authenticated tenant Trace Store retention policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceRetentionPolicy {
    configured: CatalogLogRetentionPolicy,
}

impl TraceRetentionPolicy {
    /// Reads the current Trace retention evidence from one catalog snapshot.
    pub fn from_catalog(
        snapshot: &positron_kernel::CatalogSnapshot,
    ) -> Result<Self, TraceStoreFailure> {
        let configured = snapshot
            .retention_policy(SignalKind::Traces)
            .map_err(TraceStoreFailure::catalog)?;
        Ok(Self { configured })
    }

    #[must_use]
    pub const fn retention_seconds(self) -> u64 {
        self.configured.retention_seconds().get()
    }

    pub fn bucket(
        self,
        tenant: TenantId,
        ingest_time: IngestTime,
    ) -> Result<TraceRetentionBucket, TraceStoreFailure> {
        if tenant != self.configured.tenant() {
            return Err(TraceStoreFailure::physical_scope_mismatch());
        }
        positron_kernel::RetentionBucket::for_ingest_time(
            tenant,
            SignalKind::Traces,
            ingest_time,
            self.configured.retention_seconds(),
        )
        .map(TraceRetentionBucket)
        .map_err(TraceStoreFailure::kernel)
    }

    pub(super) const fn kernel_policy(self) -> CatalogLogRetentionPolicy {
        self.configured
    }
}

/// Fixed tenant-and-Trace-Store ingest-time interval used by compaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceRetentionBucket(positron_kernel::RetentionBucket);

impl TraceRetentionBucket {
    #[must_use]
    pub const fn tenant(self) -> TenantId {
        self.0.tenant()
    }
    #[must_use]
    pub const fn signal_kind(self) -> SignalKind {
        SignalKind::Traces
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

/// Result of one Trace Store retention pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceRetentionOutcome {
    evaluated_at: UnixNanoseconds,
    expired_segments: usize,
    reclaimed_segments: usize,
}

impl TraceRetentionOutcome {
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
}

pub(super) fn enforce_retention<'kernel, 'catalog>(
    ledger: &ActiveSegmentLedger<'kernel, 'catalog>,
    tenant: TenantId,
    policy: TraceRetentionPolicy,
    cancellation: &dyn crate::ScanCancellation,
    observer: &dyn crate::ScanObserver,
) -> Result<TraceRetentionOutcome, TraceStoreFailure> {
    if ledger.scope().tenant_id() != tenant
        || ledger.scope().signal_kind() != SignalKind::Traces
        || policy.configured.tenant() != tenant
        || policy.configured.signal_kind() != SignalKind::Traces
        || policy.configured.instance() != ledger.catalog_instance()
    {
        return Err(TraceStoreFailure::physical_scope_mismatch());
    }
    let current = ledger
        .current_catalog_snapshot()
        .map_err(TraceStoreFailure::kernel)?;
    if current
        .retention_policy(SignalKind::Traces)
        .map_err(TraceStoreFailure::catalog)?
        != policy.configured
    {
        return Err(TraceStoreFailure::stale_generation());
    }
    super::scan::check_cancel(cancellation)?;
    let evaluation = ledger
        .begin_retention()
        .map_err(TraceStoreFailure::kernel)?;
    let active = ledger
        .active_segment_id()
        .map_err(TraceStoreFailure::kernel)?;
    for block in evaluation.blocks() {
        if block.segment_id() == active {
            continue;
        }
        observer
            .observe_scanned_bytes(
                u64::try_from(block.payload().len())
                    .map_err(|_| TraceStoreFailure::limit_exceeded())?,
            )
            .map_err(TraceStoreFailure::observation)?;
        let decoder = codec::BlockDecode::observed_with_profile(
            &super::TraceStore::value_limit_profile(),
            tenant,
            block.payload(),
            cancellation,
            observer,
        )?;
        let records = decoder.record_count();
        decoder.decode_after_with_profile(
            block,
            0,
            records,
            cancellation,
            &super::TraceStore::value_limit_profile(),
        )?;
    }
    let reclaimed = evaluation.commit().map_err(TraceStoreFailure::kernel)?;
    Ok(TraceRetentionOutcome {
        evaluated_at: reclaimed.evaluated_at(),
        expired_segments: reclaimed.logically_retired_segments(),
        reclaimed_segments: reclaimed.physically_reclaimed_segments(),
    })
}
