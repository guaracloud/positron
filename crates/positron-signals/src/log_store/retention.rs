use std::collections::BTreeMap;

use positron_domain::identity::TenantId;
use positron_domain::time::UnixNanoseconds;
use positron_kernel::{
    ActiveSegmentLedger, LedgerFailureCode, LifecycleClock, LifecycleClockSource, SegmentId,
};

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
}

/// The lifecycle authority used to decide retention eligibility.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetentionClockProvenance {
    LifecycleClock,
}

/// Result of one bounded Log Store retention pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogRetentionOutcome {
    evaluated_at: UnixNanoseconds,
    expired_segments: usize,
    reclaimed_segments: usize,
    clock_provenance: RetentionClockProvenance,
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
    pub const fn clock_provenance(self) -> RetentionClockProvenance {
        self.clock_provenance
    }
}

pub(super) fn enforce_retention<'kernel, 'catalog, S: LifecycleClockSource>(
    ledger: &ActiveSegmentLedger<'kernel, 'catalog>,
    clock: &LifecycleClock<S>,
    tenant: TenantId,
    policy: LogRetentionPolicy,
) -> Result<LogRetentionOutcome, LogStoreFailure> {
    if ledger.scope().tenant_id() != tenant
        || ledger.scope().signal_kind() != positron_domain::routing::SignalKind::Logs
    {
        return Err(LogStoreFailure::physical_scope_mismatch());
    }
    let evaluated_at = clock
        .retention_time()
        .map_err(|failure| match failure {
            positron_kernel::LifecycleClockFailure::Unavailable => {
                LogStoreFailure::clock_unavailable()
            },
            positron_kernel::LifecycleClockFailure::Uncertain => LogStoreFailure::clock_uncertain(),
        })?
        .instant();
    let now_seconds = evaluated_at
        .value()
        .checked_div(NANOS_PER_SECOND)
        .and_then(|seconds| u64::try_from(seconds).ok())
        .ok_or_else(LogStoreFailure::limit_exceeded)?;
    let retention_nanos = i64::try_from(policy.retention_seconds)
        .ok()
        .and_then(|seconds| seconds.checked_mul(NANOS_PER_SECOND))
        .ok_or_else(LogStoreFailure::limit_exceeded)?;
    let cutoff = evaluated_at
        .value()
        .checked_sub(retention_nanos)
        .ok_or_else(LogStoreFailure::limit_exceeded)?;
    let snapshot = ledger.snapshot().map_err(map_kernel_failure)?;
    let active_segment = ledger.active_segment_id().map_err(map_kernel_failure)?;
    let mut latest_by_segment = BTreeMap::<SegmentId, i64>::new();
    for block in snapshot.blocks() {
        if block.segment_id() == active_segment {
            continue;
        }
        let latest = codec::block_retention_range(tenant, &snapshot, block.payload())?
            .ok_or_else(LogStoreFailure::malformed_block)?;
        latest_by_segment
            .entry(block.segment_id())
            .and_modify(|current| *current = (*current).max(latest))
            .or_insert(latest);
    }
    let expired = latest_by_segment
        .into_iter()
        .filter_map(|(segment, latest)| (latest <= cutoff).then_some(segment))
        .collect::<Vec<_>>();
    drop(snapshot);
    let reclamation = ledger
        .retire_sealed_segments(&expired, now_seconds)
        .map_err(map_kernel_failure)?;
    Ok(LogRetentionOutcome {
        evaluated_at,
        expired_segments: reclamation.logically_retired_segments(),
        reclaimed_segments: reclamation.physically_reclaimed_segments(),
        clock_provenance: RetentionClockProvenance::LifecycleClock,
    })
}

fn map_kernel_failure(failure: positron_kernel::LedgerFailure) -> LogStoreFailure {
    match failure.code() {
        LedgerFailureCode::InvalidInput => LogStoreFailure::invalid_input(),
        LedgerFailureCode::PhysicalScopeMismatch => LogStoreFailure::physical_scope_mismatch(),
        LedgerFailureCode::LimitExceeded => LogStoreFailure::limit_exceeded(),
        LedgerFailureCode::ResourceAdmissionRefused => {
            LogStoreFailure::resource_admission_refused()
        },
        _ => LogStoreFailure::kernel(failure),
    }
}
