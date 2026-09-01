use positron_domain::identity::TenantId;
use positron_kernel::{ActiveSegmentLedger, CompactionBlock};

use super::{
    LogRetentionBucket, LogRetentionPolicy, LogStoreFailure, ScanCancellation, ScanObserver,
    check_scan_cancellation, codec,
};

/// Result of one bounded Log Store compaction publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogCompactionOutcome {
    bucket: LogRetentionBucket,
    input_segments: usize,
    output_segments: usize,
    input_blocks: usize,
}

impl LogCompactionOutcome {
    #[must_use]
    pub const fn bucket(self) -> LogRetentionBucket {
        self.bucket
    }

    #[must_use]
    pub const fn input_segments(self) -> usize {
        self.input_segments
    }

    #[must_use]
    pub const fn output_segments(self) -> usize {
        self.output_segments
    }

    #[must_use]
    pub const fn input_blocks(self) -> usize {
        self.input_blocks
    }
}

impl LogRetentionPolicy {
    pub(super) fn verify_current<'kernel, 'catalog>(
        &self,
        ledger: &ActiveSegmentLedger<'kernel, 'catalog>,
    ) -> Result<(), LogStoreFailure> {
        let current = ledger
            .current_catalog_snapshot()
            .map_err(LogStoreFailure::kernel)?;
        let current = Self::from_catalog(&current)?;
        if current != *self {
            return Err(LogStoreFailure::corrupt_policy());
        }
        Ok(())
    }
}

pub(super) fn compact<'kernel, 'catalog>(
    ledger: &ActiveSegmentLedger<'kernel, 'catalog>,
    tenant: TenantId,
    policy: LogRetentionPolicy,
    bucket: LogRetentionBucket,
    cancellation: &dyn ScanCancellation,
    observer: &dyn ScanObserver,
) -> Result<LogCompactionOutcome, LogStoreFailure> {
    if ledger.scope().tenant_id() != tenant
        || ledger.scope().signal_kind() != positron_domain::routing::SignalKind::Logs
        || bucket.tenant() != tenant
        || bucket.signal_kind() != positron_domain::routing::SignalKind::Logs
    {
        return Err(LogStoreFailure::physical_scope_mismatch());
    }
    policy.verify_current(ledger)?;
    check_scan_cancellation(cancellation)?;
    let active = ledger
        .active_segment_id()
        .map_err(LogStoreFailure::kernel)?;
    let snapshot = ledger.snapshot().map_err(LogStoreFailure::kernel)?;
    // Admit the kernel's complete copy-on-write peak while only the immutable
    // snapshot exists. This is intentionally before any payload is cloned.
    let preparation = ledger
        .prepare_compaction(&snapshot)
        .map_err(LogStoreFailure::kernel)?;
    let mut inputs = Vec::new();
    inputs
        .try_reserve_exact(snapshot.blocks().len())
        .map_err(|_| LogStoreFailure::resource_exhausted())?;
    for block in snapshot.blocks() {
        check_scan_cancellation(cancellation)?;
        if block.segment_id() == active {
            continue;
        }
        observer
            .observe_scanned_bytes(
                u64::try_from(block.payload().len())
                    .map_err(|_| LogStoreFailure::limit_exceeded())?,
            )
            .map_err(LogStoreFailure::observation)?;
        let decoded = codec::decode_block_observed(tenant, block, 1_024, cancellation, observer)?;
        let ingest_time = decoded
            .records
            .iter()
            .map(|record| record.ingest_time())
            .max()
            .ok_or_else(LogStoreFailure::malformed_block)?;
        let in_bucket = decoded
            .records
            .iter()
            .map(|record| {
                policy
                    .bucket(tenant, record.ingest_time())
                    .map(|candidate| candidate == bucket)
            })
            .try_fold(true, |all, current| current.map(|current| all && current))?;
        let input = in_bucket
            .then(|| {
                CompactionBlock::new(
                    snapshot.scope(),
                    block.segment_id(),
                    block.identity(),
                    block.position(),
                    clone_payload(block.payload())?,
                    block.content_digest().map_err(LogStoreFailure::kernel)?,
                    ingest_time,
                )
                .map_err(LogStoreFailure::kernel)
            })
            .transpose()?;
        inputs.extend(input);
    }
    check_scan_cancellation(cancellation)?;
    if inputs.is_empty() {
        return Ok(LogCompactionOutcome {
            bucket,
            input_segments: 0,
            output_segments: 0,
            input_blocks: 0,
        });
    }
    let mut input_segments = Vec::new();
    input_segments
        .try_reserve_exact(inputs.len())
        .map_err(|_| LogStoreFailure::resource_exhausted())?;
    for segment in inputs.iter().map(CompactionBlock::source_segment) {
        if !input_segments.contains(&segment) {
            input_segments.push(segment);
        }
    }
    if input_segments.len() < 2 {
        return Ok(LogCompactionOutcome {
            bucket,
            input_segments: 0,
            output_segments: 0,
            input_blocks: 0,
        });
    }
    let input_blocks = inputs.len();
    let publication = ledger
        .compact_sealed_with_cancellation(inputs, preparation, || cancellation.is_cancelled())
        .map_err(LogStoreFailure::kernel)?;
    Ok(LogCompactionOutcome {
        bucket,
        input_segments: publication.input_segments(),
        output_segments: publication.output_segments(),
        input_blocks,
    })
}

fn clone_payload(payload: &[u8]) -> Result<Vec<u8>, LogStoreFailure> {
    let mut clone = Vec::new();
    clone
        .try_reserve_exact(payload.len())
        .map_err(|_| LogStoreFailure::resource_exhausted())?;
    clone.extend_from_slice(payload);
    Ok(clone)
}
