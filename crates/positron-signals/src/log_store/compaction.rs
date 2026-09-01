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
    let mut inputs = Vec::new();
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
        let mut in_bucket = true;
        for record in &decoded.records {
            if policy.bucket(tenant, record.ingest_time())? != bucket {
                in_bucket = false;
                break;
            }
        }
        if !in_bucket {
            continue;
        }
        inputs.push(
            CompactionBlock::new(
                snapshot.scope(),
                block.segment_id(),
                block.identity(),
                block.position(),
                block.payload().to_vec(),
                block.content_digest().map_err(LogStoreFailure::kernel)?,
                ingest_time,
            )
            .map_err(LogStoreFailure::kernel)?,
        );
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
    let input_segments = inputs
        .iter()
        .map(|block| block.source_segment())
        .collect::<BTreeSet<_>>();
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
        .compact_sealed(inputs)
        .map_err(LogStoreFailure::kernel)?;
    Ok(LogCompactionOutcome {
        bucket,
        input_segments: publication.input_segments(),
        output_segments: publication.output_segments(),
        input_blocks,
    })
}
use std::collections::BTreeSet;
