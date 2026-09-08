use positron_domain::identity::TenantId;
use positron_domain::routing::SignalKind;
use positron_kernel::{ActiveSegmentLedger, CompactionBlock};

use super::{TraceRetentionBucket, TraceRetentionPolicy, TraceStoreFailure, codec};

/// Result of one bounded Trace Store copy-on-write compaction publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceCompactionOutcome {
    bucket: TraceRetentionBucket,
    input_segments: usize,
    output_segments: usize,
    input_blocks: usize,
}
impl TraceCompactionOutcome {
    #[must_use]
    pub const fn bucket(self) -> TraceRetentionBucket {
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

pub(super) fn compact<'kernel, 'catalog>(
    ledger: &ActiveSegmentLedger<'kernel, 'catalog>,
    tenant: TenantId,
    policy: TraceRetentionPolicy,
    bucket: TraceRetentionBucket,
    cancellation: &dyn crate::ScanCancellation,
    observer: &dyn crate::ScanObserver,
) -> Result<TraceCompactionOutcome, TraceStoreFailure> {
    if ledger.scope().tenant_id() != tenant
        || ledger.scope().signal_kind() != SignalKind::Traces
        || bucket.tenant() != tenant
        || bucket.signal_kind() != SignalKind::Traces
    {
        return Err(TraceStoreFailure::physical_scope_mismatch());
    }
    let current = ledger
        .current_catalog_snapshot()
        .map_err(TraceStoreFailure::kernel)?;
    if current
        .retention_policy(SignalKind::Traces)
        .map_err(TraceStoreFailure::catalog)?
        != policy.kernel_policy()
    {
        return Err(TraceStoreFailure::stale_generation());
    }
    super::scan::check_cancel(cancellation)?;
    let active = ledger
        .active_segment_id()
        .map_err(TraceStoreFailure::kernel)?;
    let snapshot = ledger.snapshot().map_err(TraceStoreFailure::kernel)?;
    let preparation = ledger
        .prepare_compaction_with_policy(&snapshot, policy.kernel_policy())
        .map_err(TraceStoreFailure::kernel)?;
    let mut inputs = Vec::new();
    let mut segments = Vec::new();
    for block in snapshot.blocks() {
        super::scan::check_cancel(cancellation)?;
        if block.segment_id() == active {
            continue;
        }
        observer
            .observe_scanned_bytes(
                u64::try_from(block.payload().len())
                    .map_err(|_| TraceStoreFailure::limit_exceeded())?,
            )
            .map_err(TraceStoreFailure::observation)?;
        let profile = super::TraceStore::value_limit_profile();
        let decoder = codec::BlockDecode::observed_with_profile(
            &profile,
            tenant,
            block.payload(),
            cancellation,
            observer,
        )?;
        let records = decoder.record_count();
        let decoded =
            decoder.decode_after_with_profile(block, 0, records, cancellation, &profile)?;
        let ingest_time = decoded
            .observations
            .iter()
            .map(|record| record.ingest_time())
            .max()
            .ok_or_else(TraceStoreFailure::malformed_block)?;
        let complete = decoded.observations.iter().all(|record| {
            policy
                .bucket(tenant, record.ingest_time())
                .is_ok_and(|candidate| candidate == bucket)
        });
        let entry = (block.segment_id(), complete);
        if let Some((_, existing)) = segments.iter_mut().find(|(segment, _)| *segment == entry.0) {
            *existing &= entry.1;
        } else {
            segments.push(entry);
        }
        if complete {
            inputs.push(
                CompactionBlock::new(
                    snapshot.scope(),
                    block.segment_id(),
                    block.identity(),
                    block.position(),
                    block.payload().to_vec(),
                    block.content_digest().map_err(TraceStoreFailure::kernel)?,
                    ingest_time,
                )
                .map_err(TraceStoreFailure::kernel)?,
            );
        }
    }
    inputs.retain(|input| {
        segments
            .iter()
            .find(|(segment, _)| *segment == input.source_segment())
            .is_some_and(|(_, complete)| *complete)
    });
    let input_segments = inputs
        .iter()
        .map(CompactionBlock::source_segment)
        .collect::<std::collections::BTreeSet<_>>();
    if input_segments.len() < 2 {
        return Ok(TraceCompactionOutcome {
            bucket,
            input_segments: 0,
            output_segments: 0,
            input_blocks: 0,
        });
    }
    let input_blocks = inputs.len();
    let published = ledger
        .compact_sealed_with_cancellation(inputs, preparation, || cancellation.is_cancelled())
        .map_err(TraceStoreFailure::kernel)?;
    Ok(TraceCompactionOutcome {
        bucket,
        input_segments: published.input_segments(),
        output_segments: published.output_segments(),
        input_blocks,
    })
}
