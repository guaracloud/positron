use super::super::TraceStoreFailure;
use super::{SpanSummary, TraceSummary};
use crate::{ScanCancellation, ScanObserver};
use positron_kernel::IngestTime;

pub(super) struct SummaryUpdate {
    pub(super) slot: usize,
    pub(super) prior: Option<TraceSummary>,
    pub(super) updated: TraceSummary,
}

pub(super) struct StagedObservation {
    pub(super) trace_id: [u8; 16],
    pub(super) span_id: [u8; 8],
    pub(super) ingest_time: IngestTime,
    pub(super) semantic: Vec<u8>,
    pub(super) truncated: bool,
}

pub(super) fn stage_summary_update(
    existing: Option<&TraceSummary>,
    slot: usize,
    observation: StagedObservation,
    cancellation: &dyn ScanCancellation,
    observer: &dyn ScanObserver,
) -> Result<SummaryUpdate, TraceStoreFailure> {
    let prior = existing
        .map(|summary| clone_summary_observed(summary, cancellation, observer))
        .transpose()?;
    let mut updated = match &prior {
        Some(existing) => clone_summary_observed(existing, cancellation, observer)?,
        None => TraceSummary {
            trace_id: observation.trace_id,
            first_seen: observation.ingest_time,
            last_seen: observation.ingest_time,
            observation_count: 0,
            spans: Vec::new(),
            truncated: false,
            quiescent: false,
        },
    };
    updated.first_seen = updated.first_seen.min(observation.ingest_time);
    updated.last_seen = updated.last_seen.max(observation.ingest_time);
    updated.observation_count = updated
        .observation_count
        .checked_add(1)
        .ok_or_else(TraceStoreFailure::limit_exceeded)?;
    updated.quiescent = false;
    updated.truncated |= observation.truncated;
    let span_index =
        match find_span_observed(&updated.spans, observation.span_id, cancellation, observer)? {
            Ok(index) => index,
            Err(index) => {
                updated
                    .spans
                    .try_reserve_exact(1)
                    .map_err(|_| TraceStoreFailure::resource_exhausted())?;
                updated.spans.insert(
                    index,
                    SpanSummary {
                        span_id: observation.span_id,
                        variants: Vec::new(),
                    },
                );
                index
            },
        };
    let variants = &mut updated
        .spans
        .get_mut(span_index)
        .ok_or_else(TraceStoreFailure::invalid_input)?
        .variants;
    let mut duplicate = false;
    for variant in variants.iter() {
        super::super::scan::check_cancel(cancellation)?;
        observer
            .observe_work(1)
            .map_err(TraceStoreFailure::observation)?;
        if semantic_equal_observed(variant, &observation.semantic, cancellation, observer)? {
            duplicate = true;
            break;
        }
    }
    if !duplicate {
        variants
            .try_reserve_exact(1)
            .map_err(|_| TraceStoreFailure::resource_exhausted())?;
        variants.push(observation.semantic);
    }
    Ok(SummaryUpdate {
        slot,
        prior,
        updated,
    })
}

fn clone_summary_observed(
    summary: &TraceSummary,
    cancellation: &dyn ScanCancellation,
    observer: &dyn ScanObserver,
) -> Result<TraceSummary, TraceStoreFailure> {
    let mut spans = Vec::new();
    spans
        .try_reserve_exact(summary.spans.len())
        .map_err(|_| TraceStoreFailure::resource_exhausted())?;
    for span in &summary.spans {
        super::super::scan::check_cancel(cancellation)?;
        observer
            .observe_work(1)
            .map_err(TraceStoreFailure::observation)?;
        let mut variants = Vec::new();
        variants
            .try_reserve_exact(span.variants.len())
            .map_err(|_| TraceStoreFailure::resource_exhausted())?;
        for variant in &span.variants {
            super::super::scan::check_cancel(cancellation)?;
            observer
                .observe_work(1)
                .map_err(TraceStoreFailure::observation)?;
            let mut copy = Vec::new();
            copy.try_reserve_exact(variant.len())
                .map_err(|_| TraceStoreFailure::resource_exhausted())?;
            for chunk in variant.chunks(4_096) {
                super::super::scan::check_cancel(cancellation)?;
                observer
                    .observe_work(1)
                    .map_err(TraceStoreFailure::observation)?;
                copy.extend_from_slice(chunk);
            }
            variants.push(copy);
        }
        spans.push(SpanSummary {
            span_id: span.span_id,
            variants,
        });
    }
    Ok(TraceSummary {
        trace_id: summary.trace_id,
        first_seen: summary.first_seen,
        last_seen: summary.last_seen,
        observation_count: summary.observation_count,
        spans,
        truncated: summary.truncated,
        quiescent: summary.quiescent,
    })
}

fn find_span_observed(
    spans: &[SpanSummary],
    span_id: [u8; 8],
    cancellation: &dyn ScanCancellation,
    observer: &dyn ScanObserver,
) -> Result<Result<usize, usize>, TraceStoreFailure> {
    find_sorted_observed(spans, span_id, |span| span.span_id, cancellation, observer)
}

fn find_sorted_observed<T, K: Ord + Copy>(
    values: &[T],
    key: K,
    item_key: impl Fn(&T) -> K,
    cancellation: &dyn ScanCancellation,
    observer: &dyn ScanObserver,
) -> Result<Result<usize, usize>, TraceStoreFailure> {
    let mut lower = 0_usize;
    let mut upper = values.len();
    while lower < upper {
        super::super::scan::check_cancel(cancellation)?;
        observer
            .observe_work(1)
            .map_err(TraceStoreFailure::observation)?;
        let middle = lower
            .checked_add(upper - lower)
            .and_then(|sum| sum.checked_div(2))
            .ok_or_else(TraceStoreFailure::limit_exceeded)?;
        let value = values
            .get(middle)
            .ok_or_else(TraceStoreFailure::invalid_input)?;
        match key.cmp(&item_key(value)) {
            std::cmp::Ordering::Less => upper = middle,
            std::cmp::Ordering::Equal => return Ok(Ok(middle)),
            std::cmp::Ordering::Greater => {
                lower = lower
                    .checked_add(1)
                    .ok_or_else(TraceStoreFailure::limit_exceeded)?;
            },
        }
    }
    Ok(Err(lower))
}

fn semantic_equal_observed(
    left: &[u8],
    right: &[u8],
    cancellation: &dyn ScanCancellation,
    observer: &dyn ScanObserver,
) -> Result<bool, TraceStoreFailure> {
    if left.len() != right.len() {
        return Ok(false);
    }
    for (left, right) in left.chunks(4_096).zip(right.chunks(4_096)) {
        super::super::scan::check_cancel(cancellation)?;
        observer
            .observe_work(1)
            .map_err(TraceStoreFailure::observation)?;
        if left != right {
            return Ok(false);
        }
    }
    Ok(true)
}
