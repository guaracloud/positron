use super::super::failure::TraceStoreFailure;
use super::super::scan::ScannedSpanObservation;
use super::{ConsolidationContext, LogicalSpan, observe_consolidation_unit, physical_order};

const SEMANTIC_KEY_WORK_CHUNK_BYTES: usize = 4_096;

pub(super) struct ConsolidationEntry {
    observation: ScannedSpanObservation,
    semantic_key: Vec<u8>,
}

pub(super) struct SemanticKeySizes {
    values: Vec<usize>,
    pub(super) total_bytes: u64,
}

pub(super) fn observed_semantic_key_sizes(
    observations: &[ScannedSpanObservation],
    context: &ConsolidationContext<'_>,
) -> Result<SemanticKeySizes, TraceStoreFailure> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(observations.len())
        .map_err(|_| TraceStoreFailure::resource_exhausted())?;
    let mut total_bytes = 0_u64;
    for observation in observations {
        observe_consolidation_unit(context)?;
        let encoded = super::super::codec::encoded_record_bytes_with_profile_observed(
            context.profile,
            observation.observation(),
            context.cancellation,
            context.observer,
        )?;
        let semantic = encoded
            .checked_sub(8)
            .ok_or_else(TraceStoreFailure::invalid_input)?;
        total_bytes = total_bytes
            .checked_add(u64::try_from(semantic).map_err(|_| TraceStoreFailure::limit_exceeded())?)
            .ok_or_else(TraceStoreFailure::limit_exceeded)?;
        values.push(semantic);
    }
    Ok(SemanticKeySizes {
        values,
        total_bytes,
    })
}

pub(super) fn entries_with_semantic_keys(
    observations: Vec<ScannedSpanObservation>,
    semantic_sizes: SemanticKeySizes,
    context: &ConsolidationContext<'_>,
) -> Result<Vec<ConsolidationEntry>, TraceStoreFailure> {
    if observations.len() != semantic_sizes.values.len() {
        return Err(TraceStoreFailure::invalid_input());
    }
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(observations.len())
        .map_err(|_| TraceStoreFailure::resource_exhausted())?;
    for (observation, expected) in observations.into_iter().zip(semantic_sizes.values) {
        observe_consolidation_unit(context)?;
        let semantic_key = super::super::codec::encode_semantic_observation_with_profile_observed(
            context.profile,
            observation.observation(),
            expected,
            context.cancellation,
            context.observer,
        )?;
        entries.push(ConsolidationEntry {
            observation,
            semantic_key,
        });
    }
    Ok(entries)
}

pub(super) fn interruptible_sort(
    mut entries: Vec<ConsolidationEntry>,
    context: &ConsolidationContext<'_>,
) -> Result<Vec<Option<ConsolidationEntry>>, TraceStoreFailure> {
    let length = entries.len();
    let mut source = Vec::new();
    source
        .try_reserve_exact(length)
        .map_err(|_| TraceStoreFailure::resource_exhausted())?;
    for entry in entries.drain(..) {
        source.push(Some(entry));
    }
    if length < 2 {
        return Ok(source);
    }
    let mut destination = Vec::new();
    destination
        .try_reserve_exact(length)
        .map_err(|_| TraceStoreFailure::resource_exhausted())?;
    for _ in 0..length {
        destination.push(None);
    }
    let mut width = 1_usize;
    while width < length {
        let mut start = 0_usize;
        while start < length {
            let middle = start.saturating_add(width).min(length);
            let end = middle.saturating_add(width).min(length);
            merge_runs(&mut source, &mut destination, start, middle, end, context)?;
            start = end;
        }
        std::mem::swap(&mut source, &mut destination);
        width = width
            .checked_mul(2)
            .ok_or_else(TraceStoreFailure::limit_exceeded)?;
    }
    Ok(source)
}

#[allow(clippy::too_many_arguments)]
fn merge_runs(
    source: &mut [Option<ConsolidationEntry>],
    destination: &mut [Option<ConsolidationEntry>],
    start: usize,
    middle: usize,
    end: usize,
    context: &ConsolidationContext<'_>,
) -> Result<(), TraceStoreFailure> {
    let mut left = start;
    let mut right = middle;
    let mut output = start;
    while left < middle && right < end {
        observe_consolidation_unit(context)?;
        let left_entry = source
            .get(left)
            .and_then(Option::as_ref)
            .ok_or_else(TraceStoreFailure::invalid_input)?;
        let right_entry = source
            .get(right)
            .and_then(Option::as_ref)
            .ok_or_else(TraceStoreFailure::invalid_input)?;
        let input = if entry_order(left_entry, right_entry, context)?.is_gt() {
            let input = right;
            right = right
                .checked_add(1)
                .ok_or_else(TraceStoreFailure::limit_exceeded)?;
            input
        } else {
            let input = left;
            left = left
                .checked_add(1)
                .ok_or_else(TraceStoreFailure::limit_exceeded)?;
            input
        };
        move_entry(source, destination, input, output)?;
        output = output
            .checked_add(1)
            .ok_or_else(TraceStoreFailure::limit_exceeded)?;
    }
    while left < middle {
        observe_consolidation_unit(context)?;
        move_entry(source, destination, left, output)?;
        left = left
            .checked_add(1)
            .ok_or_else(TraceStoreFailure::limit_exceeded)?;
        output = output
            .checked_add(1)
            .ok_or_else(TraceStoreFailure::limit_exceeded)?;
    }
    while right < end {
        observe_consolidation_unit(context)?;
        move_entry(source, destination, right, output)?;
        right = right
            .checked_add(1)
            .ok_or_else(TraceStoreFailure::limit_exceeded)?;
        output = output
            .checked_add(1)
            .ok_or_else(TraceStoreFailure::limit_exceeded)?;
    }
    Ok(())
}

fn move_entry(
    source: &mut [Option<ConsolidationEntry>],
    destination: &mut [Option<ConsolidationEntry>],
    input: usize,
    output: usize,
) -> Result<(), TraceStoreFailure> {
    let entry = source
        .get_mut(input)
        .and_then(Option::take)
        .ok_or_else(TraceStoreFailure::invalid_input)?;
    let slot = destination
        .get_mut(output)
        .ok_or_else(TraceStoreFailure::invalid_input)?;
    if slot.is_some() {
        return Err(TraceStoreFailure::invalid_input());
    }
    *slot = Some(entry);
    Ok(())
}

pub(super) fn group_observations(
    entries: Vec<Option<ConsolidationEntry>>,
    context: &ConsolidationContext<'_>,
) -> Result<Vec<LogicalSpan>, TraceStoreFailure> {
    let mut spans: Vec<LogicalSpan> = Vec::new();
    spans
        .try_reserve_exact(entries.len())
        .map_err(|_| TraceStoreFailure::resource_exhausted())?;
    let mut active_key: Option<Vec<u8>> = None;
    for entry in entries {
        let entry = entry.ok_or_else(TraceStoreFailure::invalid_input)?;
        observe_consolidation_unit(context)?;
        let same_identity = spans
            .last()
            .is_some_and(|span| span.has_identity(&entry.observation));
        let same_variant = match (same_identity, active_key.as_ref()) {
            (true, Some(key)) => semantic_key_order(key, &entry.semantic_key, context)?.is_eq(),
            _ => false,
        };
        if same_variant {
            spans
                .last_mut()
                .ok_or_else(TraceStoreFailure::invalid_input)?
                .record_last_variant()?;
        } else if same_identity {
            active_key = Some(entry.semantic_key);
            spans
                .last_mut()
                .ok_or_else(TraceStoreFailure::invalid_input)?
                .record_new_variant(entry.observation)?;
        } else {
            active_key = Some(entry.semantic_key);
            spans.push(LogicalSpan::new(entry.observation)?);
        }
    }
    Ok(spans)
}

fn entry_order(
    left: &ConsolidationEntry,
    right: &ConsolidationEntry,
    context: &ConsolidationContext<'_>,
) -> Result<std::cmp::Ordering, TraceStoreFailure> {
    let identity_order = left
        .observation
        .observation()
        .trace_id()
        .cmp(&right.observation.observation().trace_id())
        .then_with(|| {
            left.observation
                .observation()
                .span_id()
                .cmp(&right.observation.observation().span_id())
        });
    if !identity_order.is_eq() {
        return Ok(identity_order);
    }
    let semantic_order = semantic_key_order(&left.semantic_key, &right.semantic_key, context)?;
    if !semantic_order.is_eq() {
        return Ok(semantic_order);
    }
    Ok(physical_order(&left.observation, &right.observation))
}

fn semantic_key_order(
    left: &[u8],
    right: &[u8],
    context: &ConsolidationContext<'_>,
) -> Result<std::cmp::Ordering, TraceStoreFailure> {
    let shared = left.len().min(right.len());
    let mut offset = 0_usize;
    while offset < shared {
        observe_consolidation_unit(context)?;
        let end = offset
            .checked_add(SEMANTIC_KEY_WORK_CHUNK_BYTES)
            .map(|end| end.min(shared))
            .ok_or_else(TraceStoreFailure::limit_exceeded)?;
        let order = left
            .get(offset..end)
            .ok_or_else(TraceStoreFailure::invalid_input)?
            .cmp(
                right
                    .get(offset..end)
                    .ok_or_else(TraceStoreFailure::invalid_input)?,
            );
        if !order.is_eq() {
            return Ok(order);
        }
        offset = end;
    }
    Ok(left.len().cmp(&right.len()))
}
