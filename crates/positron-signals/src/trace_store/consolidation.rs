use super::failure::TraceStoreFailure;
use super::scan::{ScannedSpanObservation, TraceIncompleteness, check_cancel};
#[cfg(fuzzing)]
use crate::ScanObservationFailureCode;
use crate::{ScanCancellation, ScanObserver};
use positron_domain::value::{NativeValueObserver, ValueLimitProfile};
use positron_kernel::ResourceReservation;

const SEMANTIC_KEY_WORK_CHUNK_BYTES: usize = 4_096;

struct ConsolidationEntry {
    observation: ScannedSpanObservation,
    semantic_key: Vec<u8>,
}

pub(super) struct ConsolidationContext<'a> {
    pub(super) profile: &'a ValueLimitProfile,
    pub(super) cancellation: &'a dyn ScanCancellation,
    pub(super) observer: &'a dyn ScanObserver,
}

/// A semantic variant retained for one logical span.
#[derive(Debug)]
pub struct SpanObservationVariant {
    observation: ScannedSpanObservation,
    observation_count: u64,
}

impl SpanObservationVariant {
    fn new(observation: ScannedSpanObservation) -> Result<Self, TraceStoreFailure> {
        Ok(Self {
            observation,
            observation_count: 1,
        })
    }

    fn record(&mut self) -> Result<(), TraceStoreFailure> {
        self.observation_count = self
            .observation_count
            .checked_add(1)
            .ok_or_else(TraceStoreFailure::limit_exceeded)?;
        Ok(())
    }

    /// Returns the earliest committed observation for this semantic variant.
    #[must_use]
    pub const fn observation(&self) -> &ScannedSpanObservation {
        &self.observation
    }

    /// Returns every received observation coalesced into this semantic variant.
    #[must_use]
    pub const fn observation_count(&self) -> u64 {
        self.observation_count
    }
}

/// One tenant-scoped trace and span identity with its immutable variants.
#[derive(Debug)]
pub struct LogicalSpan {
    trace_id: [u8; 16],
    span_id: [u8; 8],
    variants: Vec<SpanObservationVariant>,
    observation_count: u64,
    structural_variant: usize,
}

impl LogicalSpan {
    fn new(observation: ScannedSpanObservation) -> Result<Self, TraceStoreFailure> {
        let trace_id = observation.observation().trace_id();
        let span_id = observation.observation().span_id();
        let mut variants = Vec::new();
        variants
            .try_reserve_exact(1)
            .map_err(|_| TraceStoreFailure::resource_exhausted())?;
        variants.push(SpanObservationVariant::new(observation)?);
        Ok(Self {
            trace_id,
            span_id,
            variants,
            observation_count: 1,
            structural_variant: 0,
        })
    }

    fn has_identity(&self, observation: &ScannedSpanObservation) -> bool {
        self.trace_id == observation.observation().trace_id()
            && self.span_id == observation.observation().span_id()
    }

    fn record_last_variant(&mut self) -> Result<(), TraceStoreFailure> {
        self.observation_count = self
            .observation_count
            .checked_add(1)
            .ok_or_else(TraceStoreFailure::limit_exceeded)?;
        self.variants
            .last_mut()
            .ok_or_else(TraceStoreFailure::invalid_input)?
            .record()
    }

    fn record_new_variant(
        &mut self,
        observation: ScannedSpanObservation,
    ) -> Result<(), TraceStoreFailure> {
        self.observation_count = self
            .observation_count
            .checked_add(1)
            .ok_or_else(TraceStoreFailure::limit_exceeded)?;
        let is_earlier = self
            .structural_representative()
            .is_some_and(|representative| physical_order(&observation, representative).is_lt());
        self.variants
            .try_reserve_exact(1)
            .map_err(|_| TraceStoreFailure::resource_exhausted())?;
        self.variants
            .push(SpanObservationVariant::new(observation)?);
        if is_earlier {
            self.structural_variant = self
                .variants
                .len()
                .checked_sub(1)
                .ok_or_else(TraceStoreFailure::invalid_input)?;
        }
        Ok(())
    }

    #[must_use]
    pub const fn trace_id(&self) -> [u8; 16] {
        self.trace_id
    }

    #[must_use]
    pub const fn span_id(&self) -> [u8; 8] {
        self.span_id
    }

    /// Returns the semantic variants without overwriting conflicting evidence.
    #[must_use]
    pub fn variants(&self) -> &[SpanObservationVariant] {
        &self.variants
    }

    /// Returns every received observation for this identity, including retries.
    #[must_use]
    pub const fn observation_count(&self) -> u64 {
        self.observation_count
    }

    /// Returns whether this identity has more than one semantic observation.
    ///
    /// A conflict leaves all variants queryable and makes later structural
    /// analysis unable to select one authoritative observation on this fact.
    #[must_use]
    pub fn conflicted(&self) -> bool {
        self.variants.len() > 1
    }

    /// Returns the deterministic earliest committed structural representative.
    #[must_use]
    pub fn structural_representative(&self) -> Option<&ScannedSpanObservation> {
        self.variants
            .get(self.structural_variant)
            .map(SpanObservationVariant::observation)
    }
}

/// A logical view over one bounded physical Trace Store scan.
#[derive(Debug)]
pub struct LogicalTraceScanResult<'kernel> {
    spans: Vec<LogicalSpan>,
    decoded_observations: u64,
    complete: bool,
    scanned_bytes: u64,
    scanned_bytes_limited: bool,
    retained_size_bytes: u64,
    _capacity: ResourceReservation<'kernel>,
}

impl LogicalTraceScanResult<'_> {
    #[must_use]
    pub fn spans(&self) -> &[LogicalSpan] {
        &self.spans
    }

    /// Returns every committed observation decoded for this logical result.
    #[must_use]
    pub const fn decoded_observations(&self) -> u64 {
        self.decoded_observations
    }

    #[must_use]
    pub const fn complete(&self) -> bool {
        self.complete
    }

    #[must_use]
    pub const fn scanned_bytes(&self) -> u64 {
        self.scanned_bytes
    }

    #[must_use]
    pub const fn incompleteness(&self) -> TraceIncompleteness {
        if self.complete {
            TraceIncompleteness::None
        } else if self.scanned_bytes_limited {
            TraceIncompleteness::ScannedBytesLimit
        } else {
            TraceIncompleteness::ResultLimit
        }
    }

    #[must_use]
    pub const fn retained_size_bytes(&self) -> u64 {
        self.retained_size_bytes
    }
}

pub(super) fn consolidate<'kernel>(
    observations: Vec<ScannedSpanObservation>,
    complete: bool,
    scanned_bytes: u64,
    scanned_bytes_limited: bool,
    retained_size_bytes: u64,
    mut capacity: ResourceReservation<'kernel>,
    context: ConsolidationContext<'_>,
) -> Result<LogicalTraceScanResult<'kernel>, TraceStoreFailure> {
    let decoded_observations =
        u64::try_from(observations.len()).map_err(|_| TraceStoreFailure::limit_exceeded())?;
    let staging_bytes = consolidation_staging_bytes(&observations, retained_size_bytes, &context)?;
    super::scan::resize_capacity(&mut capacity, staging_bytes.max(1))?;
    let entries = entries_with_semantic_keys(observations, &context)?;
    let entries = interruptible_sort(entries, &context)?;
    let spans = group_observations(entries, &context)?;
    let mut retained_observer = ObservedRetainedSize { context: &context };
    let retained_size_bytes =
        logical_retained_size(&spans, spans.capacity(), &mut retained_observer)?;
    super::scan::resize_capacity(&mut capacity, retained_size_bytes.max(1))?;
    Ok(LogicalTraceScanResult {
        spans,
        decoded_observations,
        complete,
        scanned_bytes,
        scanned_bytes_limited,
        retained_size_bytes,
        _capacity: capacity,
    })
}

fn consolidation_staging_bytes(
    observations: &[ScannedSpanObservation],
    retained_size_bytes: u64,
    context: &ConsolidationContext<'_>,
) -> Result<u64, TraceStoreFailure> {
    let key_bytes = observations.iter().try_fold(0_u64, |total, observation| {
        observe_consolidation_unit(context)?;
        let encoded = super::codec::encoded_record_bytes_with_profile_observed(
            context.profile,
            observation.observation(),
            context.cancellation,
            context.observer,
        )?;
        let semantic = encoded
            .checked_sub(8)
            .ok_or_else(TraceStoreFailure::invalid_input)?;
        total
            .checked_add(u64::try_from(semantic).map_err(|_| TraceStoreFailure::limit_exceeded())?)
            .ok_or_else(TraceStoreFailure::limit_exceeded)
    })?;
    let count = observations.len();
    let entry_slots = vector_slots_bytes::<ConsolidationEntry>(count)?;
    let scratch_slots = vector_slots_bytes::<Option<ConsolidationEntry>>(count)?;
    let maximum_container_bytes = vector_slots_bytes::<LogicalSpan>(count)?
        .checked_add(vector_slots_bytes::<SpanObservationVariant>(count)?)
        .ok_or_else(TraceStoreFailure::limit_exceeded)?;
    let staging_bytes = retained_size_bytes
        .checked_add(key_bytes)
        .and_then(|bytes| bytes.checked_add(entry_slots))
        .and_then(|bytes| bytes.checked_add(scratch_slots))
        .and_then(|bytes| bytes.checked_add(scratch_slots))
        .and_then(|bytes| bytes.checked_add(maximum_container_bytes))
        .ok_or_else(TraceStoreFailure::limit_exceeded)?;
    Ok(staging_bytes)
}

fn vector_slots_bytes<T>(count: usize) -> Result<u64, TraceStoreFailure> {
    u64::try_from(count)
        .map_err(|_| TraceStoreFailure::limit_exceeded())?
        .checked_mul(
            u64::try_from(std::mem::size_of::<T>())
                .map_err(|_| TraceStoreFailure::limit_exceeded())?,
        )
        .ok_or_else(TraceStoreFailure::limit_exceeded)
}

fn entries_with_semantic_keys(
    observations: Vec<ScannedSpanObservation>,
    context: &ConsolidationContext<'_>,
) -> Result<Vec<ConsolidationEntry>, TraceStoreFailure> {
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(observations.len())
        .map_err(|_| TraceStoreFailure::resource_exhausted())?;
    for observation in observations {
        observe_consolidation_unit(context)?;
        let semantic_key = super::codec::encode_semantic_observation_with_profile_observed(
            context.profile,
            observation.observation(),
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

fn interruptible_sort(
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

fn group_observations(
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

fn physical_order(
    left: &ScannedSpanObservation,
    right: &ScannedSpanObservation,
) -> std::cmp::Ordering {
    left.commit_position()
        .cmp(&right.commit_position())
        .then_with(|| left.record_ordinal().cmp(&right.record_ordinal()))
}

fn observe_consolidation_unit(context: &ConsolidationContext<'_>) -> Result<(), TraceStoreFailure> {
    check_cancel(context.cancellation)?;
    context
        .observer
        .observe_work(1)
        .map_err(TraceStoreFailure::observation)
}

struct ObservedRetainedSize<'a, 'context> {
    context: &'a ConsolidationContext<'context>,
}

impl NativeValueObserver for ObservedRetainedSize<'_, '_> {
    type Error = TraceStoreFailure;

    fn observe_structure(&mut self) -> Result<(), Self::Error> {
        observe_consolidation_unit(self.context)
    }

    fn observe_payload(&mut self, _payload: &[u8]) -> Result<(), Self::Error> {
        observe_consolidation_unit(self.context)
    }
}

#[cfg(fuzzing)]
pub(super) fn fuzz_group_observations(
    observations: Vec<ScannedSpanObservation>,
) -> Result<(), TraceStoreFailure> {
    let expected =
        u64::try_from(observations.len()).map_err(|_| TraceStoreFailure::limit_exceeded())?;
    let profile = ValueLimitProfile::release_1_system_maximum();
    let context = ConsolidationContext {
        profile: &profile,
        cancellation: &FuzzNeverCancelled,
        observer: &FuzzUnobserved,
    };
    let entries = entries_with_semantic_keys(observations, &context)?;
    let entries = interruptible_sort(entries, &context)?;
    let spans = group_observations(entries, &context)?;
    let counted = spans.iter().try_fold(0_u64, |total, span| {
        if span.structural_representative().is_none()
            || span.variants().iter().any(|variant| {
                variant.observation_count() == 0
                    || variant.observation().observation().trace_id() != span.trace_id()
                    || variant.observation().observation().span_id() != span.span_id()
            })
        {
            return Err(TraceStoreFailure::invalid_input());
        }
        total
            .checked_add(span.observation_count())
            .ok_or_else(TraceStoreFailure::limit_exceeded)
    })?;
    if counted == expected {
        Ok(())
    } else {
        Err(TraceStoreFailure::invalid_input())
    }
}

#[cfg(fuzzing)]
struct FuzzNeverCancelled;

#[cfg(fuzzing)]
impl ScanCancellation for FuzzNeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

#[cfg(fuzzing)]
struct FuzzUnobserved;

#[cfg(fuzzing)]
impl ScanObserver for FuzzUnobserved {
    fn observe_work(&self, _units: u64) -> Result<(), ScanObservationFailureCode> {
        Ok(())
    }
}

fn logical_retained_size(
    spans: &[LogicalSpan],
    span_capacity: usize,
    observer: &mut impl NativeValueObserver<Error = TraceStoreFailure>,
) -> Result<u64, TraceStoreFailure> {
    observer.observe_structure()?;
    let span_slots = u64::try_from(span_capacity)
        .map_err(|_| TraceStoreFailure::limit_exceeded())?
        .checked_mul(
            u64::try_from(std::mem::size_of::<LogicalSpan>())
                .map_err(|_| TraceStoreFailure::limit_exceeded())?,
        )
        .ok_or_else(TraceStoreFailure::limit_exceeded)?;
    spans.iter().try_fold(span_slots, |total, span| {
        observer.observe_structure()?;
        let variant_slots = u64::try_from(span.variants.capacity())
            .map_err(|_| TraceStoreFailure::limit_exceeded())?
            .checked_mul(
                u64::try_from(std::mem::size_of::<SpanObservationVariant>())
                    .map_err(|_| TraceStoreFailure::limit_exceeded())?,
            )
            .ok_or_else(TraceStoreFailure::limit_exceeded)?;
        let variants = span
            .variants
            .iter()
            .try_fold(variant_slots, |size, variant| {
                observer.observe_structure()?;
                let dynamic = u64::try_from(
                    variant
                        .observation()
                        .observation()
                        .retained_heap_bytes_observed(observer)?,
                )
                .map_err(|_| TraceStoreFailure::limit_exceeded())?;
                size.checked_add(dynamic)
                    .ok_or_else(TraceStoreFailure::limit_exceeded)
            })?;
        total
            .checked_add(variants)
            .ok_or_else(TraceStoreFailure::limit_exceeded)
    })
}
