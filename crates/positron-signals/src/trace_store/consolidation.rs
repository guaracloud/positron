use super::failure::TraceStoreFailure;
use super::scan::{ScannedSpanObservation, TraceIncompleteness, check_cancel};
use crate::{ScanCancellation, ScanObserver};
use positron_domain::value::ValueLimitProfile;
use positron_kernel::ResourceReservation;

mod accounting;
mod entries;
#[cfg(fuzzing)]
mod fuzz;

use accounting::{ObservedRetainedSize, logical_retained_size};
use entries::{
    ConsolidationEntry, entries_with_semantic_keys, group_observations, interruptible_sort,
    observed_semantic_key_sizes,
};
#[cfg(fuzzing)]
pub(super) fn fuzz_group_observations(
    observations: Vec<ScannedSpanObservation>,
) -> Result<(), TraceStoreFailure> {
    fuzz::fuzz_group_observations(observations)
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
    selected: bool,
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
            selected: false,
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

    pub(crate) fn select(&mut self) {
        self.selected = true;
    }

    pub(crate) fn deselect(&mut self) {
        self.selected = false;
    }

    pub(crate) const fn selected(&self) -> bool {
        self.selected
    }
}

/// A logical view over one bounded physical Trace Store scan.
#[derive(Debug)]
pub struct LogicalTraceScanResult<'kernel> {
    pub(super) spans: Vec<LogicalSpan>,
    pub(super) decoded_observations: u64,
    pub(super) complete: bool,
    pub(super) scanned_bytes: u64,
    pub(super) scanned_bytes_limited: bool,
    pub(super) retained_size_bytes: u64,
    pub(super) _capacity: ResourceReservation<'kernel>,
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
    let semantic_size_bytes = vector_slots_bytes::<usize>(observations.len())?;
    let preflight_bytes = retained_size_bytes
        .checked_add(semantic_size_bytes)
        .ok_or_else(TraceStoreFailure::limit_exceeded)?;
    super::scan::resize_capacity(&mut capacity, preflight_bytes.max(1))?;
    let semantic_sizes = observed_semantic_key_sizes(&observations, &context)?;
    let staging_bytes = consolidation_staging_bytes(
        observations.len(),
        retained_size_bytes,
        semantic_size_bytes,
        semantic_sizes.total_bytes,
    )?;
    super::scan::resize_capacity(&mut capacity, staging_bytes.max(1))?;
    let entries = entries_with_semantic_keys(observations, semantic_sizes, &context)?;
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
    count: usize,
    retained_size_bytes: u64,
    semantic_size_bytes: u64,
    key_bytes: u64,
) -> Result<u64, TraceStoreFailure> {
    let entry_slots = vector_slots_bytes::<ConsolidationEntry>(count)?;
    let scratch_slots = vector_slots_bytes::<Option<ConsolidationEntry>>(count)?;
    let maximum_container_bytes = vector_slots_bytes::<LogicalSpan>(count)?
        .checked_add(vector_slots_bytes::<SpanObservationVariant>(count)?)
        .ok_or_else(TraceStoreFailure::limit_exceeded)?;
    retained_size_bytes
        .checked_add(key_bytes)
        .and_then(|bytes| bytes.checked_add(semantic_size_bytes))
        .and_then(|bytes| bytes.checked_add(entry_slots))
        .and_then(|bytes| bytes.checked_add(scratch_slots))
        .and_then(|bytes| bytes.checked_add(scratch_slots))
        .and_then(|bytes| bytes.checked_add(maximum_container_bytes))
        .ok_or_else(TraceStoreFailure::limit_exceeded)
}

pub(super) fn vector_slots_bytes<T>(count: usize) -> Result<u64, TraceStoreFailure> {
    u64::try_from(count)
        .map_err(|_| TraceStoreFailure::limit_exceeded())?
        .checked_mul(
            u64::try_from(std::mem::size_of::<T>())
                .map_err(|_| TraceStoreFailure::limit_exceeded())?,
        )
        .ok_or_else(TraceStoreFailure::limit_exceeded)
}

pub(super) fn physical_order(
    left: &ScannedSpanObservation,
    right: &ScannedSpanObservation,
) -> std::cmp::Ordering {
    left.commit_position()
        .cmp(&right.commit_position())
        .then_with(|| left.record_ordinal().cmp(&right.record_ordinal()))
}

pub(super) fn observe_consolidation_unit(
    context: &ConsolidationContext<'_>,
) -> Result<(), TraceStoreFailure> {
    check_cancel(context.cancellation)?;
    context
        .observer
        .observe_work(1)
        .map_err(TraceStoreFailure::observation)
}
