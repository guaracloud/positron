use super::failure::TraceStoreFailure;
use super::scan::{ScannedSpanObservation, TraceIncompleteness};
use positron_kernel::ResourceReservation;

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

    fn matches(&self, observation: &ScannedSpanObservation) -> bool {
        self.observation.observation() == observation.observation()
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
        })
    }

    fn has_identity(&self, observation: &ScannedSpanObservation) -> bool {
        self.trace_id == observation.observation().trace_id()
            && self.span_id == observation.observation().span_id()
    }

    fn record(&mut self, observation: ScannedSpanObservation) -> Result<(), TraceStoreFailure> {
        self.observation_count = self
            .observation_count
            .checked_add(1)
            .ok_or_else(TraceStoreFailure::limit_exceeded)?;
        if let Some(variant) = self
            .variants
            .iter_mut()
            .find(|variant| variant.matches(&observation))
        {
            return variant.record();
        }
        self.variants
            .try_reserve_exact(1)
            .map_err(|_| TraceStoreFailure::resource_exhausted())?;
        self.variants
            .push(SpanObservationVariant::new(observation)?);
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
    #[must_use]
    pub fn conflicted(&self) -> bool {
        self.variants.len() > 1
    }

    /// Conflicting variants make structural analysis explicitly incomplete.
    #[must_use]
    pub fn structurally_incomplete(&self) -> bool {
        self.conflicted()
    }

    /// Returns the deterministic earliest committed structural representative.
    #[must_use]
    pub fn structural_representative(&self) -> Option<&ScannedSpanObservation> {
        self.variants
            .first()
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
) -> Result<LogicalTraceScanResult<'kernel>, TraceStoreFailure> {
    let decoded_observations =
        u64::try_from(observations.len()).map_err(|_| TraceStoreFailure::limit_exceeded())?;
    let maximum_container_bytes = u64::try_from(observations.len())
        .map_err(|_| TraceStoreFailure::limit_exceeded())?
        .checked_mul(
            u64::try_from(
                std::mem::size_of::<LogicalSpan>() + std::mem::size_of::<SpanObservationVariant>(),
            )
            .map_err(|_| TraceStoreFailure::limit_exceeded())?,
        )
        .ok_or_else(TraceStoreFailure::limit_exceeded)?;
    let staging_bytes = retained_size_bytes
        .checked_add(maximum_container_bytes)
        .ok_or_else(TraceStoreFailure::limit_exceeded)?;
    super::scan::resize_capacity(&mut capacity, staging_bytes.max(1))?;
    let spans = group_observations(observations)?;
    let retained_size_bytes = logical_retained_size(&spans, spans.capacity())?;
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

fn group_observations(
    mut observations: Vec<ScannedSpanObservation>,
) -> Result<Vec<LogicalSpan>, TraceStoreFailure> {
    observations.sort_unstable_by(|left, right| {
        left.observation()
            .trace_id()
            .cmp(&right.observation().trace_id())
            .then_with(|| {
                left.observation()
                    .span_id()
                    .cmp(&right.observation().span_id())
            })
            .then_with(|| left.commit_position().cmp(&right.commit_position()))
            .then_with(|| left.record_ordinal().cmp(&right.record_ordinal()))
    });
    let mut spans: Vec<LogicalSpan> = Vec::new();
    spans
        .try_reserve_exact(observations.len())
        .map_err(|_| TraceStoreFailure::resource_exhausted())?;
    for observation in observations {
        if let Some(span) = spans
            .last_mut()
            .filter(|span| span.has_identity(&observation))
        {
            span.record(observation)?;
        } else {
            spans.push(LogicalSpan::new(observation)?);
        }
    }
    Ok(spans)
}

#[cfg(fuzzing)]
pub(super) fn fuzz_group_observations(
    observations: Vec<ScannedSpanObservation>,
) -> Result<(), TraceStoreFailure> {
    let expected =
        u64::try_from(observations.len()).map_err(|_| TraceStoreFailure::limit_exceeded())?;
    let spans = group_observations(observations)?;
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

fn logical_retained_size(
    spans: &[LogicalSpan],
    span_capacity: usize,
) -> Result<u64, TraceStoreFailure> {
    let span_slots = u64::try_from(span_capacity)
        .map_err(|_| TraceStoreFailure::limit_exceeded())?
        .checked_mul(
            u64::try_from(std::mem::size_of::<LogicalSpan>())
                .map_err(|_| TraceStoreFailure::limit_exceeded())?,
        )
        .ok_or_else(TraceStoreFailure::limit_exceeded)?;
    spans.iter().try_fold(span_slots, |total, span| {
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
                let dynamic =
                    u64::try_from(variant.observation().observation().retained_heap_bytes()?)
                        .map_err(|_| TraceStoreFailure::limit_exceeded())?;
                size.checked_add(dynamic)
                    .ok_or_else(TraceStoreFailure::limit_exceeded)
            })?;
        total
            .checked_add(variants)
            .ok_or_else(TraceStoreFailure::limit_exceeded)
    })
}
