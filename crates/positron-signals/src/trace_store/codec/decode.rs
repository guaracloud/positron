use positron_domain::identity::TenantId;
use positron_domain::time::{EventTime, SourceTimeQuality, UnixNanoseconds};
use positron_domain::value::{
    AttributeOccurrenceSetCandidate, CandidateAttributeValue, CandidateKeyValue, ValueLimitProfile,
};
use positron_kernel::CommittedBlock;

use super::super::details::{
    MAX_DETAIL_COLLECTION, SpanAttributeSet, SpanEvent, SpanLink, SpanObservationDetails,
    SpanResourceMetadata, SpanScopeMetadata, SpanStatus,
};
use super::super::failure::TraceStoreFailure;
use super::super::observation::SpanObservation;
use super::super::types::{StoredSpanObservation, TraceLimits, release_1_limits};
use super::format::{
    MAGIC, MAX_RECORDS, VERSION, check_cancel, decode_kind, decode_namespace, decode_quality,
    decode_sampling, decode_status_tag, supported_version,
};
use crate::{ScanCancellation, ScanObserver};

pub(crate) struct BlockDecode<'input> {
    pub(crate) input: Input<'input>,
    count: usize,
    version: u16,
}

impl<'input> BlockDecode<'input> {
    pub(crate) fn observed(
        expected_tenant: TenantId,
        bytes: &'input [u8],
        cancellation: &'input dyn ScanCancellation,
        observer: &'input dyn ScanObserver,
    ) -> Result<Self, TraceStoreFailure> {
        let mut input = Input::observed(bytes, cancellation, observer);
        input.observe_component()?;
        if input.take(MAGIC.len())? != MAGIC {
            return Err(TraceStoreFailure::malformed_block());
        }
        let version = input.u16()?;
        if !supported_version(version) {
            return Err(TraceStoreFailure::malformed_block());
        }
        let tenant = input.array::<16>()?;
        if tenant != expected_tenant.to_bytes() {
            return Err(TraceStoreFailure::physical_scope_mismatch());
        }
        let count = input.count(MAX_RECORDS)?;
        if count == 0 {
            return Err(TraceStoreFailure::malformed_block());
        }
        Ok(Self {
            input,
            count,
            version,
        })
    }

    pub(crate) const fn record_count(&self) -> usize {
        self.count
    }

    #[cfg(fuzzing)]
    pub(crate) const fn version(&self) -> u16 {
        self.version
    }

    pub(crate) fn decode_after(
        mut self,
        block: &CommittedBlock,
        skip: usize,
        limit: usize,
        cancellation: &dyn ScanCancellation,
    ) -> Result<DecodedBlock, TraceStoreFailure> {
        let skipped = skip.min(self.count);
        for _ in 0..skipped {
            check_cancel(cancellation)?;
            let (_, encoded_ingest_time) =
                decode_observation_version(&mut self.input, self.version)?;
            block
                .observe_ingest_time(encoded_ingest_time)
                .map_err(TraceStoreFailure::kernel)?;
        }
        let retained = self.count.saturating_sub(skipped).min(limit);
        let mut observations = Vec::new();
        observations
            .try_reserve_exact(retained)
            .map_err(|_| TraceStoreFailure::resource_exhausted())?;
        for _ in 0..retained {
            check_cancel(cancellation)?;
            let (observation, encoded_ingest_time) =
                decode_observation_version(&mut self.input, self.version)?;
            let ingest_time = block
                .observe_ingest_time(encoded_ingest_time)
                .map_err(TraceStoreFailure::kernel)?;
            self.input.observe_decoded_record()?;
            observations.push(StoredSpanObservation::new(observation, ingest_time));
        }
        // Validate and consume the unretained tail so malformed bytes never
        // disappear merely because the caller requested a small result bound.
        let mut tail = self.input.remaining_input();
        for _ in skipped + retained..self.count {
            check_cancel(cancellation)?;
            let (_, encoded_ingest_time) = decode_observation_version(&mut tail, self.version)?;
            block
                .observe_ingest_time(encoded_ingest_time)
                .map_err(TraceStoreFailure::kernel)?;
        }
        if !tail.is_empty() {
            return Err(TraceStoreFailure::malformed_block());
        }
        Ok(DecodedBlock { observations })
    }
}

pub(crate) struct DecodedBlock {
    pub(crate) observations: Vec<StoredSpanObservation>,
}

#[cfg(any(test, fuzzing))]
pub(crate) fn decode_observation(
    input: &mut Input<'_>,
) -> Result<(SpanObservation, UnixNanoseconds), TraceStoreFailure> {
    decode_observation_version(input, super::format::LEGACY_VERSION)
}

pub(crate) fn decode_observation_version(
    input: &mut Input<'_>,
    version: u16,
) -> Result<(SpanObservation, UnixNanoseconds), TraceStoreFailure> {
    input.observe_component()?;
    let trace_id = input.array::<16>()?;
    let span_id = input.array::<8>()?;
    let parent_span_id = match input.u8()? {
        0 => None,
        1 => Some(input.array::<8>()?),
        _ => return Err(TraceStoreFailure::malformed_block()),
    };
    let kind = decode_kind(input.u8()?)?;
    let sampling = decode_sampling(input.u8()?)?;
    let start = decode_time(input)?;
    let end = decode_time(input)?;
    let limits = release_1_limits()?;
    let name = input.string(limits.key_path_bytes)?;
    let attributes_count = input.count(limits.attribute_sets)?;
    let mut attributes = Vec::new();
    attributes
        .try_reserve_exact(attributes_count)
        .map_err(|_| TraceStoreFailure::resource_exhausted())?;
    let mut occurrences_by_namespace = [0_usize; 3];
    for _ in 0..attributes_count {
        input.observe_component()?;
        let namespace = decode_namespace(input.u8()?)?;
        let key = input.string(limits.key_path_bytes)?;
        let count = input.count(limits.occurrences_per_namespace)?;
        if count == 0 {
            return Err(TraceStoreFailure::malformed_block());
        }
        let namespace_index = super::format::namespace_index(namespace)?;
        occurrences_by_namespace[namespace_index] = occurrences_by_namespace[namespace_index]
            .checked_add(count)
            .filter(|total| *total <= limits.occurrences_per_namespace)
            .ok_or_else(TraceStoreFailure::malformed_block)?;
        let mut values = Vec::new();
        values
            .try_reserve_exact(count)
            .map_err(|_| TraceStoreFailure::resource_exhausted())?;
        for _ in 0..count {
            values.push(decode_value(input, limits.nesting_depth, &limits)?);
        }
        let candidate = AttributeOccurrenceSetCandidate::new(namespace, key, values);
        attributes.push(
            candidate
                .validate(ValueLimitProfile::release_1_system_maximum())
                .map_err(TraceStoreFailure::validation)?,
        );
    }
    let details = if version == VERSION {
        decode_details(input)?
    } else {
        // BlockDecode::observed admits only VERSION or LEGACY_VERSION.
        SpanObservationDetails::default()
    };
    let policy = decode_policy(input)?;
    let observation = SpanObservation::checked_native_with_details(
        trace_id,
        span_id,
        parent_span_id,
        name,
        start,
        end,
        attributes,
        kind,
        sampling,
        policy,
        details,
    )
    .map_err(|_| TraceStoreFailure::malformed_block())?;
    let ingest_time = UnixNanoseconds::new(input.i64()?);
    Ok((observation, ingest_time))
}

fn decode_details(input: &mut Input<'_>) -> Result<SpanObservationDetails, TraceStoreFailure> {
    let limits = release_1_limits()?;
    let trace_state = input.string(limits.key_path_bytes)?;
    let flags = input.u32()?;
    let status_code = decode_status_tag(input.u8()?)?;
    let status_message = input.string(limits.key_path_bytes)?;
    let status = SpanStatus::checked(status_code, status_message)
        .map_err(|_| TraceStoreFailure::malformed_block())?;
    let dropped_attributes_count = input.u32()?;
    let dropped_events_count = input.u32()?;
    let dropped_links_count = input.u32()?;
    let resource_dropped_attributes_count = input.u32()?;
    let resource_schema_url = input.string(limits.key_path_bytes)?;
    let scope_name = input.string(limits.key_path_bytes)?;
    let scope_version = input.string(limits.key_path_bytes)?;
    let scope_dropped_attributes_count = input.u32()?;
    let scope_schema_url = input.string(limits.key_path_bytes)?;
    let events_count = input.count(MAX_DETAIL_COLLECTION)?;
    let mut events = Vec::new();
    events
        .try_reserve_exact(events_count)
        .map_err(|_| TraceStoreFailure::resource_exhausted())?;
    for _ in 0..events_count {
        events.push(decode_event(
            input,
            limits.key_path_bytes,
            limits.nesting_depth,
        )?);
    }
    let links_count = input.count(MAX_DETAIL_COLLECTION)?;
    let mut links = Vec::new();
    links
        .try_reserve_exact(links_count)
        .map_err(|_| TraceStoreFailure::resource_exhausted())?;
    for _ in 0..links_count {
        links.push(decode_link(
            input,
            limits.key_path_bytes,
            limits.nesting_depth,
        )?);
    }
    SpanObservationDetails::checked(
        trace_state,
        flags,
        status,
        events,
        links,
        dropped_attributes_count,
        dropped_events_count,
        dropped_links_count,
        SpanResourceMetadata::checked(resource_dropped_attributes_count, resource_schema_url)
            .map_err(|_| TraceStoreFailure::malformed_block())?,
        SpanScopeMetadata::checked(
            scope_name,
            scope_version,
            scope_dropped_attributes_count,
            scope_schema_url,
        )
        .map_err(|_| TraceStoreFailure::malformed_block())?,
    )
    .map_err(|_| TraceStoreFailure::malformed_block())
}

fn decode_event(
    input: &mut Input<'_>,
    key_limit: usize,
    depth: u8,
) -> Result<SpanEvent, TraceStoreFailure> {
    let timestamp = decode_time(input)?;
    let name = input.string(key_limit)?;
    let dropped_attributes_count = input.u32()?;
    let attributes = decode_span_attributes(input, depth)?;
    SpanEvent::checked(timestamp, name, attributes, dropped_attributes_count)
        .map_err(|_| TraceStoreFailure::malformed_block())
}

fn decode_link(
    input: &mut Input<'_>,
    key_limit: usize,
    depth: u8,
) -> Result<SpanLink, TraceStoreFailure> {
    let trace_id = input.array::<16>()?;
    let span_id = input.array::<8>()?;
    let trace_state = input.string(key_limit)?;
    let flags = input.u32()?;
    let dropped_attributes_count = input.u32()?;
    let attributes = decode_span_attributes(input, depth)?;
    SpanLink::checked(
        trace_id,
        span_id,
        trace_state,
        flags,
        attributes,
        dropped_attributes_count,
    )
    .map_err(|_| TraceStoreFailure::malformed_block())
}

fn decode_span_attributes(
    input: &mut Input<'_>,
    depth: u8,
) -> Result<Vec<SpanAttributeSet>, TraceStoreFailure> {
    let limits = release_1_limits()?;
    let count = input.count(MAX_DETAIL_COLLECTION)?;
    let mut attributes = Vec::new();
    attributes
        .try_reserve_exact(count)
        .map_err(|_| TraceStoreFailure::resource_exhausted())?;
    for _ in 0..count {
        let key = input.string(limits.key_path_bytes)?;
        let occurrence_count = input.count(limits.occurrences_per_namespace)?;
        if occurrence_count == 0 {
            return Err(TraceStoreFailure::malformed_block());
        }
        let mut values = Vec::new();
        values
            .try_reserve_exact(occurrence_count)
            .map_err(|_| TraceStoreFailure::resource_exhausted())?;
        for _ in 0..occurrence_count {
            values.push(decode_value(input, depth, &limits)?);
        }
        attributes.push(
            SpanAttributeSet::checked(key, values, ValueLimitProfile::release_1_system_maximum())
                .map_err(|_| TraceStoreFailure::malformed_block())?,
        );
    }
    Ok(attributes)
}

fn decode_policy(
    input: &mut Input<'_>,
) -> Result<positron_policy::PolicyProvenance, TraceStoreFailure> {
    let generation = input.u64()?;
    let digest = input.array::<32>()?;
    let count = input.count(positron_policy::PolicyProvenance::MAX_APPLIED_RULES)?;
    let mut rules = Vec::new();
    rules
        .try_reserve_exact(count)
        .map_err(|_| TraceStoreFailure::resource_exhausted())?;
    for _ in 0..count {
        input.observe_component()?;
        rules.push(input.string(positron_policy::PolicyProvenance::MAX_RULE_ID_BYTES)?);
    }
    positron_policy::PolicyProvenance::new(generation, digest, rules)
        .map_err(|_| TraceStoreFailure::malformed_block())
}

fn decode_time(input: &mut Input<'_>) -> Result<EventTime, TraceStoreFailure> {
    let quality = decode_quality(input.u8()?)?;
    if quality == SourceTimeQuality::Missing {
        return Ok(EventTime::missing());
    }
    EventTime::received(UnixNanoseconds::new(input.i64()?), quality)
        .map_err(|_| TraceStoreFailure::malformed_block())
}

fn decode_value(
    input: &mut Input<'_>,
    depth: u8,
    limits: &TraceLimits,
) -> Result<CandidateAttributeValue, TraceStoreFailure> {
    input.observe_component()?;
    match input.u8()? {
        0 => Ok(CandidateAttributeValue::null()),
        1 => match input.u8()? {
            0 => Ok(CandidateAttributeValue::boolean(false)),
            1 => Ok(CandidateAttributeValue::boolean(true)),
            _ => Err(TraceStoreFailure::malformed_block()),
        },
        2 => Ok(CandidateAttributeValue::signed_integer(input.i64()?)),
        3 => Ok(CandidateAttributeValue::floating_point_bits(input.u64()?)),
        4 => Ok(CandidateAttributeValue::string(
            input.string(limits.value_bytes)?,
        )),
        5 => Ok(CandidateAttributeValue::bytes(
            input.bytes(limits.value_bytes)?,
        )),
        6 => {
            let next = depth
                .checked_sub(1)
                .ok_or_else(TraceStoreFailure::malformed_block)?;
            let count = input.count(limits.array_entries)?;
            let mut values = Vec::new();
            values
                .try_reserve_exact(count)
                .map_err(|_| TraceStoreFailure::resource_exhausted())?;
            for _ in 0..count {
                values.push(decode_value(input, next, limits)?);
            }
            Ok(CandidateAttributeValue::array(values))
        },
        7 => {
            let next = depth
                .checked_sub(1)
                .ok_or_else(TraceStoreFailure::malformed_block)?;
            let count = input.count(limits.key_value_list_entries)?;
            let mut values = Vec::new();
            values
                .try_reserve_exact(count)
                .map_err(|_| TraceStoreFailure::resource_exhausted())?;
            for _ in 0..count {
                let key = input.string(limits.key_path_bytes)?;
                values.push(CandidateKeyValue::new(
                    key,
                    decode_value(input, next, limits)?,
                ));
            }
            Ok(CandidateAttributeValue::key_value_list(values))
        },
        _ => Err(TraceStoreFailure::malformed_block()),
    }
}

pub(crate) struct Input<'a> {
    remaining: &'a [u8],
    cancellation: Option<&'a dyn ScanCancellation>,
    observer: Option<&'a dyn ScanObserver>,
}

impl<'a> Input<'a> {
    #[cfg(test)]
    pub(crate) fn cancelable(bytes: &'a [u8], cancellation: &'a dyn ScanCancellation) -> Self {
        Self {
            remaining: bytes,
            cancellation: Some(cancellation),
            observer: None,
        }
    }

    pub(crate) fn observed(
        bytes: &'a [u8],
        cancellation: &'a dyn ScanCancellation,
        observer: &'a dyn ScanObserver,
    ) -> Self {
        Self {
            remaining: bytes,
            cancellation: Some(cancellation),
            observer: Some(observer),
        }
    }

    pub(crate) fn take(&mut self, count: usize) -> Result<&'a [u8], TraceStoreFailure> {
        self.poll()?;
        let (value, remaining) = self
            .remaining
            .split_at_checked(count)
            .ok_or_else(TraceStoreFailure::malformed_block)?;
        self.remaining = remaining;
        Ok(value)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, TraceStoreFailure> {
        self.take(1)?
            .first()
            .copied()
            .ok_or_else(TraceStoreFailure::malformed_block)
    }

    pub(crate) fn u16(&mut self) -> Result<u16, TraceStoreFailure> {
        self.take(2)
            .and_then(|value| {
                value
                    .try_into()
                    .map_err(|_| TraceStoreFailure::malformed_block())
            })
            .map(u16::from_be_bytes)
    }

    pub(crate) fn u32(&mut self) -> Result<u32, TraceStoreFailure> {
        self.take(4)
            .and_then(|value| {
                value
                    .try_into()
                    .map_err(|_| TraceStoreFailure::malformed_block())
            })
            .map(u32::from_be_bytes)
    }

    pub(crate) fn u64(&mut self) -> Result<u64, TraceStoreFailure> {
        self.take(8)
            .and_then(|value| {
                value
                    .try_into()
                    .map_err(|_| TraceStoreFailure::malformed_block())
            })
            .map(u64::from_be_bytes)
    }

    pub(crate) fn i64(&mut self) -> Result<i64, TraceStoreFailure> {
        self.take(8)
            .and_then(|value| {
                value
                    .try_into()
                    .map_err(|_| TraceStoreFailure::malformed_block())
            })
            .map(i64::from_be_bytes)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], TraceStoreFailure> {
        self.take(N).and_then(|value| {
            value
                .try_into()
                .map_err(|_| TraceStoreFailure::malformed_block())
        })
    }

    pub(crate) fn count(&mut self, maximum: usize) -> Result<usize, TraceStoreFailure> {
        let count = usize::from(self.u16()?);
        if count > maximum {
            Err(TraceStoreFailure::malformed_block())
        } else {
            Ok(count)
        }
    }

    fn bytes(&mut self, maximum: usize) -> Result<Vec<u8>, TraceStoreFailure> {
        let bytes = self.raw_bytes(maximum)?;
        let mut value = Vec::new();
        value
            .try_reserve_exact(bytes.len())
            .map_err(|_| TraceStoreFailure::resource_exhausted())?;
        value.extend_from_slice(bytes);
        Ok(value)
    }

    pub(crate) fn raw_bytes(&mut self, maximum: usize) -> Result<&'a [u8], TraceStoreFailure> {
        let count =
            usize::try_from(self.u32()?).map_err(|_| TraceStoreFailure::malformed_block())?;
        if count > maximum {
            return Err(TraceStoreFailure::malformed_block());
        }
        self.take(count)
    }

    fn string(&mut self, maximum: usize) -> Result<String, TraceStoreFailure> {
        let bytes = self.bytes(maximum)?;
        String::from_utf8(bytes).map_err(|_| TraceStoreFailure::malformed_block())
    }

    pub(crate) fn raw_string(&mut self, maximum: usize) -> Result<&'a str, TraceStoreFailure> {
        std::str::from_utf8(self.raw_bytes(maximum)?)
            .map_err(|_| TraceStoreFailure::malformed_block())
    }

    pub(crate) fn observe_component(&mut self) -> Result<(), TraceStoreFailure> {
        self.poll()?;
        if let Some(observer) = self.observer {
            observer
                .observe_work(1)
                .map_err(TraceStoreFailure::observation)?;
        }
        Ok(())
    }

    pub(crate) fn observe_decoded_record(&mut self) -> Result<(), TraceStoreFailure> {
        self.observer.map_or(Ok(()), |observer| {
            observer
                .observe_decoded_records(1)
                .map_err(TraceStoreFailure::observation)
        })
    }

    pub(crate) fn remaining_input(&self) -> Self {
        Self {
            remaining: self.remaining,
            cancellation: self.cancellation,
            observer: self.observer,
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }

    fn poll(&self) -> Result<(), TraceStoreFailure> {
        if self.cancellation.is_some_and(|value| value.is_cancelled()) {
            return Err(TraceStoreFailure::cancelled());
        }
        Ok(())
    }
}
