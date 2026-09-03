use positron_domain::value::{CandidateAttributeValue, CandidateKeyValue, ValueLimitProfile};

use super::super::super::details::{
    MAX_DETAIL_COLLECTION, SpanAttributeSet, SpanEvent, SpanLink, SpanObservationDetails,
    SpanResourceMetadata, SpanScopeMetadata, SpanStatus,
};
use super::super::super::failure::TraceStoreFailure;
use super::super::super::types::limits_for;
use super::super::format::decode_status_tag;
use super::{Input, decode_time};

pub(super) fn decode_details(
    input: &mut Input<'_>,
    profile: &ValueLimitProfile,
) -> Result<SpanObservationDetails, TraceStoreFailure> {
    let limits = limits_for(profile)?;
    let trace_state = input.string(limits.key_path_bytes)?;
    let flags = input.u32()?;
    let status_code = decode_status_tag(input.u8()?)?;
    let status_message = input.string(limits.key_path_bytes)?;
    let status = SpanStatus::checked_with_profile(status_code, status_message, profile)
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
            profile,
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
            profile,
        )?);
    }
    SpanObservationDetails::checked_with_profile(
        trace_state,
        flags,
        status,
        events,
        links,
        dropped_attributes_count,
        dropped_events_count,
        dropped_links_count,
        SpanResourceMetadata::checked_with_profile(
            resource_dropped_attributes_count,
            resource_schema_url,
            profile,
        )
        .map_err(|_| TraceStoreFailure::malformed_block())?,
        SpanScopeMetadata::checked_with_profile(
            scope_name,
            scope_version,
            scope_dropped_attributes_count,
            scope_schema_url,
            profile,
        )
        .map_err(|_| TraceStoreFailure::malformed_block())?,
        profile,
    )
    .map_err(|_| TraceStoreFailure::malformed_block())
}

fn decode_event(
    input: &mut Input<'_>,
    key_limit: usize,
    depth: u8,
    profile: &ValueLimitProfile,
) -> Result<SpanEvent, TraceStoreFailure> {
    let timestamp = decode_time(input)?;
    let name = input.string(key_limit)?;
    let dropped_attributes_count = input.u32()?;
    let attributes = decode_span_attributes(input, depth, profile)?;
    SpanEvent::checked_with_profile(
        timestamp,
        name,
        attributes,
        dropped_attributes_count,
        profile,
    )
    .map_err(|_| TraceStoreFailure::malformed_block())
}

fn decode_link(
    input: &mut Input<'_>,
    key_limit: usize,
    depth: u8,
    profile: &ValueLimitProfile,
) -> Result<SpanLink, TraceStoreFailure> {
    let trace_id = input.array::<16>()?;
    let span_id = input.array::<8>()?;
    let trace_state = input.string(key_limit)?;
    let flags = input.u32()?;
    let dropped_attributes_count = input.u32()?;
    let attributes = decode_span_attributes(input, depth, profile)?;
    SpanLink::checked_with_profile(
        trace_id,
        span_id,
        trace_state,
        flags,
        attributes,
        dropped_attributes_count,
        profile,
    )
    .map_err(|_| TraceStoreFailure::malformed_block())
}

fn decode_span_attributes(
    input: &mut Input<'_>,
    depth: u8,
    profile: &ValueLimitProfile,
) -> Result<Vec<SpanAttributeSet>, TraceStoreFailure> {
    let limits = limits_for(profile)?;
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
            SpanAttributeSet::checked_with_profile(key, values, profile)
                .map_err(|_| TraceStoreFailure::malformed_block())?,
        );
    }
    Ok(attributes)
}

pub(super) fn decode_policy(
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

pub(super) fn decode_value(
    input: &mut Input<'_>,
    depth: u8,
    limits: &super::super::super::types::TraceLimits,
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
