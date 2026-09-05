use std::collections::BTreeMap;

use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
use positron_domain::time::{EventTime, SourceTimeQuality, UnixNanoseconds};
use positron_domain::value::{CandidateAttributeValue, CandidateKeyValue, ValueLimitProfile};
use positron_policy::TracePolicyEvaluation;
use positron_signals::{
    SpanAttributeSet, SpanEvent, SpanLink, SpanObservation, SpanObservationDetails,
    SpanResourceMetadata, SpanScopeMetadata, SpanStatus, SpanStatusCode,
};

use super::super::{TraceLimitClass, TraceLimitViolation, TraceReceiveFailure};
use super::{NativeSpanDetailDraft, NativeSpanDraft};

impl NativeSpanDraft {
    pub(crate) fn evaluate(
        self,
        policy: &positron_policy::IngestPolicy,
        receiver: crate::PolicyReceiver,
        profile: &ValueLimitProfile,
    ) -> Result<Option<SpanObservation>, TraceReceiveFailure> {
        let Self {
            trace_id,
            span_id,
            parent_span_id,
            name,
            start_time_unix_nano,
            end_time_unix_nano,
            start_time_present,
            end_time_present,
            attributes,
            kind,
            flags,
            details,
            has_entity_refs,
        } = self;
        let candidate = positron_policy::NativeTraceCandidate::new(attributes);
        let evaluation = policy
            .evaluate_trace(candidate, receiver)
            .map_err(|_| TraceReceiveFailure::PolicyEvaluationFailed)?;
        let TracePolicyEvaluation::Accepted(evaluated) = evaluation else {
            return Ok(None);
        };
        let key_limit = usize::try_from(
            profile
                .effective_limits()
                .dynamic_value()
                .key_path_bytes()
                .value(),
        )
        .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?;
        if name.len() > key_limit {
            return Err(detail_failure(
                TraceLimitClass::KeyPathBytes,
                name.len(),
                key_limit,
            ));
        }
        if let Some(detail) = post_policy_limit_violation(evaluated.attributes(), profile) {
            return Err(TraceReceiveFailure::ValueLimitExceededWithDetail(detail));
        }
        if has_entity_refs {
            return Err(TraceReceiveFailure::MalformedPayload);
        }
        let trace_id = super::super::checked_identifier::<16>(&trace_id)?;
        let span_id = super::super::checked_identifier::<8>(&span_id)?;
        let parent_span_id = if parent_span_id.is_empty() {
            None
        } else {
            Some(super::super::checked_identifier::<8>(&parent_span_id)?)
        };
        let start_time = event_time(start_time_unix_nano, start_time_present)?;
        let end_time = event_time(end_time_unix_nano, end_time_present)?;
        let end_time = if end_time
            .instant()
            .zip(start_time.instant())
            .is_some_and(|(end, start)| end.value() < start.value())
        {
            EventTime::received(
                end_time
                    .instant()
                    .ok_or(TraceReceiveFailure::TimestampOutOfRange)?,
                SourceTimeQuality::Contradictory,
            )
            .map_err(|_| TraceReceiveFailure::TimestampOutOfRange)?
        } else {
            end_time
        };
        let kind = super::drafts::native_kind(kind)?;
        let sampling = super::drafts::sampling_decision(flags);
        let details = materialize_details(&details, profile)?;
        SpanObservation::checked_evaluated_with_profile(
            profile,
            trace_id,
            span_id,
            parent_span_id,
            name,
            start_time,
            end_time,
            kind,
            sampling,
            *evaluated,
            details,
        )
        .map(Some)
        .map_err(super::super::map_store_failure)
    }
}

fn materialize_details(
    detail: &NativeSpanDetailDraft,
    profile: &ValueLimitProfile,
) -> Result<SpanObservationDetails, TraceReceiveFailure> {
    let limits = profile.effective_limits();
    let detail_limit = usize::try_from(limits.request().records().value())
        .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?;
    if detail.events.len() > detail_limit || detail.links.len() > detail_limit {
        return Err(detail_failure(
            TraceLimitClass::RecordCount,
            detail.events.len().max(detail.links.len()),
            detail_limit,
        ));
    }
    let events = detail
        .events
        .iter()
        .enumerate()
        .map(|(index, event)| {
            SpanEvent::checked_with_profile(
                event_time(
                    event.time_unix_nano,
                    detail
                        .event_time_present
                        .get(index)
                        .copied()
                        .unwrap_or(true),
                )?,
                event.name.clone(),
                span_detail_attributes(&event.attributes, profile)?,
                event.dropped_attributes_count,
                profile,
            )
            .map_err(map_detail_failure)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let links = detail
        .links
        .iter()
        .map(|link| {
            SpanLink::checked_with_profile(
                super::super::checked_identifier::<16>(&link.trace_id)?,
                super::super::checked_identifier::<8>(&link.span_id)?,
                link.trace_state.clone(),
                link.flags,
                span_detail_attributes(&link.attributes, profile)?,
                link.dropped_attributes_count,
                profile,
            )
            .map_err(map_detail_failure)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let status = detail.status.clone().unwrap_or_default();
    let status_code =
        match opentelemetry_proto::tonic::trace::v1::status::StatusCode::try_from(status.code) {
            Ok(opentelemetry_proto::tonic::trace::v1::status::StatusCode::Unset) => {
                SpanStatusCode::Unset
            },
            Ok(opentelemetry_proto::tonic::trace::v1::status::StatusCode::Ok) => SpanStatusCode::Ok,
            Ok(opentelemetry_proto::tonic::trace::v1::status::StatusCode::Error) => {
                SpanStatusCode::Error
            },
            Err(_) => return Err(TraceReceiveFailure::MalformedPayload),
        };
    let status = SpanStatus::checked_with_profile(status_code, status.message, profile)
        .map_err(map_detail_failure)?;
    SpanObservationDetails::checked_with_profile(
        detail.trace_state.clone(),
        detail.flags,
        status,
        events,
        links,
        detail.dropped_attributes_count,
        detail.dropped_events_count,
        detail.dropped_links_count,
        SpanResourceMetadata::checked_with_profile(
            detail.metadata.resource_dropped_attributes_count,
            detail.metadata.resource_schema_url.clone(),
            profile,
        )
        .map_err(map_detail_failure)?,
        SpanScopeMetadata::checked_with_profile(
            detail.metadata.scope_name.clone(),
            detail.metadata.scope_version.clone(),
            detail.metadata.scope_dropped_attributes_count,
            detail.metadata.scope_schema_url.clone(),
            profile,
        )
        .map_err(map_detail_failure)?,
        profile,
    )
    .map_err(map_detail_failure)
}

fn post_policy_limit_violation(
    attributes: &[positron_policy::NativePolicyAttribute],
    profile: &ValueLimitProfile,
) -> Option<TraceLimitViolation> {
    let dynamic = profile.effective_limits().dynamic_value();
    let key_limit = usize::try_from(dynamic.key_path_bytes().value()).ok()?;
    let attribute_limit = usize::try_from(dynamic.attributes_per_namespace().value()).ok()?;
    let value_limit = usize::try_from(dynamic.individual_value_bytes().value()).ok()?;
    let depth_limit = dynamic.nesting_depth().value();
    let array_limit = usize::try_from(dynamic.array_entries().value()).ok()?;
    let list_limit = usize::try_from(dynamic.key_value_list_entries().value()).ok()?;

    attributes.iter().find_map(|attribute| {
        if attribute.key().len() > key_limit {
            return Some(violation(
                TraceLimitClass::KeyPathBytes,
                attribute.key().len(),
                key_limit,
            ));
        }
        if attribute.occurrences().len() > attribute_limit {
            return Some(violation(
                TraceLimitClass::AttributesPerNamespace,
                attribute.occurrences().len(),
                attribute_limit,
            ));
        }
        attribute.occurrences().iter().find_map(|value| {
            inspect_candidate_value(
                value,
                depth_limit,
                value_limit,
                key_limit,
                array_limit,
                list_limit,
            )
            .err()
        })
    })
}

fn inspect_candidate_value(
    value: &CandidateAttributeValue,
    remaining_depth: u16,
    value_limit: usize,
    key_limit: usize,
    array_limit: usize,
    list_limit: usize,
) -> Result<usize, TraceLimitViolation> {
    let size = match value {
        CandidateAttributeValue::Null
        | CandidateAttributeValue::Boolean(_)
        | CandidateAttributeValue::SignedInteger(_)
        | CandidateAttributeValue::FloatingPointBits(_)
        | CandidateAttributeValue::Marker(_) => 0,
        CandidateAttributeValue::String(value) => {
            if value.len() > value_limit {
                return Err(violation(
                    TraceLimitClass::IndividualValueBytes,
                    value.len(),
                    value_limit,
                ));
            }
            value.len()
        },
        CandidateAttributeValue::Bytes(value) => {
            if value.len() > value_limit {
                return Err(violation(
                    TraceLimitClass::IndividualValueBytes,
                    value.len(),
                    value_limit,
                ));
            }
            value.len()
        },
        CandidateAttributeValue::Array(values) => {
            if remaining_depth == 0 {
                return Err(violation(
                    TraceLimitClass::NestingDepth,
                    usize::from(remaining_depth).saturating_add(1),
                    usize::from(remaining_depth),
                ));
            }
            if values.len() > array_limit {
                return Err(violation(
                    TraceLimitClass::ArrayEntries,
                    values.len(),
                    array_limit,
                ));
            }
            let child_depth = remaining_depth - 1;
            values.iter().try_fold(0_usize, |total, child| {
                let child_size = inspect_candidate_value(
                    child,
                    child_depth,
                    value_limit,
                    key_limit,
                    array_limit,
                    list_limit,
                )?;
                total.checked_add(child_size).ok_or_else(|| {
                    violation(
                        TraceLimitClass::IndividualValueBytes,
                        usize::MAX,
                        value_limit,
                    )
                })
            })?
        },
        CandidateAttributeValue::KeyValueList(values) => {
            if remaining_depth == 0 {
                return Err(violation(
                    TraceLimitClass::NestingDepth,
                    usize::from(remaining_depth).saturating_add(1),
                    usize::from(remaining_depth),
                ));
            }
            if values.len() > list_limit {
                return Err(violation(
                    TraceLimitClass::KeyValueListEntries,
                    values.len(),
                    list_limit,
                ));
            }
            let child_depth = remaining_depth - 1;
            values.iter().try_fold(0_usize, |total, entry| {
                if entry.key().len() > key_limit {
                    return Err(violation(
                        TraceLimitClass::KeyPathBytes,
                        entry.key().len(),
                        key_limit,
                    ));
                }
                let child_size = inspect_candidate_value(
                    entry.value(),
                    child_depth,
                    value_limit,
                    key_limit,
                    array_limit,
                    list_limit,
                )?;
                total
                    .checked_add(entry.key().len())
                    .and_then(|total| total.checked_add(child_size))
                    .ok_or_else(|| {
                        violation(
                            TraceLimitClass::IndividualValueBytes,
                            usize::MAX,
                            value_limit,
                        )
                    })
            })?
        },
        CandidateAttributeValue::Truncated { value, .. } => inspect_candidate_value(
            value,
            remaining_depth,
            value_limit,
            key_limit,
            array_limit,
            list_limit,
        )?,
    };
    if size > value_limit {
        return Err(violation(
            TraceLimitClass::IndividualValueBytes,
            size,
            value_limit,
        ));
    }
    Ok(size)
}

fn violation(class: TraceLimitClass, actual: usize, allowed: usize) -> TraceLimitViolation {
    let actual = usize_as_u64(actual);
    let allowed = usize_as_u64(allowed);
    TraceLimitViolation::new(class, actual, allowed)
}

fn usize_as_u64(value: usize) -> u64 {
    if usize::BITS > u64::BITS && value > u64::MAX as usize {
        u64::MAX
    } else {
        value as u64
    }
}

fn detail_failure(class: TraceLimitClass, actual: usize, allowed: usize) -> TraceReceiveFailure {
    TraceReceiveFailure::ValueLimitExceededWithDetail(violation(class, actual, allowed))
}

fn span_detail_attributes(
    attributes: &[KeyValue],
    profile: &ValueLimitProfile,
) -> Result<Vec<SpanAttributeSet>, TraceReceiveFailure> {
    let limits = profile.effective_limits();
    let attribute_limit =
        usize::try_from(limits.dynamic_value().attributes_per_namespace().value())
            .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?;
    if attributes.len() > attribute_limit {
        return Err(detail_failure(
            TraceLimitClass::AttributesPerNamespace,
            attributes.len(),
            attribute_limit,
        ));
    }
    let mut groups = BTreeMap::<String, Vec<CandidateAttributeValue>>::new();
    for attribute in attributes {
        if attribute.key_strindex != 0 {
            return Err(TraceReceiveFailure::UnsupportedValue);
        }
        check_text(&attribute.key, profile)?;
        let key = attribute.key.clone();
        let values = match groups.entry(key.clone()) {
            std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::btree_map::Entry::Vacant(entry) => {
                let count = attributes.iter().try_fold(0_usize, |total, value| {
                    if value.key == key {
                        total
                            .checked_add(1)
                            .ok_or(TraceReceiveFailure::ValueLimitExceeded)
                    } else {
                        Ok(total)
                    }
                })?;
                let mut values = Vec::new();
                values
                    .try_reserve_exact(count)
                    .map_err(|_| TraceReceiveFailure::CapacityUnavailable)?;
                entry.insert(values)
            },
        };
        let value = attribute.value.clone().map_or_else(
            || Ok(CandidateAttributeValue::null()),
            |value| {
                candidate_value(
                    value,
                    profile,
                    limits.dynamic_value().nesting_depth().value(),
                )
            },
        )?;
        values.push(value);
    }
    groups
        .into_iter()
        .map(|(key, values)| {
            SpanAttributeSet::checked_with_profile(key, values, profile).map_err(map_detail_failure)
        })
        .collect()
}

fn map_detail_failure(failure: positron_signals::TraceStoreFailure) -> TraceReceiveFailure {
    match failure.code() {
        positron_signals::TraceStoreFailureCode::LimitExceeded => {
            TraceReceiveFailure::ValueLimitExceeded
        },
        positron_signals::TraceStoreFailureCode::ResourceExhausted => {
            TraceReceiveFailure::CapacityUnavailable
        },
        _ => TraceReceiveFailure::MalformedPayload,
    }
}

pub(crate) fn candidate_value(
    value: AnyValue,
    profile: &ValueLimitProfile,
    remaining_depth: u16,
) -> Result<CandidateAttributeValue, TraceReceiveFailure> {
    let Some(value) = value.value else {
        return Ok(CandidateAttributeValue::null());
    };
    let limits = profile.effective_limits();
    let dynamic = limits.dynamic_value();
    match value {
        any_value::Value::StringValue(value) => {
            let maximum = usize::try_from(dynamic.individual_value_bytes().value())
                .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?;
            if value.len() > maximum {
                return Err(detail_failure(
                    TraceLimitClass::IndividualValueBytes,
                    value.len(),
                    maximum,
                ));
            }
            Ok(CandidateAttributeValue::string(value))
        },
        any_value::Value::BoolValue(value) => Ok(CandidateAttributeValue::boolean(value)),
        any_value::Value::IntValue(value) => Ok(CandidateAttributeValue::signed_integer(value)),
        any_value::Value::DoubleValue(value) => Ok(CandidateAttributeValue::floating_point_bits(
            value.to_bits(),
        )),
        any_value::Value::BytesValue(value) => {
            if value.len()
                > usize::try_from(dynamic.individual_value_bytes().value())
                    .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?
            {
                return Err(detail_failure(
                    TraceLimitClass::IndividualValueBytes,
                    value.len(),
                    usize::try_from(dynamic.individual_value_bytes().value())
                        .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?,
                ));
            }
            Ok(CandidateAttributeValue::bytes(value))
        },
        any_value::Value::StringValueStrindex(_) => Err(TraceReceiveFailure::UnsupportedValue),
        any_value::Value::ArrayValue(value) => {
            let next_depth = remaining_depth.checked_sub(1).ok_or_else(|| {
                detail_failure(
                    TraceLimitClass::NestingDepth,
                    usize::from(dynamic.nesting_depth().value()).saturating_add(1),
                    usize::from(dynamic.nesting_depth().value()),
                )
            })?;
            let maximum = usize::try_from(dynamic.array_entries().value())
                .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?;
            if value.values.len() > maximum {
                return Err(detail_failure(
                    TraceLimitClass::ArrayEntries,
                    value.values.len(),
                    maximum,
                ));
            }
            let mut values = Vec::new();
            values
                .try_reserve_exact(value.values.len())
                .map_err(|_| TraceReceiveFailure::CapacityUnavailable)?;
            for child in value.values {
                values.push(candidate_value(child, profile, next_depth)?);
            }
            let candidate = CandidateAttributeValue::array(values);
            candidate
                .validate_shape(*profile)
                .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?;
            Ok(candidate)
        },
        any_value::Value::KvlistValue(value) => {
            let next_depth = remaining_depth.checked_sub(1).ok_or_else(|| {
                detail_failure(
                    TraceLimitClass::NestingDepth,
                    usize::from(dynamic.nesting_depth().value()).saturating_add(1),
                    usize::from(dynamic.nesting_depth().value()),
                )
            })?;
            let maximum = usize::try_from(dynamic.key_value_list_entries().value())
                .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?;
            if value.values.len() > maximum {
                return Err(detail_failure(
                    TraceLimitClass::KeyValueListEntries,
                    value.values.len(),
                    maximum,
                ));
            }
            let mut values = Vec::new();
            values
                .try_reserve_exact(value.values.len())
                .map_err(|_| TraceReceiveFailure::CapacityUnavailable)?;
            for entry in value.values {
                check_text(&entry.key, profile)?;
                let value = entry.value.map_or_else(
                    || Ok(CandidateAttributeValue::null()),
                    |value| candidate_value(value, profile, next_depth),
                )?;
                values.push(CandidateKeyValue::new(entry.key, value));
            }
            let candidate = CandidateAttributeValue::key_value_list(values);
            candidate
                .validate_shape(*profile)
                .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?;
            Ok(candidate)
        },
    }
}

fn check_text(value: &str, profile: &ValueLimitProfile) -> Result<(), TraceReceiveFailure> {
    let maximum = usize::try_from(
        profile
            .effective_limits()
            .dynamic_value()
            .key_path_bytes()
            .value(),
    )
    .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?;
    if value.len() > maximum {
        return Err(detail_failure(
            TraceLimitClass::KeyPathBytes,
            value.len(),
            maximum,
        ));
    }
    Ok(())
}

fn event_time(value: u64, present: bool) -> Result<EventTime, TraceReceiveFailure> {
    if !present {
        return Ok(EventTime::missing());
    }
    if value > i64::MAX as u64 {
        return EventTime::out_of_range(value)
            .map_err(|_| TraceReceiveFailure::TimestampOutOfRange);
    }
    let timestamp = value as i64;
    let quality = if timestamp == 0 {
        SourceTimeQuality::Zero
    } else {
        SourceTimeQuality::Usable
    };
    EventTime::received(UnixNanoseconds::new(timestamp), quality)
        .map_err(|_| TraceReceiveFailure::TimestampOutOfRange)
}
