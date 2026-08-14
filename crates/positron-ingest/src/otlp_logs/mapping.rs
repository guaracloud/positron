use std::collections::BTreeMap;

use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
use positron_domain::value::{AttributeNamespace, CandidateAttributeValue, CandidateKeyValue};

use super::{NativeLogAttribute, ReceiveFailure};

pub(super) fn checked_timestamp(value: u64) -> Result<i64, ReceiveFailure> {
    i64::try_from(value).map_err(|_| ReceiveFailure::TimestampOutOfRange)
}

pub(super) fn grouped_attributes(
    resource: &[KeyValue],
    scope: &[KeyValue],
    record: &[KeyValue],
    maximum_nesting_depth: u16,
) -> Result<Vec<NativeLogAttribute>, ReceiveFailure> {
    let mut groups = BTreeMap::<(AttributeNamespace, String), Vec<CandidateAttributeValue>>::new();
    for (namespace, attributes) in [
        (AttributeNamespace::Resource, resource),
        (AttributeNamespace::InstrumentationScope, scope),
        (AttributeNamespace::Record, record),
    ] {
        for attribute in attributes {
            let candidate = match &attribute.value {
                Some(value) => candidate_value(value.clone(), maximum_nesting_depth)?,
                None => CandidateAttributeValue::null(),
            };
            groups
                .entry((namespace, attribute.key.clone()))
                .or_default()
                .push(candidate);
        }
    }
    Ok(groups
        .into_iter()
        .map(|((namespace, key), occurrences)| NativeLogAttribute {
            namespace,
            key,
            occurrences,
        })
        .collect())
}

pub(super) fn candidate_value(
    value: AnyValue,
    remaining_depth: u16,
) -> Result<CandidateAttributeValue, ReceiveFailure> {
    let Some(value) = value.value else {
        return Ok(CandidateAttributeValue::null());
    };
    match value {
        any_value::Value::StringValue(value) => Ok(CandidateAttributeValue::string(value)),
        any_value::Value::BoolValue(value) => Ok(CandidateAttributeValue::boolean(value)),
        any_value::Value::IntValue(value) => Ok(CandidateAttributeValue::signed_integer(value)),
        any_value::Value::DoubleValue(value) => Ok(CandidateAttributeValue::floating_point_bits(
            value.to_bits(),
        )),
        any_value::Value::BytesValue(value) => Ok(CandidateAttributeValue::bytes(value)),
        any_value::Value::StringValueStrindex(_) => Err(ReceiveFailure::UnsupportedValue),
        any_value::Value::ArrayValue(value) => {
            let next = remaining_depth
                .checked_sub(1)
                .ok_or(ReceiveFailure::ValueLimitExceeded)?;
            value
                .values
                .into_iter()
                .map(|value| candidate_value(value, next))
                .collect::<Result<Vec<_>, _>>()
                .map(CandidateAttributeValue::array)
        },
        any_value::Value::KvlistValue(value) => {
            let next = remaining_depth
                .checked_sub(1)
                .ok_or(ReceiveFailure::ValueLimitExceeded)?;
            value
                .values
                .into_iter()
                .map(|entry| {
                    let value = entry.value.map_or_else(
                        || Ok(CandidateAttributeValue::null()),
                        |value| candidate_value(value, next),
                    )?;
                    Ok(CandidateKeyValue::new(entry.key, value))
                })
                .collect::<Result<Vec<_>, _>>()
                .map(CandidateAttributeValue::key_value_list)
        },
    }
}
