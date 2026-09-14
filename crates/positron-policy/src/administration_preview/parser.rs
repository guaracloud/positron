//! Bounded JSON decoding for non-mutating policy preview input.

use positron_domain::{
    routing::SignalKind,
    value::{AttributeNamespace, AttributeValueKind, CandidateAttributeValue, CandidateKeyValue},
};
use serde_json::{Map, Value};

use super::{
    MAX_POLICY_PREVIEW_BYTES, MAX_PREVIEW_ATTRIBUTES, MAX_PREVIEW_OCCURRENCES,
    MAX_PREVIEW_VALUE_NESTING, PolicyPreviewFailure, PreviewRule,
};
use crate::{
    NativePolicyAttribute, PolicyAction, PolicyAttributePath, PolicyCompileFailure,
    PolicyPredicate, PolicyReceiver, PolicyRule, PolicyTarget,
};

pub(super) fn parse_rule(
    value: &Value,
) -> Result<(String, PolicyRule, PreviewRule), PolicyPreviewFailure> {
    let object = object(value, PolicyPreviewFailure::InvalidPolicy)?;
    exact_fields(
        object,
        &["id", "predicates", "action"],
        PolicyPreviewFailure::InvalidPolicy,
    )?;
    let id = string(object.get("id"), PolicyPreviewFailure::InvalidPolicy)?.to_owned();
    if !stable_rule_id(&id) {
        return Err(PolicyPreviewFailure::InvalidPolicy);
    }
    let predicates = array(
        object.get("predicates"),
        PolicyPreviewFailure::InvalidPolicy,
    )?
    .iter()
    .map(parse_predicate)
    .collect::<Result<Vec<_>, _>>()?;
    let action = parse_action(object.get("action"))?;
    let rule = PolicyRule::new(id.clone(), predicates.clone(), action.clone())
        .map_err(map_compile_failure)?;
    Ok((id, rule, PreviewRule { predicates, action }))
}

fn parse_predicate(value: &Value) -> Result<PolicyPredicate, PolicyPreviewFailure> {
    let predicate_object = object(value, PolicyPreviewFailure::InvalidPolicy)?;
    if predicate_object.len() != 1 {
        return Err(PolicyPreviewFailure::InvalidPolicy);
    }
    let (kind, value) = predicate_object
        .iter()
        .next()
        .ok_or(PolicyPreviewFailure::InvalidPolicy)?;
    match kind.as_str() {
        "attribute_exists" => Ok(PolicyPredicate::attribute_exists(parse_path(value)?)),
        "body_exact_text" => PolicyPredicate::body_exact_text(string(
            Some(value),
            PolicyPreviewFailure::InvalidPolicy,
        )?)
        .map_err(map_compile_failure),
        "signal_store" => Ok(PolicyPredicate::signal_store(parse_signal(string(
            Some(value),
            PolicyPreviewFailure::InvalidPolicy,
        )?)?)),
        "receiver" => Ok(PolicyPredicate::receiver(parse_receiver(string(
            Some(value),
            PolicyPreviewFailure::InvalidPolicy,
        )?)?)),
        "attribute_type" => {
            let type_object = object(value, PolicyPreviewFailure::InvalidPolicy)?;
            exact_fields(
                type_object,
                &["path", "kind"],
                PolicyPreviewFailure::InvalidPolicy,
            )?;
            Ok(PolicyPredicate::attribute_type(
                parse_path(
                    type_object
                        .get("path")
                        .ok_or(PolicyPreviewFailure::InvalidPolicy)?,
                )?,
                parse_kind(string(
                    type_object.get("kind"),
                    PolicyPreviewFailure::InvalidPolicy,
                )?)?,
            ))
        },
        "service_identity" => PolicyPredicate::service_identity(string(
            Some(value),
            PolicyPreviewFailure::InvalidPolicy,
        )?)
        .map_err(map_compile_failure),
        "log_severity" => Ok(PolicyPredicate::log_severity(signed(
            Some(value),
            PolicyPreviewFailure::InvalidPolicy,
        )?)),
        _ => Err(PolicyPreviewFailure::InvalidPolicy),
    }
}

fn parse_action(value: Option<&Value>) -> Result<PolicyAction, PolicyPreviewFailure> {
    if let Some(Value::String(value)) = value {
        return match value.as_str() {
            "accept" => Ok(PolicyAction::Accept),
            "reject" => Ok(PolicyAction::Reject),
            _ => Err(PolicyPreviewFailure::InvalidPolicy),
        };
    }
    let object = object(
        value.ok_or(PolicyPreviewFailure::InvalidPolicy)?,
        PolicyPreviewFailure::InvalidPolicy,
    )?;
    if object.len() != 1 {
        return Err(PolicyPreviewFailure::InvalidPolicy);
    }
    let (kind, value) = object
        .iter()
        .next()
        .ok_or(PolicyPreviewFailure::InvalidPolicy)?;
    match kind.as_str() {
        "accept" if value == &Value::Bool(true) => Ok(PolicyAction::Accept),
        "reject" if value == &Value::Bool(true) => Ok(PolicyAction::Reject),
        "remove" => Ok(PolicyAction::Remove(parse_target(value)?)),
        "redact" => Ok(PolicyAction::Redact(parse_target(value)?)),
        "truncate_bytes" => parse_truncation(value, true),
        "truncate_elements" => parse_truncation(value, false),
        _ => Err(PolicyPreviewFailure::InvalidPolicy),
    }
}

fn parse_truncation(value: &Value, bytes: bool) -> Result<PolicyAction, PolicyPreviewFailure> {
    let object = object(value, PolicyPreviewFailure::InvalidPolicy)?;
    exact_fields(
        object,
        &["target", "limit"],
        PolicyPreviewFailure::InvalidPolicy,
    )?;
    let target = parse_target(
        object
            .get("target")
            .ok_or(PolicyPreviewFailure::InvalidPolicy)?,
    )?;
    if bytes {
        Ok(PolicyAction::TruncateBytes(
            target,
            u32::try_from(unsigned(
                object.get("limit"),
                PolicyPreviewFailure::InvalidPolicy,
            )?)
            .map_err(|_| PolicyPreviewFailure::InvalidPolicy)?,
        ))
    } else {
        Ok(PolicyAction::TruncateElements(
            target,
            u16::try_from(unsigned(
                object.get("limit"),
                PolicyPreviewFailure::InvalidPolicy,
            )?)
            .map_err(|_| PolicyPreviewFailure::InvalidPolicy)?,
        ))
    }
}

fn parse_target(value: &Value) -> Result<PolicyTarget, PolicyPreviewFailure> {
    if value == "body" {
        return Ok(PolicyTarget::body());
    }
    let object = object(value, PolicyPreviewFailure::InvalidPolicy)?;
    exact_fields(object, &["attribute"], PolicyPreviewFailure::InvalidPolicy)?;
    Ok(PolicyTarget::attribute(parse_path(
        object
            .get("attribute")
            .ok_or(PolicyPreviewFailure::InvalidPolicy)?,
    )?))
}

fn parse_path(value: &Value) -> Result<PolicyAttributePath, PolicyPreviewFailure> {
    let path_object = object(value, PolicyPreviewFailure::InvalidPolicy)?;
    allowed_fields(
        path_object,
        &["namespace", "key", "occurrence", "segments"],
        PolicyPreviewFailure::InvalidPolicy,
    )?;
    require_fields(
        path_object,
        &["namespace", "key"],
        PolicyPreviewFailure::InvalidPolicy,
    )?;
    let mut path = PolicyAttributePath::new(
        parse_namespace(string(
            path_object.get("namespace"),
            PolicyPreviewFailure::InvalidPolicy,
        )?)?,
        string(path_object.get("key"), PolicyPreviewFailure::InvalidPolicy)?,
    )
    .map_err(map_compile_failure)?;
    if let Some(occurrence) = path_object.get("occurrence") {
        path = path.at_occurrence(
            u16::try_from(unsigned(
                Some(occurrence),
                PolicyPreviewFailure::InvalidPolicy,
            )?)
            .map_err(|_| PolicyPreviewFailure::InvalidPolicy)?,
        );
    }
    if let Some(segments) = path_object.get("segments") {
        for segment in array(Some(segments), PolicyPreviewFailure::InvalidPolicy)? {
            let segment_object = object(segment, PolicyPreviewFailure::InvalidPolicy)?;
            if segment_object.len() != 1 {
                return Err(PolicyPreviewFailure::InvalidPolicy);
            }
            let (kind, value) = segment_object
                .iter()
                .next()
                .ok_or(PolicyPreviewFailure::InvalidPolicy)?;
            path = match kind.as_str() {
                "key" => path
                    .key(string(Some(value), PolicyPreviewFailure::InvalidPolicy)?)
                    .map_err(map_compile_failure)?,
                "array_index" => path
                    .array_index(
                        u16::try_from(unsigned(Some(value), PolicyPreviewFailure::InvalidPolicy)?)
                            .map_err(|_| PolicyPreviewFailure::InvalidPolicy)?,
                    )
                    .map_err(map_compile_failure)?,
                _ => return Err(PolicyPreviewFailure::InvalidPolicy),
            };
        }
    }
    Ok(path)
}

pub(super) fn parse_attributes(
    values: &[Value],
) -> Result<Vec<NativePolicyAttribute>, PolicyPreviewFailure> {
    if values.len() > MAX_PREVIEW_ATTRIBUTES {
        return Err(PolicyPreviewFailure::MalformedCandidate);
    }
    values
        .iter()
        .map(|value| {
            let object = object(value, PolicyPreviewFailure::MalformedCandidate)?;
            exact_fields(
                object,
                &["namespace", "key", "occurrences"],
                PolicyPreviewFailure::MalformedCandidate,
            )?;
            let occurrences = array(
                object.get("occurrences"),
                PolicyPreviewFailure::MalformedCandidate,
            )?;
            if occurrences.len() > MAX_PREVIEW_OCCURRENCES {
                return Err(PolicyPreviewFailure::MalformedCandidate);
            }
            Ok(NativePolicyAttribute::new(
                parse_namespace(string(
                    object.get("namespace"),
                    PolicyPreviewFailure::MalformedCandidate,
                )?)?,
                string(object.get("key"), PolicyPreviewFailure::MalformedCandidate)?.to_owned(),
                occurrences
                    .iter()
                    .map(|value| parse_value(value, 0))
                    .collect::<Result<Vec<_>, _>>()?,
            ))
        })
        .collect()
}

pub(super) fn parse_value(
    value: &Value,
    depth: usize,
) -> Result<CandidateAttributeValue, PolicyPreviewFailure> {
    if depth > MAX_PREVIEW_VALUE_NESTING {
        return Err(PolicyPreviewFailure::MalformedCandidate);
    }
    match value {
        Value::Null => Ok(CandidateAttributeValue::null()),
        Value::Bool(value) => Ok(CandidateAttributeValue::boolean(*value)),
        Value::String(value) => Ok(CandidateAttributeValue::string(value.clone())),
        Value::Number(value) => value
            .as_i64()
            .map(CandidateAttributeValue::signed_integer)
            .ok_or(PolicyPreviewFailure::MalformedCandidate),
        Value::Array(_) => Err(PolicyPreviewFailure::MalformedCandidate),
        Value::Object(value_object) if value_object.len() == 1 => {
            let (kind, payload) = value_object
                .iter()
                .next()
                .ok_or(PolicyPreviewFailure::MalformedCandidate)?;
            match kind.as_str() {
                "floating_point_bits" => Ok(CandidateAttributeValue::floating_point_bits(
                    unsigned(Some(payload), PolicyPreviewFailure::MalformedCandidate)?,
                )),
                "bytes" => Ok(CandidateAttributeValue::bytes(
                    array(Some(payload), PolicyPreviewFailure::MalformedCandidate)?
                        .iter()
                        .map(|byte| {
                            u8::try_from(unsigned(
                                Some(byte),
                                PolicyPreviewFailure::MalformedCandidate,
                            )?)
                            .map_err(|_| PolicyPreviewFailure::MalformedCandidate)
                        })
                        .collect::<Result<Vec<_>, _>>()?,
                )),
                "array" => {
                    let values = array(Some(payload), PolicyPreviewFailure::MalformedCandidate)?;
                    if values.len() > MAX_PREVIEW_OCCURRENCES {
                        return Err(PolicyPreviewFailure::MalformedCandidate);
                    }
                    Ok(CandidateAttributeValue::array(
                        values
                            .iter()
                            .map(|value| parse_value(value, depth + 1))
                            .collect::<Result<Vec<_>, _>>()?,
                    ))
                },
                "key_value_list" => {
                    let values = array(Some(payload), PolicyPreviewFailure::MalformedCandidate)?;
                    if values.len() > MAX_PREVIEW_OCCURRENCES {
                        return Err(PolicyPreviewFailure::MalformedCandidate);
                    }
                    Ok(CandidateAttributeValue::key_value_list(
                        values
                            .iter()
                            .map(|entry| {
                                let entry_object =
                                    object(entry, PolicyPreviewFailure::MalformedCandidate)?;
                                exact_fields(
                                    entry_object,
                                    &["key", "value"],
                                    PolicyPreviewFailure::MalformedCandidate,
                                )?;
                                Ok(CandidateKeyValue::new(
                                    string(
                                        entry_object.get("key"),
                                        PolicyPreviewFailure::MalformedCandidate,
                                    )?
                                    .to_owned(),
                                    parse_value(
                                        entry_object
                                            .get("value")
                                            .ok_or(PolicyPreviewFailure::MalformedCandidate)?,
                                        depth + 1,
                                    )?,
                                ))
                            })
                            .collect::<Result<Vec<_>, _>>()?,
                    ))
                },
                _ => Err(PolicyPreviewFailure::MalformedCandidate),
            }
        },
        Value::Object(_) => Err(PolicyPreviewFailure::MalformedCandidate),
    }
}

pub(super) fn parse_json(bytes: &[u8]) -> Result<Value, PolicyPreviewFailure> {
    if bytes.len() > MAX_POLICY_PREVIEW_BYTES {
        return Err(PolicyPreviewFailure::RequestTooLarge);
    }
    serde_json::from_slice(bytes).map_err(|_| PolicyPreviewFailure::MalformedCandidate)
}

pub(super) fn object(
    value: &Value,
    failure: PolicyPreviewFailure,
) -> Result<&Map<String, Value>, PolicyPreviewFailure> {
    value.as_object().ok_or(failure)
}

pub(super) fn array(
    value: Option<&Value>,
    failure: PolicyPreviewFailure,
) -> Result<&[Value], PolicyPreviewFailure> {
    value
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or(failure)
}

pub(super) fn string(
    value: Option<&Value>,
    failure: PolicyPreviewFailure,
) -> Result<&str, PolicyPreviewFailure> {
    value.and_then(Value::as_str).ok_or(failure)
}

pub(super) fn unsigned(
    value: Option<&Value>,
    failure: PolicyPreviewFailure,
) -> Result<u64, PolicyPreviewFailure> {
    value.and_then(Value::as_u64).ok_or(failure)
}

pub(super) fn signed(
    value: Option<&Value>,
    failure: PolicyPreviewFailure,
) -> Result<i32, PolicyPreviewFailure> {
    value
        .and_then(Value::as_i64)
        .and_then(|value| i32::try_from(value).ok())
        .ok_or(failure)
}

fn require_fields(
    object: &Map<String, Value>,
    required: &[&str],
    failure: PolicyPreviewFailure,
) -> Result<(), PolicyPreviewFailure> {
    if required.iter().all(|field| object.contains_key(*field)) {
        Ok(())
    } else {
        Err(failure)
    }
}

pub(super) fn allowed_fields(
    object: &Map<String, Value>,
    allowed: &[&str],
    failure: PolicyPreviewFailure,
) -> Result<(), PolicyPreviewFailure> {
    if object.keys().all(|key| allowed.contains(&key.as_str())) {
        Ok(())
    } else {
        Err(failure)
    }
}

pub(super) fn exact_fields(
    object: &Map<String, Value>,
    fields: &[&str],
    failure: PolicyPreviewFailure,
) -> Result<(), PolicyPreviewFailure> {
    require_fields(object, fields, failure.clone())?;
    allowed_fields(object, fields, failure)
}

fn parse_signal(value: &str) -> Result<SignalKind, PolicyPreviewFailure> {
    match value {
        "logs" => Ok(SignalKind::Logs),
        "traces" => Ok(SignalKind::Traces),
        _ => Err(PolicyPreviewFailure::InvalidPolicy),
    }
}

pub(super) fn parse_receiver(value: &str) -> Result<PolicyReceiver, PolicyPreviewFailure> {
    match value {
        "otlp_grpc" => Ok(PolicyReceiver::OtlpGrpc),
        "otlp_http_json" => Ok(PolicyReceiver::OtlpHttpJson),
        "otlp_http_protobuf" => Ok(PolicyReceiver::OtlpHttpProtobuf),
        "loki_push_json" => Ok(PolicyReceiver::LokiPushJson),
        "loki_push_protobuf" => Ok(PolicyReceiver::LokiPushProtobuf),
        "loki_otlp_protobuf" => Ok(PolicyReceiver::LokiOtlpProtobuf),
        "loki_otlp_json" => Ok(PolicyReceiver::LokiOtlpJson),
        _ => Err(PolicyPreviewFailure::MalformedCandidate),
    }
}

fn parse_namespace(value: &str) -> Result<AttributeNamespace, PolicyPreviewFailure> {
    match value {
        "stream" => Ok(AttributeNamespace::Stream),
        "resource" => Ok(AttributeNamespace::Resource),
        "instrumentation-scope" => Ok(AttributeNamespace::InstrumentationScope),
        "record" => Ok(AttributeNamespace::Record),
        _ => Err(PolicyPreviewFailure::InvalidPolicy),
    }
}

fn parse_kind(value: &str) -> Result<AttributeValueKind, PolicyPreviewFailure> {
    match value {
        "null" => Ok(AttributeValueKind::Null),
        "boolean" => Ok(AttributeValueKind::Boolean),
        "signed_integer" => Ok(AttributeValueKind::SignedInteger),
        "floating_point" => Ok(AttributeValueKind::FloatingPoint),
        "string" => Ok(AttributeValueKind::String),
        "bytes" => Ok(AttributeValueKind::Bytes),
        "array" => Ok(AttributeValueKind::Array),
        "key_value_list" => Ok(AttributeValueKind::KeyValueList),
        _ => Err(PolicyPreviewFailure::InvalidPolicy),
    }
}

pub(super) fn map_compile_failure(_: PolicyCompileFailure) -> PolicyPreviewFailure {
    PolicyPreviewFailure::InvalidPolicy
}

pub(super) fn action_name(action: &PolicyAction) -> &'static str {
    match action {
        PolicyAction::Accept => "accept",
        PolicyAction::Reject => "reject",
        PolicyAction::Remove(_) => "remove",
        PolicyAction::Redact(_) => "redact",
        PolicyAction::TruncateBytes(_, _) => "truncate_bytes",
        PolicyAction::TruncateElements(_, _) => "truncate_elements",
    }
}

fn stable_rule_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().enumerate().all(|(index, byte)| {
            if index == 0 {
                byte.is_ascii_lowercase()
            } else {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
            }
        })
}
