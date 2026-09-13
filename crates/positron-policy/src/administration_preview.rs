//! Bounded, non-mutating administrative previews for declarative Ingest Policy.

use std::collections::{BTreeMap, BTreeSet};

use positron_domain::{
    routing::SignalKind,
    value::{AttributeNamespace, AttributeValueKind, CandidateAttributeValue, CandidateKeyValue},
};
use serde_json::{Map, Value};

use crate::{
    IngestPolicy, LogMetadata, NativeLogCandidate, NativePolicyAttribute, NativeTraceCandidate,
    PolicyAction, PolicyAttributePath, PolicyCompileFailure, PolicyPredicate, PolicyReceiver,
    PolicyRule, PolicyTarget,
};

pub const MAX_POLICY_PREVIEW_BYTES: usize = 65_536;
const MAX_PREVIEW_ATTRIBUTES: usize = 1_024;
const MAX_PREVIEW_OCCURRENCES: usize = 1_024;
const MAX_PREVIEW_VALUE_NESTING: usize = 16;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyPreviewFailure {
    RequestTooLarge,
    MalformedCandidate,
    InvalidPolicy,
    EvaluationUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyPreviewOutcome {
    Accepted,
    Rejected,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyPreviewValidation {
    generation: u64,
    digest: [u8; 32],
    rule_count: usize,
    maximum_evaluation_steps: u64,
    maximum_reserved_memory_bytes: u64,
}
impl PolicyPreviewValidation {
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
    #[must_use]
    pub const fn rule_count(&self) -> usize {
        self.rule_count
    }
    #[must_use]
    pub const fn maximum_evaluation_steps(&self) -> u64 {
        self.maximum_evaluation_steps
    }
    #[must_use]
    pub const fn maximum_reserved_memory_bytes(&self) -> u64 {
        self.maximum_reserved_memory_bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyPreviewCandidate {
    receiver: PolicyReceiver,
    record: PreviewRecord,
}
#[derive(Clone, Debug, Eq, PartialEq)]
enum PreviewRecord {
    Log(Box<NativeLogCandidate>),
    Trace(NativeTraceCandidate),
}

#[derive(Clone, Debug)]
pub struct PolicyPreviewPolicy {
    compiled: IngestPolicy,
    rules: BTreeMap<String, PreviewRule>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct PreviewRule {
    predicates: Vec<PolicyPredicate>,
    action: PolicyAction,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyPreviewResult {
    outcome: PolicyPreviewOutcome,
    generation: u64,
    digest: [u8; 32],
    applied_rule_ids: Vec<String>,
}
impl PolicyPreviewResult {
    #[must_use]
    pub const fn outcome(&self) -> PolicyPreviewOutcome {
        self.outcome
    }
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
    #[must_use]
    pub const fn applied_rule_count(&self) -> usize {
        self.applied_rule_ids.len()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyPreview {
    rendered: String,
}

impl PolicyPreview {
    /// Evaluates only an in-memory fixture through the shared policy transition.
    pub fn test(
        policy: &PolicyPreviewPolicy,
        candidate: PolicyPreviewCandidate,
    ) -> Result<PolicyPreviewResult, PolicyPreviewFailure> {
        let (accepted, provenance) = match candidate.record {
            PreviewRecord::Log(record) => policy.compiled.preview_log(*record, candidate.receiver),
            PreviewRecord::Trace(record) => {
                policy.compiled.preview_trace(record, candidate.receiver)
            },
        }
        .map_err(|_| PolicyPreviewFailure::EvaluationUnavailable)?;
        Ok(PolicyPreviewResult {
            outcome: if accepted {
                PolicyPreviewOutcome::Accepted
            } else {
                PolicyPreviewOutcome::Rejected
            },
            generation: provenance.generation(),
            digest: provenance.digest(),
            applied_rule_ids: provenance.applied_rules().to_vec(),
        })
    }

    /// Produces deterministic policy evidence without serializing fixture values.
    pub fn explain(
        policy: &PolicyPreviewPolicy,
        result: PolicyPreviewResult,
    ) -> Result<Self, PolicyPreviewFailure> {
        if result.generation != policy.compiled.generation()
            || result.digest != policy.compiled.digest()
        {
            return Err(PolicyPreviewFailure::InvalidPolicy);
        }
        let mut rendered = match result.outcome {
            PolicyPreviewOutcome::Accepted => String::from("accepted"),
            PolicyPreviewOutcome::Rejected => String::from("rejected"),
        };
        for id in result.applied_rule_ids {
            let rule = policy
                .rules
                .get(&id)
                .ok_or(PolicyPreviewFailure::InvalidPolicy)?;
            rendered.push_str("; matched rule");
            rendered.push_str(" action=");
            rendered.push_str(action_name(&rule.action));
        }
        Ok(Self { rendered })
    }

    pub fn explain_default(
        candidate: PolicyPreviewCandidate,
    ) -> Result<Self, PolicyPreviewFailure> {
        let policy = PolicyPreviewPolicy::from_ingest(
            IngestPolicy::release_1_default()
                .map_err(|_| PolicyPreviewFailure::EvaluationUnavailable)?,
        );
        Self::explain(&policy, Self::test(&policy, candidate)?)
    }
    #[must_use]
    pub fn rendered(&self) -> &str {
        &self.rendered
    }

    #[must_use]
    pub fn diff(before: &PolicyPreviewPolicy, after: &PolicyPreviewPolicy) -> PolicyPreviewDiff {
        let mut changes = Vec::new();
        if before.compiled.generation() != after.compiled.generation() {
            changes.push(PolicyPreviewSemanticChange::GenerationChanged {
                from: before.compiled.generation(),
                to: after.compiled.generation(),
            });
        }
        let ids: BTreeSet<_> = before
            .rules
            .keys()
            .chain(after.rules.keys())
            .cloned()
            .collect();
        for id in ids {
            match (before.rules.get(&id), after.rules.get(&id)) {
                (None, Some(rule)) => changes.push(PolicyPreviewSemanticChange::RuleAdded {
                    rule_id: id,
                    action: action_name(&rule.action),
                }),
                (Some(rule), None) => changes.push(PolicyPreviewSemanticChange::RuleRemoved {
                    rule_id: id,
                    action: action_name(&rule.action),
                }),
                (Some(left), Some(right)) => {
                    if left.predicates != right.predicates {
                        changes.push(PolicyPreviewSemanticChange::RulePredicatesChanged {
                            rule_id: id.clone(),
                        });
                    }
                    if left.action != right.action {
                        changes.push(PolicyPreviewSemanticChange::RuleActionChanged {
                            from: action_name(&left.action),
                            to: action_name(&right.action),
                        });
                    }
                },
                (None, None) => {},
            }
        }
        PolicyPreviewDiff { changes }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyPreviewDiff {
    changes: Vec<PolicyPreviewSemanticChange>,
}
impl PolicyPreviewDiff {
    #[must_use]
    pub fn changes(&self) -> &[PolicyPreviewSemanticChange] {
        &self.changes
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyPreviewSemanticChange {
    GenerationChanged {
        from: u64,
        to: u64,
    },
    RuleAdded {
        rule_id: String,
        action: &'static str,
    },
    RuleRemoved {
        rule_id: String,
        action: &'static str,
    },
    RulePredicatesChanged {
        rule_id: String,
    },
    RuleActionChanged {
        from: &'static str,
        to: &'static str,
    },
}

impl PolicyPreviewPolicy {
    pub fn from_json(bytes: &[u8]) -> Result<Self, PolicyPreviewFailure> {
        let value = parse_json(bytes)?;
        let object = object(&value, PolicyPreviewFailure::InvalidPolicy)?;
        exact_fields(
            object,
            &["generation", "rules"],
            PolicyPreviewFailure::InvalidPolicy,
        )?;
        let generation = unsigned(
            object.get("generation"),
            PolicyPreviewFailure::InvalidPolicy,
        )?;
        let rules = array(object.get("rules"), PolicyPreviewFailure::InvalidPolicy)?;
        let mut compiled_rules = Vec::with_capacity(rules.len());
        let mut preview_rules = BTreeMap::new();
        for value in rules {
            let (id, rule, preview) = parse_rule(value)?;
            if preview_rules.insert(id.clone(), preview).is_some() {
                return Err(PolicyPreviewFailure::InvalidPolicy);
            }
            compiled_rules.push(rule);
        }
        let compiled =
            IngestPolicy::compile(generation, compiled_rules).map_err(map_compile_failure)?;
        Ok(Self {
            compiled,
            rules: preview_rules,
        })
    }
    fn from_ingest(compiled: IngestPolicy) -> Self {
        Self {
            compiled,
            rules: BTreeMap::new(),
        }
    }
    /// Transfers the bounded candidate to the prospective activation transition.
    /// The external JSON representation never enters the runtime boundary.
    #[must_use]
    pub fn into_ingest_policy(self) -> IngestPolicy {
        self.compiled
    }
    #[must_use]
    pub fn validation(&self) -> PolicyPreviewValidation {
        let budget = self.compiled.budget();
        PolicyPreviewValidation {
            generation: self.compiled.generation(),
            digest: self.compiled.digest(),
            rule_count: self.rules.len(),
            maximum_evaluation_steps: budget.evaluation_steps(),
            maximum_reserved_memory_bytes: budget.reserved_memory_bytes().unwrap_or(u64::MAX),
        }
    }
}

impl PolicyPreviewCandidate {
    pub fn from_json(bytes: &[u8]) -> Result<Self, PolicyPreviewFailure> {
        let value = parse_json(bytes)?;
        let object = object(&value, PolicyPreviewFailure::MalformedCandidate)?;
        let receiver = parse_receiver(string(
            object.get("receiver"),
            PolicyPreviewFailure::MalformedCandidate,
        )?)?;
        let signal = string(
            object.get("signal"),
            PolicyPreviewFailure::MalformedCandidate,
        )?;
        let attributes = parse_attributes(array(
            object.get("attributes"),
            PolicyPreviewFailure::MalformedCandidate,
        )?)?;
        match signal {
            "logs" => {
                allowed_fields(
                    object,
                    &["receiver", "signal", "body", "severity", "attributes"],
                    PolicyPreviewFailure::MalformedCandidate,
                )?;
                let body = object
                    .get("body")
                    .map(|value| parse_value(value, 0))
                    .transpose()?;
                let severity = object
                    .get("severity")
                    .map(|value| signed(Some(value), PolicyPreviewFailure::MalformedCandidate))
                    .transpose()?
                    .unwrap_or(0);
                Ok(Self {
                    receiver,
                    record: PreviewRecord::Log(Box::new(NativeLogCandidate::new(
                        None,
                        None,
                        body,
                        attributes,
                        LogMetadata::new(
                            severity,
                            String::new(),
                            None,
                            None,
                            0,
                            0,
                            0,
                            String::new(),
                            String::new(),
                            String::new(),
                            0,
                            String::new(),
                        ),
                    ))),
                })
            },
            "traces" => {
                exact_fields(
                    object,
                    &["receiver", "signal", "attributes"],
                    PolicyPreviewFailure::MalformedCandidate,
                )?;
                Ok(Self {
                    receiver,
                    record: PreviewRecord::Trace(NativeTraceCandidate::new(attributes)),
                })
            },
            _ => Err(PolicyPreviewFailure::MalformedCandidate),
        }
    }
}

fn parse_rule(value: &Value) -> Result<(String, PolicyRule, PreviewRule), PolicyPreviewFailure> {
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
fn parse_attributes(values: &[Value]) -> Result<Vec<NativePolicyAttribute>, PolicyPreviewFailure> {
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
fn parse_value(
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
fn parse_json(bytes: &[u8]) -> Result<Value, PolicyPreviewFailure> {
    if bytes.len() > MAX_POLICY_PREVIEW_BYTES {
        return Err(PolicyPreviewFailure::RequestTooLarge);
    }
    serde_json::from_slice(bytes).map_err(|_| PolicyPreviewFailure::MalformedCandidate)
}
fn object(
    value: &Value,
    failure: PolicyPreviewFailure,
) -> Result<&Map<String, Value>, PolicyPreviewFailure> {
    value.as_object().ok_or(failure)
}
fn array(
    value: Option<&Value>,
    failure: PolicyPreviewFailure,
) -> Result<&[Value], PolicyPreviewFailure> {
    value
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or(failure)
}
fn string(
    value: Option<&Value>,
    failure: PolicyPreviewFailure,
) -> Result<&str, PolicyPreviewFailure> {
    value.and_then(Value::as_str).ok_or(failure)
}
fn unsigned(
    value: Option<&Value>,
    failure: PolicyPreviewFailure,
) -> Result<u64, PolicyPreviewFailure> {
    value.and_then(Value::as_u64).ok_or(failure)
}
fn signed(
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
fn allowed_fields(
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
fn exact_fields(
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
fn parse_receiver(value: &str) -> Result<PolicyReceiver, PolicyPreviewFailure> {
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
fn map_compile_failure(_: PolicyCompileFailure) -> PolicyPreviewFailure {
    PolicyPreviewFailure::InvalidPolicy
}
fn action_name(action: &PolicyAction) -> &'static str {
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
