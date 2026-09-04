use positron_domain::routing::SignalKind;
use positron_domain::value::{AttributeValueKind, CandidateAttributeValue};

use super::{
    IngestPolicy, PolicyAction, PolicyAttributePath, PolicyEvaluation, PolicyEvaluationFailure,
    PolicyOccurrence, PolicyPathSegment, PolicyPredicate, PolicyReceiver, PolicyRule, PolicyTarget,
    TracePolicyEvaluation,
};
use crate::{
    EvaluatedLogRecord, EvaluatedTraceRecord, NativeLogCandidate, NativePolicyAttribute,
    NativeTraceCandidate, PolicyProvenance,
};

impl IngestPolicy {
    pub fn evaluate(
        &self,
        record: NativeLogCandidate,
        receiver: PolicyReceiver,
    ) -> Result<PolicyEvaluation, PolicyEvaluationFailure> {
        let Some((record, provenance)) = self.evaluate_record(record, receiver)? else {
            return Ok(PolicyEvaluation::Rejected);
        };
        Ok(PolicyEvaluation::Accepted(Box::new(
            EvaluatedLogRecord::new(record, provenance),
        )))
    }

    pub fn evaluate_trace(
        &self,
        record: NativeTraceCandidate,
        receiver: PolicyReceiver,
    ) -> Result<TracePolicyEvaluation, PolicyEvaluationFailure> {
        let Some((record, provenance)) = self.evaluate_record(record, receiver)? else {
            return Ok(TracePolicyEvaluation::Rejected);
        };
        Ok(TracePolicyEvaluation::Accepted(Box::new(
            EvaluatedTraceRecord::new(record, provenance),
        )))
    }

    fn evaluate_record<C: PolicyRecord>(
        &self,
        mut record: C,
        receiver: PolicyReceiver,
    ) -> Result<Option<(C, PolicyProvenance)>, PolicyEvaluationFailure> {
        if record
            .body()
            .is_some_and(CandidateAttributeValue::contains_policy_marker)
            || record.attributes().iter().any(|attribute| {
                attribute
                    .occurrences()
                    .iter()
                    .any(CandidateAttributeValue::contains_policy_marker)
            })
        {
            return Err(PolicyEvaluationFailure::UntrustedMarker);
        }
        let mut applied = Vec::with_capacity(self.rules.len());
        let mut steps = StepBudget(self.budget.evaluation_steps());
        for rule in &self.rules {
            let charge = rule
                .worst_case_steps()
                .map_err(|_| PolicyEvaluationFailure::StepBudgetExhausted)?;
            steps.consume(charge)?;
            if !rule.matches(&record, receiver) {
                continue;
            }
            let changed = match &rule.action {
                PolicyAction::Accept => {
                    applied.push(rule.id.clone());
                    break;
                },
                PolicyAction::Reject => return Ok(None),
                PolicyAction::Remove(target) => {
                    transform_target(&mut record, target, Transformation::Remove)?
                },
                PolicyAction::Redact(target) => {
                    transform_target(&mut record, target, Transformation::Redact)?
                },
                PolicyAction::TruncateBytes(target, limit) => {
                    transform_target(&mut record, target, Transformation::TruncateBytes(*limit))?
                },
                PolicyAction::TruncateElements(target, limit) => transform_target(
                    &mut record,
                    target,
                    Transformation::TruncateElements(*limit),
                )?,
            };
            if changed {
                applied.push(rule.id.clone());
            }
        }
        Ok(Some((
            record,
            PolicyProvenance::evaluated(self.generation, self.digest, applied),
        )))
    }
}

trait PolicyRecord: Sized {
    fn attributes(&self) -> &[NativePolicyAttribute];
    fn attributes_mut(&mut self) -> &mut Vec<NativePolicyAttribute>;
    fn body(&self) -> Option<&CandidateAttributeValue>;
    fn body_mut(&mut self) -> &mut Option<CandidateAttributeValue>;
    fn signal(&self) -> SignalKind;
    fn log_severity(&self) -> Option<i32>;
}

impl PolicyRecord for NativeLogCandidate {
    fn attributes(&self) -> &[NativePolicyAttribute] {
        self.attributes()
    }

    fn attributes_mut(&mut self) -> &mut Vec<NativePolicyAttribute> {
        self.attributes_mut()
    }

    fn body(&self) -> Option<&CandidateAttributeValue> {
        self.body()
    }

    fn body_mut(&mut self) -> &mut Option<CandidateAttributeValue> {
        self.body_mut()
    }

    fn signal(&self) -> SignalKind {
        SignalKind::Logs
    }

    fn log_severity(&self) -> Option<i32> {
        Some(self.metadata().severity_number())
    }
}

impl PolicyRecord for NativeTraceCandidate {
    fn attributes(&self) -> &[NativePolicyAttribute] {
        self.attributes()
    }

    fn attributes_mut(&mut self) -> &mut Vec<NativePolicyAttribute> {
        self.attributes_mut()
    }

    fn body(&self) -> Option<&CandidateAttributeValue> {
        self.body()
    }

    fn body_mut(&mut self) -> &mut Option<CandidateAttributeValue> {
        self.body_mut()
    }

    fn signal(&self) -> SignalKind {
        SignalKind::Traces
    }

    fn log_severity(&self) -> Option<i32> {
        None
    }
}

struct StepBudget(u64);

impl StepBudget {
    fn consume(&mut self, amount: u64) -> Result<(), PolicyEvaluationFailure> {
        self.0 = self
            .0
            .checked_sub(amount)
            .ok_or(PolicyEvaluationFailure::StepBudgetExhausted)?;
        Ok(())
    }
}

impl PolicyRule {
    fn matches<C: PolicyRecord>(&self, record: &C, receiver: PolicyReceiver) -> bool {
        self.predicates.iter().all(|predicate| match predicate {
            PolicyPredicate::AttributeExists(path) => path_exists(record, path),
            PolicyPredicate::BodyExactText(expected) => record
                .body()
                .and_then(candidate_text)
                .is_some_and(|actual| actual == expected),
            PolicyPredicate::SignalStore(signal) => {
                *signal == record.signal()
            },
            PolicyPredicate::Receiver(expected) => *expected == receiver,
            PolicyPredicate::AttributeType(path, expected) => {
                path_has_type(record, path, *expected)
            },
            PolicyPredicate::ServiceIdentity(expected) => record.attributes().iter().any(|attribute| {
                attribute.namespace() == positron_domain::value::AttributeNamespace::Resource
                    && attribute.key() == "service.name"
                    && attribute.occurrences().iter().any(|value| {
                        matches!(value, CandidateAttributeValue::String(actual) if actual == expected)
                    })
            }),
            PolicyPredicate::LogSeverity(expected) => {
                record.log_severity() == Some(*expected)
            },
        })
    }
}

fn candidate_text(value: &CandidateAttributeValue) -> Option<&str> {
    match value {
        CandidateAttributeValue::String(value) => Some(value),
        CandidateAttributeValue::Truncated { value, .. } => candidate_text(value),
        _ => None,
    }
}

#[derive(Clone, Copy)]
enum Transformation {
    Remove,
    Redact,
    TruncateBytes(u32),
    TruncateElements(u16),
}

fn find_attribute<'record>(
    record: &'record impl PolicyRecord,
    path: &PolicyAttributePath,
) -> Option<&'record NativePolicyAttribute> {
    record
        .attributes()
        .iter()
        .find(|attribute| attribute.namespace() == path.namespace && attribute.key() == path.key)
}

fn path_exists(record: &impl PolicyRecord, path: &PolicyAttributePath) -> bool {
    find_attribute(record, path).is_some_and(|attribute| {
        selected(attribute.occurrences(), path.occurrence)
            .any(|value| value_path_exists(value, &path.segments))
    })
}

fn path_has_type(
    record: &impl PolicyRecord,
    path: &PolicyAttributePath,
    expected: AttributeValueKind,
) -> bool {
    find_attribute(record, path).is_some_and(|attribute| {
        selected(attribute.occurrences(), path.occurrence)
            .any(|value| value_path_has_type(value, &path.segments, expected))
    })
}

fn value_path_has_type(
    value: &CandidateAttributeValue,
    segments: &[PolicyPathSegment],
    expected: AttributeValueKind,
) -> bool {
    let Some((first, rest)) = segments.split_first() else {
        return candidate_kind(value) == expected;
    };
    if let CandidateAttributeValue::Truncated { value, .. } = value {
        return value_path_has_type(value, segments, expected);
    }
    match (first, value) {
        (PolicyPathSegment::Key(key), CandidateAttributeValue::KeyValueList(entries)) => entries
            .iter()
            .any(|entry| entry.key() == key && value_path_has_type(entry.value(), rest, expected)),
        (PolicyPathSegment::ArrayIndex(index), CandidateAttributeValue::Array(values)) => values
            .get(usize::from(*index))
            .is_some_and(|value| value_path_has_type(value, rest, expected)),
        _ => false,
    }
}

fn candidate_kind(value: &CandidateAttributeValue) -> AttributeValueKind {
    match value {
        CandidateAttributeValue::Null => AttributeValueKind::Null,
        CandidateAttributeValue::Boolean(_) => AttributeValueKind::Boolean,
        CandidateAttributeValue::SignedInteger(_) => AttributeValueKind::SignedInteger,
        CandidateAttributeValue::FloatingPointBits(_) => AttributeValueKind::FloatingPoint,
        CandidateAttributeValue::String(_) => AttributeValueKind::String,
        CandidateAttributeValue::Bytes(_) => AttributeValueKind::Bytes,
        CandidateAttributeValue::Array(_) => AttributeValueKind::Array,
        CandidateAttributeValue::KeyValueList(_) => AttributeValueKind::KeyValueList,
        CandidateAttributeValue::Marker(_) => AttributeValueKind::Marker,
        CandidateAttributeValue::Truncated { value, .. } => candidate_kind(value),
    }
}

fn value_path_exists(value: &CandidateAttributeValue, segments: &[PolicyPathSegment]) -> bool {
    let Some((first, rest)) = segments.split_first() else {
        return true;
    };
    if let CandidateAttributeValue::Truncated { value, .. } = value {
        return value_path_exists(value, segments);
    }
    match (first, value) {
        (PolicyPathSegment::Key(key), CandidateAttributeValue::KeyValueList(entries)) => entries
            .iter()
            .any(|entry| entry.key() == key && value_path_exists(entry.value(), rest)),
        (PolicyPathSegment::ArrayIndex(index), CandidateAttributeValue::Array(values)) => values
            .get(usize::from(*index))
            .is_some_and(|value| value_path_exists(value, rest)),
        _ => false,
    }
}

fn selected(
    values: &[CandidateAttributeValue],
    occurrence: PolicyOccurrence,
) -> impl Iterator<Item = &CandidateAttributeValue> {
    values.iter().enumerate().filter_map(move |(index, value)| {
        matches!(occurrence, PolicyOccurrence::All)
            .then_some(value)
            .or_else(|| match occurrence {
                PolicyOccurrence::Index(expected) if index == usize::from(expected) => Some(value),
                PolicyOccurrence::All | PolicyOccurrence::Index(_) => None,
            })
    })
}

fn transform_target(
    record: &mut impl PolicyRecord,
    target: &PolicyTarget,
    transformation: Transformation,
) -> Result<bool, PolicyEvaluationFailure> {
    match target {
        PolicyTarget::Body => record
            .body_mut()
            .as_mut()
            .map_or(Ok(false), |body| transform_leaf(body, transformation)),
        PolicyTarget::Attribute(path) => {
            let Some(attribute) = record.attributes_mut().iter_mut().find(|attribute| {
                attribute.namespace() == path.namespace && attribute.key() == path.key
            }) else {
                return Ok(false);
            };
            transform_selected(attribute, path, Some(transformation))
        },
    }
}

fn transform_selected(
    attribute: &mut NativePolicyAttribute,
    path: &PolicyAttributePath,
    transformation: Option<Transformation>,
) -> Result<bool, PolicyEvaluationFailure> {
    let occurrence = path.occurrence;
    let mut changed = false;
    for (index, value) in attribute.occurrences_mut().iter_mut().enumerate() {
        if matches!(occurrence, PolicyOccurrence::All)
            || matches!(occurrence, PolicyOccurrence::Index(expected) if index == usize::from(expected))
        {
            changed = transform_value(value, &path.segments, transformation)? || changed;
        }
    }
    Ok(changed)
}

fn transform_value(
    value: &mut CandidateAttributeValue,
    segments: &[PolicyPathSegment],
    transformation: Option<Transformation>,
) -> Result<bool, PolicyEvaluationFailure> {
    let Some((first, rest)) = segments.split_first() else {
        return transformation.map_or(Ok(false), |transformation| {
            transform_leaf(value, transformation)
        });
    };
    if let CandidateAttributeValue::Truncated { value: inner, .. } = value {
        return transform_value(inner, segments, transformation);
    }
    match (first, value) {
        (PolicyPathSegment::Key(key), CandidateAttributeValue::KeyValueList(entries)) => entries
            .iter_mut()
            .filter(|entry| entry.key() == key)
            .try_fold(false, |changed, entry| {
                Ok(transform_value(entry.value_mut(), rest, transformation)? || changed)
            }),
        (PolicyPathSegment::ArrayIndex(index), CandidateAttributeValue::Array(values)) => {
            if let Some(value) = values.get_mut(usize::from(*index)) {
                transform_value(value, rest, transformation)
            } else {
                Ok(false)
            }
        },
        _ => Ok(false),
    }
}

fn transform_leaf(
    value: &mut CandidateAttributeValue,
    transformation: Transformation,
) -> Result<bool, PolicyEvaluationFailure> {
    match transformation {
        Transformation::Remove | Transformation::Redact => {
            let kind = candidate_kind(value);
            if matches!(kind, AttributeValueKind::Marker) {
                return Ok(false);
            }
            let action = match transformation {
                Transformation::Remove => positron_domain::value::MarkerAction::Removed,
                Transformation::Redact => positron_domain::value::MarkerAction::Redacted,
                Transformation::TruncateBytes(_) | Transformation::TruncateElements(_) => {
                    return Ok(false);
                },
            };
            *value = CandidateAttributeValue::redaction_marker(kind, action);
            Ok(true)
        },
        Transformation::TruncateBytes(limit) => truncate_bytes(value, limit),
        Transformation::TruncateElements(limit) => truncate_elements(value, limit),
    }
}

fn truncate_bytes(
    value: &mut CandidateAttributeValue,
    limit: u32,
) -> Result<bool, PolicyEvaluationFailure> {
    let Ok(limit) = usize::try_from(limit) else {
        return Ok(false);
    };
    match value {
        CandidateAttributeValue::String(text) if text.len() > limit => {
            let mut boundary = limit;
            while !text.is_char_boundary(boundary) {
                boundary = boundary.saturating_sub(1);
            }
            let mut sanitized = String::new();
            sanitized
                .try_reserve_exact(boundary)
                .map_err(|_| PolicyEvaluationFailure::EvidenceBoundExceeded)?;
            sanitized.push_str(&text[..boundary]);
            *value = CandidateAttributeValue::truncated(
                CandidateAttributeValue::string(sanitized),
                positron_domain::value::MarkerAction::TruncatedBytes,
            );
            Ok(true)
        },
        CandidateAttributeValue::Bytes(bytes) if bytes.len() > limit => {
            let mut sanitized = Vec::new();
            sanitized
                .try_reserve_exact(limit)
                .map_err(|_| PolicyEvaluationFailure::EvidenceBoundExceeded)?;
            sanitized.extend_from_slice(&bytes[..limit]);
            *value = CandidateAttributeValue::truncated(
                CandidateAttributeValue::bytes(sanitized),
                positron_domain::value::MarkerAction::TruncatedBytes,
            );
            Ok(true)
        },
        _ => Ok(false),
    }
}

fn truncate_elements(
    value: &mut CandidateAttributeValue,
    limit: u16,
) -> Result<bool, PolicyEvaluationFailure> {
    let limit = usize::from(limit);
    match value {
        CandidateAttributeValue::Array(values) if values.len() > limit => {
            let original = std::mem::take(values);
            let keep = original.len().min(limit);
            let mut sanitized = Vec::new();
            sanitized
                .try_reserve_exact(keep)
                .map_err(|_| PolicyEvaluationFailure::EvidenceBoundExceeded)?;
            sanitized.extend(original.into_iter().take(keep));
            *value = CandidateAttributeValue::truncated(
                CandidateAttributeValue::array(sanitized),
                positron_domain::value::MarkerAction::TruncatedElements,
            );
            Ok(true)
        },
        CandidateAttributeValue::KeyValueList(values) if values.len() > limit => {
            let original = std::mem::take(values);
            let keep = original.len().min(limit);
            let mut sanitized = Vec::new();
            sanitized
                .try_reserve_exact(keep)
                .map_err(|_| PolicyEvaluationFailure::EvidenceBoundExceeded)?;
            sanitized.extend(original.into_iter().take(keep));
            *value = CandidateAttributeValue::truncated(
                CandidateAttributeValue::key_value_list(sanitized),
                positron_domain::value::MarkerAction::TruncatedElements,
            );
            Ok(true)
        },
        _ => Ok(false),
    }
}
