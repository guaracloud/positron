use positron_domain::value::{AttributeValueKind, CandidateAttributeValue};

use super::{
    IngestPolicy, PolicyAction, PolicyAttributePath, PolicyEvaluation, PolicyEvaluationFailure,
    PolicyOccurrence, PolicyPathSegment, PolicyPredicate, PolicyReceiver, PolicyRule, PolicyTarget,
};
use crate::{EvaluatedLogRecord, NativeLogAttribute, NativeLogCandidate, PolicyProvenance};

impl IngestPolicy {
    pub fn evaluate(
        &self,
        mut record: NativeLogCandidate,
        receiver: PolicyReceiver,
    ) -> Result<PolicyEvaluation, PolicyEvaluationFailure> {
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
                PolicyAction::Reject => return Ok(PolicyEvaluation::Rejected),
                PolicyAction::Remove(target) => remove_target(&mut record, target),
                PolicyAction::Redact(target) => {
                    transform_target(&mut record, target, Transformation::Redact)
                },
                PolicyAction::TruncateBytes(target, limit) => {
                    transform_target(&mut record, target, Transformation::TruncateBytes(*limit))
                },
                PolicyAction::TruncateElements(target, limit) => transform_target(
                    &mut record,
                    target,
                    Transformation::TruncateElements(*limit),
                ),
            };
            if changed {
                applied.push(rule.id.clone());
            }
        }
        Ok(PolicyEvaluation::Accepted(Box::new(
            EvaluatedLogRecord::new(
                record,
                PolicyProvenance::evaluated(self.generation, self.digest, applied),
            ),
        )))
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
    fn matches(&self, record: &NativeLogCandidate, receiver: PolicyReceiver) -> bool {
        self.predicates.iter().all(|predicate| match predicate {
            PolicyPredicate::AttributeExists(path) => path_exists(record, path),
            PolicyPredicate::BodyExactText(expected) => record
                .body()
                .and_then(candidate_text)
                .is_some_and(|actual| actual == expected),
            PolicyPredicate::SignalStore(signal) => {
                *signal == positron_domain::routing::SignalKind::Logs
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
                record.metadata().severity_number() == *expected
            },
        })
    }
}

fn candidate_text(value: &CandidateAttributeValue) -> Option<&str> {
    match value {
        CandidateAttributeValue::String(value) => Some(value),
        _ => None,
    }
}

#[derive(Clone, Copy)]
enum Transformation {
    Redact,
    TruncateBytes(u32),
    TruncateElements(u16),
}

fn find_attribute<'record>(
    record: &'record NativeLogCandidate,
    path: &PolicyAttributePath,
) -> Option<&'record NativeLogAttribute> {
    record
        .attributes()
        .iter()
        .find(|attribute| attribute.namespace() == path.namespace && attribute.key() == path.key)
}

fn path_exists(record: &NativeLogCandidate, path: &PolicyAttributePath) -> bool {
    find_attribute(record, path).is_some_and(|attribute| {
        selected(attribute.occurrences(), path.occurrence)
            .any(|value| value_path_exists(value, &path.segments))
    })
}

fn path_has_type(
    record: &NativeLogCandidate,
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
    }
}

fn value_path_exists(value: &CandidateAttributeValue, segments: &[PolicyPathSegment]) -> bool {
    let Some((first, rest)) = segments.split_first() else {
        return true;
    };
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

fn remove_target(record: &mut NativeLogCandidate, target: &PolicyTarget) -> bool {
    match target {
        PolicyTarget::Body => record.body_mut().take().is_some(),
        PolicyTarget::Attribute(path) => remove_path(record, path),
    }
}

fn remove_path(record: &mut NativeLogCandidate, path: &PolicyAttributePath) -> bool {
    let Some(position) = record.attributes().iter().position(|attribute| {
        attribute.namespace() == path.namespace && attribute.key() == path.key
    }) else {
        return false;
    };
    if path.segments.is_empty() && matches!(path.occurrence, PolicyOccurrence::All) {
        record.attributes_mut().remove(position);
        return true;
    }
    let attribute = &mut record.attributes_mut()[position];
    let changed = if path.segments.is_empty() {
        match path.occurrence {
            PolicyOccurrence::All => false,
            PolicyOccurrence::Index(index)
                if usize::from(index) < attribute.occurrences().len() =>
            {
                attribute.occurrences_mut().remove(usize::from(index));
                true
            },
            PolicyOccurrence::Index(_) => false,
        }
    } else {
        transform_selected(attribute, path, None)
    };
    if attribute.occurrences().is_empty() {
        record.attributes_mut().remove(position);
    }
    changed
}

fn transform_target(
    record: &mut NativeLogCandidate,
    target: &PolicyTarget,
    transformation: Transformation,
) -> bool {
    match target {
        PolicyTarget::Body => record
            .body_mut()
            .as_mut()
            .is_some_and(|body| transform_leaf(body, transformation)),
        PolicyTarget::Attribute(path) => {
            let Some(attribute) = record.attributes_mut().iter_mut().find(|attribute| {
                attribute.namespace() == path.namespace && attribute.key() == path.key
            }) else {
                return false;
            };
            transform_selected(attribute, path, Some(transformation))
        },
    }
}

fn transform_selected(
    attribute: &mut NativeLogAttribute,
    path: &PolicyAttributePath,
    transformation: Option<Transformation>,
) -> bool {
    let occurrence = path.occurrence;
    attribute
        .occurrences_mut()
        .iter_mut()
        .enumerate()
        .filter(|(index, _)| match occurrence {
            PolicyOccurrence::All => true,
            PolicyOccurrence::Index(expected) => *index == usize::from(expected),
        })
        .fold(false, |changed, (_, value)| {
            transform_value(value, &path.segments, transformation) || changed
        })
}

#[expect(
    clippy::unnecessary_fold,
    reason = "every duplicate key must be transformed; Iterator::any would short-circuit"
)]
fn transform_value(
    value: &mut CandidateAttributeValue,
    segments: &[PolicyPathSegment],
    transformation: Option<Transformation>,
) -> bool {
    let Some((first, rest)) = segments.split_first() else {
        return transformation.is_some_and(|transformation| transform_leaf(value, transformation));
    };
    match (first, value) {
        (PolicyPathSegment::Key(key), CandidateAttributeValue::KeyValueList(entries))
            if rest.is_empty() && transformation.is_none() =>
        {
            let before = entries.len();
            entries.retain(|entry| entry.key() != key);
            entries.len() != before
        },
        (PolicyPathSegment::Key(key), CandidateAttributeValue::KeyValueList(entries)) => entries
            .iter_mut()
            .filter(|entry| entry.key() == key)
            .fold(false, |changed, entry| {
                transform_value(entry.value_mut(), rest, transformation) || changed
            }),
        (PolicyPathSegment::ArrayIndex(index), CandidateAttributeValue::Array(values))
            if rest.is_empty() && transformation.is_none() =>
        {
            let index = usize::from(*index);
            if index < values.len() {
                values.remove(index);
                true
            } else {
                false
            }
        },
        (PolicyPathSegment::ArrayIndex(index), CandidateAttributeValue::Array(values)) => values
            .get_mut(usize::from(*index))
            .is_some_and(|value| transform_value(value, rest, transformation)),
        _ => false,
    }
}

fn transform_leaf(value: &mut CandidateAttributeValue, transformation: Transformation) -> bool {
    match transformation {
        Transformation::Redact if !matches!(value, CandidateAttributeValue::Null) => {
            *value = CandidateAttributeValue::null();
            true
        },
        Transformation::Redact => false,
        Transformation::TruncateBytes(limit) => truncate_bytes(value, limit),
        Transformation::TruncateElements(limit) => truncate_elements(value, limit),
    }
}

fn truncate_bytes(value: &mut CandidateAttributeValue, limit: u32) -> bool {
    let Ok(limit) = usize::try_from(limit) else {
        return false;
    };
    match value {
        CandidateAttributeValue::String(text) if text.len() > limit => {
            let mut boundary = limit;
            while !text.is_char_boundary(boundary) {
                boundary = boundary.saturating_sub(1);
            }
            text.truncate(boundary);
            true
        },
        CandidateAttributeValue::Bytes(bytes) if bytes.len() > limit => {
            bytes.truncate(limit);
            true
        },
        _ => false,
    }
}

fn truncate_elements(value: &mut CandidateAttributeValue, limit: u16) -> bool {
    let limit = usize::from(limit);
    match value {
        CandidateAttributeValue::Array(values) if values.len() > limit => {
            values.truncate(limit);
            true
        },
        CandidateAttributeValue::KeyValueList(values) if values.len() > limit => {
            values.truncate(limit);
            true
        },
        _ => false,
    }
}
