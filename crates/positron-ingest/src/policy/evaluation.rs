use positron_domain::value::{CandidateAttributeValue, PolicyValueMarker};
use positron_signals::{LogStoreFailure, PolicyProvenance};

use super::{
    IngestPolicy, PolicyAction, PolicyAttributePath, PolicyDecision, PolicyOccurrence,
    PolicyPathSegment, PolicyPredicate, PolicyRule, PolicyTarget,
};
use crate::{NativeLogAttribute, NativeLogCandidate};

#[cfg(test)]
#[path = "evaluation/tests.rs"]
mod tests;

impl IngestPolicy {
    pub(crate) fn evaluate(
        &self,
        record: NativeLogCandidate,
        receiver: super::PolicyReceiver,
    ) -> Result<PolicyDecision, LogStoreFailure> {
        let mut record = record;
        let mut applied = Vec::new();
        for rule in &self.rules {
            if !rule.matches(&record, receiver) {
                continue;
            }
            let applied_action = match &rule.action {
                PolicyAction::Accept => {
                    applied.push(rule.id.clone());
                    break;
                },
                PolicyAction::Reject => return Ok(PolicyDecision::Reject),
                PolicyAction::Remove(path) => {
                    transform_target(&mut record, path, Transformation::Remove)
                },
                PolicyAction::Redact(path) => {
                    transform_target(&mut record, path, Transformation::Redact)
                },
                PolicyAction::TruncateBytes(path, limit) => {
                    transform_target(&mut record, path, Transformation::TruncateBytes(*limit))
                },
                PolicyAction::TruncateElements(path, limit) => {
                    transform_target(&mut record, path, Transformation::TruncateElements(*limit))
                },
            };
            if applied_action {
                applied.push(rule.id.clone());
            }
        }
        let provenance = PolicyProvenance::new(
            self.provenance.generation(),
            self.provenance.digest(),
            applied,
        )?;
        Ok(PolicyDecision::Accept {
            record: Box::new(record),
            provenance,
        })
    }
}

impl PolicyRule {
    fn matches(&self, record: &NativeLogCandidate, receiver: super::PolicyReceiver) -> bool {
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
        CandidateAttributeValue::Truncated(value) => candidate_text(value),
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
    record: &'record NativeLogCandidate,
    path: &PolicyAttributePath,
) -> Option<&'record NativeLogAttribute> {
    record
        .attributes()
        .iter()
        .find(|attribute| attribute.namespace() == path.namespace && attribute.key() == path.key)
}

fn path_exists(record: &NativeLogCandidate, path: &PolicyAttributePath) -> bool {
    let Some(attribute) = find_attribute(record, path) else {
        return false;
    };
    selected(attribute.occurrences(), path.occurrence)
        .any(|value| value_path_exists(value, &path.segments))
}

fn path_has_type(
    record: &NativeLogCandidate,
    path: &PolicyAttributePath,
    expected: positron_domain::value::AttributeValueKind,
) -> bool {
    let Some(attribute) = find_attribute(record, path) else {
        return false;
    };
    selected(attribute.occurrences(), path.occurrence)
        .any(|value| value_path_has_type(value, &path.segments, expected))
}

fn value_path_has_type(
    value: &CandidateAttributeValue,
    segments: &[PolicyPathSegment],
    expected: positron_domain::value::AttributeValueKind,
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
        (_, CandidateAttributeValue::Truncated(value)) => {
            value_path_has_type(value, segments, expected)
        },
        _ => false,
    }
}

fn candidate_kind(value: &CandidateAttributeValue) -> positron_domain::value::AttributeValueKind {
    use positron_domain::value::AttributeValueKind;
    match value {
        CandidateAttributeValue::Null => AttributeValueKind::Null,
        CandidateAttributeValue::Boolean(_) => AttributeValueKind::Boolean,
        CandidateAttributeValue::SignedInteger(_) => AttributeValueKind::SignedInteger,
        CandidateAttributeValue::FloatingPointBits(_) => AttributeValueKind::FloatingPoint,
        CandidateAttributeValue::String(_) => AttributeValueKind::String,
        CandidateAttributeValue::Bytes(_) => AttributeValueKind::Bytes,
        CandidateAttributeValue::Array(_) => AttributeValueKind::Array,
        CandidateAttributeValue::KeyValueList(_) => AttributeValueKind::KeyValueList,
        CandidateAttributeValue::PolicyMarker(_) => AttributeValueKind::PolicyMarker,
        CandidateAttributeValue::Truncated(value) => candidate_kind(value),
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
        (_, CandidateAttributeValue::Truncated(value)) => value_path_exists(value, segments),
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

fn transform_path(
    record: &mut NativeLogCandidate,
    path: &PolicyAttributePath,
    transformation: Transformation,
) -> bool {
    let Some(attribute) = record
        .attributes_mut()
        .iter_mut()
        .find(|attribute| attribute.namespace() == path.namespace && attribute.key() == path.key)
    else {
        return false;
    };
    if path.segments.is_empty()
        && matches!(path.occurrence, PolicyOccurrence::All)
        && matches!(transformation, Transformation::Remove)
    {
        attribute.replace_occurrences(vec![CandidateAttributeValue::policy_marker(
            PolicyValueMarker::Removed,
        )]);
        return true;
    }
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

fn transform_target(
    record: &mut NativeLogCandidate,
    target: &PolicyTarget,
    transformation: Transformation,
) -> bool {
    match target {
        PolicyTarget::Body => record
            .body_mut()
            .is_some_and(|body| transform_leaf(body, transformation)),
        PolicyTarget::Attribute(path) => transform_path(record, path, transformation),
    }
}

fn transform_value(
    value: &mut CandidateAttributeValue,
    segments: &[PolicyPathSegment],
    transformation: Transformation,
) -> bool {
    let Some((first, rest)) = segments.split_first() else {
        return transform_leaf(value, transformation);
    };
    match first {
        PolicyPathSegment::Key(key) => match value {
            CandidateAttributeValue::KeyValueList(entries) => {
                let mut changed = false;
                for entry in entries.iter_mut().filter(|entry| entry.key() == key) {
                    changed |= transform_value(entry.value_mut(), rest, transformation);
                }
                changed
            },
            CandidateAttributeValue::Truncated(value) => {
                transform_value(value, segments, transformation)
            },
            _ => false,
        },
        PolicyPathSegment::ArrayIndex(index) => match value {
            CandidateAttributeValue::Array(values) => values
                .get_mut(usize::from(*index))
                .is_some_and(|value| transform_value(value, rest, transformation)),
            CandidateAttributeValue::Truncated(value) => {
                transform_value(value, segments, transformation)
            },
            _ => false,
        },
    }
}

fn transform_leaf(value: &mut CandidateAttributeValue, transformation: Transformation) -> bool {
    match transformation {
        Transformation::Remove => {
            *value = CandidateAttributeValue::policy_marker(PolicyValueMarker::Removed);
            true
        },
        Transformation::Redact => {
            *value = CandidateAttributeValue::policy_marker(PolicyValueMarker::Redacted);
            true
        },
        Transformation::TruncateBytes(limit) => truncate_bytes(value, limit),
        Transformation::TruncateElements(limit) => truncate_elements(value, limit),
    }
}

fn truncate_bytes(value: &mut CandidateAttributeValue, limit: u32) -> bool {
    if let CandidateAttributeValue::Truncated(value) = value {
        return truncate_bytes(value, limit);
    }
    let Ok(limit) = usize::try_from(limit) else {
        return false;
    };
    let changed = match value {
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
    };
    wrap_truncated(value, changed)
}

fn truncate_elements(value: &mut CandidateAttributeValue, limit: u16) -> bool {
    if let CandidateAttributeValue::Truncated(value) = value {
        return truncate_elements(value, limit);
    }
    let limit = usize::from(limit);
    let changed = match value {
        CandidateAttributeValue::Array(values) if values.len() > limit => {
            values.truncate(limit);
            true
        },
        CandidateAttributeValue::KeyValueList(values) if values.len() > limit => {
            values.truncate(limit);
            true
        },
        _ => false,
    };
    wrap_truncated(value, changed)
}

fn wrap_truncated(value: &mut CandidateAttributeValue, changed: bool) -> bool {
    if changed {
        let retained = std::mem::replace(value, CandidateAttributeValue::null());
        *value = CandidateAttributeValue::truncated(retained);
    }
    changed
}
