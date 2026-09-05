use positron_domain::value::{CandidateAttributeValue, ValueLimitProfile};

use super::super::{TraceLimitClass, TraceLimitViolation, TraceReceiveFailure};

pub(super) fn post_policy_limit_violation(
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

pub(super) fn detail_failure(
    class: TraceLimitClass,
    actual: usize,
    allowed: usize,
) -> TraceReceiveFailure {
    TraceReceiveFailure::ValueLimitExceededWithDetail(violation(class, actual, allowed))
}
