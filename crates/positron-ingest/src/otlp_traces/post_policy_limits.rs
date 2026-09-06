use positron_domain::value::{CandidateShapeFailure, ValueLimitDimension, ValueLimitProfile};

use super::super::{TraceLimitClass, TraceLimitViolation, TraceReceiveFailure};

pub(super) fn post_policy_limit_violation(
    attributes: &[positron_policy::NativePolicyAttribute],
    profile: &ValueLimitProfile,
) -> Option<TraceLimitViolation> {
    let dynamic = profile.effective_limits().dynamic_value();
    let key_limit = usize::try_from(dynamic.key_path_bytes().value()).ok()?;
    let attribute_limit = usize::try_from(dynamic.attributes_per_namespace().value()).ok()?;

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
            value
                .validate_shape_detailed(*profile)
                .err()
                .and_then(domain_violation)
        })
    })
}

fn domain_violation(failure: CandidateShapeFailure) -> Option<TraceLimitViolation> {
    let CandidateShapeFailure::Limit(detail) = failure else {
        return None;
    };
    let class = match detail.dimension() {
        ValueLimitDimension::KeyPathBytes => TraceLimitClass::KeyPathBytes,
        ValueLimitDimension::IndividualValueBytes => TraceLimitClass::IndividualValueBytes,
        ValueLimitDimension::NestingDepth => TraceLimitClass::NestingDepth,
        ValueLimitDimension::ArrayEntries => TraceLimitClass::ArrayEntries,
        ValueLimitDimension::KeyValueListEntries => TraceLimitClass::KeyValueListEntries,
    };
    Some(TraceLimitViolation::new(
        class,
        detail.actual(),
        detail.allowed(),
    ))
}

fn violation(class: TraceLimitClass, actual: usize, allowed: usize) -> TraceLimitViolation {
    let actual = usize_as_u64(actual);
    let allowed = usize_as_u64(allowed);
    TraceLimitViolation::new(class, actual, allowed)
}

fn usize_as_u64(value: usize) -> u64 {
    let Ok(value) = u64::try_from(value) else {
        return u64::MAX;
    };
    value
}

pub(super) fn detail_failure(
    class: TraceLimitClass,
    actual: usize,
    allowed: usize,
) -> TraceReceiveFailure {
    TraceReceiveFailure::ValueLimitExceededWithDetail(violation(class, actual, allowed))
}
