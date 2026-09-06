use super::{
    ByteLimit, CandidateAttributeValue, ValueLimitSet, checked_decoded_add, exceeds_byte_limit,
    exceeds_collection_limit,
};

/// A finite dimension of a dynamic candidate shape.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ValueLimitDimension {
    KeyPathBytes,
    IndividualValueBytes,
    NestingDepth,
    ArrayEntries,
    KeyValueListEntries,
}

/// Payload-free detail for one dynamic candidate limit failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValueLimitViolation {
    dimension: ValueLimitDimension,
    actual: u64,
    allowed: u64,
}

impl ValueLimitViolation {
    #[must_use]
    pub const fn new(dimension: ValueLimitDimension, actual: u64, allowed: u64) -> Self {
        Self {
            dimension,
            actual,
            allowed,
        }
    }

    #[must_use]
    pub const fn dimension(self) -> ValueLimitDimension {
        self.dimension
    }

    #[must_use]
    pub const fn actual(self) -> u64 {
        self.actual
    }

    #[must_use]
    pub const fn allowed(self) -> u64 {
        self.allowed
    }
}

/// The allocation-free result of checking a candidate's recursive shape.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateShapeFailure {
    Invalid,
    Limit(ValueLimitViolation),
}

pub(super) fn validate(
    candidate: &CandidateAttributeValue,
    limits: ValueLimitSet,
    value_bytes: ByteLimit,
    remaining_depth: u16,
) -> Result<usize, CandidateShapeFailure> {
    let size = match candidate {
        CandidateAttributeValue::Null => 0,
        CandidateAttributeValue::Boolean(_) => 1,
        CandidateAttributeValue::SignedInteger(_)
        | CandidateAttributeValue::FloatingPointBits(_) => 8,
        CandidateAttributeValue::String(value) => value.len(),
        CandidateAttributeValue::Bytes(value) => value.len(),
        CandidateAttributeValue::Array(values) => {
            let child_depth = remaining_depth
                .checked_sub(1)
                .ok_or_else(|| depth_limit_failure(remaining_depth))?;
            if exceeds_collection_limit(values.len(), limits.dynamic_value().array_entries()) {
                return Err(limit_failure(
                    ValueLimitDimension::ArrayEntries,
                    values.len(),
                    limits.dynamic_value().array_entries().value(),
                ));
            }
            values.iter().try_fold(0, |total, value| {
                let child_size = validate(value, limits, value_bytes, child_depth)?;
                checked_decoded_add(total, child_size).map_err(|_| CandidateShapeFailure::Invalid)
            })?
        },
        CandidateAttributeValue::KeyValueList(values) => {
            let child_depth = remaining_depth
                .checked_sub(1)
                .ok_or_else(|| depth_limit_failure(remaining_depth))?;
            if exceeds_collection_limit(
                values.len(),
                limits.dynamic_value().key_value_list_entries(),
            ) {
                return Err(limit_failure(
                    ValueLimitDimension::KeyValueListEntries,
                    values.len(),
                    limits.dynamic_value().key_value_list_entries().value(),
                ));
            }
            values.iter().try_fold(0, |total, entry| {
                if entry.key.is_empty() {
                    return Err(CandidateShapeFailure::Invalid);
                }
                if exceeds_byte_limit(entry.key.len(), limits.dynamic_value().key_path_bytes()) {
                    return Err(limit_failure(
                        ValueLimitDimension::KeyPathBytes,
                        entry.key.len(),
                        limits.dynamic_value().key_path_bytes().value(),
                    ));
                }
                let child_size = validate(&entry.value, limits, value_bytes, child_depth)?;
                checked_decoded_add(total, child_size).map_err(|_| CandidateShapeFailure::Invalid)
            })?
        },
        CandidateAttributeValue::Marker(marker) if marker.is_valid() => 0,
        CandidateAttributeValue::Marker(_) => return Err(CandidateShapeFailure::Invalid),
        CandidateAttributeValue::Truncated { value, action } => {
            if matches!(
                value.as_ref(),
                CandidateAttributeValue::Marker(_) | CandidateAttributeValue::Truncated { .. }
            ) || !super::truncation_action_valid(
                *action,
                super::candidate_native_kind(value).ok_or(CandidateShapeFailure::Invalid)?,
            ) {
                return Err(CandidateShapeFailure::Invalid);
            }
            validate(value, limits, value_bytes, remaining_depth)?
        },
    };
    if exceeds_byte_limit(size, value_bytes) {
        return Err(limit_failure(
            ValueLimitDimension::IndividualValueBytes,
            size,
            value_bytes.value(),
        ));
    }
    Ok(size)
}

fn depth_limit_failure(remaining_depth: u16) -> CandidateShapeFailure {
    limit_failure(
        ValueLimitDimension::NestingDepth,
        usize::from(remaining_depth) + 1,
        u32::from(remaining_depth),
    )
}

fn limit_failure(
    dimension: ValueLimitDimension,
    actual: usize,
    allowed: u32,
) -> CandidateShapeFailure {
    let Ok(actual) = u64::try_from(actual) else {
        return CandidateShapeFailure::Invalid;
    };
    CandidateShapeFailure::Limit(ValueLimitViolation::new(
        dimension,
        actual,
        u64::from(allowed),
    ))
}
