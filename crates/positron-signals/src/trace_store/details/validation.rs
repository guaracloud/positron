use positron_domain::value::ValueLimitProfile;

use super::{SpanAttributeSet, TraceStoreFailure};

pub(crate) fn validate_detail_name(name: &str, limit: usize) -> Result<(), TraceStoreFailure> {
    if name.is_empty() || name.len() > limit {
        Err(TraceStoreFailure::invalid_input())
    } else {
        Ok(())
    }
}

pub(crate) fn detail_limits(
    profile: &ValueLimitProfile,
) -> Result<(usize, usize), TraceStoreFailure> {
    let dynamic = profile.effective_limits().dynamic_value();
    let key_path_bytes = usize::try_from(dynamic.key_path_bytes().value())
        .map_err(|_| TraceStoreFailure::limit_exceeded())?;
    let occurrences_per_namespace = usize::try_from(dynamic.attributes_per_namespace().value())
        .map_err(|_| TraceStoreFailure::limit_exceeded())?;
    Ok((key_path_bytes, occurrences_per_namespace))
}

pub(crate) fn validate_detail_attributes(
    attributes: &[SpanAttributeSet],
    occurrence_limit: usize,
) -> Result<(), TraceStoreFailure> {
    if attributes.len() > super::MAX_DETAIL_COLLECTION {
        return Err(TraceStoreFailure::limit_exceeded());
    }
    let mut occurrences = 0_usize;
    for attribute in attributes {
        occurrences = occurrences
            .checked_add(attribute.len())
            .filter(|count| *count <= occurrence_limit)
            .ok_or_else(TraceStoreFailure::limit_exceeded)?;
    }
    Ok(())
}

pub(crate) fn detail_decoded_bytes(
    current: usize,
    name_bytes: usize,
    attributes: &[SpanAttributeSet],
    limit: usize,
) -> Result<usize, TraceStoreFailure> {
    let mut decoded = current
        .checked_add(name_bytes)
        .ok_or_else(TraceStoreFailure::limit_exceeded)?;
    for attribute in attributes {
        decoded = decoded
            .checked_add(attribute.key().len())
            .ok_or_else(TraceStoreFailure::limit_exceeded)?;
        for index in 0..attribute.len() {
            let value = attribute
                .occurrence(index)
                .ok_or_else(TraceStoreFailure::invalid_input)?;
            decoded = decoded
                .checked_add(
                    value
                        .decoded_size_bytes()
                        .map_err(TraceStoreFailure::domain)?,
                )
                .filter(|size| *size <= limit)
                .ok_or_else(TraceStoreFailure::limit_exceeded)?;
        }
    }
    Ok(decoded)
}
