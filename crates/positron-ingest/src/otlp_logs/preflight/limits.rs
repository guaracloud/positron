use positron_domain::value::ValueLimitProfile;

use crate::ReceiveFailure;

#[derive(Clone, Copy)]
pub(crate) struct StructuralLimits {
    pub(crate) containers: usize,
    pub(crate) records: usize,
    pub(crate) attributes: usize,
    pub(crate) attribute_entries: usize,
    pub(crate) array_entries: usize,
    pub(crate) key_value_entries: usize,
    pub(crate) nesting_depth: usize,
    pub(crate) value_bytes: usize,
    pub(crate) key_bytes: usize,
}

impl StructuralLimits {
    pub(crate) fn from_profile(profile: ValueLimitProfile) -> Result<Self, ReceiveFailure> {
        let limits = profile.system_limits();
        let request = limits.request();
        let dynamic = limits.dynamic_value();
        Ok(Self {
            containers: usize::try_from(request.records().value())
                .map_err(|_| ReceiveFailure::ValueLimitExceeded)?,
            records: usize::try_from(request.records().value())
                .map_err(|_| ReceiveFailure::ValueLimitExceeded)?,
            attributes: usize::try_from(request.aggregate_attributes().value())
                .map_err(|_| ReceiveFailure::ValueLimitExceeded)?,
            attribute_entries: usize::try_from(dynamic.attributes_per_namespace().value())
                .map_err(|_| ReceiveFailure::ValueLimitExceeded)?,
            array_entries: usize::try_from(dynamic.array_entries().value())
                .map_err(|_| ReceiveFailure::ValueLimitExceeded)?,
            key_value_entries: usize::try_from(dynamic.key_value_list_entries().value())
                .map_err(|_| ReceiveFailure::ValueLimitExceeded)?,
            nesting_depth: usize::from(dynamic.nesting_depth().value()),
            value_bytes: usize::try_from(dynamic.individual_value_bytes().value())
                .map_err(|_| ReceiveFailure::ValueLimitExceeded)?,
            key_bytes: usize::try_from(dynamic.key_path_bytes().value())
                .map_err(|_| ReceiveFailure::ValueLimitExceeded)?,
        })
    }
}

pub(crate) fn increment(value: &mut usize, limit: usize) -> Result<(), ReceiveFailure> {
    *value = value
        .checked_add(1)
        .filter(|next| *next <= limit)
        .ok_or(ReceiveFailure::ValueLimitExceeded)?;
    Ok(())
}
