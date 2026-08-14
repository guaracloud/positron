use crate::log_store::LogStoreFailure;
use crate::log_store::types::value_profile;

#[derive(Clone, Copy)]
pub(super) struct CodecLimits {
    pub(super) records: usize,
    pub(super) attribute_groups: usize,
    pub(super) occurrences: usize,
    pub(super) nesting_depth: u8,
    pub(super) body_bytes: usize,
    pub(super) value_bytes: usize,
    pub(super) key_bytes: usize,
    pub(super) array_entries: usize,
    pub(super) key_value_list_entries: usize,
}

impl CodecLimits {
    pub(super) fn release_1() -> Result<Self, LogStoreFailure> {
        let profile = value_profile().system_limits();
        let dynamic = profile.dynamic_value();
        let occurrences = to_usize(dynamic.attributes_per_namespace().value())?;
        let attribute_groups = occurrences
            .checked_mul(3)
            .ok_or_else(LogStoreFailure::invalid_input)?;
        Ok(Self {
            records: to_usize(profile.request().records().value())?,
            attribute_groups,
            occurrences,
            nesting_depth: u8::try_from(dynamic.nesting_depth().value())
                .map_err(|_| LogStoreFailure::invalid_input())?,
            body_bytes: to_usize(profile.record().log_body_bytes().value())?,
            value_bytes: to_usize(dynamic.individual_value_bytes().value())?,
            key_bytes: to_usize(dynamic.key_path_bytes().value())?,
            array_entries: to_usize(dynamic.array_entries().value())?,
            key_value_list_entries: to_usize(dynamic.key_value_list_entries().value())?,
        })
    }
}

fn to_usize(value: u32) -> Result<usize, LogStoreFailure> {
    usize::try_from(value).map_err(|_| LogStoreFailure::invalid_input())
}
