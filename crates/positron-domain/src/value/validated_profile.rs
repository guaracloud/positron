use super::{
    ByteLimit, DomainFailure, ValidatedAttributeValue, ValidatedAttributeValueInner, ValueLimitSet,
    checked_decoded_add, exceeds_byte_limit, exceeds_collection_limit,
};

impl ValidatedAttributeValue {
    /// Revalidates this already-typed value under one possibly lowered profile.
    ///
    /// The traversal is allocation-free and remains the single authority for
    /// recursively checking retained validated values before profile transfer.
    pub(super) fn validate_against(
        &self,
        limits: ValueLimitSet,
        value_bytes: ByteLimit,
        remaining_depth: u16,
    ) -> Result<(), DomainFailure> {
        self.validated_size_against(limits, value_bytes, remaining_depth)
            .map(|_| ())
    }

    fn validated_size_against(
        &self,
        limits: ValueLimitSet,
        value_bytes: ByteLimit,
        remaining_depth: u16,
    ) -> Result<usize, DomainFailure> {
        let size = match &self.inner {
            ValidatedAttributeValueInner::Null => 0,
            ValidatedAttributeValueInner::Boolean(_) => 1,
            ValidatedAttributeValueInner::SignedInteger(_)
            | ValidatedAttributeValueInner::FloatingPointBits(_) => 8,
            ValidatedAttributeValueInner::String(value) => value.len(),
            ValidatedAttributeValueInner::Bytes(value) => value.len(),
            ValidatedAttributeValueInner::Array(values) => {
                let child_depth = child_depth(remaining_depth)?;
                if exceeds_collection_limit(values.len(), limits.dynamic_value().array_entries()) {
                    return Err(DomainFailure::value_limit_exceeded());
                }
                values.iter().try_fold(0_usize, |total, value| {
                    checked_decoded_add(
                        total,
                        value.validated_size_against(limits, value_bytes, child_depth)?,
                    )
                })?
            },
            ValidatedAttributeValueInner::KeyValueList(values) => {
                let child_depth = child_depth(remaining_depth)?;
                if exceeds_collection_limit(
                    values.len(),
                    limits.dynamic_value().key_value_list_entries(),
                ) {
                    return Err(DomainFailure::value_limit_exceeded());
                }
                values.iter().try_fold(0_usize, |total, entry| {
                    if entry.key.is_empty()
                        || exceeds_byte_limit(
                            entry.key.len(),
                            limits.dynamic_value().key_path_bytes(),
                        )
                    {
                        return Err(DomainFailure::value_limit_exceeded());
                    }
                    checked_decoded_add(
                        total,
                        entry
                            .value
                            .validated_size_against(limits, value_bytes, child_depth)?,
                    )
                })?
            },
        };
        if exceeds_byte_limit(size, value_bytes) {
            return Err(DomainFailure::value_limit_exceeded());
        }
        Ok(size)
    }
}

fn child_depth(remaining_depth: u16) -> Result<u16, DomainFailure> {
    remaining_depth
        .checked_sub(1)
        .ok_or_else(DomainFailure::value_limit_exceeded)
}
