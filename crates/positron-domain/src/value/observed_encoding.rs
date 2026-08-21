use super::observed::{observe_payload, observe_structure};
use super::{
    AttributeNamespace, AttributeOccurrenceSet, DomainFailure, NATIVE_VALUE_PAYLOAD_CHUNK_BYTES,
    NativeValueObserver, ObservedValueFailure, ValidatedAttributeValue,
    ValidatedAttributeValueInner,
};

impl ValidatedAttributeValue {
    /// Returns canonical logical-output bytes while observing every component.
    pub fn canonical_encoded_size_bytes_observed<O: NativeValueObserver>(
        &self,
        observer: &mut O,
    ) -> Result<usize, ObservedValueFailure<O::Error>> {
        observe_structure(observer)?;
        match &self.inner {
            ValidatedAttributeValueInner::Null => Ok(1),
            ValidatedAttributeValueInner::Boolean(_) => Ok(2),
            ValidatedAttributeValueInner::SignedInteger(_)
            | ValidatedAttributeValueInner::FloatingPointBits(_) => Ok(9),
            ValidatedAttributeValueInner::String(value) => {
                observe_payload(value.as_bytes(), observer)?;
                canonical_sequence_size(value.len())
            },
            ValidatedAttributeValueInner::Bytes(value) => {
                observe_payload(value, observer)?;
                canonical_sequence_size(value.len())
            },
            ValidatedAttributeValueInner::Array(values) => {
                values
                    .iter()
                    .try_fold(canonical_prefix_size(values.len())?, |total, value| {
                        checked_add(
                            total,
                            value.canonical_encoded_size_bytes_observed(observer)?,
                        )
                    })
            },
            ValidatedAttributeValueInner::KeyValueList(values) => {
                values
                    .iter()
                    .try_fold(canonical_prefix_size(values.len())?, |total, entry| {
                        observe_structure(observer)?;
                        observe_payload(entry.key.as_bytes(), observer)?;
                        let total = checked_add(total, 8)?;
                        let total = checked_add(total, entry.key.len())?;
                        checked_add(
                            total,
                            entry
                                .value
                                .canonical_encoded_size_bytes_observed(observer)?,
                        )
                    })
            },
        }
    }

    /// Streams canonical logical-output bytes without materializing an encoding buffer.
    pub fn visit_canonical_encoding_observed<O: NativeValueObserver>(
        &self,
        observer: &mut O,
        visit: &mut impl FnMut(&[u8]),
    ) -> Result<(), ObservedValueFailure<O::Error>> {
        observe_structure(observer)?;
        match &self.inner {
            ValidatedAttributeValueInner::Null => visit(&[0]),
            ValidatedAttributeValueInner::Boolean(value) => visit(&[1, u8::from(*value)]),
            ValidatedAttributeValueInner::SignedInteger(value) => {
                visit(&[2]);
                visit(&value.to_be_bytes());
            },
            ValidatedAttributeValueInner::FloatingPointBits(value) => {
                visit(&[3]);
                visit(&value.to_be_bytes());
            },
            ValidatedAttributeValueInner::String(value) => {
                visit(&[4]);
                visit_length(value.len(), visit)?;
                visit_observed_payload(value.as_bytes(), observer, visit)?;
            },
            ValidatedAttributeValueInner::Bytes(value) => {
                visit(&[5]);
                visit_length(value.len(), visit)?;
                visit_observed_payload(value, observer, visit)?;
            },
            ValidatedAttributeValueInner::Array(values) => {
                visit(&[6]);
                visit_length(values.len(), visit)?;
                for value in values {
                    value.visit_canonical_encoding_observed(observer, visit)?;
                }
            },
            ValidatedAttributeValueInner::KeyValueList(values) => {
                visit(&[7]);
                visit_length(values.len(), visit)?;
                for entry in values {
                    observe_structure(observer)?;
                    visit_length(entry.key.len(), visit)?;
                    visit_observed_payload(entry.key.as_bytes(), observer, visit)?;
                    entry
                        .value
                        .visit_canonical_encoding_observed(observer, visit)?;
                }
            },
        }
        Ok(())
    }
}

impl AttributeOccurrenceSet {
    /// Returns canonical occurrence-set output bytes with observed native traversal.
    pub fn canonical_encoded_size_bytes_observed<O: NativeValueObserver>(
        &self,
        observer: &mut O,
    ) -> Result<usize, ObservedValueFailure<O::Error>> {
        observe_structure(observer)?;
        observe_payload(self.key().as_bytes(), observer)?;
        let mut total = checked_add(17, self.key().len())?;
        for index in 0..self.len() {
            observe_structure(observer)?;
            let value = self
                .occurrence(index)
                .ok_or_else(DomainFailure::value_limit_exceeded)?;
            total = checked_add(
                total,
                value.canonical_encoded_size_bytes_observed(observer)?,
            )?;
        }
        Ok(total)
    }

    /// Streams the canonical occurrence-set digest encoding with observed traversal.
    pub fn visit_canonical_encoding_observed<O: NativeValueObserver>(
        &self,
        observer: &mut O,
        visit: &mut impl FnMut(&[u8]),
    ) -> Result<(), ObservedValueFailure<O::Error>> {
        observe_structure(observer)?;
        visit(&[match self.namespace() {
            AttributeNamespace::Stream => 0,
            AttributeNamespace::Resource => 1,
            AttributeNamespace::InstrumentationScope => 2,
            AttributeNamespace::Record => 3,
        }]);
        visit_length(self.key().len(), visit)?;
        visit_observed_payload(self.key().as_bytes(), observer, visit)?;
        visit_length(self.len(), visit)?;
        for index in 0..self.len() {
            observe_structure(observer)?;
            let value = self
                .occurrence(index)
                .ok_or_else(DomainFailure::value_limit_exceeded)?;
            value.visit_canonical_encoding_observed(observer, visit)?;
        }
        Ok(())
    }
}

fn checked_add<E>(left: usize, right: usize) -> Result<usize, ObservedValueFailure<E>> {
    left.checked_add(right)
        .ok_or_else(|| DomainFailure::value_limit_exceeded().into())
}

fn canonical_sequence_size<E>(payload: usize) -> Result<usize, ObservedValueFailure<E>> {
    checked_add(canonical_prefix_size(payload)?, payload)
}

fn canonical_prefix_size<E>(length: usize) -> Result<usize, ObservedValueFailure<E>> {
    u64::try_from(length).map_err(|_| DomainFailure::value_limit_exceeded())?;
    Ok(9)
}

fn visit_length<E>(
    length: usize,
    visit: &mut impl FnMut(&[u8]),
) -> Result<(), ObservedValueFailure<E>> {
    let length = u64::try_from(length).map_err(|_| DomainFailure::value_limit_exceeded())?;
    visit(&length.to_be_bytes());
    Ok(())
}

fn visit_observed_payload<O: NativeValueObserver>(
    payload: &[u8],
    observer: &mut O,
    visit: &mut impl FnMut(&[u8]),
) -> Result<(), ObservedValueFailure<O::Error>> {
    for chunk in payload.chunks(NATIVE_VALUE_PAYLOAD_CHUNK_BYTES) {
        observer
            .observe_payload(chunk)
            .map_err(ObservedValueFailure::Observer)?;
        visit(chunk);
    }
    Ok(())
}
