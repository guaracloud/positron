use std::cmp::Ordering;

use super::{
    DomainFailure, ValidatedAttributeValue, ValidatedAttributeValueInner, ValidatedKeyValue,
    checked_decoded_add,
};

impl Ord for ValidatedKeyValue {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key
            .cmp(&other.key)
            .then_with(|| self.value.cmp(&other.value))
    }
}

impl PartialOrd for ValidatedKeyValue {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl ValidatedAttributeValue {
    /// Returns the bounded canonical logical encoding length used for output and digests.
    pub fn canonical_encoded_size_bytes(&self) -> Result<usize, DomainFailure> {
        match &self.inner {
            ValidatedAttributeValueInner::Null => Ok(1),
            ValidatedAttributeValueInner::Boolean(_) => Ok(2),
            ValidatedAttributeValueInner::SignedInteger(_)
            | ValidatedAttributeValueInner::FloatingPointBits(_) => Ok(9),
            ValidatedAttributeValueInner::String(value) => canonical_sequence_size(value.len()),
            ValidatedAttributeValueInner::Bytes(value) => canonical_sequence_size(value.len()),
            ValidatedAttributeValueInner::Array(values) => values
                .iter()
                .try_fold(canonical_prefix_size(values.len())?, |total, value| {
                    checked_decoded_add(total, value.canonical_encoded_size_bytes()?)
                }),
            ValidatedAttributeValueInner::KeyValueList(values) => {
                values
                    .iter()
                    .try_fold(canonical_prefix_size(values.len())?, |total, entry| {
                        let total = checked_decoded_add(total, 8)?;
                        let total = checked_decoded_add(total, entry.key.len())?;
                        checked_decoded_add(total, entry.value.canonical_encoded_size_bytes()?)
                    })
            },
        }
    }

    /// Appends one self-delimiting canonical logical value without changing its native type.
    pub fn append_canonical_encoding(&self, output: &mut Vec<u8>) -> Result<(), DomainFailure> {
        let encoded = self.canonical_encoded_size_bytes()?;
        output
            .try_reserve_exact(encoded)
            .map_err(|_| DomainFailure::allocation_unavailable())?;
        self.append_canonical_encoding_reserved(output)?;
        Ok(())
    }

    /// Returns the bounded length of the order-preserving comparison encoding.
    ///
    /// This encoding is distinct from logical digest/output encoding: bytewise
    /// lexicographic comparison is exactly equivalent to this value's canonical
    /// [`Ord`] implementation.
    pub fn comparison_encoded_size_bytes(&self) -> Result<usize, DomainFailure> {
        match &self.inner {
            ValidatedAttributeValueInner::Null => Ok(1),
            ValidatedAttributeValueInner::Boolean(_) => Ok(2),
            ValidatedAttributeValueInner::SignedInteger(_)
            | ValidatedAttributeValueInner::FloatingPointBits(_) => Ok(9),
            ValidatedAttributeValueInner::String(value) => comparison_sequence_size(value.len()),
            ValidatedAttributeValueInner::Bytes(value) => comparison_sequence_size(value.len()),
            ValidatedAttributeValueInner::Array(values) => {
                values.iter().try_fold(2_usize, |total, value| {
                    let total = checked_decoded_add(total, 1)?;
                    checked_decoded_add(total, value.comparison_encoded_size_bytes()?)
                })
            },
            ValidatedAttributeValueInner::KeyValueList(values) => {
                values.iter().try_fold(2_usize, |total, entry| {
                    let total = checked_decoded_add(total, 1)?;
                    let total = checked_decoded_add(
                        total,
                        comparison_bare_sequence_size(entry.key.len())?,
                    )?;
                    checked_decoded_add(total, entry.value.comparison_encoded_size_bytes()?)
                })
            },
        }
    }

    /// Appends the domain-owned order-preserving comparison encoding.
    pub fn append_comparison_encoding(&self, output: &mut Vec<u8>) -> Result<(), DomainFailure> {
        let encoded = self.comparison_encoded_size_bytes()?;
        output
            .try_reserve_exact(encoded)
            .map_err(|_| DomainFailure::allocation_unavailable())?;
        self.visit_comparison_encoding(&mut |bytes| {
            output.extend_from_slice(bytes);
            Ok::<(), DomainFailure>(())
        })
    }

    /// Visits the domain-owned order-preserving comparison encoding without allocating.
    ///
    /// Callers can meter, cancel, or stream each bounded encoding fragment while this
    /// domain type remains the single authority for native-value comparison bytes.
    pub fn visit_comparison_encoding<E>(
        &self,
        visit: &mut impl FnMut(&[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        match &self.inner {
            ValidatedAttributeValueInner::Null => visit(&[0]),
            ValidatedAttributeValueInner::Boolean(value) => visit(&[1, u8::from(*value)]),
            ValidatedAttributeValueInner::SignedInteger(value) => {
                visit(&[2])?;
                let ordered = (*value as u64) ^ (1_u64 << 63);
                visit(&ordered.to_be_bytes())
            },
            ValidatedAttributeValueInner::FloatingPointBits(bits) => {
                visit(&[3])?;
                let ordered = if bits & (1_u64 << 63) == 0 {
                    bits ^ (1_u64 << 63)
                } else {
                    !bits
                };
                visit(&ordered.to_be_bytes())
            },
            ValidatedAttributeValueInner::String(value) => {
                visit(&[4])?;
                visit_comparison_sequence(value.as_bytes(), visit)
            },
            ValidatedAttributeValueInner::Bytes(value) => {
                visit(&[5])?;
                visit_comparison_sequence(value, visit)
            },
            ValidatedAttributeValueInner::Array(values) => {
                visit(&[6])?;
                for value in values {
                    visit(&[1])?;
                    value.visit_comparison_encoding(visit)?;
                }
                visit(&[0])
            },
            ValidatedAttributeValueInner::KeyValueList(values) => {
                visit(&[7])?;
                for entry in values {
                    visit(&[1])?;
                    visit_comparison_sequence(entry.key.as_bytes(), visit)?;
                    entry.value.visit_comparison_encoding(visit)?;
                }
                visit(&[0])
            },
        }
    }

    /// Returns only heap storage retained beyond the value's owning inline slot.
    pub fn retained_heap_bytes(&self) -> Result<usize, DomainFailure> {
        const ARRAY_VALUE_SLOT_BYTES: usize = 64;
        const KEY_VALUE_ENTRY_SLOT_BYTES: usize = 96;

        match &self.inner {
            ValidatedAttributeValueInner::Null
            | ValidatedAttributeValueInner::Boolean(_)
            | ValidatedAttributeValueInner::SignedInteger(_)
            | ValidatedAttributeValueInner::FloatingPointBits(_) => Ok(0),
            ValidatedAttributeValueInner::String(value) => Ok(value.len()),
            ValidatedAttributeValueInner::Bytes(value) => Ok(value.len()),
            ValidatedAttributeValueInner::Array(values) => {
                values.iter().try_fold(0_usize, |total, value| {
                    let total = checked_decoded_add(total, ARRAY_VALUE_SLOT_BYTES)?;
                    checked_decoded_add(total, value.retained_heap_bytes()?)
                })
            },
            ValidatedAttributeValueInner::KeyValueList(values) => {
                values.iter().try_fold(0_usize, |total, entry| {
                    let total = checked_decoded_add(total, KEY_VALUE_ENTRY_SLOT_BYTES)?;
                    let total = checked_decoded_add(total, entry.key.len())?;
                    checked_decoded_add(total, entry.value.retained_heap_bytes()?)
                })
            },
        }
    }

    fn append_canonical_encoding_reserved(
        &self,
        output: &mut Vec<u8>,
    ) -> Result<(), DomainFailure> {
        match &self.inner {
            ValidatedAttributeValueInner::Null => output.push(0),
            ValidatedAttributeValueInner::Boolean(value) => {
                output.push(1);
                output.push(u8::from(*value));
            },
            ValidatedAttributeValueInner::SignedInteger(value) => {
                output.push(2);
                output.extend_from_slice(&value.to_be_bytes());
            },
            ValidatedAttributeValueInner::FloatingPointBits(value) => {
                output.push(3);
                output.extend_from_slice(&value.to_be_bytes());
            },
            ValidatedAttributeValueInner::String(value) => {
                output.push(4);
                append_length(output, value.len())?;
                output.extend_from_slice(value.as_bytes());
            },
            ValidatedAttributeValueInner::Bytes(value) => {
                output.push(5);
                append_length(output, value.len())?;
                output.extend_from_slice(value);
            },
            ValidatedAttributeValueInner::Array(values) => {
                output.push(6);
                append_length(output, values.len())?;
                for value in values {
                    value.append_canonical_encoding_reserved(output)?;
                }
            },
            ValidatedAttributeValueInner::KeyValueList(values) => {
                output.push(7);
                append_length(output, values.len())?;
                for entry in values {
                    append_length(output, entry.key.len())?;
                    output.extend_from_slice(entry.key.as_bytes());
                    entry.value.append_canonical_encoding_reserved(output)?;
                }
            },
        }
        Ok(())
    }
}

impl Ord for ValidatedAttributeValue {
    fn cmp(&self, other: &Self) -> Ordering {
        match (&self.inner, &other.inner) {
            (ValidatedAttributeValueInner::Null, ValidatedAttributeValueInner::Null) => {
                Ordering::Equal
            },
            (
                ValidatedAttributeValueInner::Boolean(left),
                ValidatedAttributeValueInner::Boolean(right),
            ) => left.cmp(right),
            (
                ValidatedAttributeValueInner::SignedInteger(left),
                ValidatedAttributeValueInner::SignedInteger(right),
            ) => left.cmp(right),
            (
                ValidatedAttributeValueInner::FloatingPointBits(left),
                ValidatedAttributeValueInner::FloatingPointBits(right),
            ) => f64::from_bits(*left).total_cmp(&f64::from_bits(*right)),
            (
                ValidatedAttributeValueInner::String(left),
                ValidatedAttributeValueInner::String(right),
            ) => left.cmp(right),
            (
                ValidatedAttributeValueInner::Bytes(left),
                ValidatedAttributeValueInner::Bytes(right),
            ) => left.cmp(right),
            (
                ValidatedAttributeValueInner::Array(left),
                ValidatedAttributeValueInner::Array(right),
            ) => left.cmp(right),
            (
                ValidatedAttributeValueInner::KeyValueList(left),
                ValidatedAttributeValueInner::KeyValueList(right),
            ) => left.cmp(right),
            _ => self.kind().cmp(&other.kind()),
        }
    }
}

impl PartialOrd for ValidatedAttributeValue {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn comparison_sequence_size(length: usize) -> Result<usize, DomainFailure> {
    checked_decoded_add(1, comparison_bare_sequence_size(length)?)
}

fn comparison_bare_sequence_size(length: usize) -> Result<usize, DomainFailure> {
    length
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(1))
        .ok_or_else(DomainFailure::value_limit_exceeded)
}

pub(super) fn visit_comparison_sequence<E>(
    bytes: &[u8],
    visit: &mut impl FnMut(&[u8]) -> Result<(), E>,
) -> Result<(), E> {
    for byte in bytes {
        visit(&[1, *byte])?;
    }
    visit(&[0])
}

fn canonical_sequence_size(payload: usize) -> Result<usize, DomainFailure> {
    checked_decoded_add(canonical_prefix_size(payload)?, payload)
}

fn canonical_prefix_size(length: usize) -> Result<usize, DomainFailure> {
    u64::try_from(length).map_err(|_| DomainFailure::value_limit_exceeded())?;
    Ok(9)
}

fn append_length(output: &mut Vec<u8>, length: usize) -> Result<(), DomainFailure> {
    let length = u64::try_from(length).map_err(|_| DomainFailure::value_limit_exceeded())?;
    output.extend_from_slice(&length.to_be_bytes());
    Ok(())
}
