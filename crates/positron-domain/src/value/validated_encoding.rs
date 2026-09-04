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
        let mut observer = super::observed::UnobservedNativeValue;
        super::observed::remove_observation(
            self.canonical_encoded_size_bytes_observed(&mut observer),
        )
    }

    /// Appends one self-delimiting canonical logical value without changing its native type.
    pub fn append_canonical_encoding(&self, output: &mut Vec<u8>) -> Result<(), DomainFailure> {
        let encoded = self.canonical_encoded_size_bytes()?;
        output
            .try_reserve_exact(encoded)
            .map_err(|_| DomainFailure::allocation_unavailable())?;
        let mut observer = super::observed::UnobservedNativeValue;
        super::observed::remove_observation(
            self.visit_canonical_encoding_observed(&mut observer, &mut |bytes| {
                output.extend_from_slice(bytes)
            }),
        )
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
            ValidatedAttributeValueInner::Marker(_) => Ok(3),
            ValidatedAttributeValueInner::Truncated { value, .. } => {
                value.comparison_encoded_size_bytes()
            },
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
            ValidatedAttributeValueInner::Marker(marker) => visit(&[
                8,
                comparison_marker_action_tag(marker.action()),
                comparison_native_kind_tag(marker.original_kind()),
            ]),
            ValidatedAttributeValueInner::Truncated { value, .. } => {
                value.visit_comparison_encoding(visit)
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
            | ValidatedAttributeValueInner::FloatingPointBits(_)
            | ValidatedAttributeValueInner::Marker(_) => Ok(0),
            ValidatedAttributeValueInner::Truncated { value, .. } => value.retained_heap_bytes(),
            ValidatedAttributeValueInner::String(value) => Ok(value.capacity()),
            ValidatedAttributeValueInner::Bytes(value) => Ok(value.capacity()),
            ValidatedAttributeValueInner::Array(values) => {
                let retained = values
                    .capacity()
                    .checked_mul(ARRAY_VALUE_SLOT_BYTES)
                    .ok_or_else(DomainFailure::value_limit_exceeded)?;
                values.iter().try_fold(retained, |total, value| {
                    checked_decoded_add(total, value.retained_heap_bytes()?)
                })
            },
            ValidatedAttributeValueInner::KeyValueList(values) => {
                let retained = values
                    .capacity()
                    .checked_mul(KEY_VALUE_ENTRY_SLOT_BYTES)
                    .ok_or_else(DomainFailure::value_limit_exceeded)?;
                values.iter().try_fold(retained, |total, entry| {
                    let total = checked_decoded_add(total, entry.key.capacity())?;
                    checked_decoded_add(total, entry.value.retained_heap_bytes()?)
                })
            },
        }
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
            (
                ValidatedAttributeValueInner::Marker(left),
                ValidatedAttributeValueInner::Marker(right),
            ) => left
                .original_kind()
                .cmp(&right.original_kind())
                .then_with(|| left.action().cmp(&right.action())),
            (ValidatedAttributeValueInner::Truncated { value, .. }, _) => value.as_ref().cmp(other),
            (_, ValidatedAttributeValueInner::Truncated { value, .. }) => self.cmp(value.as_ref()),
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

fn comparison_marker_action_tag(action: super::MarkerAction) -> u8 {
    match action {
        super::MarkerAction::Removed => 0,
        super::MarkerAction::Redacted => 1,
        super::MarkerAction::TruncatedBytes => 2,
        super::MarkerAction::TruncatedElements => 3,
    }
}

fn comparison_native_kind_tag(kind: super::AttributeValueKind) -> u8 {
    match kind {
        super::AttributeValueKind::Null => 0,
        super::AttributeValueKind::Boolean => 1,
        super::AttributeValueKind::SignedInteger => 2,
        super::AttributeValueKind::FloatingPoint => 3,
        super::AttributeValueKind::String => 4,
        super::AttributeValueKind::Bytes => 5,
        super::AttributeValueKind::Array => 6,
        super::AttributeValueKind::KeyValueList => 7,
        super::AttributeValueKind::Marker => 0,
    }
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
