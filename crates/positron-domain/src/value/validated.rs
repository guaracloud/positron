/// The type of a validated dynamic attribute value.
///
/// The variants remain distinct: no implicit conversion treats a textual
/// `"42"` as the numeric value `42`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AttributeValueKind {
    /// The explicit null value.
    Null,
    /// A boolean value.
    Boolean,
    /// A signed integer value.
    SignedInteger,
    /// An IEEE 754 floating-point bit pattern.
    FloatingPoint,
    /// A UTF-8 string value.
    String,
    /// An opaque byte value.
    Bytes,
    /// A recursively typed array.
    Array,
    /// An ordered key/value list.
    KeyValueList,
}
/// A profile-bounded typed dynamic attribute value.
///
/// Its constructor is private: callers receive it only after the corresponding
/// `AttributeOccurrenceSetCandidate` validates namespace, key, occurrence
/// count, and value size. Wire and durable serialization remain outside this
/// module.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedAttributeValue {
    inner: ValidatedAttributeValueInner,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ValidatedAttributeValueInner {
    Null,
    Boolean(bool),
    SignedInteger(i64),
    FloatingPointBits(u64),
    String(String),
    Bytes(Vec<u8>),
    Array(Vec<ValidatedAttributeValue>),
    KeyValueList(Vec<ValidatedKeyValue>),
}

/// A profile-bounded ordered key/value entry.
///
/// It retains the original key and typed value without last-write-wins
/// collapse. Its fields remain private so only validation constructs it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedKeyValue {
    key: String,
    value: ValidatedAttributeValue,
}

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

impl ValidatedKeyValue {
    /// Returns the checked key text.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Returns the checked typed value.
    #[must_use]
    pub fn value(&self) -> &ValidatedAttributeValue {
        &self.value
    }
}

impl ValidatedAttributeValue {
    /// Fallibly clones a previously bounded value without an unchecked heap allocation.
    pub fn try_clone(&self) -> Result<Self, DomainFailure> {
        let inner = match &self.inner {
            ValidatedAttributeValueInner::Null => ValidatedAttributeValueInner::Null,
            ValidatedAttributeValueInner::Boolean(value) => {
                ValidatedAttributeValueInner::Boolean(*value)
            },
            ValidatedAttributeValueInner::SignedInteger(value) => {
                ValidatedAttributeValueInner::SignedInteger(*value)
            },
            ValidatedAttributeValueInner::FloatingPointBits(value) => {
                ValidatedAttributeValueInner::FloatingPointBits(*value)
            },
            ValidatedAttributeValueInner::String(value) => {
                ValidatedAttributeValueInner::String(try_string(value)?)
            },
            ValidatedAttributeValueInner::Bytes(value) => {
                let mut cloned = Vec::new();
                cloned
                    .try_reserve_exact(value.len())
                    .map_err(|_| DomainFailure::allocation_unavailable())?;
                cloned.extend_from_slice(value);
                ValidatedAttributeValueInner::Bytes(cloned)
            },
            ValidatedAttributeValueInner::Array(values) => {
                let mut cloned = Vec::new();
                cloned
                    .try_reserve_exact(values.len())
                    .map_err(|_| DomainFailure::allocation_unavailable())?;
                for value in values {
                    cloned.push(value.try_clone()?);
                }
                ValidatedAttributeValueInner::Array(cloned)
            },
            ValidatedAttributeValueInner::KeyValueList(values) => {
                let mut cloned = Vec::new();
                cloned
                    .try_reserve_exact(values.len())
                    .map_err(|_| DomainFailure::allocation_unavailable())?;
                for entry in values {
                    cloned.push(ValidatedKeyValue {
                        key: try_string(&entry.key)?,
                        value: entry.value.try_clone()?,
                    });
                }
                ValidatedAttributeValueInner::KeyValueList(cloned)
            },
        };
        Ok(Self { inner })
    }

    /// Returns the preserved native value kind.
    #[must_use]
    pub const fn kind(&self) -> AttributeValueKind {
        match &self.inner {
            ValidatedAttributeValueInner::Null => AttributeValueKind::Null,
            ValidatedAttributeValueInner::Boolean(_) => AttributeValueKind::Boolean,
            ValidatedAttributeValueInner::SignedInteger(_) => AttributeValueKind::SignedInteger,
            ValidatedAttributeValueInner::FloatingPointBits(_) => AttributeValueKind::FloatingPoint,
            ValidatedAttributeValueInner::String(_) => AttributeValueKind::String,
            ValidatedAttributeValueInner::Bytes(_) => AttributeValueKind::Bytes,
            ValidatedAttributeValueInner::Array(_) => AttributeValueKind::Array,
            ValidatedAttributeValueInner::KeyValueList(_) => AttributeValueKind::KeyValueList,
        }
    }

    /// Returns the signed integer only when this value retains that exact type.
    #[must_use]
    pub const fn as_signed_integer(&self) -> Option<i64> {
        match &self.inner {
            ValidatedAttributeValueInner::Null
            | ValidatedAttributeValueInner::Boolean(_)
            | ValidatedAttributeValueInner::FloatingPointBits(_)
            | ValidatedAttributeValueInner::String(_)
            | ValidatedAttributeValueInner::Bytes(_)
            | ValidatedAttributeValueInner::Array(_)
            | ValidatedAttributeValueInner::KeyValueList(_) => None,
            ValidatedAttributeValueInner::SignedInteger(value) => Some(*value),
        }
    }

    /// Returns whether this is the explicit native null value.
    #[must_use]
    pub const fn is_null(&self) -> bool {
        matches!(self.inner, ValidatedAttributeValueInner::Null)
    }

    /// Returns the boolean only when this value retains that exact type.
    #[must_use]
    pub const fn as_boolean(&self) -> Option<bool> {
        match &self.inner {
            ValidatedAttributeValueInner::Boolean(value) => Some(*value),
            ValidatedAttributeValueInner::Null
            | ValidatedAttributeValueInner::SignedInteger(_)
            | ValidatedAttributeValueInner::FloatingPointBits(_)
            | ValidatedAttributeValueInner::String(_)
            | ValidatedAttributeValueInner::Bytes(_)
            | ValidatedAttributeValueInner::Array(_)
            | ValidatedAttributeValueInner::KeyValueList(_) => None,
        }
    }

    /// Returns the exact IEEE 754 bits only when this value is floating point.
    #[must_use]
    pub const fn as_floating_point_bits(&self) -> Option<u64> {
        match &self.inner {
            ValidatedAttributeValueInner::FloatingPointBits(value) => Some(*value),
            ValidatedAttributeValueInner::Null
            | ValidatedAttributeValueInner::Boolean(_)
            | ValidatedAttributeValueInner::SignedInteger(_)
            | ValidatedAttributeValueInner::String(_)
            | ValidatedAttributeValueInner::Bytes(_)
            | ValidatedAttributeValueInner::Array(_)
            | ValidatedAttributeValueInner::KeyValueList(_) => None,
        }
    }

    /// Returns the text only when this value retains the string type.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match &self.inner {
            ValidatedAttributeValueInner::Null
            | ValidatedAttributeValueInner::Boolean(_)
            | ValidatedAttributeValueInner::SignedInteger(_)
            | ValidatedAttributeValueInner::FloatingPointBits(_)
            | ValidatedAttributeValueInner::Bytes(_)
            | ValidatedAttributeValueInner::Array(_)
            | ValidatedAttributeValueInner::KeyValueList(_) => None,
            ValidatedAttributeValueInner::String(value) => Some(value),
        }
    }

    /// Returns bytes only when this value retains the opaque byte type.
    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match &self.inner {
            ValidatedAttributeValueInner::Bytes(value) => Some(value),
            ValidatedAttributeValueInner::Null
            | ValidatedAttributeValueInner::Boolean(_)
            | ValidatedAttributeValueInner::SignedInteger(_)
            | ValidatedAttributeValueInner::FloatingPointBits(_)
            | ValidatedAttributeValueInner::String(_)
            | ValidatedAttributeValueInner::Array(_)
            | ValidatedAttributeValueInner::KeyValueList(_) => None,
        }
    }

    /// Returns the finite child count only when this value is a validated array.
    #[must_use]
    pub fn array_len(&self) -> Option<usize> {
        match &self.inner {
            ValidatedAttributeValueInner::Array(values) => Some(values.len()),
            ValidatedAttributeValueInner::Null
            | ValidatedAttributeValueInner::Boolean(_)
            | ValidatedAttributeValueInner::SignedInteger(_)
            | ValidatedAttributeValueInner::FloatingPointBits(_)
            | ValidatedAttributeValueInner::String(_)
            | ValidatedAttributeValueInner::Bytes(_)
            | ValidatedAttributeValueInner::KeyValueList(_) => None,
        }
    }

    /// Returns one ordered array entry by explicit optional index.
    #[must_use]
    pub fn array_entry(&self, index: usize) -> Option<&ValidatedAttributeValue> {
        match &self.inner {
            ValidatedAttributeValueInner::Array(values) => values.get(index),
            ValidatedAttributeValueInner::Null
            | ValidatedAttributeValueInner::Boolean(_)
            | ValidatedAttributeValueInner::SignedInteger(_)
            | ValidatedAttributeValueInner::FloatingPointBits(_)
            | ValidatedAttributeValueInner::String(_)
            | ValidatedAttributeValueInner::Bytes(_)
            | ValidatedAttributeValueInner::KeyValueList(_) => None,
        }
    }

    /// Returns the finite entry count only when this value is a validated key/value list.
    #[must_use]
    pub fn key_value_list_len(&self) -> Option<usize> {
        match &self.inner {
            ValidatedAttributeValueInner::KeyValueList(values) => Some(values.len()),
            ValidatedAttributeValueInner::Null
            | ValidatedAttributeValueInner::Boolean(_)
            | ValidatedAttributeValueInner::SignedInteger(_)
            | ValidatedAttributeValueInner::FloatingPointBits(_)
            | ValidatedAttributeValueInner::String(_)
            | ValidatedAttributeValueInner::Bytes(_)
            | ValidatedAttributeValueInner::Array(_) => None,
        }
    }

    /// Returns one ordered key/value entry by explicit optional index.
    #[must_use]
    pub fn key_value_entry(&self, index: usize) -> Option<&ValidatedKeyValue> {
        match &self.inner {
            ValidatedAttributeValueInner::KeyValueList(values) => values.get(index),
            ValidatedAttributeValueInner::Null
            | ValidatedAttributeValueInner::Boolean(_)
            | ValidatedAttributeValueInner::SignedInteger(_)
            | ValidatedAttributeValueInner::FloatingPointBits(_)
            | ValidatedAttributeValueInner::String(_)
            | ValidatedAttributeValueInner::Bytes(_)
            | ValidatedAttributeValueInner::Array(_) => None,
        }
    }

    /// Returns the checked decoded payload bytes retained by this native value.
    pub fn decoded_size_bytes(&self) -> Result<usize, DomainFailure> {
        match &self.inner {
            ValidatedAttributeValueInner::Null => Ok(0),
            ValidatedAttributeValueInner::Boolean(_) => Ok(1),
            ValidatedAttributeValueInner::SignedInteger(_)
            | ValidatedAttributeValueInner::FloatingPointBits(_) => Ok(8),
            ValidatedAttributeValueInner::String(value) => Ok(value.len()),
            ValidatedAttributeValueInner::Bytes(value) => Ok(value.len()),
            ValidatedAttributeValueInner::Array(values) => {
                values.iter().try_fold(0_usize, |total, value| {
                    checked_decoded_add(total, value.decoded_size_bytes()?)
                })
            },
            ValidatedAttributeValueInner::KeyValueList(values) => {
                values.iter().try_fold(0_usize, |total, entry| {
                    let total = checked_decoded_add(total, entry.key.len())?;
                    checked_decoded_add(total, entry.value.decoded_size_bytes()?)
                })
            },
        }
    }

    /// Returns the bounded canonical logical encoding length used for output and digests.
    pub fn canonical_encoded_size_bytes(&self) -> Result<usize, DomainFailure> {
        match &self.inner {
            ValidatedAttributeValueInner::Null => Ok(1),
            ValidatedAttributeValueInner::Boolean(_) => Ok(2),
            ValidatedAttributeValueInner::SignedInteger(_)
            | ValidatedAttributeValueInner::FloatingPointBits(_) => Ok(9),
            ValidatedAttributeValueInner::String(value) => canonical_sequence_size(value.len()),
            ValidatedAttributeValueInner::Bytes(value) => canonical_sequence_size(value.len()),
            ValidatedAttributeValueInner::Array(values) => values.iter().try_fold(
                canonical_prefix_size(values.len())?,
                |total, value| {
                    checked_decoded_add(total, value.canonical_encoded_size_bytes()?)
                },
            ),
            ValidatedAttributeValueInner::KeyValueList(values) => values.iter().try_fold(
                canonical_prefix_size(values.len())?,
                |total, entry| {
                    let total = checked_decoded_add(total, 8)?;
                    let total = checked_decoded_add(total, entry.key.len())?;
                    checked_decoded_add(total, entry.value.canonical_encoded_size_bytes()?)
                },
            ),
        }
    }

    /// Appends one self-delimiting canonical logical value without changing its native type.
    pub fn append_canonical_encoding(
        &self,
        output: &mut Vec<u8>,
    ) -> Result<(), DomainFailure> {
        let encoded = self.canonical_encoded_size_bytes()?;
        output
            .try_reserve_exact(encoded)
            .map_err(|_| DomainFailure::allocation_unavailable())?;
        self.append_canonical_encoding_reserved(output)?;
        Ok(())
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
            ValidatedAttributeValueInner::Array(values) => values.iter().try_fold(
                0_usize,
                |total, value| {
                    let total = checked_decoded_add(total, ARRAY_VALUE_SLOT_BYTES)?;
                    checked_decoded_add(total, value.retained_heap_bytes()?)
                },
            ),
            ValidatedAttributeValueInner::KeyValueList(values) => values.iter().try_fold(
                0_usize,
                |total, entry| {
                    let total = checked_decoded_add(total, KEY_VALUE_ENTRY_SLOT_BYTES)?;
                    let total = checked_decoded_add(total, entry.key.len())?;
                    checked_decoded_add(total, entry.value.retained_heap_bytes()?)
                },
            ),
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

    pub(crate) fn value_size_bytes(&self) -> Result<usize, DomainFailure> {
        match &self.inner {
            ValidatedAttributeValueInner::Null => Ok(0),
            ValidatedAttributeValueInner::Boolean(_) => Ok(1),
            ValidatedAttributeValueInner::SignedInteger(_)
            | ValidatedAttributeValueInner::FloatingPointBits(_) => Ok(8),
            ValidatedAttributeValueInner::String(value) => Ok(value.len()),
            ValidatedAttributeValueInner::Bytes(value) => Ok(value.len()),
            ValidatedAttributeValueInner::Array(values) => {
                values.iter().try_fold(0_usize, |total, value| {
                    checked_decoded_add(total, value.value_size_bytes()?)
                })
            },
            ValidatedAttributeValueInner::KeyValueList(values) => {
                values.iter().try_fold(0_usize, |total, entry| {
                    checked_decoded_add(total, entry.value.value_size_bytes()?)
                })
            },
        }
    }
}

impl Ord for ValidatedAttributeValue {
    fn cmp(&self, other: &Self) -> Ordering {
        let kind = self.kind().cmp(&other.kind());
        if kind != Ordering::Equal {
            return kind;
        }
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
            _ => Ordering::Equal,
        }
    }
}

impl PartialOrd for ValidatedAttributeValue {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn try_string(value: &str) -> Result<String, DomainFailure> {
    let mut cloned = String::new();
    cloned
        .try_reserve_exact(value.len())
        .map_err(|_| DomainFailure::allocation_unavailable())?;
    cloned.push_str(value);
    Ok(cloned)
}

fn checked_decoded_add(left: usize, right: usize) -> Result<usize, DomainFailure> {
    left.checked_add(right)
        .ok_or_else(DomainFailure::value_limit_exceeded)
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
use std::cmp::Ordering;
