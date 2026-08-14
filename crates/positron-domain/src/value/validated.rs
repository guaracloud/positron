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
}

fn checked_decoded_add(left: usize, right: usize) -> Result<usize, DomainFailure> {
    left.checked_add(right)
        .ok_or_else(DomainFailure::value_limit_exceeded)
}
