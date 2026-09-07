use super::{
    AttributeValueKind, MarkerAction, ValidatedAttributeValue, ValidatedAttributeValueInner,
};
use crate::value::{NativeValueObserver, ObservedValueFailure};

impl ValidatedAttributeValue {
    /// Returns the payload-free redaction/removal action, if present.
    #[must_use]
    pub const fn marker_action(&self) -> Option<MarkerAction> {
        match &self.inner {
            ValidatedAttributeValueInner::Marker(marker) => Some(marker.action()),
            ValidatedAttributeValueInner::Null
            | ValidatedAttributeValueInner::Boolean(_)
            | ValidatedAttributeValueInner::SignedInteger(_)
            | ValidatedAttributeValueInner::FloatingPointBits(_)
            | ValidatedAttributeValueInner::String(_)
            | ValidatedAttributeValueInner::Bytes(_)
            | ValidatedAttributeValueInner::Array(_)
            | ValidatedAttributeValueInner::KeyValueList(_)
            | ValidatedAttributeValueInner::Truncated { .. } => None,
        }
    }

    /// Returns the original native kind carried by a redaction/removal marker.
    #[must_use]
    pub const fn marker_original_kind(&self) -> Option<AttributeValueKind> {
        match &self.inner {
            ValidatedAttributeValueInner::Marker(marker) => Some(marker.original_kind()),
            ValidatedAttributeValueInner::Null
            | ValidatedAttributeValueInner::Boolean(_)
            | ValidatedAttributeValueInner::SignedInteger(_)
            | ValidatedAttributeValueInner::FloatingPointBits(_)
            | ValidatedAttributeValueInner::String(_)
            | ValidatedAttributeValueInner::Bytes(_)
            | ValidatedAttributeValueInner::Array(_)
            | ValidatedAttributeValueInner::KeyValueList(_)
            | ValidatedAttributeValueInner::Truncated { .. } => None,
        }
    }

    /// Returns truncation evidence, if present.
    #[must_use]
    pub const fn truncation_action(&self) -> Option<MarkerAction> {
        match &self.inner {
            ValidatedAttributeValueInner::Truncated { action, .. } => Some(*action),
            ValidatedAttributeValueInner::Null
            | ValidatedAttributeValueInner::Boolean(_)
            | ValidatedAttributeValueInner::SignedInteger(_)
            | ValidatedAttributeValueInner::FloatingPointBits(_)
            | ValidatedAttributeValueInner::String(_)
            | ValidatedAttributeValueInner::Bytes(_)
            | ValidatedAttributeValueInner::Array(_)
            | ValidatedAttributeValueInner::KeyValueList(_)
            | ValidatedAttributeValueInner::Marker(_) => None,
        }
    }

    /// Returns the sanitized native value retained by a truncation marker.
    #[must_use]
    pub fn truncated_value(&self) -> Option<&ValidatedAttributeValue> {
        match &self.inner {
            ValidatedAttributeValueInner::Truncated { value, .. } => Some(value),
            ValidatedAttributeValueInner::Null
            | ValidatedAttributeValueInner::Boolean(_)
            | ValidatedAttributeValueInner::SignedInteger(_)
            | ValidatedAttributeValueInner::FloatingPointBits(_)
            | ValidatedAttributeValueInner::String(_)
            | ValidatedAttributeValueInner::Bytes(_)
            | ValidatedAttributeValueInner::Array(_)
            | ValidatedAttributeValueInner::KeyValueList(_)
            | ValidatedAttributeValueInner::Marker(_) => None,
        }
    }

    /// Returns whether this is a payload-free marker.
    #[must_use]
    pub const fn is_marker(&self) -> bool {
        matches!(self.inner, ValidatedAttributeValueInner::Marker(_))
    }

    /// Returns whether this value or any retained descendant is a policy marker.
    #[must_use]
    pub fn contains_marker(&self) -> bool {
        match &self.inner {
            ValidatedAttributeValueInner::Marker(_) => true,
            ValidatedAttributeValueInner::Truncated { value, .. } => value.contains_marker(),
            ValidatedAttributeValueInner::Array(values) =>
                values.iter().any(ValidatedAttributeValue::contains_marker),
            ValidatedAttributeValueInner::KeyValueList(values) => values
                .iter()
                .any(|entry| entry.value.contains_marker()),
            ValidatedAttributeValueInner::Null
            | ValidatedAttributeValueInner::Boolean(_)
            | ValidatedAttributeValueInner::SignedInteger(_)
            | ValidatedAttributeValueInner::FloatingPointBits(_)
            | ValidatedAttributeValueInner::String(_)
            | ValidatedAttributeValueInner::Bytes(_) => false,
        }
    }

    /// Returns whether this value or a retained descendant records truncation,
    /// observing every structural node before it is visited.
    pub fn contains_truncation_observed<O: NativeValueObserver>(
        &self,
        observer: &mut O,
    ) -> Result<bool, ObservedValueFailure<O::Error>> {
        observer
            .observe_structure()
            .map_err(ObservedValueFailure::Observer)?;
        match &self.inner {
            ValidatedAttributeValueInner::Truncated { .. } => Ok(true),
            ValidatedAttributeValueInner::Array(values) => {
                for value in values {
                    if value.contains_truncation_observed(observer)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            },
            ValidatedAttributeValueInner::KeyValueList(values) => {
                for entry in values {
                    if entry.value.contains_truncation_observed(observer)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            },
            ValidatedAttributeValueInner::Marker(_)
            | ValidatedAttributeValueInner::Null
            | ValidatedAttributeValueInner::Boolean(_)
            | ValidatedAttributeValueInner::SignedInteger(_)
            | ValidatedAttributeValueInner::FloatingPointBits(_)
            | ValidatedAttributeValueInner::String(_)
            | ValidatedAttributeValueInner::Bytes(_) => Ok(false),
        }
    }

    /// Compares logical native payloads while excluding policy markers.
    /// Truncated values compare as their sanitized native value.
    #[must_use]
    pub fn equals_exact(&self, other: &Self) -> bool {
        match (&self.inner, &other.inner) {
            (ValidatedAttributeValueInner::Marker(_), _)
            | (_, ValidatedAttributeValueInner::Marker(_)) => false,
            (
                ValidatedAttributeValueInner::Truncated { value: left, .. },
                ValidatedAttributeValueInner::Truncated { value: right, .. },
            ) => left.equals_exact(right),
            (ValidatedAttributeValueInner::Truncated { value, .. }, _) => {
                value.equals_exact(other)
            },
            (_, ValidatedAttributeValueInner::Truncated { value, .. }) => {
                self.equals_exact(value)
            },
            (
                ValidatedAttributeValueInner::Array(left),
                ValidatedAttributeValueInner::Array(right),
            ) => {
                left.len() == right.len()
                    && left
                        .iter()
                        .zip(right)
                        .all(|(left, right)| left.equals_exact(right))
            },
            (
                ValidatedAttributeValueInner::KeyValueList(left),
                ValidatedAttributeValueInner::KeyValueList(right),
            ) => {
                left.len() == right.len()
                    && left.iter().zip(right).all(|(left, right)| {
                        left.key == right.key && left.value.equals_exact(&right.value)
                    })
            },
            _ => self == other,
        }
    }
}
