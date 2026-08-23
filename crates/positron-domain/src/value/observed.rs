use super::{
    DomainFailure, ValidatedAttributeValue, ValidatedAttributeValueInner, ValidatedKeyValue,
};

/// Maximum raw native payload observed between cooperative cancellation polls.
pub const NATIVE_VALUE_PAYLOAD_CHUNK_BYTES: usize = 1_024;

/// Query-agnostic observation of bounded native-value traversal work.
///
/// Structural work is reported before it is performed. Raw scalar and key
/// payloads are reported in bounded chunks so callers can poll cancellation
/// without treating byte volume as CPU work.
pub trait NativeValueObserver {
    type Error;

    fn observe_structure(&mut self) -> Result<(), Self::Error>;
    fn observe_payload(&mut self, payload: &[u8]) -> Result<(), Self::Error>;

    /// Admits canonical output capacity before a validated collection is
    /// allocated while its candidate values remain live.
    fn observe_allocation(&mut self, _bytes: usize) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Releases an output-capacity admission when validation cannot finish.
    fn release_allocation(&mut self, _bytes: usize) -> Result<(), Self::Error> {
        Ok(())
    }
}

pub(super) struct UnobservedNativeValue;

impl NativeValueObserver for UnobservedNativeValue {
    type Error = core::convert::Infallible;

    fn observe_structure(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn observe_payload(&mut self, _payload: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }
}

pub(super) fn remove_observation<T>(
    result: Result<T, ObservedValueFailure<core::convert::Infallible>>,
) -> Result<T, DomainFailure> {
    match result {
        Ok(value) => Ok(value),
        Err(ObservedValueFailure::Domain(failure)) => Err(failure),
        Err(ObservedValueFailure::Observer(never)) => match never {},
    }
}

/// Distinguishes invariant/domain failures from caller observation failures.
#[derive(Debug, Eq, PartialEq)]
pub enum ObservedValueFailure<E> {
    Domain(DomainFailure),
    Observer(E),
}

/// Validated value plus the bounded facts needed to transfer it between
/// domain and query ownership. The facts are produced during validation so a
/// caller does not need to traverse the value again merely to size it.
#[derive(Debug, Eq, PartialEq)]
pub struct ObservedValueTransfer {
    pub(super) value: ValidatedAttributeValue,
    pub(super) value_size_bytes: usize,
    pub(super) retained_heap_bytes: usize,
    pub(super) allocation_bytes: usize,
}

impl ObservedValueTransfer {
    pub(super) const fn new(
        value: ValidatedAttributeValue,
        value_size_bytes: usize,
        retained_heap_bytes: usize,
        allocation_bytes: usize,
    ) -> Self {
        Self {
            value,
            value_size_bytes,
            retained_heap_bytes,
            allocation_bytes,
        }
    }

    /// Returns the validated value while transferring ownership to the caller.
    #[must_use]
    pub fn into_value(self) -> ValidatedAttributeValue {
        self.value
    }

    /// Returns the profile-transfer value size measured during validation.
    #[must_use]
    pub const fn value_size_bytes(&self) -> usize {
        self.value_size_bytes
    }

    /// Returns retained heap bytes measured during validation.
    #[must_use]
    pub const fn retained_heap_bytes(&self) -> usize {
        self.retained_heap_bytes
    }

    pub(super) const fn allocation_bytes(&self) -> usize {
        self.allocation_bytes
    }

    /// Borrows the validated value without starting another traversal.
    #[must_use]
    pub const fn value(&self) -> &ValidatedAttributeValue {
        &self.value
    }
}

impl<E> From<DomainFailure> for ObservedValueFailure<E> {
    fn from(failure: DomainFailure) -> Self {
        Self::Domain(failure)
    }
}

impl ValidatedAttributeValue {
    /// Compares two native values exactly while observing every visited component.
    pub fn equals_observed<O: NativeValueObserver>(
        &self,
        other: &Self,
        observer: &mut O,
    ) -> Result<bool, ObservedValueFailure<O::Error>> {
        observe_structure(observer)?;
        match (&self.inner, &other.inner) {
            (ValidatedAttributeValueInner::Null, ValidatedAttributeValueInner::Null) => Ok(true),
            (
                ValidatedAttributeValueInner::Boolean(left),
                ValidatedAttributeValueInner::Boolean(right),
            ) => Ok(left == right),
            (
                ValidatedAttributeValueInner::SignedInteger(left),
                ValidatedAttributeValueInner::SignedInteger(right),
            ) => Ok(left == right),
            (
                ValidatedAttributeValueInner::FloatingPointBits(left),
                ValidatedAttributeValueInner::FloatingPointBits(right),
            ) => Ok(left == right),
            (
                ValidatedAttributeValueInner::String(left),
                ValidatedAttributeValueInner::String(right),
            ) => observed_bytes_equal(left.as_bytes(), right.as_bytes(), observer),
            (
                ValidatedAttributeValueInner::Bytes(left),
                ValidatedAttributeValueInner::Bytes(right),
            ) => observed_bytes_equal(left, right, observer),
            (
                ValidatedAttributeValueInner::Array(left),
                ValidatedAttributeValueInner::Array(right),
            ) => observed_values_equal(left, right, observer),
            (
                ValidatedAttributeValueInner::KeyValueList(left),
                ValidatedAttributeValueInner::KeyValueList(right),
            ) => observed_entries_equal(left, right, observer),
            _ => Ok(false),
        }
    }

    /// Returns retained heap bytes while observing every sizing operation.
    pub fn retained_heap_bytes_observed<O: NativeValueObserver>(
        &self,
        observer: &mut O,
    ) -> Result<usize, ObservedValueFailure<O::Error>> {
        const ARRAY_VALUE_SLOT_BYTES: usize = 64;
        const KEY_VALUE_ENTRY_SLOT_BYTES: usize = 96;

        observe_structure(observer)?;
        match &self.inner {
            ValidatedAttributeValueInner::Null
            | ValidatedAttributeValueInner::Boolean(_)
            | ValidatedAttributeValueInner::SignedInteger(_)
            | ValidatedAttributeValueInner::FloatingPointBits(_) => Ok(0),
            ValidatedAttributeValueInner::String(value) => {
                observe_payload(value.as_bytes(), observer)?;
                Ok(value.len())
            },
            ValidatedAttributeValueInner::Bytes(value) => {
                observe_payload(value, observer)?;
                Ok(value.len())
            },
            ValidatedAttributeValueInner::Array(values) => {
                values.iter().try_fold(0_usize, |total, value| {
                    observe_structure(observer)?;
                    let total = checked_add(total, ARRAY_VALUE_SLOT_BYTES)?;
                    checked_add(total, value.retained_heap_bytes_observed(observer)?)
                })
            },
            ValidatedAttributeValueInner::KeyValueList(values) => {
                values.iter().try_fold(0_usize, |total, entry| {
                    observe_structure(observer)?;
                    observe_payload(entry.key.as_bytes(), observer)?;
                    let total = checked_add(total, KEY_VALUE_ENTRY_SLOT_BYTES)?;
                    let total = checked_add(total, entry.key.len())?;
                    checked_add(total, entry.value.retained_heap_bytes_observed(observer)?)
                })
            },
        }
    }

    /// Fallibly clones after caller-owned memory admission, observing all allocations and copies.
    pub fn try_clone_observed<O: NativeValueObserver>(
        &self,
        observer: &mut O,
    ) -> Result<Self, ObservedValueFailure<O::Error>> {
        observe_structure(observer)?;
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
                observe_payload(value.as_bytes(), observer)?;
                ValidatedAttributeValueInner::String(super::try_string(value)?)
            },
            ValidatedAttributeValueInner::Bytes(value) => {
                observe_payload(value, observer)?;
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
                    observe_structure(observer)?;
                    cloned.push(value.try_clone_observed(observer)?);
                }
                ValidatedAttributeValueInner::Array(cloned)
            },
            ValidatedAttributeValueInner::KeyValueList(values) => {
                let mut cloned = Vec::new();
                cloned
                    .try_reserve_exact(values.len())
                    .map_err(|_| DomainFailure::allocation_unavailable())?;
                for entry in values {
                    observe_structure(observer)?;
                    observe_payload(entry.key.as_bytes(), observer)?;
                    cloned.push(ValidatedKeyValue {
                        key: super::try_string(&entry.key)?,
                        value: entry.value.try_clone_observed(observer)?,
                    });
                }
                ValidatedAttributeValueInner::KeyValueList(cloned)
            },
        };
        Ok(Self { inner })
    }
}

fn observed_values_equal<O: NativeValueObserver>(
    left: &[ValidatedAttributeValue],
    right: &[ValidatedAttributeValue],
    observer: &mut O,
) -> Result<bool, ObservedValueFailure<O::Error>> {
    if left.len() != right.len() {
        return Ok(false);
    }
    for (left, right) in left.iter().zip(right) {
        observe_structure(observer)?;
        if !left.equals_observed(right, observer)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn observed_entries_equal<O: NativeValueObserver>(
    left: &[ValidatedKeyValue],
    right: &[ValidatedKeyValue],
    observer: &mut O,
) -> Result<bool, ObservedValueFailure<O::Error>> {
    if left.len() != right.len() {
        return Ok(false);
    }
    for (left, right) in left.iter().zip(right) {
        observe_structure(observer)?;
        if !observed_bytes_equal(left.key.as_bytes(), right.key.as_bytes(), observer)?
            || !left.value.equals_observed(&right.value, observer)?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn observed_bytes_equal<O: NativeValueObserver>(
    left: &[u8],
    right: &[u8],
    observer: &mut O,
) -> Result<bool, ObservedValueFailure<O::Error>> {
    observe_payload(left, observer)?;
    observe_payload(right, observer)?;
    Ok(left == right)
}

pub(super) fn observe_structure<O: NativeValueObserver>(
    observer: &mut O,
) -> Result<(), ObservedValueFailure<O::Error>> {
    observer
        .observe_structure()
        .map_err(ObservedValueFailure::Observer)
}

pub(super) fn observe_payload<O: NativeValueObserver>(
    payload: &[u8],
    observer: &mut O,
) -> Result<(), ObservedValueFailure<O::Error>> {
    for chunk in payload.chunks(NATIVE_VALUE_PAYLOAD_CHUNK_BYTES) {
        observer
            .observe_payload(chunk)
            .map_err(ObservedValueFailure::Observer)?;
    }
    Ok(())
}

fn checked_add<E>(left: usize, right: usize) -> Result<usize, ObservedValueFailure<E>> {
    left.checked_add(right)
        .ok_or_else(|| DomainFailure::value_limit_exceeded().into())
}
