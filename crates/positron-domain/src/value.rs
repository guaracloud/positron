//! Bounded native dynamic attribute values.

use crate::outcome::{DomainFailure, FailureSource};

/// The native namespace that owns one dynamic attribute occurrence.
///
/// Resource, instrumentation-scope, and record attributes remain separate even
/// when their textual paths match. This taxonomy is not a wire representation
/// and never allows an attribute to shadow a signal-defined intrinsic field.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AttributeNamespace {
    /// Attributes attached to the telemetry resource.
    Resource,
    /// Attributes attached to the instrumentation scope.
    InstrumentationScope,
    /// Attributes attached to the individual signal record.
    Record,
}

impl AttributeNamespace {
    /// Returns the stable lowercase native namespace name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Resource => "resource",
            Self::InstrumentationScope => "instrumentation-scope",
            Self::Record => "record",
        }
    }
}

/// A non-zero byte bound used by a Value Limit Profile.
///
/// This native unit prevents byte counts from being confused with collection
/// entries or nesting depth. Configuration owns source loading and system
/// ceilings; this type makes no wire or durable serialization promise.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ByteLimit(u32);

impl ByteLimit {
    /// Creates a non-zero byte limit.
    pub fn new(value: u32) -> Result<Self, DomainFailure> {
        if value == 0 {
            return Err(DomainFailure::invalid_limit(FailureSource::ValueLimit));
        }
        Ok(Self(value))
    }

    /// Returns the exact bounded byte count.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }
}

/// A non-zero collection-entry bound used by a Value Limit Profile.
///
/// This unit remains distinct from bytes and nesting so a caller cannot use an
/// allocation byte budget as an attribute or array count by accident.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CollectionLimit(u32);

impl CollectionLimit {
    /// Creates a non-zero collection-entry limit.
    pub fn new(value: u32) -> Result<Self, DomainFailure> {
        if value == 0 {
            return Err(DomainFailure::invalid_limit(FailureSource::ValueLimit));
        }
        Ok(Self(value))
    }

    /// Returns the exact bounded entry count.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }
}

/// A non-zero nesting-depth bound used by a Value Limit Profile.
///
/// It is intentionally a separate unit from byte and collection limits. A
/// receiver must apply it before recursive decode or construction.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NestingLimit(u16);

impl NestingLimit {
    /// Creates a non-zero nesting-depth limit.
    pub fn new(value: u16) -> Result<Self, DomainFailure> {
        if value == 0 {
            return Err(DomainFailure::invalid_limit(FailureSource::ValueLimit));
        }
        Ok(Self(value))
    }

    /// Returns the exact bounded nesting depth.
    #[must_use]
    pub const fn value(self) -> u16 {
        self.0
    }
}

/// One coherent set of typed dynamic-value limits.
///
/// A set contains the byte, collection, and nesting bounds needed by the
/// current M0 native dynamic-value constructors. The configuration owner later
/// supplies complete system ceilings and may add further limits without using
/// wire or provider types in this module.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValueLimitSet {
    key_bytes: ByteLimit,
    value_bytes: ByteLimit,
    collection_entries: CollectionLimit,
    nesting_depth: NestingLimit,
}

impl ValueLimitSet {
    /// Groups already-valid typed limits into one candidate limit set.
    #[must_use]
    pub const fn new(
        key_bytes: ByteLimit,
        value_bytes: ByteLimit,
        collection_entries: CollectionLimit,
        nesting_depth: NestingLimit,
    ) -> Self {
        Self {
            key_bytes,
            value_bytes,
            collection_entries,
            nesting_depth,
        }
    }

    /// Returns the maximum bytes in one dynamic attribute key.
    #[must_use]
    pub const fn key_bytes(self) -> ByteLimit {
        self.key_bytes
    }

    /// Returns the maximum bytes in one dynamic value payload.
    #[must_use]
    pub const fn value_bytes(self) -> ByteLimit {
        self.value_bytes
    }

    /// Returns the maximum entries in one bounded dynamic collection.
    #[must_use]
    pub const fn collection_entries(self) -> CollectionLimit {
        self.collection_entries
    }

    /// Returns the maximum permitted nested collection depth.
    #[must_use]
    pub const fn nesting_depth(self) -> NestingLimit {
        self.nesting_depth
    }

    const fn exceeds(self, system: Self) -> bool {
        self.key_bytes.value() > system.key_bytes.value()
            || self.value_bytes.value() > system.value_bytes.value()
            || self.collection_entries.value() > system.collection_entries.value()
            || self.nesting_depth.value() > system.nesting_depth.value()
    }
}

/// A pre-validation system and optional tenant value-limit profile.
///
/// This is deliberately a pre-validation state: it can represent an invalid
/// tenant increase so configuration and policy owners must call `validate`
/// before passing limits to any native value construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValueLimitProfileCandidate {
    system: ValueLimitSet,
    tenant: Option<ValueLimitSet>,
}

impl ValueLimitProfileCandidate {
    /// Builds a candidate profile that still requires system-ceiling validation.
    #[must_use]
    pub const fn new(system: ValueLimitSet, tenant: Option<ValueLimitSet>) -> Self {
        Self { system, tenant }
    }

    /// Produces the post-validation profile only when tenant values do not raise ceilings.
    pub fn validate(self) -> Result<ValueLimitProfile, DomainFailure> {
        if let Some(tenant) = self.tenant
            && tenant.exceeds(self.system)
        {
            return Err(DomainFailure::limit_exceeds_system());
        }
        Ok(ValueLimitProfile {
            system: self.system,
            tenant: self.tenant,
        })
    }
}

/// A system-ceiling-respecting profile safe for native value validation.
///
/// There is no public unchecked constructor. The only transition from a
/// candidate is `ValueLimitProfileCandidate::validate`, which preserves every
/// system ceiling and allows tenant settings only to lower effective bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValueLimitProfile {
    system: ValueLimitSet,
    tenant: Option<ValueLimitSet>,
}

impl ValueLimitProfile {
    /// Returns the complete configured system-ceiling limit set.
    #[must_use]
    pub const fn system_limits(self) -> ValueLimitSet {
        self.system
    }

    /// Returns the optional tenant-lowered limit set.
    #[must_use]
    pub const fn tenant_limits(self) -> Option<ValueLimitSet> {
        self.tenant
    }

    /// Returns the effective limit set after applying the tenant lowering.
    #[must_use]
    pub const fn effective_limits(self) -> ValueLimitSet {
        match self.tenant {
            Some(tenant) => tenant,
            None => self.system,
        }
    }
}

/// An unvalidated native dynamic attribute value.
///
/// This pre-validation state may retain caller-supplied text that exceeds the
/// eventual profile. It must be converted through an occurrence-set candidate
/// and `validate` before a Signal Store, index, or query type observes it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CandidateAttributeValue {
    /// The explicit native null value.
    Null,
    /// A boolean value.
    Boolean(bool),
    /// A signed integer is already typed but still belongs to a pre-validation tree.
    SignedInteger(i64),
    /// An IEEE 754 floating-point bit pattern, retained without normalization.
    FloatingPointBits(u64),
    /// A string value whose byte length requires profile validation.
    String(String),
    /// An opaque byte value whose length requires profile validation.
    Bytes(Vec<u8>),
    /// A recursively typed array whose entries and nesting require validation.
    Array(Vec<CandidateAttributeValue>),
    /// An ordered key/value list whose keys and values require validation.
    KeyValueList(Vec<CandidateKeyValue>),
}

/// One unvalidated key/value entry in a native dynamic value list.
///
/// Duplicate keys and their order are retained. The entry remains pre-
/// validation until its containing `CandidateAttributeValue` is validated with
/// a `ValueLimitProfile`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateKeyValue {
    key: String,
    value: CandidateAttributeValue,
}

impl CandidateKeyValue {
    /// Builds one ordered pre-validation key/value entry.
    #[must_use]
    pub fn new(key: String, value: CandidateAttributeValue) -> Self {
        Self { key, value }
    }
}

impl CandidateAttributeValue {
    /// Builds an unvalidated explicit null value.
    #[must_use]
    pub const fn null() -> Self {
        Self::Null
    }

    /// Builds an unvalidated boolean value.
    #[must_use]
    pub const fn boolean(value: bool) -> Self {
        Self::Boolean(value)
    }

    /// Builds an unvalidated signed integer value.
    #[must_use]
    pub const fn signed_integer(value: i64) -> Self {
        Self::SignedInteger(value)
    }

    /// Builds an unvalidated exact IEEE 754 floating-point bit pattern.
    #[must_use]
    pub const fn floating_point_bits(value: u64) -> Self {
        Self::FloatingPointBits(value)
    }

    /// Builds an unvalidated string value that will be bounded during validation.
    #[must_use]
    pub fn string(value: String) -> Self {
        Self::String(value)
    }

    /// Builds an unvalidated opaque byte value that will be bounded during validation.
    #[must_use]
    pub fn bytes(value: Vec<u8>) -> Self {
        Self::Bytes(value)
    }

    /// Builds an unvalidated recursively typed array.
    #[must_use]
    pub fn array(value: Vec<CandidateAttributeValue>) -> Self {
        Self::Array(value)
    }

    /// Builds an unvalidated ordered key/value list.
    #[must_use]
    pub fn key_value_list(value: Vec<CandidateKeyValue>) -> Self {
        Self::KeyValueList(value)
    }
}

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
}

/// A pre-validation ordered set of repeated occurrences for one attribute key.
///
/// Duplicate occurrences are intentionally preserved in input order. This
/// candidate may be too large or contain over-limit text, so it is not safe for
/// Signal Store, catalog, or query use until `validate` returns the later state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttributeOccurrenceSetCandidate {
    namespace: AttributeNamespace,
    key: String,
    occurrences: Vec<CandidateAttributeValue>,
}

impl AttributeOccurrenceSetCandidate {
    /// Builds the pre-validation representation of one repeated attribute key.
    #[must_use]
    pub fn new(
        namespace: AttributeNamespace,
        key: String,
        occurrences: Vec<CandidateAttributeValue>,
    ) -> Self {
        Self {
            namespace,
            key,
            occurrences,
        }
    }

    /// Validates bounds and produces the later invariant-bearing occurrence set.
    pub fn validate(
        self,
        profile: ValueLimitProfile,
    ) -> Result<AttributeOccurrenceSet, DomainFailure> {
        let limits = profile.effective_limits();
        if exceeds_byte_limit(self.key.len(), limits.key_bytes())
            || self.occurrences.is_empty()
            || exceeds_collection_limit(self.occurrences.len(), limits.collection_entries())
        {
            return Err(DomainFailure::value_limit_exceeded());
        }
        let mut validated = Vec::new();
        validated
            .try_reserve_exact(self.occurrences.len())
            .map_err(|_| DomainFailure::allocation_unavailable())?;
        for candidate in self.occurrences {
            validated.push(validate_attribute_value(
                candidate,
                limits,
                limits.nesting_depth().value(),
            )?);
        }
        Ok(AttributeOccurrenceSet {
            namespace: self.namespace,
            key: self.key,
            occurrences: validated,
        })
    }
}

/// A profile-bounded ordered set of repeated typed values for one attribute key.
///
/// This is the post-validation state. It preserves namespace, key, occurrence
/// order, and typed variants; callers cannot construct it unchecked or use
/// indexing without an explicit optional result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttributeOccurrenceSet {
    namespace: AttributeNamespace,
    key: String,
    occurrences: Vec<ValidatedAttributeValue>,
}

impl AttributeOccurrenceSet {
    /// Returns the namespace that owns this occurrence set.
    #[must_use]
    pub const fn namespace(&self) -> AttributeNamespace {
        self.namespace
    }

    /// Returns the validated attribute key.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Returns the finite number of preserved occurrences.
    #[must_use]
    pub fn len(&self) -> usize {
        self.occurrences.len()
    }

    /// Returns whether this checked occurrence set contains no values.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.occurrences.is_empty()
    }

    /// Returns one occurrence by explicit optional index.
    #[must_use]
    pub fn occurrence(&self, index: usize) -> Option<&ValidatedAttributeValue> {
        self.occurrences.get(index)
    }
}

fn validate_attribute_value(
    candidate: CandidateAttributeValue,
    limits: ValueLimitSet,
    remaining_depth: u16,
) -> Result<ValidatedAttributeValue, DomainFailure> {
    let inner = match candidate {
        CandidateAttributeValue::Null => ValidatedAttributeValueInner::Null,
        CandidateAttributeValue::Boolean(value) => ValidatedAttributeValueInner::Boolean(value),
        CandidateAttributeValue::SignedInteger(value) => {
            ValidatedAttributeValueInner::SignedInteger(value)
        },
        CandidateAttributeValue::FloatingPointBits(value) => {
            ValidatedAttributeValueInner::FloatingPointBits(value)
        },
        CandidateAttributeValue::String(value) => {
            if exceeds_byte_limit(value.len(), limits.value_bytes()) {
                return Err(DomainFailure::value_limit_exceeded());
            }
            ValidatedAttributeValueInner::String(value)
        },
        CandidateAttributeValue::Bytes(value) => {
            if exceeds_byte_limit(value.len(), limits.value_bytes()) {
                return Err(DomainFailure::value_limit_exceeded());
            }
            ValidatedAttributeValueInner::Bytes(value)
        },
        CandidateAttributeValue::Array(values) => ValidatedAttributeValueInner::Array(
            validate_attribute_array(values, limits, remaining_depth)?,
        ),
        CandidateAttributeValue::KeyValueList(values) => {
            ValidatedAttributeValueInner::KeyValueList(validate_key_value_list(
                values,
                limits,
                remaining_depth,
            )?)
        },
    };
    Ok(ValidatedAttributeValue { inner })
}

fn validate_attribute_array(
    values: Vec<CandidateAttributeValue>,
    limits: ValueLimitSet,
    remaining_depth: u16,
) -> Result<Vec<ValidatedAttributeValue>, DomainFailure> {
    let Some(child_depth) = remaining_depth.checked_sub(1) else {
        return Err(DomainFailure::value_limit_exceeded());
    };
    if exceeds_collection_limit(values.len(), limits.collection_entries()) {
        return Err(DomainFailure::value_limit_exceeded());
    }
    let mut validated = Vec::new();
    validated
        .try_reserve_exact(values.len())
        .map_err(|_| DomainFailure::allocation_unavailable())?;
    for value in values {
        validated.push(validate_attribute_value(value, limits, child_depth)?);
    }
    Ok(validated)
}

fn validate_key_value_list(
    values: Vec<CandidateKeyValue>,
    limits: ValueLimitSet,
    remaining_depth: u16,
) -> Result<Vec<ValidatedKeyValue>, DomainFailure> {
    let Some(child_depth) = remaining_depth.checked_sub(1) else {
        return Err(DomainFailure::value_limit_exceeded());
    };
    if exceeds_collection_limit(values.len(), limits.collection_entries()) {
        return Err(DomainFailure::value_limit_exceeded());
    }
    let mut validated = Vec::new();
    validated
        .try_reserve_exact(values.len())
        .map_err(|_| DomainFailure::allocation_unavailable())?;
    for CandidateKeyValue { key, value } in values {
        if key.is_empty() || exceeds_byte_limit(key.len(), limits.key_bytes()) {
            return Err(DomainFailure::value_limit_exceeded());
        }
        validated.push(ValidatedKeyValue {
            key,
            value: validate_attribute_value(value, limits, child_depth)?,
        });
    }
    Ok(validated)
}

fn exceeds_byte_limit(actual: usize, limit: ByteLimit) -> bool {
    match usize::try_from(limit.value()) {
        Ok(limit) => actual > limit,
        Err(_) => false,
    }
}

fn exceeds_collection_limit(actual: usize, limit: CollectionLimit) -> bool {
    match usize::try_from(limit.value()) {
        Ok(limit) => actual > limit,
        Err(_) => false,
    }
}
