/// The policy transformation represented by a typed value marker.
///
/// Redaction and removal markers carry no source payload. Truncation markers
/// wrap only the already-sanitized native value and remain query-visible.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum MarkerAction {
    Removed,
    Redacted,
    TruncatedBytes,
    TruncatedElements,
}

/// The bounded, payload-free identity of a policy-created redaction marker.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RedactionMarker {
    original_kind: AttributeValueKind,
    action: MarkerAction,
}

impl RedactionMarker {
    /// Creates a marker identity. Candidate markers are rejected at the
    /// policy boundary unless they were created by that policy transition.
    #[must_use]
    pub const fn new(original_kind: AttributeValueKind, action: MarkerAction) -> Self {
        Self {
            original_kind,
            action,
        }
    }

    #[must_use]
    pub const fn original_kind(self) -> AttributeValueKind {
        self.original_kind
    }

    #[must_use]
    pub const fn action(self) -> MarkerAction {
        self.action
    }

    pub(crate) const fn is_valid(self) -> bool {
        !matches!(self.original_kind, AttributeValueKind::Marker)
            && matches!(self.action, MarkerAction::Removed | MarkerAction::Redacted)
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
    /// A payload-free policy marker. Live producer candidates are rejected by
    /// the policy transition before this value can reach native storage.
    Marker(RedactionMarker),
    /// A policy marker retaining only a sanitized same-kind value.
    Truncated {
        value: Box<CandidateAttributeValue>,
        action: MarkerAction,
    },
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

    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    #[must_use]
    pub fn value(&self) -> &CandidateAttributeValue {
        &self.value
    }

    #[must_use]
    pub fn value_mut(&mut self) -> &mut CandidateAttributeValue {
        &mut self.value
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

    /// Checks the recursive shape without allocating a validated copy.
    ///
    /// Decoded protocol messages use this transition before policy evaluation,
    /// because their wire preflight has already been bypassed. The consuming
    /// validation methods remain the authority for producing native values;
    /// this method only prevents an over-limit candidate tree from reaching a
    /// policy or native materialization boundary.
    pub fn validate_shape(&self, profile: ValueLimitProfile) -> Result<(), DomainFailure> {
        self.validate_shape_detailed(profile)
            .map_err(|_| DomainFailure::value_limit_exceeded())
    }

    /// Checks the recursive shape and retains one bounded semantic violation
    /// when a dynamic-value limit is exceeded.
    ///
    /// This borrowed transition is the allocation-free domain seam used by
    /// policy-aware adapters before they materialize a replacement value.
    pub fn validate_shape_detailed(
        &self,
        profile: ValueLimitProfile,
    ) -> Result<(), CandidateShapeFailure> {
        let limits = profile.effective_limits();
        candidate_shape::validate(
            self,
            limits,
            limits.dynamic_value().individual_value_bytes(),
            limits.dynamic_value().nesting_depth().value(),
        )
        .map(|_| ())
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

    /// Builds a payload-free redaction or removal marker.
    #[must_use]
    pub const fn redaction_marker(
        original_kind: AttributeValueKind,
        action: MarkerAction,
    ) -> Self {
        Self::Marker(RedactionMarker::new(original_kind, action))
    }

    /// Builds a truncation marker around a sanitized native value.
    #[must_use]
    pub fn truncated(value: Self, action: MarkerAction) -> Self {
        Self::Truncated {
            value: Box::new(value),
            action,
        }
    }

    /// Returns the redaction/removal action when this is a payload-free marker.
    #[must_use]
    pub const fn marker_action(&self) -> Option<MarkerAction> {
        match self {
            Self::Marker(marker) => Some(marker.action()),
            Self::Null
            | Self::Boolean(_)
            | Self::SignedInteger(_)
            | Self::FloatingPointBits(_)
            | Self::String(_)
            | Self::Bytes(_)
            | Self::Array(_)
            | Self::KeyValueList(_)
            | Self::Truncated { .. } => None,
        }
    }

    /// Returns the original native kind when this is a payload-free marker.
    #[must_use]
    pub const fn marker_original_kind(&self) -> Option<AttributeValueKind> {
        match self {
            Self::Marker(marker) => Some(marker.original_kind()),
            Self::Null
            | Self::Boolean(_)
            | Self::SignedInteger(_)
            | Self::FloatingPointBits(_)
            | Self::String(_)
            | Self::Bytes(_)
            | Self::Array(_)
            | Self::KeyValueList(_)
            | Self::Truncated { .. } => None,
        }
    }

    /// Returns truncation evidence, if present.
    #[must_use]
    pub const fn truncation_action(&self) -> Option<MarkerAction> {
        match self {
            Self::Truncated { action, .. } => Some(*action),
            Self::Null
            | Self::Boolean(_)
            | Self::SignedInteger(_)
            | Self::FloatingPointBits(_)
            | Self::String(_)
            | Self::Bytes(_)
            | Self::Array(_)
            | Self::KeyValueList(_)
            | Self::Marker(_) => None,
        }
    }

    /// Returns text from an ordinary or sanitized truncated string candidate.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            Self::Truncated { value, .. } => value.as_str(),
            Self::Null
            | Self::Boolean(_)
            | Self::SignedInteger(_)
            | Self::FloatingPointBits(_)
            | Self::Bytes(_)
            | Self::Array(_)
            | Self::KeyValueList(_)
            | Self::Marker(_) => None,
        }
    }

    /// Returns whether this candidate contains any policy-created marker.
    pub fn contains_policy_marker(&self) -> bool {
        match self {
            Self::Marker(_) | Self::Truncated { .. } => true,
            Self::Array(values) => values.iter().any(Self::contains_policy_marker),
            Self::KeyValueList(values) => values
                .iter()
                .any(|entry| entry.value().contains_policy_marker()),
            Self::Null
            | Self::Boolean(_)
            | Self::SignedInteger(_)
            | Self::FloatingPointBits(_)
            | Self::String(_)
            | Self::Bytes(_) => false,
        }
    }

    /// Validates one dynamic attribute value under the profile's individual-value ceiling.
    pub fn validate_attribute(
        self,
        profile: ValueLimitProfile,
    ) -> Result<ValidatedAttributeValue, DomainFailure> {
        let limits = profile.effective_limits();
        validate_attribute_value(
            self,
            limits,
            limits.dynamic_value().individual_value_bytes(),
            limits.dynamic_value().nesting_depth().value(),
        )
    }

    /// Validates one log body under the same profile's distinct body ceiling.
    pub fn validate_log_body(
        self,
        profile: ValueLimitProfile,
    ) -> Result<ValidatedAttributeValue, DomainFailure> {
        let limits = profile.effective_limits();
        validate_attribute_value(
            self,
            limits,
            limits.record().log_body_bytes(),
            limits.dynamic_value().nesting_depth().value(),
        )
    }

    /// Validates one log body while observing every recursive validation pass.
    pub fn validate_log_body_observed<O: NativeValueObserver>(
        self,
        profile: ValueLimitProfile,
        observer: &mut O,
    ) -> Result<ValidatedAttributeValue, ObservedValueFailure<O::Error>> {
        self.validate_log_body_observed_with_facts(profile, observer)
            .map(ObservedValueTransfer::into_value)
    }

    /// Validates a log body and returns its transfer facts from the same pass.
    pub fn validate_log_body_observed_with_facts<O: NativeValueObserver>(
        self,
        profile: ValueLimitProfile,
        observer: &mut O,
    ) -> Result<ObservedValueTransfer, ObservedValueFailure<O::Error>> {
        let limits = profile.effective_limits();
        validate_attribute_value_observed_with_facts(
            self,
            limits,
            limits.record().log_body_bytes(),
            limits.dynamic_value().nesting_depth().value(),
            observer,
        )
    }

    /// Validates an attribute value while exposing every bounded output allocation.
    pub fn validate_attribute_observed_with_facts<O: NativeValueObserver>(
        self,
        profile: ValueLimitProfile,
        observer: &mut O,
    ) -> Result<ObservedValueTransfer, ObservedValueFailure<O::Error>> {
        let limits = profile.effective_limits();
        validate_attribute_value_observed_with_facts(
            self,
            limits,
            limits.dynamic_value().individual_value_bytes(),
            limits.dynamic_value().nesting_depth().value(),
            observer,
        )
    }
}

fn candidate_native_kind(value: &CandidateAttributeValue) -> Option<AttributeValueKind> {
    match value {
        CandidateAttributeValue::Null => Some(AttributeValueKind::Null),
        CandidateAttributeValue::Boolean(_) => Some(AttributeValueKind::Boolean),
        CandidateAttributeValue::SignedInteger(_) => Some(AttributeValueKind::SignedInteger),
        CandidateAttributeValue::FloatingPointBits(_) => Some(AttributeValueKind::FloatingPoint),
        CandidateAttributeValue::String(_) => Some(AttributeValueKind::String),
        CandidateAttributeValue::Bytes(_) => Some(AttributeValueKind::Bytes),
        CandidateAttributeValue::Array(_) => Some(AttributeValueKind::Array),
        CandidateAttributeValue::KeyValueList(_) => Some(AttributeValueKind::KeyValueList),
        CandidateAttributeValue::Marker(marker) => Some(marker.original_kind()),
        CandidateAttributeValue::Truncated { value, .. } => candidate_native_kind(value),
    }
}

const fn truncation_action_valid(action: MarkerAction, kind: AttributeValueKind) -> bool {
    matches!(
        (action, kind),
        (MarkerAction::TruncatedBytes, AttributeValueKind::String | AttributeValueKind::Bytes)
            | (
                MarkerAction::TruncatedElements,
                AttributeValueKind::Array | AttributeValueKind::KeyValueList
            )
    )
}
