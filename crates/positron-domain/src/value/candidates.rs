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
        let limits = profile.effective_limits();
        candidate_shape(
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

fn candidate_shape(
    candidate: &CandidateAttributeValue,
    limits: ValueLimitSet,
    value_bytes: ByteLimit,
    remaining_depth: u16,
) -> Result<usize, DomainFailure> {
    let size = match candidate {
        CandidateAttributeValue::Null => 0,
        CandidateAttributeValue::Boolean(_) => 1,
        CandidateAttributeValue::SignedInteger(_)
        | CandidateAttributeValue::FloatingPointBits(_) => 8,
        CandidateAttributeValue::String(value) => value.len(),
        CandidateAttributeValue::Bytes(value) => value.len(),
        CandidateAttributeValue::Array(values) => {
            let child_depth = remaining_depth
                .checked_sub(1)
                .ok_or_else(DomainFailure::value_limit_exceeded)?;
            if exceeds_collection_limit(values.len(), limits.dynamic_value().array_entries()) {
                return Err(DomainFailure::value_limit_exceeded());
            }
            values.iter().try_fold(0_usize, |total, value| {
                checked_decoded_add(total, candidate_shape(value, limits, value_bytes, child_depth)?)
            })?
        },
        CandidateAttributeValue::KeyValueList(values) => {
            let child_depth = remaining_depth
                .checked_sub(1)
                .ok_or_else(DomainFailure::value_limit_exceeded)?;
            if exceeds_collection_limit(
                values.len(),
                limits.dynamic_value().key_value_list_entries(),
            ) {
                return Err(DomainFailure::value_limit_exceeded());
            }
            values.iter().try_fold(0_usize, |total, entry| {
                if entry.key.is_empty()
                    || exceeds_byte_limit(entry.key.len(), limits.dynamic_value().key_path_bytes())
                {
                    return Err(DomainFailure::value_limit_exceeded());
                }
                let total = checked_decoded_add(total, entry.key.len())?;
                checked_decoded_add(
                    total,
                    candidate_shape(&entry.value, limits, value_bytes, child_depth)?,
                )
            })?
        },
    };
    if exceeds_byte_limit(size, value_bytes) {
        return Err(DomainFailure::value_limit_exceeded());
    }
    Ok(size)
}
