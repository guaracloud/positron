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
        if self.key.is_empty()
            || exceeds_byte_limit(self.key.len(), limits.dynamic_value().key_path_bytes())
            || self.occurrences.is_empty()
            || exceeds_collection_limit(
                self.occurrences.len(),
                limits.dynamic_value().attributes_per_namespace(),
            )
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
                limits.dynamic_value().individual_value_bytes(),
                limits.dynamic_value().nesting_depth().value(),
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
    /// Canonical bytes reserved for one projected occurrence slot.
    ///
    /// The charge deliberately exceeds the current private representation so query
    /// accounting is independent of allocator and enum layout details.
    pub const PROJECTED_OCCURRENCE_SLOT_BYTES: usize = 64;

    /// Builds a projected occurrence set from values that already passed this profile.
    pub fn from_validated(
        namespace: AttributeNamespace,
        key: String,
        occurrences: Vec<ValidatedAttributeValue>,
        profile: ValueLimitProfile,
    ) -> Result<Self, DomainFailure> {
        let limits = profile.effective_limits();
        if key.is_empty()
            || exceeds_byte_limit(key.len(), limits.dynamic_value().key_path_bytes())
            || occurrences.is_empty()
            || exceeds_collection_limit(
                occurrences.len(),
                limits.dynamic_value().attributes_per_namespace(),
            )
        {
            return Err(DomainFailure::value_limit_exceeded());
        }
        Ok(Self {
            namespace,
            key,
            occurrences,
        })
    }

    /// Fallibly clones this bounded occurrence set for retained store state.
    pub fn try_clone(&self) -> Result<Self, DomainFailure> {
        let mut key = String::new();
        key.try_reserve_exact(self.key.len())
            .map_err(|_| DomainFailure::allocation_unavailable())?;
        key.push_str(&self.key);
        let mut occurrences = Vec::new();
        occurrences
            .try_reserve_exact(self.occurrences.len())
            .map_err(|_| DomainFailure::allocation_unavailable())?;
        for occurrence in &self.occurrences {
            occurrences.push(occurrence.try_clone()?);
        }
        Ok(Self {
            namespace: self.namespace,
            key,
            occurrences,
        })
    }

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

    /// Returns the canonical retained bytes for one occurrence slot and value.
    pub fn retained_occurrence_bytes(
        value: &ValidatedAttributeValue,
    ) -> Result<usize, DomainFailure> {
        checked_decoded_add(
            std::mem::size_of::<ValidatedAttributeValue>(),
            value.retained_heap_bytes()?,
        )
    }

    /// Returns the canonical capacity charge for a projected occurrence vector.
    pub fn projected_occurrence_capacity_bytes(
        profile: ValueLimitProfile,
    ) -> Result<usize, DomainFailure> {
        let maximum = usize::try_from(
            profile
                .effective_limits()
                .dynamic_value()
                .attributes_per_namespace()
                .value(),
        )
        .map_err(|_| DomainFailure::value_limit_exceeded())?;
        maximum
            .checked_mul(Self::PROJECTED_OCCURRENCE_SLOT_BYTES)
            .ok_or_else(DomainFailure::value_limit_exceeded)
    }

    /// Returns the self-delimiting canonical logical encoding length.
    pub fn canonical_encoded_size_bytes(&self) -> Result<usize, DomainFailure> {
        self.occurrences.iter().try_fold(
            checked_decoded_add(17, self.key.len())?,
            |total, value| {
                checked_decoded_add(total, value.canonical_encoded_size_bytes()?)
            },
        )
    }

    /// Visits the domain-owned order-preserving occurrence-set encoding.
    pub fn visit_comparison_encoding<E>(
        &self,
        visit: &mut impl FnMut(&[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        visit(&[namespace_tag(self.namespace)])?;
        visit_comparison_sequence(self.key.as_bytes(), visit)?;
        for value in &self.occurrences {
            visit(&[1])?;
            value.visit_comparison_encoding(visit)?;
        }
        visit(&[0])
    }
}

const _: () = assert!(
    std::mem::size_of::<ValidatedAttributeValue>()
        <= AttributeOccurrenceSet::PROJECTED_OCCURRENCE_SLOT_BYTES
);

const fn namespace_tag(namespace: AttributeNamespace) -> u8 {
    match namespace {
        AttributeNamespace::Stream => 0,
        AttributeNamespace::Resource => 1,
        AttributeNamespace::InstrumentationScope => 2,
        AttributeNamespace::Record => 3,
    }
}

fn validate_attribute_value(
    candidate: CandidateAttributeValue,
    limits: ValueLimitSet,
    value_bytes: ByteLimit,
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
            if exceeds_byte_limit(value.len(), value_bytes) {
                return Err(DomainFailure::value_limit_exceeded());
            }
            ValidatedAttributeValueInner::String(value)
        },
        CandidateAttributeValue::Bytes(value) => {
            if exceeds_byte_limit(value.len(), value_bytes) {
                return Err(DomainFailure::value_limit_exceeded());
            }
            ValidatedAttributeValueInner::Bytes(value)
        },
        CandidateAttributeValue::Array(values) => ValidatedAttributeValueInner::Array(
            validate_attribute_array(values, limits, value_bytes, remaining_depth)?,
        ),
        CandidateAttributeValue::KeyValueList(values) => {
            ValidatedAttributeValueInner::KeyValueList(validate_key_value_list(
                values,
                limits,
                value_bytes,
                remaining_depth,
            )?)
        },
    };
    let validated = ValidatedAttributeValue { inner };
    if exceeds_byte_limit(validated.value_size_bytes()?, value_bytes) {
        return Err(DomainFailure::value_limit_exceeded());
    }
    Ok(validated)
}

fn validate_attribute_array(
    values: Vec<CandidateAttributeValue>,
    limits: ValueLimitSet,
    value_bytes: ByteLimit,
    remaining_depth: u16,
) -> Result<Vec<ValidatedAttributeValue>, DomainFailure> {
    let Some(child_depth) = remaining_depth.checked_sub(1) else {
        return Err(DomainFailure::value_limit_exceeded());
    };
    if exceeds_collection_limit(values.len(), limits.dynamic_value().array_entries()) {
        return Err(DomainFailure::value_limit_exceeded());
    }
    let mut validated = Vec::new();
    validated
        .try_reserve_exact(values.len())
        .map_err(|_| DomainFailure::allocation_unavailable())?;
    for value in values {
        validated.push(validate_attribute_value(
            value,
            limits,
            value_bytes,
            child_depth,
        )?);
    }
    Ok(validated)
}

fn validate_key_value_list(
    values: Vec<CandidateKeyValue>,
    limits: ValueLimitSet,
    value_bytes: ByteLimit,
    remaining_depth: u16,
) -> Result<Vec<ValidatedKeyValue>, DomainFailure> {
    let Some(child_depth) = remaining_depth.checked_sub(1) else {
        return Err(DomainFailure::value_limit_exceeded());
    };
    if exceeds_collection_limit(
        values.len(),
        limits.dynamic_value().key_value_list_entries(),
    ) {
        return Err(DomainFailure::value_limit_exceeded());
    }
    let mut validated = Vec::new();
    validated
        .try_reserve_exact(values.len())
        .map_err(|_| DomainFailure::allocation_unavailable())?;
    for CandidateKeyValue { key, value } in values {
        if key.is_empty() || exceeds_byte_limit(key.len(), limits.dynamic_value().key_path_bytes())
        {
            return Err(DomainFailure::value_limit_exceeded());
        }
        validated.push(ValidatedKeyValue {
            key,
            value: validate_attribute_value(value, limits, value_bytes, child_depth)?,
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
