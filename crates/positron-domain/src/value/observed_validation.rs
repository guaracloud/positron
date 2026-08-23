const ARRAY_VALUE_SLOT_BYTES: usize = 64;
const KEY_VALUE_ENTRY_SLOT_BYTES: usize = 96;

fn validate_attribute_value(
    candidate: CandidateAttributeValue,
    limits: ValueLimitSet,
    value_bytes: ByteLimit,
    remaining_depth: u16,
) -> Result<ValidatedAttributeValue, DomainFailure> {
    let mut observer = observed::UnobservedNativeValue;
    observed::remove_observation(validate_attribute_value_observed(
        candidate,
        limits,
        value_bytes,
        remaining_depth,
        &mut observer,
    ))
}

fn validate_attribute_value_observed<O: NativeValueObserver>(
    candidate: CandidateAttributeValue,
    limits: ValueLimitSet,
    value_bytes: ByteLimit,
    remaining_depth: u16,
    observer: &mut O,
) -> Result<ValidatedAttributeValue, ObservedValueFailure<O::Error>> {
    validate_attribute_value_observed_with_facts(
        candidate,
        limits,
        value_bytes,
        remaining_depth,
        observer,
    )
    .map(ObservedValueTransfer::into_value)
}

fn validate_attribute_value_observed_with_facts<O: NativeValueObserver>(
    candidate: CandidateAttributeValue,
    limits: ValueLimitSet,
    value_bytes: ByteLimit,
    remaining_depth: u16,
    observer: &mut O,
) -> Result<ObservedValueTransfer, ObservedValueFailure<O::Error>> {
    observed::observe_structure(observer)?;
    let (inner, value_size_bytes, retained_heap_bytes) = match candidate {
        CandidateAttributeValue::Null => (ValidatedAttributeValueInner::Null, 0, 0),
        CandidateAttributeValue::Boolean(value) => {
            (ValidatedAttributeValueInner::Boolean(value), 1, 0)
        },
        CandidateAttributeValue::SignedInteger(value) => {
            (ValidatedAttributeValueInner::SignedInteger(value), 8, 0)
        },
        CandidateAttributeValue::FloatingPointBits(value) => {
            (ValidatedAttributeValueInner::FloatingPointBits(value), 8, 0)
        },
        CandidateAttributeValue::String(value) => {
            observed::observe_payload(value.as_bytes(), observer)?;
            if exceeds_byte_limit(value.len(), value_bytes) {
                return Err(DomainFailure::value_limit_exceeded().into());
            }
            let size = value.len();
            (ValidatedAttributeValueInner::String(value), size, size)
        },
        CandidateAttributeValue::Bytes(value) => {
            observed::observe_payload(&value, observer)?;
            if exceeds_byte_limit(value.len(), value_bytes) {
                return Err(DomainFailure::value_limit_exceeded().into());
            }
            let size = value.len();
            (ValidatedAttributeValueInner::Bytes(value), size, size)
        },
        CandidateAttributeValue::Array(values) => {
            let (values, value_size, retained) = validate_attribute_array_observed(
                values,
                limits,
                value_bytes,
                remaining_depth,
                observer,
            )?;
            (
                ValidatedAttributeValueInner::Array(values),
                value_size,
                retained,
            )
        },
        CandidateAttributeValue::KeyValueList(values) => {
            let (values, value_size, retained) = validate_key_value_list_observed(
                values,
                limits,
                value_bytes,
                remaining_depth,
                observer,
            )?;
            (
                ValidatedAttributeValueInner::KeyValueList(values),
                value_size,
                retained,
            )
        },
    };
    if exceeds_byte_limit(value_size_bytes, value_bytes) {
        return Err(DomainFailure::value_limit_exceeded().into());
    }
    Ok(ObservedValueTransfer::new(
        ValidatedAttributeValue { inner },
        value_size_bytes,
        retained_heap_bytes,
    ))
}

fn validate_attribute_array_observed<O: NativeValueObserver>(
    values: Vec<CandidateAttributeValue>,
    limits: ValueLimitSet,
    value_bytes: ByteLimit,
    remaining_depth: u16,
    observer: &mut O,
) -> Result<(Vec<ValidatedAttributeValue>, usize, usize), ObservedValueFailure<O::Error>> {
    let Some(child_depth) = remaining_depth.checked_sub(1) else {
        return Err(DomainFailure::value_limit_exceeded().into());
    };
    if exceeds_collection_limit(values.len(), limits.dynamic_value().array_entries()) {
        return Err(DomainFailure::value_limit_exceeded().into());
    }
    let mut validated = Vec::new();
    validated
        .try_reserve_exact(values.len())
        .map_err(|_| DomainFailure::allocation_unavailable())?;
    let mut value_size_bytes = 0_usize;
    let mut retained_heap_bytes = 0_usize;
    for value in values {
        let transfer = validate_attribute_value_observed_with_facts(
            value,
            limits,
            value_bytes,
            child_depth,
            observer,
        )?;
        value_size_bytes = checked_add(value_size_bytes, transfer.value_size_bytes)?;
        let child_retained = checked_add(ARRAY_VALUE_SLOT_BYTES, transfer.retained_heap_bytes)?;
        retained_heap_bytes = checked_add(retained_heap_bytes, child_retained)?;
        validated.push(transfer.value);
    }
    Ok((validated, value_size_bytes, retained_heap_bytes))
}

fn validate_key_value_list_observed<O: NativeValueObserver>(
    values: Vec<CandidateKeyValue>,
    limits: ValueLimitSet,
    value_bytes: ByteLimit,
    remaining_depth: u16,
    observer: &mut O,
) -> Result<(Vec<ValidatedKeyValue>, usize, usize), ObservedValueFailure<O::Error>> {
    let Some(child_depth) = remaining_depth.checked_sub(1) else {
        return Err(DomainFailure::value_limit_exceeded().into());
    };
    if exceeds_collection_limit(
        values.len(),
        limits.dynamic_value().key_value_list_entries(),
    ) {
        return Err(DomainFailure::value_limit_exceeded().into());
    }
    let mut validated = Vec::new();
    validated
        .try_reserve_exact(values.len())
        .map_err(|_| DomainFailure::allocation_unavailable())?;
    let mut value_size_bytes = 0_usize;
    let mut retained_heap_bytes = 0_usize;
    for CandidateKeyValue { key, value } in values {
        observed::observe_structure(observer)?;
        observed::observe_payload(key.as_bytes(), observer)?;
        if key.is_empty() || exceeds_byte_limit(key.len(), limits.dynamic_value().key_path_bytes())
        {
            return Err(DomainFailure::value_limit_exceeded().into());
        }
        let transfer = validate_attribute_value_observed_with_facts(
            value,
            limits,
            value_bytes,
            child_depth,
            observer,
        )?;
        value_size_bytes = checked_add(value_size_bytes, transfer.value_size_bytes)?;
        let entry_retained = checked_add(KEY_VALUE_ENTRY_SLOT_BYTES, key.len())?;
        let entry_retained = checked_add(entry_retained, transfer.retained_heap_bytes)?;
        retained_heap_bytes = checked_add(retained_heap_bytes, entry_retained)?;
        validated.push(ValidatedKeyValue {
            key,
            value: transfer.value,
        });
    }
    Ok((validated, value_size_bytes, retained_heap_bytes))
}

fn checked_add(left: usize, right: usize) -> Result<usize, DomainFailure> {
    left.checked_add(right)
        .ok_or_else(DomainFailure::value_limit_exceeded)
}

fn exceeds_byte_limit(actual: usize, limit: ByteLimit) -> bool {
    actual > usize::try_from(limit.value()).unwrap_or(usize::MAX)
}

fn exceeds_collection_limit(actual: usize, limit: CollectionLimit) -> bool {
    actual > usize::try_from(limit.value()).unwrap_or(usize::MAX)
}
