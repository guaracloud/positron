const ARRAY_VALUE_SLOT_BYTES: usize = 64;
const KEY_VALUE_ENTRY_SLOT_BYTES: usize = 96;

type ValidatedArray = (Vec<ValidatedAttributeValue>, usize, usize, usize);
type ValidatedKeyValueList = (Vec<ValidatedKeyValue>, usize, usize, usize);

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
    let (inner, value_size_bytes, retained_heap_bytes, allocation_bytes) = match candidate {
        CandidateAttributeValue::Null => (ValidatedAttributeValueInner::Null, 0, 0, 0),
        CandidateAttributeValue::Boolean(value) => {
            (ValidatedAttributeValueInner::Boolean(value), 1, 0, 0)
        },
        CandidateAttributeValue::SignedInteger(value) => {
            (ValidatedAttributeValueInner::SignedInteger(value), 8, 0, 0)
        },
        CandidateAttributeValue::FloatingPointBits(value) => {
            (ValidatedAttributeValueInner::FloatingPointBits(value), 8, 0, 0)
        },
        CandidateAttributeValue::String(value) => {
            observed::observe_payload(value.as_bytes(), observer)?;
            if exceeds_byte_limit(value.len(), value_bytes) {
                return Err(DomainFailure::value_limit_exceeded().into());
            }
            let size = value.len();
            let retained = value.capacity();
            (
                ValidatedAttributeValueInner::String(value),
                size,
                retained,
                0,
            )
        },
        CandidateAttributeValue::Bytes(value) => {
            observed::observe_payload(&value, observer)?;
            if exceeds_byte_limit(value.len(), value_bytes) {
                return Err(DomainFailure::value_limit_exceeded().into());
            }
            let size = value.len();
            let retained = value.capacity();
            (
                ValidatedAttributeValueInner::Bytes(value),
                size,
                retained,
                0,
            )
        },
        CandidateAttributeValue::Array(values) => {
            let (values, value_size, retained, allocation_bytes) = validate_attribute_array_observed(
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
                allocation_bytes,
            )
        },
        CandidateAttributeValue::KeyValueList(values) => {
            let (values, value_size, retained, allocation_bytes) =
                validate_key_value_list_observed(
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
                allocation_bytes,
            )
        },
    };
    Ok(ObservedValueTransfer::new(
        ValidatedAttributeValue { inner },
        value_size_bytes,
        retained_heap_bytes,
        allocation_bytes,
    ))
}

fn validate_attribute_array_observed<O: NativeValueObserver>(
    values: Vec<CandidateAttributeValue>,
    limits: ValueLimitSet,
    value_bytes: ByteLimit,
    remaining_depth: u16,
    observer: &mut O,
) -> Result<ValidatedArray, ObservedValueFailure<O::Error>> {
    let Some(child_depth) = remaining_depth.checked_sub(1) else {
        return Err(DomainFailure::value_limit_exceeded().into());
    };
    if exceeds_collection_limit(values.len(), limits.dynamic_value().array_entries()) {
        return Err(DomainFailure::value_limit_exceeded().into());
    }
    let allocation_bytes = reserve_output_capacity(
        values.len(),
        ARRAY_VALUE_SLOT_BYTES,
        observer,
    )?;
    let mut validated = Vec::new();
    if validated.try_reserve_exact(values.len()).is_err() {
        release_output_capacity(allocation_bytes, observer)?;
        return Err(DomainFailure::allocation_unavailable().into());
    }
    let allocation_bytes = reconcile_output_capacity(
        &validated,
        ARRAY_VALUE_SLOT_BYTES,
        allocation_bytes,
        observer,
    )?;
    let mut value_size_bytes = 0_usize;
    let mut retained_heap_bytes = checked_capacity_bytes(
        validated.capacity(),
        ARRAY_VALUE_SLOT_BYTES,
    )?;
    let mut total_allocation_bytes = allocation_bytes;
    let result = (|| {
        for value in values {
            let transfer = validate_attribute_value_observed_with_facts(
                value,
                limits,
                value_bytes,
                child_depth,
                observer,
            )?;
            let child_allocation_bytes = transfer.allocation_bytes();
            total_allocation_bytes = match total_allocation_bytes
                .checked_add(child_allocation_bytes)
            {
                Some(bytes) => bytes,
                None => {
                    release_output_capacity(child_allocation_bytes, observer)?;
                    return Err(DomainFailure::value_limit_exceeded().into());
                },
            };
            value_size_bytes = checked_add(value_size_bytes, transfer.value_size_bytes())?;
            if exceeds_byte_limit(value_size_bytes, value_bytes) {
                return Err(DomainFailure::value_limit_exceeded().into());
            }
            retained_heap_bytes = checked_add(retained_heap_bytes, transfer.retained_heap_bytes())?;
            validated.push(transfer.into_value());
        }
        Ok((
            validated,
            value_size_bytes,
            retained_heap_bytes,
            total_allocation_bytes,
        ))
    })();
    if result.is_err() {
        release_output_capacity(total_allocation_bytes, observer)?;
    }
    result
}

fn validate_key_value_list_observed<O: NativeValueObserver>(
    values: Vec<CandidateKeyValue>,
    limits: ValueLimitSet,
    value_bytes: ByteLimit,
    remaining_depth: u16,
    observer: &mut O,
) -> Result<ValidatedKeyValueList, ObservedValueFailure<O::Error>> {
    let Some(child_depth) = remaining_depth.checked_sub(1) else {
        return Err(DomainFailure::value_limit_exceeded().into());
    };
    if exceeds_collection_limit(
        values.len(),
        limits.dynamic_value().key_value_list_entries(),
    ) {
        return Err(DomainFailure::value_limit_exceeded().into());
    }
    let allocation_bytes = reserve_output_capacity(
        values.len(),
        KEY_VALUE_ENTRY_SLOT_BYTES,
        observer,
    )?;
    let mut validated = Vec::new();
    if validated.try_reserve_exact(values.len()).is_err() {
        release_output_capacity(allocation_bytes, observer)?;
        return Err(DomainFailure::allocation_unavailable().into());
    }
    let allocation_bytes = reconcile_output_capacity(
        &validated,
        KEY_VALUE_ENTRY_SLOT_BYTES,
        allocation_bytes,
        observer,
    )?;
    let mut value_size_bytes = 0_usize;
    let mut retained_heap_bytes = checked_capacity_bytes(
        validated.capacity(),
        KEY_VALUE_ENTRY_SLOT_BYTES,
    )?;
    let mut total_allocation_bytes = allocation_bytes;
    let result = (|| {
        for CandidateKeyValue { key, value } in values {
            observed::observe_structure(observer)?;
            observed::observe_payload(key.as_bytes(), observer)?;
            if key.is_empty()
                || exceeds_byte_limit(key.len(), limits.dynamic_value().key_path_bytes())
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
            let child_allocation_bytes = transfer.allocation_bytes();
            total_allocation_bytes = match total_allocation_bytes
                .checked_add(child_allocation_bytes)
            {
                Some(bytes) => bytes,
                None => {
                    release_output_capacity(child_allocation_bytes, observer)?;
                    return Err(DomainFailure::value_limit_exceeded().into());
                },
            };
            value_size_bytes = checked_add(value_size_bytes, transfer.value_size_bytes())?;
            if exceeds_byte_limit(value_size_bytes, value_bytes) {
                return Err(DomainFailure::value_limit_exceeded().into());
            }
            let entry_retained = checked_add(key.capacity(), transfer.retained_heap_bytes())?;
            retained_heap_bytes = checked_add(retained_heap_bytes, entry_retained)?;
            validated.push(ValidatedKeyValue {
                key,
                value: transfer.into_value(),
            });
        }
        Ok((
            validated,
            value_size_bytes,
            retained_heap_bytes,
            total_allocation_bytes,
        ))
    })();
    if result.is_err() {
        release_output_capacity(total_allocation_bytes, observer)?;
    }
    result
}

fn reserve_output_capacity<O: NativeValueObserver>(
    count: usize,
    slot_bytes: usize,
    observer: &mut O,
) -> Result<usize, ObservedValueFailure<O::Error>> {
    if count == 0 {
        return Ok(0);
    }
    let capacity = count
        .checked_next_power_of_two()
        .ok_or_else(DomainFailure::value_limit_exceeded)?;
    let bytes = capacity
        .checked_mul(slot_bytes)
        .ok_or_else(DomainFailure::value_limit_exceeded)?;
    observer
        .observe_allocation(bytes)
        .map_err(ObservedValueFailure::Observer)?;
    Ok(bytes)
}

fn reconcile_output_capacity<T, O: NativeValueObserver>(
    values: &Vec<T>,
    slot_bytes: usize,
    admitted_bytes: usize,
    observer: &mut O,
) -> Result<usize, ObservedValueFailure<O::Error>> {
    let actual_bytes = checked_capacity_bytes(values.capacity(), slot_bytes)?;
    if actual_bytes > admitted_bytes {
        let additional = actual_bytes
            .checked_sub(admitted_bytes)
            .ok_or_else(DomainFailure::value_limit_exceeded)?;
        observer
            .observe_allocation(additional)
            .map_err(ObservedValueFailure::Observer)?;
        return Ok(actual_bytes);
    }
    let slack = admitted_bytes - actual_bytes;
    if slack > 0 {
        release_output_capacity(slack, observer)?;
    }
    Ok(actual_bytes)
}

fn checked_capacity_bytes(capacity: usize, slot_bytes: usize) -> Result<usize, DomainFailure> {
    capacity
        .checked_mul(slot_bytes)
        .ok_or_else(DomainFailure::value_limit_exceeded)
}

fn release_output_capacity<O: NativeValueObserver>(
    bytes: usize,
    observer: &mut O,
) -> Result<(), ObservedValueFailure<O::Error>> {
    observer
        .release_allocation(bytes)
        .map_err(ObservedValueFailure::Observer)?;
    Ok(())
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
