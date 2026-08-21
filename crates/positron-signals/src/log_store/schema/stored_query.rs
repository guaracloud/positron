use positron_domain::outcome::DomainFailureCode;
use positron_domain::value::{
    AttributeOccurrenceSet, NATIVE_VALUE_PAYLOAD_CHUNK_BYTES, NativeValueObserver,
    ObservedValueFailure, ValidatedAttributeValue,
};

use super::{
    SchemaCatalog, SchemaFailure, SchemaPath, SchemaQuery, SchemaQueryResult, SchemaRepresentation,
};
use crate::log_store::{AttributeRepresentation, StoredLogRecord};

/// Distinguishes stored-schema traversal failures from caller observation failures.
#[derive(Debug, Eq, PartialEq)]
pub enum SchemaTraversalFailure<E> {
    Schema(SchemaFailure),
    Value(ObservedValueFailure<E>),
}

impl<E> From<SchemaFailure> for SchemaTraversalFailure<E> {
    fn from(failure: SchemaFailure) -> Self {
        Self::Schema(failure)
    }
}

impl<E> From<ObservedValueFailure<E>> for SchemaTraversalFailure<E> {
    fn from(failure: ObservedValueFailure<E>) -> Self {
        Self::Value(failure)
    }
}

impl SchemaQuery {
    /// Evaluates this typed predicate against one authoritative stored record.
    #[must_use]
    pub fn matches_stored_record(&self, record: &StoredLogRecord) -> bool {
        super::query::evaluate(None, matching_attributes(record, self.path()), self).is_match()
    }

    /// Evaluates the same exact typed predicate with bounded traversal observation.
    pub fn matches_stored_record_observed<O: positron_domain::value::NativeValueObserver>(
        &self,
        record: &StoredLogRecord,
        observer: &mut O,
    ) -> Result<bool, positron_domain::value::ObservedValueFailure<O::Error>> {
        super::query::matches_observed(matching_attributes(record, self.path()), self, observer)
    }
}

impl SchemaCatalog {
    pub(crate) fn query_stored_record(
        &self,
        record: &StoredLogRecord,
        query: &SchemaQuery,
    ) -> SchemaQueryResult {
        super::query::evaluate(
            self.entry(query.path()),
            matching_attributes(record, query.path()),
            query,
        )
    }
}

impl StoredLogRecord {
    /// Returns the canonical retained bytes of a projected path without cloning its values.
    pub fn projected_attribute_retained_bytes(
        &self,
        path: &SchemaPath,
    ) -> Result<Option<usize>, SchemaFailure> {
        let path_bytes = path.as_string()?.len();
        let profile = crate::log_store::LogStore::value_limit_profile();
        let capacity = AttributeOccurrenceSet::projected_occurrence_capacity_bytes(profile)
            .map_err(map_domain_failure)?;
        let mut retained = path_bytes
            .checked_add(capacity)
            .ok_or(SchemaFailure::LimitExceeded)?;
        let mut found = false;
        visit_stored_terminals(self, path, &mut |value| {
            found = true;
            retained = retained
                .checked_add(value.retained_heap_bytes().map_err(map_domain_failure)?)
                .ok_or(SchemaFailure::LimitExceeded)?;
            Ok(true)
        })?;
        Ok(found.then_some(retained))
    }

    /// Projects every terminal value at a bounded path in producer occurrence order.
    pub fn project_attribute(
        &self,
        path: &SchemaPath,
    ) -> Result<Option<AttributeOccurrenceSet>, SchemaFailure> {
        let profile = crate::log_store::LogStore::value_limit_profile();
        let maximum = usize::try_from(
            profile
                .effective_limits()
                .dynamic_value()
                .attributes_per_namespace()
                .value(),
        )
        .map_err(|_| SchemaFailure::LimitExceeded)?;
        let mut count = 0_usize;
        visit_stored_terminals(self, path, &mut |_| {
            count = count.checked_add(1).ok_or(SchemaFailure::LimitExceeded)?;
            Ok(true)
        })?;
        if count == 0 {
            return Ok(None);
        }
        if count > maximum {
            return Err(SchemaFailure::LimitExceeded);
        }
        let mut occurrences = Vec::new();
        occurrences
            .try_reserve_exact(count)
            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        if occurrences.capacity() > maximum {
            return Err(SchemaFailure::AllocationUnavailable);
        }
        visit_stored_terminals(self, path, &mut |value| {
            occurrences.push(value.try_clone().map_err(map_domain_failure)?);
            Ok(true)
        })?;
        AttributeOccurrenceSet::from_validated(
            path.namespace(),
            path.as_string()?,
            occurrences,
            profile,
        )
        .map(Some)
        .map_err(map_domain_failure)
    }

    /// Returns projected retained bytes while observing path and value traversal.
    pub fn projected_attribute_retained_bytes_observed<O: NativeValueObserver>(
        &self,
        path: &SchemaPath,
        observer: &mut O,
    ) -> Result<Option<usize>, SchemaTraversalFailure<O::Error>> {
        let path_bytes = observed_path_size(path, observer)?;
        let profile = crate::log_store::LogStore::value_limit_profile();
        let capacity = AttributeOccurrenceSet::projected_occurrence_capacity_bytes(profile)
            .map_err(map_domain_failure)?;
        let mut retained = path_bytes
            .checked_add(capacity)
            .ok_or(SchemaFailure::LimitExceeded)?;
        let mut found = false;
        visit_stored_terminals_observed(self, path, observer, &mut |value, observer| {
            found = true;
            retained = retained
                .checked_add(value.retained_heap_bytes_observed(observer)?)
                .ok_or(SchemaFailure::LimitExceeded)?;
            Ok(true)
        })?;
        Ok(found.then_some(retained))
    }

    /// Projects every terminal value after caller-owned memory admission.
    pub fn project_attribute_observed<O: NativeValueObserver>(
        &self,
        path: &SchemaPath,
        observer: &mut O,
    ) -> Result<Option<AttributeOccurrenceSet>, SchemaTraversalFailure<O::Error>> {
        let profile = crate::log_store::LogStore::value_limit_profile();
        let maximum = usize::try_from(
            profile
                .effective_limits()
                .dynamic_value()
                .attributes_per_namespace()
                .value(),
        )
        .map_err(|_| SchemaFailure::LimitExceeded)?;
        let mut count = 0_usize;
        visit_stored_terminals_observed(self, path, observer, &mut |_, _| {
            count = count.checked_add(1).ok_or(SchemaFailure::LimitExceeded)?;
            Ok(true)
        })?;
        if count == 0 {
            return Ok(None);
        }
        if count > maximum {
            return Err(SchemaFailure::LimitExceeded.into());
        }
        let mut occurrences = Vec::new();
        occurrences
            .try_reserve_exact(count)
            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        if occurrences.capacity() > maximum {
            return Err(SchemaFailure::AllocationUnavailable.into());
        }
        visit_stored_terminals_observed(self, path, observer, &mut |value, observer| {
            occurrences.push(value.try_clone_observed(observer)?);
            Ok(true)
        })?;
        let key = observed_path_string(path, observer)?;
        AttributeOccurrenceSet::from_validated(path.namespace(), key, occurrences, profile)
            .map(Some)
            .map_err(map_domain_failure)
            .map_err(Into::into)
    }
}

fn visit_stored_terminals_observed<O: NativeValueObserver>(
    record: &StoredLogRecord,
    path: &SchemaPath,
    observer: &mut O,
    visit: &mut impl FnMut(
        &ValidatedAttributeValue,
        &mut O,
    ) -> Result<bool, SchemaTraversalFailure<O::Error>>,
) -> Result<(), SchemaTraversalFailure<O::Error>> {
    let remaining = path.segments().get(1..).ok_or(SchemaFailure::InvalidPath)?;
    for (attribute, _) in matching_attributes(record, path) {
        observed_structure(observer)?;
        observed_payload(attribute.key().as_bytes(), observer)?;
        for index in 0..attribute.len() {
            observed_structure(observer)?;
            let Some(value) = attribute.occurrence(index) else {
                return Err(SchemaFailure::InvalidValue.into());
            };
            let mut failure = None;
            let mut adapter = |terminal: &ValidatedAttributeValue, observer: &mut O| match visit(
                terminal, observer,
            ) {
                Ok(keep_going) => Ok(keep_going),
                Err(error) => {
                    failure = Some(error);
                    Ok(false)
                },
            };
            super::query::visit_terminals_observed(value, remaining, observer, &mut adapter)?;
            if let Some(error) = failure.take() {
                return Err(error);
            }
        }
    }
    Ok(())
}

fn observed_path_size<O: NativeValueObserver>(
    path: &SchemaPath,
    observer: &mut O,
) -> Result<usize, SchemaTraversalFailure<O::Error>> {
    let mut total = 0_usize;
    for (index, segment) in path.segments().iter().enumerate() {
        observed_structure(observer)?;
        observed_payload(segment.as_bytes(), observer)?;
        total = total
            .checked_add(segment.len())
            .and_then(|value| value.checked_add(usize::from(index > 0)))
            .ok_or(SchemaFailure::LimitExceeded)?;
    }
    Ok(total)
}

fn observed_path_string<O: NativeValueObserver>(
    path: &SchemaPath,
    observer: &mut O,
) -> Result<String, SchemaTraversalFailure<O::Error>> {
    let length = observed_path_size(path, observer)?;
    let mut rendered = String::new();
    rendered
        .try_reserve_exact(length)
        .map_err(|_| SchemaFailure::AllocationUnavailable)?;
    for (index, segment) in path.segments().iter().enumerate() {
        observed_structure(observer)?;
        observed_payload(segment.as_bytes(), observer)?;
        if index > 0 {
            rendered.push('.');
        }
        rendered.push_str(segment);
    }
    Ok(rendered)
}

fn observed_structure<O: NativeValueObserver>(
    observer: &mut O,
) -> Result<(), SchemaTraversalFailure<O::Error>> {
    observer
        .observe_structure()
        .map_err(ObservedValueFailure::Observer)
        .map_err(Into::into)
}

fn observed_payload<O: NativeValueObserver>(
    payload: &[u8],
    observer: &mut O,
) -> Result<(), SchemaTraversalFailure<O::Error>> {
    for chunk in payload.chunks(NATIVE_VALUE_PAYLOAD_CHUNK_BYTES) {
        observer
            .observe_payload(chunk)
            .map_err(ObservedValueFailure::Observer)?;
    }
    Ok(())
}

fn visit_stored_terminals(
    record: &StoredLogRecord,
    path: &SchemaPath,
    visit: &mut impl FnMut(&ValidatedAttributeValue) -> Result<bool, SchemaFailure>,
) -> Result<(), SchemaFailure> {
    let remaining = path.segments().get(1..).ok_or(SchemaFailure::InvalidPath)?;
    let mut failure = None;
    for (attribute, _) in matching_attributes(record, path) {
        for index in 0..attribute.len() {
            let Some(value) = attribute.occurrence(index) else {
                return Err(SchemaFailure::InvalidValue);
            };
            let mut adapter = |terminal: &ValidatedAttributeValue| match visit(terminal) {
                Ok(keep_going) => keep_going,
                Err(error) => {
                    failure = Some(error);
                    false
                },
            };
            if !super::query::visit_terminals(value, remaining, &mut adapter) {
                break;
            }
        }
        if failure.is_some() {
            break;
        }
    }
    failure.map_or(Ok(()), Err)
}

fn map_domain_failure(failure: positron_domain::outcome::DomainFailure) -> SchemaFailure {
    match failure.code() {
        DomainFailureCode::AllocationUnavailable => SchemaFailure::AllocationUnavailable,
        DomainFailureCode::ValueLimitExceeded => SchemaFailure::LimitExceeded,
        _ => SchemaFailure::InvalidValue,
    }
}

fn matching_attributes<'record>(
    record: &'record StoredLogRecord,
    path: &SchemaPath,
) -> impl Iterator<Item = (&'record AttributeOccurrenceSet, SchemaRepresentation)> {
    let root = path.segments().first().map(String::as_str);
    record.attributes().iter().filter_map(move |attribute| {
        let set = attribute.occurrences();
        (set.namespace() == path.namespace() && Some(set.key()) == root).then_some((
            set,
            match attribute.representation() {
                AttributeRepresentation::Generic => SchemaRepresentation::Cataloged,
                AttributeRepresentation::SchemaOverflow => SchemaRepresentation::Overflow,
            },
        ))
    })
}
