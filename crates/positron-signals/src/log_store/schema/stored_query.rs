use positron_domain::outcome::DomainFailureCode;
use positron_domain::value::{AttributeOccurrenceSet, ValidatedAttributeValue};

use super::{
    SchemaCatalog, SchemaFailure, SchemaPath, SchemaQuery, SchemaQueryResult, SchemaRepresentation,
};
use crate::log_store::{AttributeRepresentation, StoredLogRecord};

impl SchemaQuery {
    /// Evaluates this typed predicate against one authoritative stored record.
    #[must_use]
    pub fn matches_stored_record(&self, record: &StoredLogRecord) -> bool {
        super::query::evaluate(None, matching_attributes(record, self.path()), self).is_match()
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
        let mut retained = path_bytes;
        let mut found = false;
        visit_stored_terminals(self, path, &mut |value| {
            found = true;
            retained = retained
                .checked_add(
                    AttributeOccurrenceSet::retained_occurrence_bytes(value).map_err(
                        |failure| match failure.code() {
                            DomainFailureCode::AllocationUnavailable => {
                                SchemaFailure::AllocationUnavailable
                            },
                            _ => SchemaFailure::LimitExceeded,
                        },
                    )?,
                )
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
        let mut occurrences = Vec::new();
        visit_stored_terminals(self, path, &mut |value| {
            occurrences
                .try_reserve(1)
                .map_err(|_| SchemaFailure::AllocationUnavailable)?;
            occurrences.push(value.try_clone().map_err(map_domain_failure)?);
            Ok(true)
        })?;
        if occurrences.is_empty() {
            return Ok(None);
        }
        AttributeOccurrenceSet::from_validated(
            path.namespace(),
            path.as_string()?,
            occurrences,
            crate::log_store::LogStore::value_limit_profile(),
        )
        .map(Some)
        .map_err(map_domain_failure)
    }
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
