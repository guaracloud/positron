use std::error::Error;

use positron_domain::value::{
    AttributeNamespace, AttributeOccurrenceSetCandidate, CandidateAttributeValue, ValueLimitProfile,
};

use super::super::{
    OccurrenceSelector, SchemaBudget, SchemaCatalog, SchemaPath, SchemaQuery, SchemaValue,
};

mod codec;
mod discovery;
mod overflow;
mod query;
mod recovery;

fn profile() -> ValueLimitProfile {
    ValueLimitProfile::release_1_system_maximum()
}

fn occurrence(
    namespace: AttributeNamespace,
    key: &str,
    value: CandidateAttributeValue,
) -> Result<positron_domain::value::AttributeOccurrenceSet, Box<dyn Error>> {
    Ok(
        AttributeOccurrenceSetCandidate::new(namespace, key.to_owned(), vec![value])
            .validate(profile())?,
    )
}

fn path(namespace: AttributeNamespace, key: &str) -> SchemaPath {
    SchemaPath::new(namespace, key.to_owned()).expect("bounded test path")
}

fn small_budget() -> SchemaBudget {
    SchemaBudget::new(1, 128, 256, 64).expect("bounded test budget")
}

fn query(path: SchemaPath, value: SchemaValue, selector: OccurrenceSelector) -> SchemaQuery {
    SchemaQuery::value(path, selector, value)
}

fn catalog_with_small_budget() -> SchemaCatalog {
    SchemaCatalog::new(small_budget()).expect("bounded catalog")
}
