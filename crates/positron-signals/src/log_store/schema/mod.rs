mod budget_work;
mod catalog;
mod checkpoint;
mod codec;
pub(crate) mod delta;
mod discovery;
mod discovery_meter;
mod failure;
mod index;
mod index_path;
#[cfg(test)]
pub(crate) use index::{SchemaBlockIndex, SchemaIndexPath};
mod model;
mod observation;
mod observed_coverage;
mod promotion;
mod query;
mod query_owned;
mod replay;
mod representation;
mod session;
mod stored_query;
mod text_builder;
mod text_index;
pub(super) use text_builder::TextSummaryFailure;

pub use catalog::SchemaCatalog;
pub use checkpoint::SchemaCheckpointFrontier;
pub use delta::SchemaDelta;
pub use discovery::{
    SchemaBudgetPressure, SchemaDiscovery, SchemaDiscoveryRequest, SchemaPathDigest,
    SchemaPathSummary, SchemaPromotionDecision, SchemaPromotionReason,
};
pub use failure::SchemaFailure;
pub use model::{SchemaBudget, SchemaEntry, SchemaPath};
pub use observation::SchemaObservation;
pub use query::{OccurrenceSelector, SchemaQuery, SchemaQueryResult, SchemaValue};
pub use representation::SchemaRepresentation;
pub use session::{SchemaQueryUpdate, SchemaSessionStore};
pub use stored_query::SchemaTraversalFailure;
pub use text_index::TextSearchCandidate;
pub(crate) use text_index::{MIN_TEXT_INDEX_BUDGET_BYTES, TextBlockSummary};

#[cfg(test)]
mod tests;
