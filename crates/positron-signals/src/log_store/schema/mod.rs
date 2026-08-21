mod catalog;
mod checkpoint;
mod codec;
pub(crate) mod delta;
mod discovery;
mod failure;
mod index;
#[cfg(test)]
pub(crate) use index::{SchemaBlockIndex, SchemaIndexPath};
mod model;
mod observation;
mod promotion;
mod query;
mod representation;
mod session;
mod stored_query;

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

#[cfg(test)]
mod tests;
