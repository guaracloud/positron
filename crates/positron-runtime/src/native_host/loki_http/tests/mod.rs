use positron_domain::routing::VirtualShardId;
use positron_ingest::{
    AdmissionGroupOutcome, IngestFailureCode, IngestOutcome, IngestRequestOutcome,
};

use super::ingest_response;
use crate::ServiceFailure;

#[path = "outcomes.rs"]
mod outcomes;

#[path = "live_outcomes.rs"]
mod live_outcomes;

fn single(outcome: IngestOutcome) -> IngestRequestOutcome {
    IngestRequestOutcome::new(vec![AdmissionGroupOutcome::new(
        VirtualShardId::new(1).expect("fixed shard"),
        1,
        outcome,
    )])
}
