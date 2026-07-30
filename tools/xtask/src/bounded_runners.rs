//! Registered bounded Quality Engineering runner interface.
//!
//! Frozen registry identity, child protocol, resource modeling, scenario
//! orchestration, and diagnostic measurement verification are internal modules.
//! Parent-owned truth remains independent in `bounded_measurement_verifier`.

mod measurement;
mod protocol;
mod registry;
mod resource;
mod scenarios;

use std::path::Path;

use crate::error::XtaskError;

pub(crate) use protocol::{OwnedOutcomeTicket, run_process};
pub(crate) use registry::FrozenBoundedRunnerRegistry;

pub(crate) fn validate_source_policy(
    registry: &FrozenBoundedRunnerRegistry,
    root: &Path,
) -> Result<(), XtaskError> {
    crate::concurrency_source_policy::validate_registered_spawn_sites(
        root,
        Path::new(registry::SPAWN_SITE_REGISTRY_PATH),
        registry.spawn_sites(),
        registry::REGISTERED_SPAWN_SITE,
    )
}
