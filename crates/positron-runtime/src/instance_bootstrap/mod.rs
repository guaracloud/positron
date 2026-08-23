mod codec;
mod operation;
mod resources;
mod storage;
mod types;

#[cfg(test)]
mod tests;

#[cfg(feature = "test-support")]
pub use types::GovernanceTestFixture;
pub use types::{
    BootstrapClaim, BootstrapFailure, BootstrapFailureCode, BootstrapPaths, BootstrapState,
    InitializationPlan, InitializedInstance,
};

/// The sole Application Runtime authority for classifying and initializing an instance.
pub enum InstanceBootstrap {}

impl InstanceBootstrap {
    pub fn classify(paths: &BootstrapPaths) -> Result<BootstrapState, BootstrapFailure> {
        operation::classify(paths)
    }

    pub fn initialize(
        paths: &BootstrapPaths,
        plan: InitializationPlan,
    ) -> Result<InitializedInstance, BootstrapFailure> {
        operation::initialize(paths, plan)
    }

    pub fn reopen(paths: &BootstrapPaths) -> Result<InitializedInstance, BootstrapFailure> {
        operation::reopen(paths)
    }

    pub fn claim(paths: &BootstrapPaths) -> Result<BootstrapClaim, BootstrapFailure> {
        operation::claim(paths)
    }
}
