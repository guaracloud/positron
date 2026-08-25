mod codec;
mod operation;
mod resources;
mod storage;
#[cfg(any(test, feature = "test-support"))]
mod test_support;
mod types;

#[cfg(test)]
mod tests;

#[cfg(any(test, feature = "test-support"))]
pub use test_support::GovernanceTestFixture;
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
