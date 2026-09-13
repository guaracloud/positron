mod codec;
mod operation;
mod resources;
mod storage;
#[cfg(any(test, fuzzing, feature = "test-support"))]
mod test_support;
mod types;

// Direct bootstrap callers have no configuration authority; preserve the shipped
// configuration default until the composition root supplies its resolved value.
const DEFAULT_MAX_REGISTERED_TENANTS: u16 = 2;

#[cfg(test)]
mod tests;

#[cfg(any(test, feature = "test-support"))]
pub use test_support::GovernanceTestFixture;
pub use types::{
    BootstrapClaim, BootstrapFailure, BootstrapFailureCode, BootstrapPaths, BootstrapState,
    InitializationPlan, InitializedInstance, TenantRetentionImpactPreview,
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
        Self::initialize_with_max_registered_tenants(paths, plan, DEFAULT_MAX_REGISTERED_TENANTS)
    }

    pub fn reopen(paths: &BootstrapPaths) -> Result<InitializedInstance, BootstrapFailure> {
        Self::reopen_with_max_registered_tenants(paths, DEFAULT_MAX_REGISTERED_TENANTS)
    }

    pub(crate) fn initialize_with_max_registered_tenants(
        paths: &BootstrapPaths,
        plan: InitializationPlan,
        max_registered_tenants: u16,
    ) -> Result<InitializedInstance, BootstrapFailure> {
        operation::initialize(paths, plan, max_registered_tenants)
    }

    pub(crate) fn reopen_with_max_registered_tenants(
        paths: &BootstrapPaths,
        max_registered_tenants: u16,
    ) -> Result<InitializedInstance, BootstrapFailure> {
        operation::reopen(paths, max_registered_tenants)
    }

    pub fn claim(paths: &BootstrapPaths) -> Result<BootstrapClaim, BootstrapFailure> {
        operation::claim(paths)
    }
}
