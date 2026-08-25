use positron_domain::lifecycle::TenantLifecycleState;
use positron_kernel::{Catalog, GovernanceFixtureObject, GovernanceFixtureTarget};

use super::types::{BootstrapFailure, BootstrapFailureCode, InitializedInstance};

#[derive(Clone)]
pub struct GovernanceTestFixture {
    object: GovernanceFixtureObject,
}

impl GovernanceTestFixture {
    fn new(object: &[u8]) -> Result<Self, BootstrapFailure> {
        let object = GovernanceFixtureObject::from_bytes(object)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        Ok(Self { object })
    }

    pub fn install_into<T: GovernanceFixtureTarget>(
        &self,
        target: &T,
    ) -> Result<(), BootstrapFailure> {
        target
            .install_governance_fixture(&self.object)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))
    }

    pub fn with_lifecycle(
        &self,
        lifecycle: TenantLifecycleState,
    ) -> Result<Self, BootstrapFailure> {
        Ok(Self {
            object: self
                .object
                .with_lifecycle(lifecycle)
                .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?,
        })
    }

    pub fn replace_into<T: GovernanceFixtureTarget>(
        &self,
        target: &T,
    ) -> Result<(), BootstrapFailure> {
        target
            .replace_governance_fixture(&self.object)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))
    }
}

impl InitializedInstance {
    /// Returns a typed governed fixture capability for external integration
    /// tests. The authenticated Catalog object never crosses this boundary.
    #[doc(hidden)]
    pub fn governance_fixture_for_test(&self) -> Result<GovernanceTestFixture, BootstrapFailure> {
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let catalog = Catalog::open(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let snapshot = catalog
            .pin()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        for object_id in snapshot.object_identities() {
            let object = snapshot
                .object(object_id)
                .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
            if let Some(object) = object
                && (object.starts_with(b"POSGOV01")
                    || object.starts_with(b"POSGOV02")
                    || object.starts_with(b"POSGOV03"))
            {
                return GovernanceTestFixture::new(object);
            }
        }
        Err(BootstrapFailure::new(
            BootstrapFailureCode::CatalogUnavailable,
        ))
    }

    /// Replaces the durable governance lifecycle through the runtime-owned
    /// Catalog authority. This seam exists only for integration fixtures.
    #[doc(hidden)]
    pub fn set_governance_lifecycle_for_test(
        &self,
        lifecycle: TenantLifecycleState,
    ) -> Result<(), BootstrapFailure> {
        let fixture = self
            .governance_fixture_for_test()?
            .with_lifecycle(lifecycle)?;
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let catalog = Catalog::open(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        fixture.replace_into(&catalog)
    }
}
