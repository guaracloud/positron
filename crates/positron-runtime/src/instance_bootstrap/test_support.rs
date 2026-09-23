use positron_domain::lifecycle::TenantLifecycleState;
use positron_domain::routing::SignalKind;
use positron_kernel::{
    ActiveSegmentLedger, Catalog, GovernanceFixtureObject, GovernanceFixtureTarget,
    RetentionReclamation, SegmentScope,
};

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
    /// Opens the narrow Instance Integrity signing capability used by a
    /// durable Query export integration test. Product entry points obtain the
    /// same capability through their authenticated runtime composition.
    #[doc(hidden)]
    pub fn export_manifest_signer_for_test(
        &self,
    ) -> Result<positron_kernel::ExportManifestSigner, BootstrapFailure> {
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let catalog = Catalog::open(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let snapshot = catalog
            .pin()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let (_, governance) = snapshot
            .governance_object()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
        if governance.integrity_key_fingerprint() != self.integrity_key_fingerprint {
            return Err(BootstrapFailure::new(
                BootstrapFailureCode::IdentityMismatch,
            ));
        }
        let signer = self
            .key
            .export_manifest_signer(self.instance, governance.protected_integrity_key())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        if signer.identity().public_key() != governance.integrity_public_key() {
            return Err(BootstrapFailure::new(
                BootstrapFailureCode::IdentityMismatch,
            ));
        }
        Ok(signer)
    }

    /// Derives test-fixture segment protection from the same authenticated
    /// tenant envelope as ordinary service paths.
    #[doc(hidden)]
    pub(crate) fn tenant_segment_key_for_test(
        &self,
        scope: SegmentScope,
    ) -> Result<positron_kernel::SegmentProtectionKey, BootstrapFailure> {
        let identity = self.durable_identity()?;
        let envelope = identity
            .tenant_key_envelope(scope.tenant_id())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
        self.key
            .segment_key_from_tenant_envelope(self.instance, scope, envelope)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))
    }

    /// Completes one Catalog-authorized Log retention pass for integration tests.
    #[doc(hidden)]
    pub fn complete_log_retention_for_test(
        &self,
    ) -> Result<RetentionReclamation, BootstrapFailure> {
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let catalog = Catalog::open(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let scope = SegmentScope::new(self.tenant, SignalKind::Logs, self.logs_shard);
        let protection = self.tenant_segment_key_for_test(scope)?;
        let ledger = ActiveSegmentLedger::open_with_retention_time(
            &self._authority,
            &self.retention_time,
            &catalog,
            scope,
            protection,
        )
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        ledger
            .begin_retention()
            .and_then(|evaluation| evaluation.commit())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))
    }

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
                    || object.starts_with(b"POSGOV03")
                    || object.starts_with(b"POSGOV04")
                    || object.starts_with(b"POSGOV05")
                    || object.starts_with(b"POSGOV06")
                    || object.starts_with(b"POSGOV07")
                    || object.starts_with(b"POSGOV08"))
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
