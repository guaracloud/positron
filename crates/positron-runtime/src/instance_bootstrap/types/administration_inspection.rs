use super::*;

impl InitializedInstance {
    /// Borrows the initialized instance's ordinary resource-admission authority.
    #[must_use]
    pub const fn resource_governor(&self) -> positron_kernel::ResourceGovernor<'_> {
        self._authority.governor()
    }

    #[cfg(any(test, fuzzing))]
    pub fn inspect_governance_for_fixture(
        &self,
        context: positron_governance::AuthorizedContext,
    ) -> Result<
        positron_governance::GovernanceInspection<'_, '_>,
        positron_governance::AttributionFailure,
    > {
        self.identity.inspect(context, &self.audit)
    }

    #[must_use]
    pub const fn instance_id(&self) -> InstanceId {
        self.instance
    }

    #[must_use]
    pub const fn default_tenant_id(&self) -> TenantId {
        self.tenant
    }

    #[must_use]
    pub fn default_tenant_slug(&self) -> &TenantSlug {
        &self.tenant_slug
    }

    #[must_use]
    pub const fn system_administrator_id(&self) -> PrincipalId {
        self.administrator
    }

    #[must_use]
    pub const fn integrity_key_fingerprint(&self) -> [u8; 32] {
        self.integrity_key_fingerprint
    }

    #[must_use]
    pub const fn catalog_generation(&self) -> u64 {
        self.catalog_generation
    }

    #[must_use]
    pub const fn governance_audit_frontier(&self) -> u64 {
        self.governance_audit_frontier
    }

    pub(super) fn current_catalog_snapshot(
        &self,
    ) -> Result<positron_kernel::CatalogSnapshot, BootstrapFailure> {
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        Catalog::read_current_snapshot(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))
    }

    pub(super) fn authorize_tenant_inspection(
        &self,
        actor: AuthorizedContext,
    ) -> Result<(), BootstrapFailure> {
        let snapshot = self.current_catalog_snapshot()?;
        let identity = positron_governance::Identity::open(&snapshot)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
        identity
            .inspect(actor, &[])
            .map(|_| ())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ApiKeyUnauthorized))
    }

    #[must_use]
    pub const fn claim_available(&self) -> bool {
        self.claim_available
    }
}
