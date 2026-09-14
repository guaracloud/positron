use super::*;

impl InitializedInstance {
    pub fn create_api_key(
        &self,
        actor: AuthorizedContext,
        scope: Scope,
        expires_at_unix_seconds: Option<u64>,
        expected: ResourceGeneration,
        idempotency: AdministrativeIdempotencyKey,
    ) -> Result<ApiKeyCreation, BootstrapFailure> {
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let catalog = Catalog::open(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        positron_governance::ApiKeyAdministration::create(
            &catalog,
            &self.key,
            self.administrator,
            positron_governance::ApiKeyCreateRequest::new(
                actor,
                scope,
                expires_at_unix_seconds,
                expected,
                idempotency,
            ),
        )
        .map_err(map_api_key_failure)
    }

    /// Provisions a scoped API key for an explicitly named tenant without
    /// granting the system actor data-plane attribution for that tenant.
    pub fn create_api_key_for_tenant(
        &self,
        actor: AuthorizedContext,
        tenant: TenantId,
        scope: Scope,
        expires_at_unix_seconds: Option<u64>,
        expected: ResourceGeneration,
        idempotency: AdministrativeIdempotencyKey,
    ) -> Result<ApiKeyCreation, BootstrapFailure> {
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let catalog = Catalog::open(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        positron_governance::ApiKeyAdministration::create_for_tenant(
            &catalog,
            &self.key,
            self.administrator,
            positron_governance::ApiKeyCreateRequest::new(
                actor,
                scope,
                expires_at_unix_seconds,
                expected,
                idempotency,
            )
            .for_tenant(tenant),
        )
        .map_err(map_api_key_failure)
    }

    /// Durably publishes a tenant quota successor and then applies its limits
    /// to future local admission. Existing reservations are retained by the
    /// Resource Governor's bounded quota-update contract.
    pub fn update_tenant_quota(
        &self,
        actor: AuthorizedContext,
        tenant: TenantId,
        expected: ResourceGeneration,
        idempotency: AdministrativeIdempotencyKey,
        weight: u32,
        resources: [u64; 11],
    ) -> Result<positron_governance::TenantQuotaUpdate, BootstrapFailure> {
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let catalog = Catalog::open(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let identity = positron_governance::Identity::open(
            &catalog
                .pin()
                .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?,
        )
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
        let update = positron_governance::TenantQuotaAdministration::update(
            &catalog,
            &self._authority,
            &identity,
            positron_governance::TenantQuotaUpdateRequest::new(
                actor,
                tenant,
                expected,
                idempotency,
                weight,
                resources,
            ),
        )
        .map_err(map_tenant_quota_failure)?;
        Ok(update)
    }

    /// Durably updates one tenant's display label while retaining independent
    /// retention, quota, policy, and lifecycle resources unchanged.
    pub fn update_tenant_display_name(
        &self,
        actor: AuthorizedContext,
        tenant: TenantId,
        expected: ResourceGeneration,
        display_name: &str,
        idempotency: AdministrativeIdempotencyKey,
    ) -> Result<TenantDisplayNameUpdate, BootstrapFailure> {
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let catalog = Catalog::open(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let identity = positron_governance::Identity::open(
            &catalog
                .pin()
                .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?,
        )
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
        TenantProfileAdministration::update_display_name(
            &catalog,
            &identity,
            TenantDisplayNameUpdateRequest::new(actor, tenant, expected, display_name, idempotency),
        )
        .map_err(map_tenant_profile_failure)
    }

    /// Atomically publishes a new tenant registry record, then enrolls that
    /// tenant in the live bounded admission authority.
    #[cfg(any(test, feature = "test-support"))]
    #[allow(dead_code)]
    pub fn create_tenant(
        &self,
        actor: AuthorizedContext,
        tenant: TenantId,
        configuration: positron_governance::TenantCreateConfiguration,
        idempotency: AdministrativeIdempotencyKey,
    ) -> Result<positron_governance::TenantCreation, BootstrapFailure> {
        self.create_tenant_selected(actor, Some(tenant), configuration, idempotency)
    }

    /// Creates a tenant with an identity generated by the kernel CSPRNG.
    pub fn create_tenant_generated(
        &self,
        actor: AuthorizedContext,
        configuration: positron_governance::TenantCreateConfiguration,
        idempotency: AdministrativeIdempotencyKey,
    ) -> Result<positron_governance::TenantCreation, BootstrapFailure> {
        self.create_tenant_selected(actor, None, configuration, idempotency)
    }

    fn create_tenant_selected(
        &self,
        actor: AuthorizedContext,
        requested_tenant: Option<TenantId>,
        configuration: positron_governance::TenantCreateConfiguration,
        idempotency: AdministrativeIdempotencyKey,
    ) -> Result<positron_governance::TenantCreation, BootstrapFailure> {
        let resources = configuration.resources();
        let weight = u16::try_from(configuration.weight())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        let request =
            positron_governance::TenantCreateRequest::new(actor, configuration, idempotency);
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let preflight = Catalog::read_current_view(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        if let Some(replay) = positron_governance::TenantAdministration::replay_from_view(
            &preflight,
            self.administrator,
            request.clone(),
        )
        .map_err(map_tenant_administration_failure)?
        {
            return Ok(replay);
        }
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let catalog = Catalog::open(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let tenant = match positron_governance::TenantAdministration::inspect_prepared(
            &catalog,
            self.administrator,
            &request,
        )
        .map_err(map_tenant_administration_failure)?
        {
            Some(prepared) => prepared.tenant_id(),
            None => match requested_tenant {
                Some(tenant) => tenant,
                None => self.random_unregistered_tenant(&catalog)?,
            },
        };
        // The Catalog Writer serializes all governance changes that can alter
        // tenant topology. Prepare live enrollment only after acquiring it, so
        // a quota successor cannot be derived from stale membership.
        let mut drain_enrollment = self.tenant_drains.prepare_tenant(tenant)?;
        let mut enrollment = self
            ._authority
            .prepare_tenant_enrollment(tenant, weight, ResourceAmounts::new(resources))
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        let candidate = request.with_generated_tenant(tenant);
        let created = positron_governance::TenantAdministration::create(
            &catalog,
            &self.key,
            self.instance,
            self.administrator,
            candidate,
        )
        .map_err(map_tenant_administration_failure)?;
        enrollment.activate();
        drain_enrollment.activate();
        Ok(created)
    }

    fn random_unregistered_tenant(
        &self,
        catalog: &Catalog<'_>,
    ) -> Result<TenantId, BootstrapFailure> {
        Self::next_unregistered_tenant(catalog, || {
            TenantId::from_bytes(
                self.key
                    .random_identifier()
                    .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::EntropyUnavailable))?,
            )
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::EntropyUnavailable))
        })
    }

    fn next_unregistered_tenant(
        catalog: &Catalog<'_>,
        mut next: impl FnMut() -> Result<TenantId, BootstrapFailure>,
    ) -> Result<TenantId, BootstrapFailure> {
        const MAX_TENANT_ID_ATTEMPTS: usize = 8;
        let snapshot = catalog
            .pin()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let registered =
            positron_governance::TenantAdministration::registered_tenant_ids(&snapshot)
                .map_err(map_tenant_administration_failure)?;
        for _ in 0..MAX_TENANT_ID_ATTEMPTS {
            let tenant = next()?;
            if !registered.contains(&tenant) {
                return Ok(tenant);
            }
        }
        Err(BootstrapFailure::new(
            BootstrapFailureCode::ResourceUnavailable,
        ))
    }

    #[cfg(test)]
    pub(crate) fn select_unregistered_tenant_for_test(
        catalog: &Catalog<'_>,
        next: impl FnMut() -> Result<TenantId, BootstrapFailure>,
    ) -> Result<TenantId, BootstrapFailure> {
        Self::next_unregistered_tenant(catalog, next)
    }

    /// Enumerates tenant state only for the authenticated system administrator.
    pub fn list_tenants(
        &self,
        actor: AuthorizedContext,
    ) -> Result<Vec<positron_governance::TenantInspection>, BootstrapFailure> {
        self.authorize_tenant_inspection(actor)?;
        let snapshot = self.current_catalog_snapshot()?;
        positron_governance::TenantAdministration::list(&snapshot)
            .map_err(map_tenant_administration_failure)
    }

    /// Enumerates one authenticated, snapshot-pinned page of tenant state.
    pub fn list_tenant_page(
        &self,
        actor: AuthorizedContext,
        continuation: Option<positron_governance::TenantListContinuation>,
        limit: usize,
    ) -> Result<positron_governance::TenantInspectionPage, BootstrapFailure> {
        self.authorize_tenant_inspection(actor)?;
        let snapshot = self.current_catalog_snapshot()?;
        positron_governance::TenantAdministration::list_page(&snapshot, continuation, limit)
            .map_err(map_tenant_administration_failure)
    }

    /// Returns one redacted tenant-administration view without exposing keys.
    pub fn inspect_tenant(
        &self,
        actor: AuthorizedContext,
        tenant: TenantId,
    ) -> Result<positron_governance::TenantInspection, BootstrapFailure> {
        self.authorize_tenant_inspection(actor)?;
        let snapshot = self.current_catalog_snapshot()?;
        positron_governance::TenantAdministration::inspect(&snapshot, tenant)
            .map_err(map_tenant_administration_failure)
    }
}
