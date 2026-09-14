use super::*;

impl InitializedInstance {
    /// Returns redacted key descriptors for the authorized system operator.
    pub fn list_api_keys(
        &self,
        actor: AuthorizedContext,
    ) -> Result<Vec<positron_governance::ApiKeyDescriptor>, BootstrapFailure> {
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let catalog = Catalog::open(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        positron_governance::ApiKeyAdministration::list(&catalog, self.administrator, actor)
            .map_err(map_api_key_failure)
    }

    /// Returns redacted descriptors for one explicitly targeted tenant.
    pub fn list_api_keys_for_tenant(
        &self,
        actor: AuthorizedContext,
        tenant: TenantId,
    ) -> Result<Vec<positron_governance::ApiKeyDescriptor>, BootstrapFailure> {
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let catalog = Catalog::open(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        positron_governance::ApiKeyAdministration::list_for_tenant(
            &catalog,
            self.administrator,
            actor,
            tenant,
        )
        .map_err(map_api_key_failure)
    }

    /// Creates a successor credential without retiring its predecessor.  The
    /// caller must explicitly revoke the old key once dependent clients have
    /// switched, so a failed rollout never loses the only working key.
    pub fn rotate_api_key(
        &self,
        actor: AuthorizedContext,
        predecessor: PrincipalId,
        expected: ResourceGeneration,
        idempotency: AdministrativeIdempotencyKey,
    ) -> Result<ApiKeyCreation, BootstrapFailure> {
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let catalog = Catalog::open(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        positron_governance::ApiKeyAdministration::rotate(
            &catalog,
            &self.key,
            self.administrator,
            positron_governance::ApiKeyRotationRequest::new(
                actor,
                predecessor,
                expected,
                idempotency,
            ),
        )
        .map_err(map_api_key_failure)
    }

    /// Rotates a credential in one explicitly named tenant keyring.
    pub fn rotate_api_key_for_tenant(
        &self,
        actor: AuthorizedContext,
        tenant: TenantId,
        predecessor: PrincipalId,
        expected: ResourceGeneration,
        idempotency: AdministrativeIdempotencyKey,
    ) -> Result<ApiKeyCreation, BootstrapFailure> {
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let catalog = Catalog::open(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        positron_governance::ApiKeyAdministration::rotate_for_tenant(
            &catalog,
            &self.key,
            self.administrator,
            positron_governance::ApiKeyRotationRequest::new(
                actor,
                predecessor,
                expected,
                idempotency,
            )
            .for_tenant(tenant),
        )
        .map_err(map_api_key_failure)
    }

    /// Immediately disables one tenant credential while retaining its redacted
    /// descriptor as permanent identity history.
    pub fn revoke_api_key(
        &self,
        actor: AuthorizedContext,
        principal: PrincipalId,
        expected: ResourceGeneration,
        idempotency: AdministrativeIdempotencyKey,
    ) -> Result<(), BootstrapFailure> {
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let catalog = Catalog::open(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        positron_governance::ApiKeyAdministration::revoke(
            &catalog,
            self.administrator,
            actor,
            principal,
            expected,
            idempotency,
        )
        .map_err(map_api_key_failure)
    }

    /// Revokes a credential in one explicitly named tenant keyring.
    pub fn revoke_api_key_for_tenant(
        &self,
        actor: AuthorizedContext,
        tenant: TenantId,
        principal: PrincipalId,
        expected: ResourceGeneration,
        idempotency: AdministrativeIdempotencyKey,
    ) -> Result<(), BootstrapFailure> {
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let catalog = Catalog::open(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        positron_governance::ApiKeyAdministration::revoke_for_tenant(
            &catalog,
            self.administrator,
            actor,
            tenant,
            principal,
            expected,
            idempotency,
        )
        .map_err(map_api_key_failure)
    }
}
