use super::*;

impl InitializedInstance {
    pub(crate) fn enter_ingest_finalization_for(
        &self,
        tenant: TenantId,
    ) -> Result<IngestDrainPermit, BootstrapFailure> {
        self.tenant_drains.enter_ingest(tenant)
    }

    pub(crate) fn enter_query_execution_for(
        &self,
        tenant: TenantId,
        cancellation: QueryCancellation,
    ) -> Result<QueryDrainPermit, BootstrapFailure> {
        self.tenant_drains.enter_query(tenant, cancellation)
    }

    #[cfg(test)]
    pub(crate) fn install_lifecycle_preflight_hook(
        &self,
        hook: Arc<dyn Fn() + Send + Sync>,
    ) -> Result<(), BootstrapFailure> {
        *self
            .lifecycle_preflight_hook
            .lock()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))? =
            Some(hook);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn install_catalog_migration_preflight_hook(
        &self,
        hook: Arc<dyn Fn() + Send + Sync>,
    ) -> Result<(), BootstrapFailure> {
        *self
            .catalog_migration_preflight_hook
            .lock()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))? =
            Some(hook);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn install_lifecycle_query_transition_observer(
        &self,
        observer: std::sync::mpsc::Sender<()>,
    ) -> Result<(), BootstrapFailure> {
        self.tenant_drains
            .install_query_transition_observer(self.tenant, observer)
    }

    #[cfg(test)]
    pub(crate) fn install_lifecycle_transition_observer(
        &self,
        observer: std::sync::mpsc::Sender<()>,
    ) -> Result<(), BootstrapFailure> {
        self.tenant_drains
            .install_ingest_transition_observer(self.tenant, observer)
    }

    pub(crate) fn durable_identity(
        &self,
    ) -> Result<positron_governance::Identity, BootstrapFailure> {
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let snapshot = Catalog::read_current_snapshot(&self._authority, self.instance, secret)
            .map_err(|failure| {
                let code = match failure.code() {
                    CatalogFailureCode::ResourceAdmissionRefused
                    | CatalogFailureCode::LimitExceeded => {
                        BootstrapFailureCode::ResourceUnavailable
                    },
                    CatalogFailureCode::StorageUnavailable
                    | CatalogFailureCode::ConcurrentWriter
                    | CatalogFailureCode::StaleGeneration
                    | CatalogFailureCode::IdempotencyConflict
                    | CatalogFailureCode::InvalidInput
                    | CatalogFailureCode::IntegrityCorruption
                    | CatalogFailureCode::AuthenticationFailed
                    | CatalogFailureCode::UnsupportedFormat => {
                        BootstrapFailureCode::CatalogUnavailable
                    },
                };
                BootstrapFailure::new(code)
            })?;
        positron_governance::Identity::open(&snapshot)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn install_retention_time_for_test(
        &mut self,
        retention_time: RetentionTimeAuthority,
    ) -> Result<(), BootstrapFailure> {
        self.retention_time = retention_time;
        let scope =
            positron_kernel::SegmentScope::new(self.tenant, SignalKind::Logs, self.logs_shard);
        self.retention_time
            .governance_time_seconds(scope)
            .map(|_| ())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))
    }

    pub(crate) fn begin_shutdown(&self) -> Result<(), BootstrapFailure> {
        self._authority
            .begin_shutdown()
            .map(|_| ())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))
    }

    pub fn attribute(
        &self,
        credential: positron_governance::PresentedCredential,
        intent: positron_governance::RequestedIntent,
        hints: positron_governance::CompatibilityHints,
    ) -> Result<positron_governance::AuthorizedContext, positron_governance::AttributionFailure>
    {
        // Never expose the boot-cached identity as a data-plane authority.
        // Rebuild the immutable view from the current durable Catalog
        // generation for every attribution request.
        let scope =
            positron_kernel::SegmentScope::new(self.tenant, SignalKind::Logs, self.logs_shard);
        let lifecycle_seconds = self
            .retention_time
            .governance_time_seconds(scope)
            .map_err(|_| positron_governance::AttributionFailure)?;
        self.durable_identity()
            .map_err(|_| positron_governance::AttributionFailure)?
            .attribute_at(
                &self.key,
                credential,
                intent,
                hints,
                Some(lifecycle_seconds),
            )
    }

    /// Records the active explicit plaintext API transport selection through
    /// the Catalog's single joint governance-audit publication path.
    pub(crate) fn activate_public_plaintext_api_transport(&self) -> Result<(), BootstrapFailure> {
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let catalog = Catalog::open(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        ListenerTransportAdministration::activate_public_plaintext_api(&catalog, self.instance)
            .map(|_| ())
            .map_err(map_listener_transport_failure)
    }
}
