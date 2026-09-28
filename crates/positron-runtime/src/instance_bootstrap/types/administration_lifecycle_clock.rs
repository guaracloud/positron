use super::*;

impl InitializedInstance {
    /// Accepts exactly the currently observed lifecycle-clock discontinuity.
    ///
    /// The caller supplies compare-and-swap identities only. The kernel derives
    /// the safe anchor, observed wall clock, and durable correction; Governance
    /// authenticates the system administrator and publishes those values with
    /// the canonical audit record in one Catalog transaction.
    pub fn accept_lifecycle_clock_discontinuity(
        &self,
        actor: AuthorizedContext,
        expected_catalog: positron_kernel::CatalogGenerationId,
        expected_safe_anchor: positron_domain::time::UnixNanoseconds,
        idempotency: AdministrativeIdempotencyKey,
    ) -> Result<positron_governance::LifecycleClockAcceptanceUpdate, BootstrapFailure> {
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let view = Catalog::read_current_view(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let snapshot = view.snapshot();
        let identity = positron_governance::Identity::open(snapshot)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
        let (_, governance) = snapshot
            .governance_object()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
        if governance.integrity_key_fingerprint() != self.integrity_key_fingerprint {
            return Err(BootstrapFailure::new(
                BootstrapFailureCode::IdentityMismatch,
            ));
        }
        let request = positron_governance::LifecycleClockAcceptanceRequest::new(
            actor,
            expected_catalog,
            idempotency,
        );
        if let Some((update, snapshot)) =
            positron_governance::LifecycleClockAcceptanceAdministration::replay_retained(
                &view,
                &identity,
                request,
                expected_safe_anchor,
            )
            .map_err(map_lifecycle_clock_acceptance_administration_failure)?
        {
            self.retention_time
                .recover_catalog_anchor(&snapshot)
                .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
            return Ok(update);
        }
        let prepared = match self
            .retention_time
            .prepare_discontinuity_acceptance(expected_safe_anchor)
        {
            Ok(prepared) => prepared,
            Err(positron_kernel::LifecycleClockAcceptanceFailure::NotUncertain) => {
                let Some((update, snapshot)) =
                    positron_governance::LifecycleClockAcceptanceAdministration::replay_retained(
                        &view,
                        &identity,
                        request,
                        expected_safe_anchor,
                    )
                    .map_err(map_lifecycle_clock_acceptance_administration_failure)?
                else {
                    return Err(map_lifecycle_clock_acceptance_failure(
                        positron_kernel::LifecycleClockAcceptanceFailure::NotUncertain,
                    ));
                };
                self.retention_time
                    .recover_catalog_anchor(&snapshot)
                    .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
                return Ok(update);
            },
            Err(failure) => return Err(map_lifecycle_clock_acceptance_failure(failure)),
        };
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let catalog = Catalog::open(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let snapshot = catalog
            .pin()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let identity = positron_governance::Identity::open(&snapshot)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
        let (update, commit) = positron_governance::LifecycleClockAcceptanceAdministration::accept(
            &catalog, &identity, request, &prepared,
        )
        .map_err(map_lifecycle_clock_acceptance_administration_failure)?;
        prepared
            .commit_after_catalog(&commit)
            .map_err(map_lifecycle_clock_acceptance_failure)?;
        Ok(update)
    }
}
