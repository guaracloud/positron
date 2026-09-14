use super::*;

impl InitializedInstance {
    /// Reads bounded canonical segment evidence without publishing a retention change.
    pub fn inspect_tenant_retention_impact(
        &self,
        actor: AuthorizedContext,
        tenant: TenantId,
        proposed_retention_seconds: NonZeroU64,
    ) -> Result<TenantRetentionImpactPreview, BootstrapFailure> {
        self.inspect_tenant_retention_impact_at(actor, tenant, proposed_retention_seconds, None)
    }

    /// Rebuilds retention evidence at a previously trusted preview instant.
    /// The HTTP continuation verifies its full evidence digest before using
    /// this path, so callers cannot choose an arbitrary evaluation instant.
    pub(crate) fn inspect_tenant_retention_impact_at(
        &self,
        actor: AuthorizedContext,
        tenant: TenantId,
        proposed_retention_seconds: NonZeroU64,
        requested_evaluation: Option<positron_domain::time::UnixNanoseconds>,
    ) -> Result<TenantRetentionImpactPreview, BootstrapFailure> {
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let catalog = Catalog::open(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let snapshot = catalog
            .pin()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let inspection = positron_governance::TenantAdministration::inspect(&snapshot, tenant)
            .map_err(map_tenant_administration_failure)?;
        let identity = positron_governance::Identity::open(&snapshot)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
        identity
            .authorize_tenant_retention(actor, tenant)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ApiKeyUnauthorized))?;
        let ledger_scopes = [SignalKind::Logs, SignalKind::Traces]
            .into_iter()
            .map(|signal| snapshot.reachable_ledger_scopes(tenant, signal))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        let evaluation = match requested_evaluation {
            Some(value) => value,
            None => {
                let seconds = ledger_scopes
                    .iter()
                    .map(|scope| self.retention_time.governance_time_seconds(*scope))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?
                    .into_iter()
                    .max()
                    .map(Ok)
                    .unwrap_or_else(|| self.retention_time.governance_now_seconds())
                    .map_err(|_| {
                        BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable)
                    })?;
                let nanos = seconds
                    .checked_mul(1_000_000_000)
                    .and_then(|value| i64::try_from(value).ok())
                    .ok_or_else(|| {
                        BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable)
                    })?;
                positron_domain::time::UnixNanoseconds::new(nanos)
            },
        };
        let mut scopes = Vec::new();
        for scope in ledger_scopes {
            let protection = self
                .key
                .segment_key_from_tenant_envelope(
                    self.instance,
                    scope,
                    identity.tenant_key_envelope(tenant).map_err(|_| {
                        BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable)
                    })?,
                )
                .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
            let reader = CommittedLedgerReader::open(&self._authority, &catalog, scope, protection)
                .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::LedgerUnavailable))?;
            scopes.push(
                reader
                    .inspect_retention_impact_at(proposed_retention_seconds, evaluation)
                    .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::LedgerUnavailable))?,
            );
        }
        Ok(TenantRetentionImpactPreview {
            tenant,
            retention_generation: ResourceGeneration::new(inspection.retention_generation().get())
                .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?,
            proposed_retention_seconds,
            catalog_identity: snapshot.identity(),
            catalog_generation: snapshot.number(),
            evaluated_at: evaluation,
            scopes,
        })
    }

    /// Publishes a retention successor. A reduction must carry a preview that
    /// is recomputed here from the current committed ledgers before its opaque
    /// confirmation binding can reach governance.
    pub fn update_tenant_retention(
        &self,
        actor: AuthorizedContext,
        tenant: TenantId,
        proposed_retention_seconds: NonZeroU64,
        expected: ResourceGeneration,
        confirmation: Option<&TenantRetentionImpactPreview>,
        idempotency: AdministrativeIdempotencyKey,
    ) -> Result<TenantRetentionUpdate, BootstrapFailure> {
        if confirmation.is_some_and(|candidate| {
            candidate.tenant() != tenant
                || candidate.retention_generation() != expected
                || candidate.proposed_retention_seconds() != proposed_retention_seconds
        }) {
            return Err(BootstrapFailure::new(
                BootstrapFailureCode::TenantRetentionInvalidConfirmation,
            ));
        }
        self.update_tenant_retention_with_confirmation(
            actor,
            tenant,
            proposed_retention_seconds,
            expected,
            confirmation.map(|preview| {
                TenantRetentionPreviewConfirmation::new(
                    preview.confirmation_digest(),
                    preview.evaluated_at(),
                )
            }),
            idempotency,
        )
    }

    /// Publishes a retention successor using only an opaque confirmation that
    /// was returned by a prior preview. Exact retries resolve before a current
    /// preview is rebuilt; fresh reductions still bind the digest to current
    /// canonical retention evidence below.
    pub(crate) fn update_tenant_retention_with_confirmation(
        &self,
        actor: AuthorizedContext,
        tenant: TenantId,
        proposed_retention_seconds: NonZeroU64,
        expected: ResourceGeneration,
        confirmation: Option<TenantRetentionPreviewConfirmation>,
        idempotency: AdministrativeIdempotencyKey,
    ) -> Result<TenantRetentionUpdate, BootstrapFailure> {
        let requested_confirmation = confirmation
            .map(|confirmation| {
                RetentionImpactConfirmation::from_runtime_digest(confirmation.digest)
            })
            .transpose()
            .map_err(map_tenant_retention_failure)?;
        let prepared_replay = {
            let secret = self
                .key
                .catalog_secret(self.instance)
                .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
            let catalog = Catalog::open(&self._authority, self.instance, secret)
                .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
            TenantRetentionAdministration::resume_prepared_existing(
                &catalog,
                self.instance.to_bytes(),
                TenantRetentionUpdateRequest::new(
                    actor,
                    tenant,
                    proposed_retention_seconds,
                    expected,
                    requested_confirmation,
                    idempotency,
                ),
            )
            .map_err(map_tenant_retention_failure)?
        };
        if let Some(replay) = prepared_replay {
            return Ok(replay);
        }
        let (binding, preview_catalog) = if let Some(confirmation) = confirmation {
            let digest = confirmation.digest;
            let evaluation = confirmation.evaluation;
            let fresh =
                self.inspect_tenant_retention_impact(actor, tenant, proposed_retention_seconds)?;
            if evaluation > fresh.evaluated_at() {
                return Err(BootstrapFailure::new(
                    BootstrapFailureCode::TenantRetentionInvalidConfirmation,
                ));
            }
            let current = self.inspect_tenant_retention_impact_at(
                actor,
                tenant,
                proposed_retention_seconds,
                Some(evaluation),
            )?;
            if digest != current.confirmation_digest() {
                return Err(BootstrapFailure::new(
                    BootstrapFailureCode::TenantRetentionInvalidConfirmation,
                ));
            }
            if !fresh.current_impact_does_not_exceed(&current) {
                return Err(BootstrapFailure::new(
                    BootstrapFailureCode::TenantRetentionInvalidConfirmation,
                ));
            }
            (
                Some(
                    RetentionImpactConfirmation::from_runtime_digest(current.confirmation_digest())
                        .map_err(map_tenant_retention_failure)?,
                ),
                Some((current.catalog_identity(), current.catalog_generation())),
            )
        } else {
            (None, None)
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
        if preview_catalog.is_some_and(|(identity, generation)| {
            snapshot.identity() != identity || snapshot.number() != generation
        }) {
            return Err(BootstrapFailure::new(
                BootstrapFailureCode::TenantRetentionInvalidConfirmation,
            ));
        }
        let identity = positron_governance::Identity::open(&snapshot)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
        TenantRetentionAdministration::update(
            &catalog,
            &identity,
            TenantRetentionUpdateRequest::new(
                actor,
                tenant,
                proposed_retention_seconds,
                expected,
                binding,
                idempotency,
            ),
            || {
                self.retention_time
                    .governance_time_seconds(positron_kernel::SegmentScope::new(
                        tenant,
                        SignalKind::Logs,
                        self.logs_shard,
                    ))
                    .map_err(|_| TenantRetentionAdministrationFailure::TimeUnavailable)
            },
        )
        .map_err(map_tenant_retention_failure)
    }
}
