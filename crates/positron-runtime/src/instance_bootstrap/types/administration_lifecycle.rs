use super::*;

impl InitializedInstance {
    /// Accepts, checkpoints, and resumes the existing catalog-format handler.
    ///
    /// Cancellation is possible only while the record remains `Pending`.
    /// Once data admission has drained, the operation records that cancellation
    /// cannot undo a future published Catalog generation. Every checkpoint and
    /// the handler publication acquire the kernel's catalog-commit recovery
    /// reservation; restart reattaches by the original idempotency key.
    pub fn migrate_catalog_to_epoch_two_as_operation(
        &self,
        actor: AuthorizedContext,
        idempotency: AdministrativeIdempotencyKey,
    ) -> Result<DurableOperation, BootstrapFailure> {
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let catalog = Catalog::open(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let now = self.operation_time_seconds()?;
        let operation =
            match DurableOperationAdministration::inspect_by_idempotency(&catalog, idempotency)
                .map_err(map_durable_operation_failure)?
            {
                Some(existing) => {
                    if existing.request().principal() != actor.principal_id() {
                        return Err(BootstrapFailure::new(
                            BootstrapFailureCode::ApiKeyIdempotencyConflict,
                        ));
                    }
                    existing
                },
                None => {
                    let generation = catalog
                        .pin()
                        .map_err(|_| {
                            BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable)
                        })?
                        .number();
                    let request = DurableOperationRequest::catalog_format_migration(
                        actor.principal_id(),
                        idempotency,
                        generation,
                        now,
                    )
                    .map_err(map_durable_operation_failure)?;
                    DurableOperationAdministration::accept_catalog_format_migration(
                        &catalog, actor, request,
                    )
                    .map_err(map_durable_operation_failure)?
                },
            };
        if operation.status().is_terminal() {
            return Ok(operation);
        }
        let operation = if operation.status() == DurableOperationStatus::Pending {
            DurableOperationAdministration::begin(&catalog, actor, operation.operation_id(), now)
                .map_err(map_durable_operation_failure)?
        } else {
            operation
        };
        let _drain = self.tenant_drains.close_all_and_drain()?;
        let operation =
            if operation.phase() == positron_governance::DurableOperationPhase::Preflight {
                DurableOperationAdministration::mark_drained(
                    &catalog,
                    actor,
                    operation.operation_id(),
                    now,
                )
                .map_err(map_durable_operation_failure)?
            } else {
                operation
            };
        CatalogFormatMigrationAdministration::migrate_to_epoch_two(
            &catalog,
            self.administrator,
            actor,
            idempotency,
        )
        .map_err(map_catalog_format_migration_failure)?;
        DurableOperationAdministration::succeed_catalog_format_migration(
            &catalog,
            actor,
            operation.operation_id(),
            now,
        )
        .map_err(map_durable_operation_failure)
    }

    fn operation_time_seconds(&self) -> Result<u64, BootstrapFailure> {
        let scope =
            positron_kernel::SegmentScope::new(self.tenant, SignalKind::Logs, self.logs_shard);
        self.retention_time
            .governance_time_seconds(scope)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))
    }

    /// Publishes the concrete V1-to-V2 Catalog transformation while both
    /// native data admission gates are closed. Broader upgrade orchestration
    /// remains outside this narrowly scoped format transition.
    pub fn migrate_catalog_to_epoch_two(
        &self,
        actor: AuthorizedContext,
        idempotency: AdministrativeIdempotencyKey,
    ) -> Result<CatalogFormatMigration, BootstrapFailure> {
        let preflight = self.catalog_migration_preflight(actor, idempotency)?;
        if let Some(replay) = preflight {
            return Ok(replay);
        }
        #[cfg(test)]
        let catalog_migration_preflight_hook = self
            .catalog_migration_preflight_hook
            .lock()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?
            .clone();
        #[cfg(test)]
        if let Some(hook) = catalog_migration_preflight_hook {
            hook();
        }
        let _drain = self.tenant_drains.close_all_and_drain()?;
        let preflight = self.catalog_migration_preflight(actor, idempotency)?;
        if let Some(replay) = preflight {
            return Ok(replay);
        }
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let catalog = Catalog::open(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        CatalogFormatMigrationAdministration::migrate_to_epoch_two(
            &catalog,
            self.administrator,
            actor,
            idempotency,
        )
        .map_err(map_catalog_format_migration_failure)
    }

    fn catalog_migration_preflight(
        &self,
        actor: AuthorizedContext,
        idempotency: AdministrativeIdempotencyKey,
    ) -> Result<Option<CatalogFormatMigration>, BootstrapFailure> {
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let view = Catalog::read_current_view(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        if let Some(replay) = CatalogFormatMigrationAdministration::replay_from_view(
            &view,
            self.administrator,
            actor,
            idempotency,
        )
        .map_err(map_catalog_format_migration_failure)?
        {
            return Ok(Some(replay));
        }
        CatalogFormatMigrationAdministration::preflight_from_view(&view, self.administrator, actor)
            .map_err(map_catalog_format_migration_failure)?;
        Ok(None)
    }

    /// Reads the currently authenticated Catalog format without acquiring the
    /// writer or exposing any Catalog object content.
    pub fn catalog_format_epoch(
        &self,
    ) -> Result<Option<positron_kernel::FormatEpoch>, BootstrapFailure> {
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        Catalog::read_current_snapshot(&self._authority, self.instance, secret)
            .map(|snapshot| snapshot.format_epoch())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))
    }

    /// Publishes one authenticated lifecycle successor for the explicitly named tenant.
    ///
    /// `Purged` is intentionally unavailable here: only the later managed purge
    /// authority may complete the verified destructive operation.
    pub fn transition_tenant_lifecycle(
        &self,
        actor: AuthorizedContext,
        tenant: TenantId,
        target: TenantLifecycleState,
        expected: ResourceGeneration,
        idempotency: AdministrativeIdempotencyKey,
    ) -> Result<TenantLifecycleTransition, BootstrapFailure> {
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let request =
            TenantLifecycleTransitionRequest::new(actor, tenant, target, expected, idempotency);
        let preflight = Catalog::read_current_view(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        if let Some(replay) =
            TenantLifecycleAdministration::replay_from_view(&preflight, self.administrator, request)
                .map_err(map_tenant_lifecycle_failure)?
        {
            return Ok(replay);
        }
        TenantLifecycleAdministration::preflight_from_view(&preflight, self.administrator, request)
            .map_err(map_tenant_lifecycle_failure)?;
        #[cfg(test)]
        let lifecycle_preflight_hook = self
            .lifecycle_preflight_hook
            .lock()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?
            .clone();
        #[cfg(test)]
        if let Some(hook) = lifecycle_preflight_hook {
            hook();
        }
        let _mutation = self.tenant_drains.begin_lifecycle_mutation(tenant)?;
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let preflight = Catalog::read_current_view(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        if let Some(replay) =
            TenantLifecycleAdministration::replay_from_view(&preflight, self.administrator, request)
                .map_err(map_tenant_lifecycle_failure)?
        {
            return Ok(replay);
        }
        TenantLifecycleAdministration::preflight_from_view(&preflight, self.administrator, request)
            .map_err(map_tenant_lifecycle_failure)?;
        let _drain = self.tenant_drains.close_and_drain(tenant)?;
        let _query_drain = match target {
            TenantLifecycleState::Suspended | TenantLifecycleState::Purging => {
                Some(self.tenant_drains.cancel_and_drain(tenant)?)
            },
            TenantLifecycleState::Active
            | TenantLifecycleState::ReadOnly
            | TenantLifecycleState::Purged => None,
        };
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let catalog = Catalog::open(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let audit_scope =
            positron_kernel::SegmentScope::new(self.tenant, SignalKind::Logs, self.logs_shard);
        TenantLifecycleAdministration::transition(&catalog, self.administrator, request, || {
            self.retention_time
                .governance_time_seconds(audit_scope)
                .map_err(|_| TenantLifecycleAdministrationFailure::TimeUnavailable)
        })
        .map_err(map_tenant_lifecycle_failure)
    }

    /// Binds one external compatibility assertion to a tenant. The alias is
    /// never an authority selector: authentication still attributes requests
    /// to the credential's immutable tenant before this value is consulted.
    pub fn bind_tenant_alias(
        &self,
        actor: AuthorizedContext,
        tenant: TenantId,
        alias: ExternalTenantAlias,
        expected: ResourceGeneration,
        idempotency: AdministrativeIdempotencyKey,
    ) -> Result<TenantAliasBinding, BootstrapFailure> {
        let request = TenantAliasBindRequest::new(actor, tenant, alias, expected, idempotency);
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let preflight = Catalog::read_current_view(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        if let Some(replay) = TenantAliasAdministration::replay_from_view(
            &preflight,
            self.administrator,
            request.clone(),
        )
        .map_err(map_tenant_alias_failure)?
        {
            return Ok(replay);
        }
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let catalog = Catalog::open(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let audit_scope =
            positron_kernel::SegmentScope::new(self.tenant, SignalKind::Logs, self.logs_shard);
        TenantAliasAdministration::bind(&catalog, self.administrator, request, || {
            self.retention_time
                .governance_time_seconds(audit_scope)
                .map_err(|_| TenantAliasAdministrationFailure::TimeUnavailable)
        })
        .map_err(map_tenant_alias_failure)
    }

    /// Returns decoded audit evidence through the same authenticated Catalog
    /// reader used by lifecycle integration tests.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn governance_audit_for_test(
        &self,
    ) -> Result<Vec<positron_governance::GovernanceAuditEntry>, BootstrapFailure> {
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let catalog = Catalog::open(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        catalog
            .governance_audit_records()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?
            .into_iter()
            .map(|record| {
                positron_governance::GovernanceAuditEntry::decode(&record)
                    .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))
            })
            .collect()
    }
}
