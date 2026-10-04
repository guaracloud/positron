use super::*;

impl InitializedInstance {
    /// Returns the bounded, decoded Governance Audit history visible to this
    /// authenticated principal. System administrators receive the complete
    /// retained history; tenant administrators receive only entries with an
    /// explicit matching tenant attribution.
    pub fn inspect_governance_audit_history(
        &self,
        actor: positron_governance::AuthorizedContext,
    ) -> Result<GovernanceAuditHistory, BootstrapFailure> {
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let view = Catalog::read_current_view(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let identity = positron_governance::Identity::open(view.snapshot())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
        let audit = view
            .governance_audit_records()
            .iter()
            .map(positron_governance::GovernanceAuditEntry::decode)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
        let inspection = identity
            .inspect_audit(actor, &audit)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ApiKeyUnauthorized))?;
        Ok(GovernanceAuditHistory {
            records: inspection.audit_records().cloned().collect(),
            retention_anchor_position: view
                .audit_retention_anchor()
                .map(positron_kernel::AuditRetentionAnchor::position),
        })
    }

    /// Publishes a signed checkpoint for the complete currently visible
    /// Governance Audit chain. Only the authenticated system administrator may
    /// request this system-governance maintenance action. When an equivalent
    /// worker-owned task is running before its signed artifact is durable, the
    /// authenticated request returns `GovernanceAuditCheckpointInProgress`
    /// with that task's stable identity; retrying the same request returns the
    /// exact artifact once it is durable.
    pub fn publish_governance_audit_checkpoint(
        &self,
        actor: positron_governance::AuthorizedContext,
    ) -> Result<positron_kernel::GovernanceAuditCheckpoint, BootstrapFailure> {
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        // The coordinator serializes public requests from their read-only
        // attachment decision through execution. This prevents a concurrent
        // reader from racing the selected caller's Catalog writer. A worker
        // has released the coordinator before its handler, so a worker-owned
        // request below returns immediately rather than waiting on it.
        let coordinator = self
            .maintenance_coordinator()
            .lock()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        // A worker's live durability reservation intentionally prevents a
        // second Catalog Writer from attaching to its task. Inspect the
        // authenticated read view first so an equivalent public request can
        // return the worker's exact durable signed artifact without waiting
        // under the coordinator or competing for that reservation.
        let view = Catalog::read_current_view(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let identity = positron_governance::Identity::open(view.snapshot())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
        identity
            .inspect(actor, &[])
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ApiKeyUnauthorized))?;
        let (_, governance) = view
            .snapshot()
            .governance_object()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
        if governance.integrity_key_fingerprint() != self.integrity_key_fingerprint {
            return Err(BootstrapFailure::new(
                BootstrapFailureCode::IdentityMismatch,
            ));
        }
        let signer = self
            .key
            .audit_checkpoint_signer(self.instance, governance.protected_integrity_key())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        if signer.public_key() != governance.integrity_public_key() {
            return Err(BootstrapFailure::new(
                BootstrapFailureCode::IdentityMismatch,
            ));
        }
        let frontier = view
            .governance_audit_records()
            .iter()
            .next_back()
            .cloned()
            .ok_or_else(|| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
        let (task, binding) = Catalog::governance_audit_checkpoint_task(
            &frontier,
            governance.integrity_key_fingerprint(),
        )
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let requested = task.identity();
        if let Some(checkpoint) = view
            .latest_audit_checkpoint()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?
            && checkpoint.instance() == self.instance
            && checkpoint.position() == frontier.position()
            && checkpoint.record_hash() == frontier.record_hash()
        {
            checkpoint
                .verify(signer.public_key())
                .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
            return Ok(checkpoint);
        }
        drop(view);
        match coordinator.status(requested) {
            Ok(status) if status.phase() == MaintenanceTaskPhase::Running => {
                return Err(BootstrapFailure::governance_audit_checkpoint_in_progress(
                    requested,
                ));
            },
            Ok(_) | Err(MaintenanceFailure::UnknownTask) => {},
            Err(_) => {
                return Err(BootstrapFailure::new(
                    BootstrapFailureCode::CatalogUnavailable,
                ));
            },
        }
        let now = self
            .retention_time
            .governance_now_seconds()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let catalog = match Catalog::open(&self._authority, self.instance, secret) {
            Ok(catalog) => catalog,
            Err(_) => {
                if coordinator
                    .status(requested)
                    .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?
                    .phase()
                    == MaintenanceTaskPhase::Running
                {
                    return Err(BootstrapFailure::governance_audit_checkpoint_in_progress(
                        requested,
                    ));
                }
                return Err(BootstrapFailure::new(
                    BootstrapFailureCode::CatalogUnavailable,
                ));
            },
        };
        coordinator
            .submit_governance_audit_checkpoint_and_persist(&catalog, task, binding, now)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let existing = catalog
            .latest_audit_checkpoint()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        if let Some(checkpoint) = existing
            && checkpoint.instance() == self.instance
            && checkpoint.position() == frontier.position()
            && checkpoint.record_hash() == frontier.record_hash()
        {
            checkpoint
                .verify(signer.public_key())
                .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
            return Ok(checkpoint);
        }
        let execution = coordinator
            .start_task_with_reservation_and_persist(
                &catalog,
                &self._authority,
                now,
                false,
                requested,
            )
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let execution = match execution {
            Some(execution) => execution,
            None if coordinator
                .status(requested)
                .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?
                .phase()
                == MaintenanceTaskPhase::Running =>
            {
                return Err(BootstrapFailure::governance_audit_checkpoint_in_progress(
                    requested,
                ));
            },
            None => {
                return Err(BootstrapFailure::new(
                    BootstrapFailureCode::CatalogUnavailable,
                ));
            },
        };
        self.complete_governance_audit_checkpoint_execution_with_coordinator(
            &catalog,
            &execution,
            &coordinator,
        )
    }

    pub(crate) fn complete_governance_audit_checkpoint_execution(
        &self,
        catalog: &Catalog<'_>,
        execution: &positron_kernel::MaintenanceExecution<'_>,
    ) -> Result<positron_kernel::GovernanceAuditCheckpoint, BootstrapFailure> {
        let coordinator = self
            .maintenance_coordinator()
            .lock()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        self.complete_governance_audit_checkpoint_execution_with_coordinator(
            catalog,
            execution,
            &coordinator,
        )
    }

    pub(in crate::instance_bootstrap) fn complete_governance_audit_checkpoint_execution_with_coordinator(
        &self,
        catalog: &Catalog<'_>,
        execution: &positron_kernel::MaintenanceExecution<'_>,
        coordinator: &positron_kernel::MaintenanceCoordinator,
    ) -> Result<positron_kernel::GovernanceAuditCheckpoint, BootstrapFailure> {
        let snapshot = catalog
            .pin()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let (_, governance) = snapshot
            .governance_object()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
        if governance.integrity_key_fingerprint() != self.integrity_key_fingerprint {
            return self.fail_governance_audit_checkpoint_execution(
                catalog,
                execution,
                coordinator,
                BootstrapFailureCode::IdentityMismatch,
            );
        }
        let binding = positron_kernel::GovernanceAuditCheckpointBinding::from_checkpoint(
            execution.task_checkpoint(),
        )
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
        if binding.integrity_key_fingerprint() != governance.integrity_key_fingerprint() {
            return self.fail_governance_audit_checkpoint_execution(
                catalog,
                execution,
                coordinator,
                BootstrapFailureCode::IdentityMismatch,
            );
        }
        let signer = self
            .key
            .audit_checkpoint_signer(self.instance, governance.protected_integrity_key())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        if signer.public_key() != governance.integrity_public_key() {
            return self.fail_governance_audit_checkpoint_execution(
                catalog,
                execution,
                coordinator,
                BootstrapFailureCode::IdentityMismatch,
            );
        }
        let checkpoint = catalog
            .publish_admitted_audit_checkpoint(
                execution,
                &signer,
                governance.integrity_key_fingerprint(),
            )
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        // The signed artifact is idempotent. Retry the exact terminal record
        // once while its reservation remains live. If storage still refuses
        // it, put the same binding back in the durable queue before releasing
        // that reservation; a same-process attach or restart can then resume.
        if execution
            .complete_and_persist(coordinator, catalog, true)
            .is_err()
            && execution
                .complete_and_persist(coordinator, catalog, true)
                .is_err()
        {
            if execution.requeue_and_persist(coordinator, catalog).is_err() {
                execution
                    .release_for_same_process_recovery(coordinator)
                    .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
            }
            return Err(BootstrapFailure::new(
                BootstrapFailureCode::CatalogUnavailable,
            ));
        }
        Ok(checkpoint)
    }

    fn fail_governance_audit_checkpoint_execution(
        &self,
        catalog: &Catalog<'_>,
        execution: &positron_kernel::MaintenanceExecution<'_>,
        coordinator: &positron_kernel::MaintenanceCoordinator,
        failure: BootstrapFailureCode,
    ) -> Result<positron_kernel::GovernanceAuditCheckpoint, BootstrapFailure> {
        execution
            .complete_and_persist(coordinator, catalog, false)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        Err(BootstrapFailure::new(failure))
    }

    /// Verifies the complete visible Governance Audit chain against the
    /// bootstrap-pinned Instance Integrity Key and an optional external trusted
    /// checkpoint anchor.
    pub fn verify_governance_audit_history(
        &self,
        actor: positron_governance::AuthorizedContext,
        trusted_checkpoint: Option<&positron_kernel::GovernanceAuditCheckpoint>,
    ) -> Result<(), BootstrapFailure> {
        let secret = self
            .key
            .catalog_secret(self.instance)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyCustodyUnavailable))?;
        let view = Catalog::read_current_view(&self._authority, self.instance, secret)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let identity = positron_governance::Identity::open(view.snapshot())
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
        identity
            .inspect(actor, &[])
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ApiKeyUnauthorized))?;
        let (_, governance) = view
            .snapshot()
            .governance_object()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
        if governance.integrity_key_fingerprint() != self.integrity_key_fingerprint {
            return Err(BootstrapFailure::new(
                BootstrapFailureCode::IdentityMismatch,
            ));
        }
        if let Some(anchor) = view.audit_retention_anchor() {
            view.verify_retained_audit_suffix(view.governance_audit_records())
                .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
            if let Some(checkpoint) = trusted_checkpoint {
                checkpoint
                    .verify(governance.integrity_public_key())
                    .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
                if checkpoint.instance() != self.instance {
                    return Err(BootstrapFailure::new(
                        BootstrapFailureCode::CatalogUnavailable,
                    ));
                }
                let checkpoint_hash = if checkpoint.position() == anchor.position() {
                    Some(anchor.record_hash())
                } else {
                    checkpoint
                        .position()
                        .checked_sub(anchor.position())
                        .and_then(|offset| offset.checked_sub(1))
                        .and_then(|offset| usize::try_from(offset).ok())
                        .and_then(|offset| {
                            view.governance_audit_records()
                                .get(offset)
                                .map(positron_kernel::GovernanceAuditRecord::record_hash)
                        })
                };
                if checkpoint_hash != Some(checkpoint.record_hash()) {
                    return Err(BootstrapFailure::new(
                        BootstrapFailureCode::CatalogUnavailable,
                    ));
                }
            }
            return Ok(());
        }
        let stored = view
            .latest_audit_checkpoint()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let checkpoint = trusted_checkpoint.or(stored.as_ref());
        view.verify_audit_chain(governance.integrity_public_key(), checkpoint)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))
    }

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
