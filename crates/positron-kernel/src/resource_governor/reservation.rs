use super::*;

impl<'authority> ResourceReservation<'authority> {
    pub(super) fn new(
        governor: &'authority GovernorInner,
        owner: accounting::ChargeOwner,
        identity: ReservationIdentity,
        amounts: ResourceAmounts,
        slot: u16,
    ) -> Self {
        Self {
            governor,
            owner,
            identity,
            amounts,
            slot,
            active: true,
        }
    }

    /// Releases the reservation immediately. Dropping has identical accounting semantics.
    pub fn cancel(&mut self) -> Result<ReleaseOutcome, GovernorFailure> {
        if !self.active {
            return Ok(ReleaseOutcome::AlreadyInactive);
        }
        let status = self
            .governor
            .try_release(self.slot, self.owner, self.identity, self.amounts);
        if status.applied {
            self.active = false;
        }
        status.result
    }

    /// Transfers drop-based release across an asynchronous boundary without
    /// creating another capacity authority.
    pub fn transfer(mut self) -> TransferredResourceReservation {
        self.active = false;
        TransferredResourceReservation {
            drop_ledger: Arc::clone(&self.governor.drop_ledger),
            slot: self.slot,
            owner: self.owner,
            identity: self.identity,
            amounts: self.amounts,
            active: true,
        }
    }

    /// Atomically replaces the grant while preserving immutable work identity.
    pub fn try_resize(
        &mut self,
        new_amounts: ResourceAmounts,
    ) -> Result<ResizeOutcome, ResizeFailure> {
        if !self.active {
            return Err(ResizeFailure::inactive(
                self.identity.class(),
                self.governor.pressure_for_failure(),
            ));
        }
        if new_amounts.is_empty() {
            return Err(ResizeFailure::invalid(
                self.identity.class(),
                self.governor.pressure_for_failure(),
            ));
        }
        match self.governor.resize(resize::ResizeRequest {
            slot: self.slot,
            owner: self.owner,
            identity: self.identity,
            old: self.amounts,
            new: new_amounts,
        }) {
            Ok(commit) => {
                self.owner = commit.owner;
                self.amounts = new_amounts;
                Ok(commit.outcome)
            },
            Err(failure)
                if failure.existing_capacity()
                    == ExistingCapacityDisposition::CancelledBeforeLimit =>
            {
                self.active = false;
                self.amounts = ResourceAmounts::zero();
                Err(failure)
            },
            Err(failure) => Err(failure),
        }
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.active
    }

    #[must_use]
    pub const fn granted(&self) -> ResourceAmounts {
        self.amounts
    }

    /// Confirms that this move-only grant owns enough tenant ingest memory for
    /// signal-specific Store Block preparation.
    #[must_use]
    pub fn authorizes_ingest_preparation(
        &self,
        tenant: positron_domain::identity::TenantId,
        memory_bytes: u64,
    ) -> bool {
        self.active
            && matches!(
                self.identity,
                ReservationIdentity::Ordinary {
                    tenant: reserved_tenant,
                    kind: WorkKind::Ingest,
                } if reserved_tenant == tenant
            )
            && self.amounts.get(ResourceDimension::MemoryBytes) >= memory_bytes
    }

    /// Confirms that this live grant governs one tenant schema-session construction.
    #[must_use]
    pub fn authorizes_tenant_schema_session(
        &self,
        tenant: positron_domain::identity::TenantId,
        memory_bytes: u64,
    ) -> bool {
        let tenant_bound = match self.identity {
            ReservationIdentity::Ordinary {
                tenant: reserved_tenant,
                kind: WorkKind::Ingest,
            } => reserved_tenant == tenant,
            ReservationIdentity::Recovery {
                scope: RecoveryScope::Tenant(reserved_tenant),
                kind: RecoveryWorkKind::Repair,
            } => reserved_tenant == tenant,
            _ => false,
        };
        self.active
            && tenant_bound
            && self.amounts.get(ResourceDimension::MemoryBytes) >= memory_bytes
    }

    pub(crate) fn belongs_to(&self, governor: ResourceGovernor<'_>) -> bool {
        std::ptr::eq(self.governor, governor.inner)
    }

    fn release(&mut self) {
        if self.active {
            self.governor.mark_drop_pending(self.slot);
            self.active = false;
        }
    }
}

impl TransferredResourceReservation {
    /// Reports whether this move-only grant can be reclaimed by `governor`
    /// without consuming or releasing the grant.
    #[must_use]
    pub fn can_reclaim_with(&self, governor: ResourceGovernor<'_>) -> bool {
        Arc::ptr_eq(&self.drop_ledger, &governor.inner.drop_ledger)
    }

    /// Rebinds this move-only token to the same governor that granted it.
    pub fn reclaim(
        mut self,
        governor: ResourceGovernor<'_>,
    ) -> Result<ResourceReservation<'_>, GovernorFailure> {
        if !self.can_reclaim_with(governor) {
            governor.inner.mark_foreign_release();
            return Err(GovernorFailure::InternalFenced);
        }
        self.active = false;
        Ok(ResourceReservation::new(
            governor.inner,
            self.owner,
            self.identity,
            self.amounts,
            self.slot,
        ))
    }

    /// Returns this slot to the same Resource Governor that granted it.
    pub fn release(self, governor: ResourceGovernor<'_>) {
        if !Arc::ptr_eq(&self.drop_ledger, &governor.inner.drop_ledger) {
            governor.inner.mark_foreign_release();
        }
    }
}

impl Drop for TransferredResourceReservation {
    fn drop(&mut self) {
        if self.active {
            self.drop_ledger.mark_drop_pending(self.slot);
            self.active = false;
        }
    }
}

impl Drop for ResourceReservation<'_> {
    fn drop(&mut self) {
        self.release();
    }
}
