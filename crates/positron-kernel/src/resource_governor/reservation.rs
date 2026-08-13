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

impl Drop for ResourceReservation<'_> {
    fn drop(&mut self) {
        self.release();
    }
}
