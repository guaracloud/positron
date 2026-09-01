use super::*;

impl StorageKernelResourceAuthority {
    pub(super) fn from_configuration(
        ownership: KernelOwnership,
        configuration: ResourceGovernorConfiguration,
    ) -> Self {
        let ResourceGovernorConfiguration {
            inner,
            active_segment_scopes,
            volume_binding: _,
        } = configuration;
        Self {
            inner: GovernorInner::new(ownership, inner),
            catalog_writer_held: AtomicBool::new(false),
            active_segment_scopes: Mutex::new(active_segment_scopes),
            snapshot_protection: Arc::new(Mutex::new(std::collections::BTreeMap::new())),
            snapshot_barrier: RwLock::new(()),
        }
    }

    #[cfg(test)]
    pub(super) fn establish_for_test(
        inventory: ResourceInventory,
        policy: GovernorPolicy,
        recovery_pools: RecoveryPoolCapacities,
    ) -> Result<Self, GovernorFailure> {
        let configuration = ResourceGovernorConfiguration::new(inventory, policy, recovery_pools)?;
        Ok(Self::from_configuration(
            KernelOwnership::TestOnly,
            configuration,
        ))
    }

    /// Establishes an isolated complete authority for the fuzz harness.
    #[cfg(fuzzing)]
    #[doc(hidden)]
    pub fn establish_for_fuzz(
        inventory: ResourceInventory,
        policy: GovernorPolicy,
        recovery_pools: RecoveryPoolCapacities,
    ) -> Result<Self, GovernorFailure> {
        let configuration = ResourceGovernorConfiguration::new(inventory, policy, recovery_pools)?;
        Ok(Self::from_configuration(
            KernelOwnership::TestOnly,
            configuration,
        ))
    }

    /// Establishes fuzz-only authority while retaining a real owned test volume.
    #[cfg(fuzzing)]
    #[doc(hidden)]
    pub fn establish_for_fuzz_with_volume(
        volume: crate::OwnedPrimaryDataVolume,
        inventory: ResourceInventory,
        policy: GovernorPolicy,
        recovery_pools: RecoveryPoolCapacities,
    ) -> Result<Self, GovernorFailure> {
        let configuration = ResourceGovernorConfiguration::new(inventory, policy, recovery_pools)?;
        Ok(Self::from_configuration(
            KernelOwnership::Owned { volume },
            configuration,
        ))
    }

    /// Establishes the sole governor after earlier private bootstrap/recovery steps.
    #[expect(
        clippy::result_large_err,
        reason = "the recoverable mismatch must return both non-allocating move-only capabilities"
    )]
    pub fn establish(
        volume: crate::OwnedPrimaryDataVolume,
        configuration: ResourceGovernorConfiguration,
    ) -> Result<Self, EstablishmentFailure> {
        if configuration
            .volume_binding
            .as_ref()
            .is_none_or(|binding| !binding.matches(&volume))
        {
            return Err(EstablishmentFailure {
                failure: GovernorFailure::ObservedVolumeMismatch,
                volume,
                configuration,
            });
        }
        Ok(Self::from_configuration(
            KernelOwnership::Owned { volume },
            configuration,
        ))
    }

    /// Borrows ordinary admission authority without permitting duplication.
    #[must_use]
    pub const fn governor(&self) -> ResourceGovernor<'_> {
        ResourceGovernor { inner: &self.inner }
    }

    /// Borrows the governor-bound protected recovery authority.
    #[must_use]
    pub const fn recovery(&self) -> RecoveryAuthority<'_> {
        RecoveryAuthority { inner: &self.inner }
    }

    pub(crate) const fn primary_data_volume(&self) -> Option<&crate::OwnedPrimaryDataVolume> {
        match &self.inner.ownership {
            KernelOwnership::Owned { volume } => Some(volume),
            #[cfg(any(test, fuzzing))]
            KernelOwnership::TestOnly => None,
        }
    }

    pub(crate) fn acquire_catalog_writer(&self) -> Option<CatalogWriterLease<'_>> {
        self.catalog_writer_held
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| CatalogWriterLease {
                held: &self.catalog_writer_held,
            })
    }

    pub(crate) fn snapshot_protection(
        &self,
    ) -> Arc<Mutex<std::collections::BTreeMap<[u8; 16], usize>>> {
        Arc::clone(&self.snapshot_protection)
    }

    pub(crate) fn snapshot_barrier(&self) -> &RwLock<()> {
        &self.snapshot_barrier
    }

    #[cfg(test)]
    pub(super) fn reserve(
        &self,
        claim: WorkClaim,
    ) -> Result<ResourceReservation<'_>, AdmissionFailure> {
        self.governor().reserve(claim)
    }

    #[cfg(test)]
    pub(super) fn inspect(&self) -> Result<ResourceSnapshot, GovernorFailure> {
        self.governor().inspect()
    }

    /// Re-observes the retained Primary Data Volume and applies disk pressure.
    pub fn observe_disk(&self) -> Result<DiskPressureState, GovernorFailure> {
        let volume = match &self.inner.ownership {
            KernelOwnership::Owned { volume } => volume,
            #[cfg(any(test, fuzzing))]
            KernelOwnership::TestOnly => {
                return Err(GovernorFailure::PrimaryVolumeObservationUnavailable);
            },
        };
        let usable_bytes = capacity_observation::observe_disk_bytes(volume)
            .map_err(|_| GovernorFailure::PrimaryVolumeObservationUnavailable)?;
        self.inner
            .apply_disk_observation(DiskObservation::from_observed(usable_bytes))
    }

    #[cfg(test)]
    pub(crate) fn observe_disk_for_test(
        &self,
        observation: DiskObservation,
    ) -> Result<DiskPressureState, GovernorFailure> {
        self.inner.apply_disk_observation(observation)
    }

    #[cfg(fuzzing)]
    #[doc(hidden)]
    pub fn observe_disk_for_fuzz(
        &self,
        observation: DiskObservation,
    ) -> Result<DiskPressureState, GovernorFailure> {
        self.inner.apply_disk_observation(observation)
    }

    /// Closes new work without waiting and returns bounded reconciliation state.
    pub fn begin_shutdown(&self) -> Result<ShutdownReconciliation, GovernorFailure> {
        Ok(ShutdownReconciliation {
            snapshot: ResourceSnapshot::from_accounting(self.inner.begin_shutdown()?),
        })
    }
}
