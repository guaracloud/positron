use crate::Catalog;
use crate::resource_governor::{StorageKernelResourceAuthority, WorkClaim, WorkKind};

use super::capacity::{recovery_claim, snapshot_retained_claim};
use super::reconstruction::reconstruct;
use super::recovery::RecoveryMode;
use super::storage::LedgerStorage;
use super::{
    ActiveSegmentLedger, LedgerFailure, LedgerFailureCode, LedgerSnapshot, SegmentProtectionKey,
    SegmentScope,
};

const MAX_SNAPSHOT_RETRIES: usize = 2;

/// A read-only authenticated observation handle for one ledger scope.
///
/// Unlike [`super::ActiveSegmentLedger`], this handle never acquires the
/// active-segment writer lease and never repairs storage. Each snapshot pins a
/// fresh Catalog generation and reconstructs only its acknowledged objects.
pub struct CommittedLedgerReader<'kernel, 'catalog, 'ledger> {
    authority: &'kernel StorageKernelResourceAuthority,
    catalog: &'catalog Catalog<'kernel>,
    scope: SegmentScope,
    storage: LedgerStorage,
    protection: SegmentProtectionKey,
    lease_authority: Option<&'ledger ActiveSegmentLedger<'kernel, 'catalog>>,
}

impl std::fmt::Debug for CommittedLedgerReader<'_, '_, '_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CommittedLedgerReader { <storage-and-key-redacted> }")
    }
}

impl<'kernel, 'catalog, 'ledger> CommittedLedgerReader<'kernel, 'catalog, 'ledger> {
    #[must_use]
    pub const fn scope(&self) -> SegmentScope {
        self.scope
    }

    pub fn open(
        authority: &'kernel StorageKernelResourceAuthority,
        catalog: &'catalog Catalog<'kernel>,
        scope: SegmentScope,
        protection: SegmentProtectionKey,
    ) -> Result<Self, LedgerFailure> {
        let volume = authority
            .primary_data_volume()
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::StorageUnavailable))?;
        Ok(Self {
            authority,
            catalog,
            scope,
            storage: LedgerStorage::open_observed(volume)?,
            protection,
            lease_authority: None,
        })
    }

    pub(crate) fn open_with_lease_authority(
        ledger: &'ledger ActiveSegmentLedger<'kernel, 'catalog>,
    ) -> Result<Self, LedgerFailure> {
        let mut reader = Self::open(
            ledger.authority,
            ledger.catalog,
            ledger.scope,
            ledger.protection.clone(),
        )?;
        reader.lease_authority = Some(ledger);
        Ok(reader)
    }

    /// Returns the internal lease authority for a reader created by an active
    /// ledger. Tail admission uses it to pin every involved source; callers
    /// cannot release or transfer the returned capability directly.
    pub fn lease_authority(&self) -> Option<&'ledger ActiveSegmentLedger<'kernel, 'catalog>> {
        self.lease_authority
    }

    /// Captures one complete Catalog generation and its acknowledged durable
    /// blocks. A concurrent publication causes a bounded retry, never a mixed
    /// generation result.
    pub fn snapshot(&self) -> Result<LedgerSnapshot<'kernel>, LedgerFailure> {
        for attempt in 0..MAX_SNAPSHOT_RETRIES {
            self.catalog.refresh_state()?;
            let basis = self.catalog.pin()?;
            let metadata = self.storage.catalog_segments_observed(&basis, self.scope)?;
            let reconstruction_claim = WorkClaim::tenant(
                self.scope.tenant_id(),
                WorkKind::InteractiveQueryTail,
                recovery_claim(),
            )
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
            let _reconstruction_capacity = self
                .authority
                .governor()
                .reserve(reconstruction_claim)
                .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
            let reconstruction = reconstruct(
                &self.storage,
                &metadata,
                &self.protection,
                self.catalog.instance(),
                RecoveryMode::Observe,
            )?;
            self.catalog.refresh_state()?;
            let current = self.catalog.pin()?;
            let current_metadata = self
                .storage
                .catalog_segments_observed(&current, self.scope)?;
            if basis.identity() != current.identity()
                || basis.number() != current.number()
                || metadata != current_metadata
            {
                if attempt + 1 < MAX_SNAPSHOT_RETRIES {
                    continue;
                }
                return Err(LedgerFailure::new(LedgerFailureCode::StaleGeneration));
            }
            let claim = WorkClaim::tenant(
                self.scope.tenant_id(),
                WorkKind::InteractiveQueryTail,
                snapshot_retained_claim(
                    reconstruction.retained_bytes,
                    reconstruction.blocks.len(),
                )?,
            )
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
            let capacity = self
                .authority
                .governor()
                .reserve(claim)
                .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
            return Ok(LedgerSnapshot {
                _capacity: capacity,
                scope: self.scope,
                frontier: reconstruction.frontier,
                catalog_generation: basis.number(),
                catalog_identity: basis.identity(),
                blocks: reconstruction.blocks,
            });
        }
        Err(LedgerFailure::new(LedgerFailureCode::StaleGeneration))
    }
}
