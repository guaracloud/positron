use std::collections::BTreeSet;

use super::super::capacity::lease_claim;
use super::super::snapshot_lease_codec::encode;
use super::super::snapshot_lease_record::LeaseRecord;
use super::snapshot_lease_support::{map_catalog_failure, publish, publish_many, records};
use super::{ActiveSegmentLedger, LedgerFailure, LedgerFailureCode};
use crate::{WorkClaim, WorkKind};

impl<'kernel, 'catalog> ActiveSegmentLedger<'kernel, 'catalog> {
    pub(in crate::active_segment_ledger) fn retry_pending_releases(
        &self,
        state: &mut super::super::state::LedgerState<'kernel>,
    ) -> Result<(), LedgerFailure> {
        let pending = state
            .pending_lease_releases
            .identities()
            .collect::<BTreeSet<_>>();
        if pending.is_empty() {
            return Ok(());
        }
        self.catalog
            .refresh_state()
            .map_err(|failure| LedgerFailure::new(map_catalog_failure(failure.code())))?;
        let basis = self.catalog.pin()?;
        let remove = records(&basis)?
            .into_iter()
            .filter(|record| record.scope == self.scope && pending.contains(&record.identity))
            .map(|record| record.identity)
            .collect::<BTreeSet<_>>();
        if !remove.is_empty() {
            publish(self.catalog, &basis, &remove, None)?;
        }
        for identity in pending {
            state.lease_reservations.remove(&identity);
            state.lease_reservation_baselines.remove(&identity);
            state.lease_resume_markers.remove(&identity);
        }
        state.pending_lease_releases.clear();
        Ok(())
    }

    pub(super) fn normalize_legacy_lease(
        &self,
        state: &mut super::super::state::LedgerState<'kernel>,
        record: &mut LeaseRecord,
        now: u64,
    ) -> Result<(), LedgerFailure> {
        let mut normalized = record.clone();
        normalized.observed_at = now;
        let encoded = encode(&normalized)?;
        let claim = WorkClaim::tenant(
            self.scope.tenant,
            WorkKind::InteractiveQueryTail,
            lease_claim(encoded.len())?,
        )
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        let retained = self
            .authority
            .governor()
            .reserve(claim)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
        self.catalog
            .refresh_state()
            .map_err(|failure| LedgerFailure::new(map_catalog_failure(failure.code())))?;
        let basis = self.catalog.pin()?;
        publish_many(
            self.catalog,
            &basis,
            &BTreeSet::from([record.identity]),
            vec![encoded],
        )?;
        let previous = state.lease_reservations.insert(record.identity, retained);
        state.lease_reservation_baselines.remove(&record.identity);
        let Some(previous) = previous else {
            return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
        };
        drop(previous);
        *record = normalized;
        Ok(())
    }
}
