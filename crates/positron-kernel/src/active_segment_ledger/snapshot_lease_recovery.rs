use std::collections::{BTreeMap, BTreeSet};

use crate::{ResourceReservation, WorkClaim, WorkKind};

use super::capacity::lease_claim;
use super::snapshot_lease::{MAX_SNAPSHOT_LEASES, expired_in_scope, publish_many, records};
use super::snapshot_lease_codec::encode;
use super::snapshot_lease_record::{SnapshotLeaseId, validate_active_lease};
use super::{LedgerFailure, LedgerFailureCode, SegmentScope};

pub(super) struct RecoveredLeases<'kernel> {
    pub(super) reservations: BTreeMap<SnapshotLeaseId, ResourceReservation<'kernel>>,
    pub(super) last_observed: u64,
}

pub(super) fn recover_reservations<'kernel>(
    ledger_authority: &'kernel crate::StorageKernelResourceAuthority,
    catalog: &crate::Catalog<'_>,
    scope: SegmentScope,
    snapshot: &crate::CatalogSnapshot,
    now: u64,
) -> Result<RecoveredLeases<'kernel>, LedgerFailure> {
    let scoped = records(snapshot)?
        .into_iter()
        .filter(|record| record.scope == scope)
        .collect::<Vec<_>>();
    let persisted_last_observed = scoped
        .iter()
        .map(|record| record.observed_at)
        .max()
        .unwrap_or(0);
    if now < persisted_last_observed {
        return Err(LedgerFailure::new(LedgerFailureCode::InvalidInput));
    }
    let expired = expired_in_scope(&scoped, scope, now);
    let mut active = scoped
        .into_iter()
        .filter(|record| !expired.contains(&record.identity))
        .collect::<Vec<_>>();
    for record in &active {
        validate_active_lease(record, now)?;
    }
    if active.len() > MAX_SNAPSHOT_LEASES {
        return Err(LedgerFailure::new(LedgerFailureCode::LimitExceeded));
    }
    let requires_publication =
        !expired.is_empty() || active.iter().any(|record| record.observed_at != now);
    if requires_publication {
        let remove = active
            .iter()
            .map(|record| record.identity)
            .chain(expired.iter().copied())
            .collect::<BTreeSet<_>>();
        for record in &mut active {
            record.observed_at = now;
        }
        let additions = active.iter().map(encode).collect::<Result<Vec<_>, _>>()?;
        publish_many(catalog, snapshot, &remove, additions)?;
    }
    let mut retained = BTreeMap::new();
    for record in active {
        let encoded = encode(&record)?;
        let claim = WorkClaim::tenant(
            scope.tenant,
            WorkKind::InteractiveQueryTail,
            lease_claim(encoded.len())?,
        )
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        let reservation = ledger_authority
            .governor()
            .reserve(claim)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
        if retained.insert(record.identity, reservation).is_some() {
            return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
        }
    }
    Ok(RecoveredLeases {
        reservations: retained,
        last_observed: if persisted_last_observed == 0 { 0 } else { now },
    })
}
