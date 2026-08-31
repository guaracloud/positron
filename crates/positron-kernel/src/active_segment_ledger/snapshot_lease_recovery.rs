use std::collections::{BTreeMap, BTreeSet};

use crate::{ResourceReservation, WorkClaim, WorkKind};

use super::capacity::lease_claim;
use super::snapshot_lease::{MAX_SNAPSHOT_LEASES, expired_in_scope, publish_many, records};
use super::snapshot_lease_codec::encode;
use super::snapshot_lease_record::{LeaseResumeMarker, SnapshotLeaseId, validate_active_lease};
use super::{LedgerFailure, LedgerFailureCode, SegmentScope};

pub(super) struct RecoveredLeases<'kernel> {
    pub(super) reservations: BTreeMap<SnapshotLeaseId, ResourceReservation<'kernel>>,
    pub(super) resume_markers: BTreeMap<SnapshotLeaseId, LeaseResumeMarker>,
    pub(super) last_observed: u64,
}

#[derive(Clone, Copy)]
enum LeaseRecoveryObservation {
    Unavailable,
    Current(u64),
    ConservativeFloor,
}

pub(super) enum LeaseRecoveryClock {
    Conservative(Option<u64>),
    Strict(Option<u64>),
}

impl LeaseRecoveryObservation {
    fn from_durable(now: Option<u64>, persisted_floor: u64) -> Self {
        match now {
            Some(now) if now < persisted_floor => Self::ConservativeFloor,
            Some(now) => Self::Current(now),
            None if persisted_floor != 0 => Self::ConservativeFloor,
            None => Self::Unavailable,
        }
    }

    const fn expiry_time(self) -> Option<u64> {
        match self {
            Self::Current(now) => Some(now),
            Self::Unavailable | Self::ConservativeFloor => None,
        }
    }
}

pub(super) fn recover_reservations<'kernel>(
    ledger_authority: &'kernel crate::StorageKernelResourceAuthority,
    catalog: &crate::Catalog<'_>,
    scope: SegmentScope,
    snapshot: &crate::CatalogSnapshot,
    clock: LeaseRecoveryClock,
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
    let now = match clock {
        LeaseRecoveryClock::Conservative(now) => now,
        LeaseRecoveryClock::Strict(now) => {
            if now.is_some_and(|now| now < persisted_last_observed) {
                return Err(LedgerFailure::new(LedgerFailureCode::InvalidInput));
            }
            now
        },
    };
    let observation = LeaseRecoveryObservation::from_durable(now, persisted_last_observed);
    let expiry_time = observation.expiry_time();
    let expired =
        expiry_time.map_or_else(BTreeSet::new, |now| expired_in_scope(&scoped, scope, now));
    let mut active = scoped
        .into_iter()
        .filter(|record| !expired.contains(&record.identity))
        .collect::<Vec<_>>();
    for record in &active {
        validate_active_lease(record, expiry_time.unwrap_or(record.observed_at))?;
    }
    if active.len() > MAX_SNAPSHOT_LEASES {
        return Err(LedgerFailure::new(LedgerFailureCode::LimitExceeded));
    }
    if let Some(now) = expiry_time
        .filter(|now| !expired.is_empty() || active.iter().any(|record| record.observed_at != *now))
    {
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
    let mut resume_markers = BTreeMap::new();
    for record in active {
        if record.resume_count > 0 {
            resume_markers.insert(
                record.identity,
                LeaseResumeMarker {
                    sequence: record.last_resume_sequence.unwrap_or_default(),
                    prior_digest: record.last_resume_prior_digest,
                    attempts: record.resume_count,
                    repeats: record.repeated_batch_count,
                    usage: record.usage,
                },
            );
        }
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
        resume_markers,
        last_observed: if persisted_last_observed == 0 {
            0
        } else {
            expiry_time.unwrap_or(persisted_last_observed)
        },
    })
}
