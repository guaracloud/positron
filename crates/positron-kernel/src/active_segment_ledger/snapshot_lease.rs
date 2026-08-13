use std::collections::BTreeMap;

use positron_domain::routing::CommitPosition;

use crate::catalog::{CatalogObject, CatalogProposal, FormatEpoch, TransactionId};
use crate::data_protection::DataProtection;
use crate::{ResourceReservation, WorkClaim, WorkKind};

use super::capacity::{lease_claim, snapshot_claim};
use super::snapshot_lease_codec::{decode, encode};
use super::{
    ActiveSegmentLedger, FORMAT_EPOCH, LedgerFailure, LedgerFailureCode, LedgerSnapshot, SegmentId,
    SegmentScope, StoreBlockIdentity, map_frame_failure,
};
pub(super) const MAX_SNAPSHOT_LEASES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SnapshotLeaseId([u8; 16]);

impl SnapshotLeaseId {
    pub fn new(bytes: [u8; 16]) -> Result<Self, LedgerFailure> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(LedgerFailure::new(LedgerFailureCode::InvalidInput));
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn to_bytes(self) -> [u8; 16] {
        self.0
    }
}

pub struct SnapshotLeaseGrant<'kernel> {
    identity: SnapshotLeaseId,
    expiry: u64,
    snapshot: LedgerSnapshot<'kernel>,
}

impl std::fmt::Debug for SnapshotLeaseGrant<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SnapshotLeaseGrant")
            .field("identity", &self.identity)
            .field("expiry", &self.expiry)
            .field("snapshot", &"<pinned>")
            .finish()
    }
}

impl<'kernel> SnapshotLeaseGrant<'kernel> {
    #[must_use]
    pub const fn identity(&self) -> SnapshotLeaseId {
        self.identity
    }

    #[must_use]
    pub const fn expiry(&self) -> u64 {
        self.expiry
    }

    #[must_use]
    pub const fn snapshot(&self) -> &LedgerSnapshot<'kernel> {
        &self.snapshot
    }

    #[must_use]
    pub fn into_snapshot(self) -> LedgerSnapshot<'kernel> {
        self.snapshot
    }
}

#[derive(Clone)]
pub(super) struct LeaseRecord {
    pub(super) identity: SnapshotLeaseId,
    pub(super) scope: SegmentScope,
    pub(super) catalog_identity: crate::CatalogGenerationId,
    pub(super) catalog_generation: u64,
    pub(super) frontier: CommitPosition,
    pub(super) expiry: u64,
    pub(super) blocks: Vec<LeaseBlock>,
}

#[derive(Clone, Copy)]
pub(super) struct LeaseBlock {
    pub(super) identity: StoreBlockIdentity,
    pub(super) position: CommitPosition,
    pub(super) segment: SegmentId,
}

impl<'kernel, 'catalog> ActiveSegmentLedger<'kernel, 'catalog> {
    pub fn create_snapshot_lease(
        &self,
        expiry: u64,
    ) -> Result<SnapshotLeaseGrant<'kernel>, LedgerFailure> {
        if expiry == 0 {
            return Err(LedgerFailure::new(LedgerFailureCode::InvalidInput));
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))?;
        let basis = self.catalog.pin()?;
        let records = records(&basis)?;
        if records.len() >= MAX_SNAPSHOT_LEASES {
            return Err(LedgerFailure::new(LedgerFailureCode::LimitExceeded));
        }
        let identity = fresh_identity()?;
        let record = LeaseRecord {
            identity,
            scope: self.scope,
            catalog_identity: basis.identity(),
            catalog_generation: basis.number(),
            frontier: state.frontier,
            expiry,
            blocks: state.blocks.iter().map(LeaseBlock::from).collect(),
        };
        let encoded = encode(&record)?;
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
        publish(self.catalog, &basis, None, Some(encoded))?;
        state.lease_reservations.insert(identity, retained);
        let snapshot = snapshot_from_record(self, &state, &record)?;
        Ok(SnapshotLeaseGrant {
            identity,
            expiry,
            snapshot,
        })
    }

    pub fn resume_snapshot_lease(
        &self,
        identity: SnapshotLeaseId,
        now: u64,
    ) -> Result<SnapshotLeaseGrant<'kernel>, LedgerFailure> {
        let basis = self.catalog.pin()?;
        let record = records(&basis)?
            .into_iter()
            .find(|record| record.identity == identity && record.scope == self.scope)
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::SnapshotExpired))?;
        if now >= record.expiry {
            self.release_snapshot_lease(identity)?;
            return Err(LedgerFailure::new(LedgerFailureCode::SnapshotExpired));
        }
        let state = self
            .state
            .lock()
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))?;
        if !state.lease_reservations.contains_key(&identity) {
            return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
        }
        let snapshot = snapshot_from_record(self, &state, &record)?;
        Ok(SnapshotLeaseGrant {
            identity,
            expiry: record.expiry,
            snapshot,
        })
    }

    pub fn release_snapshot_lease(&self, identity: SnapshotLeaseId) -> Result<(), LedgerFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))?;
        let basis = self.catalog.pin()?;
        let Some(record) = records(&basis)?
            .into_iter()
            .find(|record| record.identity == identity && record.scope == self.scope)
        else {
            state.lease_reservations.remove(&identity);
            return Ok(());
        };
        publish(self.catalog, &basis, Some(record.identity), None)?;
        state.lease_reservations.remove(&identity);
        Ok(())
    }
}

pub(super) fn recover_reservations<'kernel>(
    ledger_authority: &'kernel crate::StorageKernelResourceAuthority,
    scope: SegmentScope,
    snapshot: &crate::CatalogSnapshot,
) -> Result<BTreeMap<SnapshotLeaseId, ResourceReservation<'kernel>>, LedgerFailure> {
    let all = records(snapshot)?;
    if all.len() > MAX_SNAPSHOT_LEASES {
        return Err(LedgerFailure::new(LedgerFailureCode::LimitExceeded));
    }
    let mut retained = BTreeMap::new();
    for record in all.into_iter().filter(|record| record.scope == scope) {
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
    Ok(retained)
}

fn snapshot_from_record<'kernel>(
    ledger: &ActiveSegmentLedger<'kernel, '_>,
    state: &super::state::LedgerState<'kernel>,
    record: &LeaseRecord,
) -> Result<LedgerSnapshot<'kernel>, LedgerFailure> {
    if record.blocks.len() > state.blocks.len() || record.frontier > state.frontier {
        return Err(LedgerFailure::new(LedgerFailureCode::SnapshotExpired));
    }
    let blocks = state
        .blocks
        .get(..record.blocks.len())
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?;
    if !blocks.iter().zip(&record.blocks).all(|(actual, expected)| {
        actual.identity == expected.identity
            && actual.position == expected.position
            && actual.segment == expected.segment
    }) || blocks
        .last()
        .map_or(CommitPosition::origin(), |block| block.position)
        != record.frontier
    {
        return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
    }
    let bytes = blocks
        .iter()
        .try_fold(0_usize, |total, block| {
            total.checked_add(block.payload.len())
        })
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let claim = WorkClaim::tenant(
        record.scope.tenant,
        WorkKind::InteractiveQueryTail,
        snapshot_claim(bytes, blocks.len())?,
    )
    .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let capacity = ledger
        .authority
        .governor()
        .reserve(claim)
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
    Ok(LedgerSnapshot {
        _capacity: capacity,
        scope: record.scope,
        frontier: record.frontier,
        catalog_generation: record.catalog_generation,
        catalog_identity: record.catalog_identity,
        blocks: blocks.to_vec(),
    })
}

fn publish(
    catalog: &crate::Catalog<'_>,
    basis: &crate::CatalogSnapshot,
    remove: Option<SnapshotLeaseId>,
    add: Option<Vec<u8>>,
) -> Result<(), LedgerFailure> {
    let mut objects = basis
        .plaintext_objects()
        .filter(|bytes| {
            decode(bytes)
                .ok()
                .flatten()
                .is_none_or(|record| Some(record.identity) != remove)
        })
        .map(|bytes| CatalogObject::new(bytes.to_vec()))
        .collect::<Result<Vec<_>, _>>()?;
    if let Some(encoded) = add {
        objects.push(CatalogObject::new(encoded)?);
    }
    let transaction = TransactionId::new(fresh_identity()?.to_bytes())?;
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(transaction, FormatEpoch::new(FORMAT_EPOCH)?, objects)?,
        None,
    )?;
    Ok(())
}

fn records(snapshot: &crate::CatalogSnapshot) -> Result<Vec<LeaseRecord>, LedgerFailure> {
    let mut records = Vec::new();
    for bytes in snapshot.plaintext_objects() {
        if let Some(record) = decode(bytes)? {
            records.push(record);
        }
    }
    Ok(records)
}

fn fresh_identity() -> Result<SnapshotLeaseId, LedgerFailure> {
    let random = DataProtection::random_identifier().map_err(map_frame_failure)?;
    let bytes = random
        .get(..16)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::StorageUnavailable))?;
    SnapshotLeaseId::new(bytes)
}
