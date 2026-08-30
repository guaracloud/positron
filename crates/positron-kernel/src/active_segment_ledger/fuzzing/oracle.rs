use positron_domain::routing::CommitPosition;

use std::collections::BTreeSet;

use super::super::{
    ActiveSegmentLedger, CommitReceipt, PreparedStoreBlock, SegmentId, StoreBlockIdentity,
};

pub(super) struct Oracle {
    records: Vec<Record>,
    frontier: CommitPosition,
    seals: usize,
    pending_protected_reclamation: BTreeSet<SegmentId>,
}

#[derive(Clone)]
pub(super) struct SnapshotExpectation {
    frontier: CommitPosition,
    records: Vec<ExpectedRecord>,
}

#[derive(Clone)]
struct ExpectedRecord {
    identity: StoreBlockIdentity,
    payload: Vec<u8>,
    position: CommitPosition,
    segment: SegmentId,
}

struct Record {
    identity: StoreBlockIdentity,
    payload: Vec<u8>,
    receipt: CommitReceipt,
}

impl Oracle {
    pub(super) const fn new() -> Self {
        Self {
            records: Vec::new(),
            frontier: CommitPosition::origin(),
            seals: 0,
            pending_protected_reclamation: BTreeSet::new(),
        }
    }

    pub(super) fn expected_position(&self) -> u64 {
        self.frontier
            .value()
            .checked_add(1)
            .expect("bounded frontier")
    }

    pub(super) fn record(
        &mut self,
        identity: StoreBlockIdentity,
        payload: Vec<u8>,
        receipt: CommitReceipt,
    ) {
        assert_eq!(receipt.position().value(), self.expected_position());
        assert!(
            self.records
                .iter()
                .all(|record| record.identity != identity)
        );
        self.records.push(Record {
            identity,
            payload,
            receipt,
        });
        self.frontier = receipt.position();
    }

    pub(super) fn first(&self) -> Option<(StoreBlockIdentity, &[u8], CommitReceipt)> {
        self.records
            .first()
            .map(|record| (record.identity, record.payload.as_slice(), record.receipt))
    }

    pub(super) fn contains(&self, identity: StoreBlockIdentity) -> bool {
        self.records
            .iter()
            .any(|record| record.identity == identity)
    }

    pub(super) fn record_seal(&mut self) {
        self.seals = self.seals.checked_add(1).expect("bounded seal count");
    }

    pub(super) fn retire_segments(&mut self, retired: &BTreeSet<SegmentId>) {
        self.records
            .retain(|record| !retired.contains(&record.receipt.segment_id()));
    }

    pub(super) fn capture(snapshot: &super::super::LedgerSnapshot<'_>) -> SnapshotExpectation {
        SnapshotExpectation {
            frontier: snapshot.frontier(),
            records: snapshot
                .blocks()
                .iter()
                .map(|block| ExpectedRecord {
                    identity: block.identity(),
                    payload: block.payload().to_vec(),
                    position: block.position(),
                    segment: block.segment_id(),
                })
                .collect(),
        }
    }

    pub(super) fn note_retention(
        &mut self,
        retired: &BTreeSet<SegmentId>,
        protected: &BTreeSet<SegmentId>,
        physically_reclaimed: usize,
    ) {
        if protected.is_empty() && !self.pending_protected_reclamation.is_empty() {
            assert!(physically_reclaimed >= self.pending_protected_reclamation.len());
            self.pending_protected_reclamation.clear();
        }
        self.pending_protected_reclamation
            .extend(retired.intersection(protected).copied());
    }

    pub(super) fn assert_ledger(&self, ledger: &ActiveSegmentLedger<'_, '_>) {
        let snapshot = ledger.snapshot().expect("oracle snapshot is available");
        assert_eq!(snapshot.frontier(), self.frontier);
        assert_eq!(snapshot.blocks().len(), self.records.len());
        for (actual, expected) in snapshot.blocks().iter().zip(&self.records) {
            assert_eq!(actual.identity(), expected.identity);
            assert_eq!(actual.payload(), expected.payload);
            assert_eq!(actual.position(), expected.receipt.position());
        }
        drop(snapshot);
        for expected in &self.records {
            let retry =
                PreparedStoreBlock::new(ledger.scope, expected.identity, expected.payload.clone())
                    .expect("oracle record remains bounded");
            assert_eq!(
                ledger.append(retry).expect("oracle replay succeeds"),
                expected.receipt
            );
        }
    }

    pub(super) fn frontier(&self) -> CommitPosition {
        self.frontier
    }
}

impl SnapshotExpectation {
    pub(super) fn assert_snapshot(&self, snapshot: &super::super::LedgerSnapshot<'_>) {
        assert_eq!(snapshot.frontier(), self.frontier);
        assert_eq!(snapshot.blocks().len(), self.records.len());
        for (actual, expected) in snapshot.blocks().iter().zip(&self.records) {
            assert_eq!(actual.identity(), expected.identity);
            assert_eq!(actual.payload(), expected.payload);
            assert_eq!(actual.position(), expected.position);
            assert_eq!(actual.segment_id(), expected.segment);
        }
    }

    pub(super) fn segments(&self) -> BTreeSet<SegmentId> {
        self.records.iter().map(|record| record.segment).collect()
    }
}
