use positron_domain::routing::CommitPosition;

use std::collections::BTreeSet;

use super::super::{
    ActiveSegmentLedger, CommitReceipt, PreparedStoreBlock, SegmentId, StoreBlockIdentity,
};

pub(super) struct Oracle {
    records: Vec<Record>,
    frontier: CommitPosition,
    seals: usize,
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
