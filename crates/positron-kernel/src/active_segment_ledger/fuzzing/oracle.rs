use positron_domain::routing::CommitPosition;

use std::collections::BTreeSet;

use super::super::{
    ActiveSegmentLedger, CommitReceipt, CompactionBlock, LedgerSnapshot, SegmentId,
    StoreBlockIdentity,
};
use crate::StorageKernelResourceAuthority;
use positron_domain::time::UnixNanoseconds;

pub(super) struct Oracle {
    records: Vec<Record>,
    frontier: CommitPosition,
    seals: usize,
    pending_protected_reclamation: BTreeSet<SegmentId>,
    compactions: usize,
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
    ingest_nanos: u64,
}

impl Oracle {
    pub(super) const fn new() -> Self {
        Self {
            records: Vec::new(),
            frontier: CommitPosition::origin(),
            seals: 0,
            pending_protected_reclamation: BTreeSet::new(),
            compactions: 0,
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
        ingest_nanos: u64,
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
            ingest_nanos,
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

    pub(super) fn expired_segments(
        &self,
        active: SegmentId,
        now_nanos: u64,
        retention_nanos: u64,
    ) -> BTreeSet<SegmentId> {
        let Some(cutoff) = now_nanos.checked_sub(retention_nanos) else {
            return BTreeSet::new();
        };
        let segments = self
            .records
            .iter()
            .filter(|record| record.receipt.segment_id() != active)
            .map(|record| record.receipt.segment_id())
            .collect::<BTreeSet<_>>();
        segments
            .into_iter()
            .filter(|segment| {
                self.records
                    .iter()
                    .filter(|record| record.receipt.segment_id() == *segment)
                    .map(|record| record.ingest_nanos)
                    .max()
                    .is_some_and(|latest| latest <= cutoff)
            })
            .collect()
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

    pub(super) fn assert_ledger<'authority>(
        &self,
        ledger: &ActiveSegmentLedger<'authority, '_>,
        authority: &'authority StorageKernelResourceAuthority,
    ) {
        let snapshot = ledger.snapshot().expect("oracle snapshot is available");
        self.assert_snapshot(&snapshot);
        drop(snapshot);
        if self.compactions == 0 {
            for expected in &self.records {
                let retry = super::prepared_retained(
                    ledger,
                    authority,
                    expected.identity,
                    expected.payload.clone(),
                );
                assert_eq!(
                    ledger.append(retry).expect("oracle replay succeeds"),
                    expected.receipt
                );
            }
        }
    }

    pub(super) fn assert_snapshot(&self, snapshot: &LedgerSnapshot<'_>) {
        assert_eq!(snapshot.frontier(), self.frontier);
        assert_eq!(snapshot.blocks().len(), self.records.len());
        for (actual, expected) in snapshot.blocks().iter().zip(&self.records) {
            assert_eq!(actual.identity(), expected.identity);
            assert_eq!(actual.payload(), expected.payload);
            assert_eq!(actual.position(), expected.receipt.position());
        }
    }

    pub(super) fn compaction_inputs(
        &self,
        snapshot: &LedgerSnapshot<'_>,
        scope: super::super::SegmentScope,
        active: SegmentId,
    ) -> Option<Vec<CompactionBlock>> {
        let sealed = snapshot
            .blocks()
            .iter()
            .filter(|block| block.segment_id() != active)
            .map(|block| block.segment_id())
            .collect::<BTreeSet<_>>();
        if sealed.len() < 2 {
            return None;
        }
        let mut blocks = Vec::new();
        blocks.reserve(snapshot.blocks().len());
        for block in snapshot
            .blocks()
            .iter()
            .filter(|block| block.segment_id() != active)
        {
            let record = self.records.iter().find(|record| {
                record.receipt.position() == block.position() && record.identity == block.identity()
            })?;
            let instant = i64::try_from(record.ingest_nanos).ok()?;
            let ingest =
                crate::IngestTime::from_authenticated_durable(UnixNanoseconds::new(instant));
            blocks.push(
                CompactionBlock::new(
                    scope,
                    block.segment_id(),
                    block.identity(),
                    block.position(),
                    block.payload().to_vec(),
                    block.content_digest().ok()?,
                    ingest,
                )
                .ok()?,
            );
        }
        Some(blocks)
    }

    pub(super) fn note_compaction(&mut self, snapshot: &LedgerSnapshot<'_>) {
        let mut changed = false;
        for record in &mut self.records {
            if let Some(block) = snapshot.blocks().iter().find(|block| {
                block.identity() == record.identity && block.position() == record.receipt.position()
            }) {
                changed |= block.segment_id() != record.receipt.segment;
                record.receipt.segment = block.segment_id();
            }
        }
        if changed {
            self.compactions = self.compactions.saturating_add(1);
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
