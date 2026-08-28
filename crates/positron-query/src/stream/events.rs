use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::{QueryBudgetDimension, QueryCursor, QueryFailure, QueryFailureCode};

use super::{QueryHeader, QueryRecord};

#[derive(Debug)]
pub(crate) struct BatchMemoryAccount {
    limit: u64,
    used: AtomicU64,
    peak: AtomicU64,
}

impl BatchMemoryAccount {
    pub(crate) const fn new(limit: u64) -> Self {
        Self {
            limit,
            used: AtomicU64::new(0),
            peak: AtomicU64::new(0),
        }
    }

    pub(crate) fn reserve(&self, bytes: u64, failure: QueryFailure) -> Result<(), QueryFailure> {
        let mut used = self.used.load(Ordering::Acquire);
        loop {
            let next = used
                .checked_add(bytes)
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
            if next > self.limit {
                return Err(failure);
            }
            match self
                .used
                .compare_exchange_weak(used, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => {
                    self.peak.fetch_max(next, Ordering::AcqRel);
                    return Ok(());
                },
                Err(observed) => used = observed,
            }
        }
    }

    pub(crate) fn release(&self, bytes: u64) {
        let _ = self
            .used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                Some(used.saturating_sub(bytes))
            });
    }

    pub(crate) fn used(&self) -> u64 {
        self.used.load(Ordering::Acquire)
    }

    pub(crate) fn peak(&self) -> u64 {
        self.peak.load(Ordering::Acquire)
    }
}

#[derive(Debug)]
pub(crate) struct BatchMemoryClaim {
    account: Arc<BatchMemoryAccount>,
    bytes: u64,
}

impl BatchMemoryClaim {
    pub(crate) fn new(account: Arc<BatchMemoryAccount>, bytes: u64) -> Arc<Self> {
        Arc::new(Self { account, bytes })
    }

    pub(crate) const fn bytes(&self) -> u64 {
        self.bytes
    }
}

impl Drop for BatchMemoryClaim {
    fn drop(&mut self) {
        self.account.release(self.bytes);
    }
}

#[derive(Debug)]
pub struct QueryBatch {
    sequence: u64,
    records: Arc<[QueryRecord]>,
    prior_digest: [u8; 32],
    digest: [u8; 32],
    claim: Option<Arc<BatchMemoryClaim>>,
}

impl QueryBatch {
    pub(crate) fn new(
        sequence: u64,
        records: Vec<QueryRecord>,
        prior_digest: [u8; 32],
        digest: [u8; 32],
    ) -> Self {
        Self {
            sequence,
            records: Arc::from(records.into_boxed_slice()),
            prior_digest,
            digest,
            claim: None,
        }
    }

    pub(crate) fn from_shared(
        sequence: u64,
        records: Arc<[QueryRecord]>,
        prior_digest: [u8; 32],
        digest: [u8; 32],
        claim: Arc<BatchMemoryClaim>,
    ) -> Self {
        Self {
            sequence,
            records,
            prior_digest,
            digest,
            claim: Some(claim),
        }
    }
    #[must_use]
    pub fn records(&self) -> &[QueryRecord] {
        &self.records
    }
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    #[must_use]
    pub const fn prior_digest(&self) -> [u8; 32] {
        self.prior_digest
    }
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

impl Clone for QueryBatch {
    fn clone(&self) -> Self {
        Self {
            sequence: self.sequence,
            records: Arc::clone(&self.records),
            prior_digest: self.prior_digest,
            digest: self.digest,
            claim: self.claim.clone(),
        }
    }
}

impl PartialEq for QueryBatch {
    fn eq(&self, other: &Self) -> bool {
        self.sequence == other.sequence
            && self.records == other.records
            && self.prior_digest == other.prior_digest
            && self.digest == other.digest
    }
}

impl Eq for QueryBatch {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Cumulative statistics for the current bounded native-query execution state.
pub struct QueryStats {
    records: u64,
    scanned_bytes: u64,
    decoded_records: u64,
    output_bytes: u64,
    memory_peak_bytes: u64,
    cpu_work_units: u64,
    wall_seconds: u64,
    last_sequence: Option<u64>,
    result_digest: [u8; 32],
    cumulative_budget: crate::QueryBudget,
    resume_count: u64,
    repeated_batch_count: u64,
    limiting_budget: Option<QueryBudgetDimension>,
    reduced_pruning: bool,
}

pub(crate) struct QueryCounters {
    pub(crate) records: u64,
    pub(crate) scanned_bytes: u64,
    pub(crate) decoded_records: u64,
    pub(crate) output_bytes: u64,
    pub(crate) memory_peak_bytes: u64,
    pub(crate) cpu_work_units: u64,
    pub(crate) wall_seconds: u64,
}

impl QueryStats {
    pub(crate) const fn new(
        counters: QueryCounters,
        last_sequence: Option<u64>,
        result_digest: [u8; 32],
        cumulative_budget: crate::QueryBudget,
        resume_count: u64,
        repeated_batch_count: u64,
    ) -> Self {
        Self {
            records: counters.records,
            scanned_bytes: counters.scanned_bytes,
            decoded_records: counters.decoded_records,
            output_bytes: counters.output_bytes,
            memory_peak_bytes: counters.memory_peak_bytes,
            cpu_work_units: counters.cpu_work_units,
            wall_seconds: counters.wall_seconds,
            last_sequence,
            result_digest,
            cumulative_budget,
            resume_count,
            repeated_batch_count,
            limiting_budget: None,
            reduced_pruning: false,
        }
    }

    pub(crate) const fn with_limiting_budget(
        mut self,
        limiting_budget: Option<QueryBudgetDimension>,
    ) -> Self {
        self.limiting_budget = limiting_budget;
        self
    }

    pub(crate) const fn with_reduced_pruning(mut self, reduced_pruning: bool) -> Self {
        self.reduced_pruning = reduced_pruning;
        self
    }
    #[must_use]
    pub const fn records(self) -> u64 {
        self.records
    }

    #[must_use]
    pub const fn scanned_bytes(self) -> u64 {
        self.scanned_bytes
    }

    #[must_use]
    pub const fn decoded_records(self) -> u64 {
        self.decoded_records
    }
    #[must_use]
    pub const fn output_bytes(self) -> u64 {
        self.output_bytes
    }

    #[must_use]
    pub const fn memory_peak_bytes(self) -> u64 {
        self.memory_peak_bytes
    }
    #[must_use]
    pub const fn cpu_work_units(self) -> u64 {
        self.cpu_work_units
    }
    #[must_use]
    pub const fn wall_seconds(self) -> u64 {
        self.wall_seconds
    }
    #[must_use]
    pub const fn last_sequence(self) -> Option<u64> {
        self.last_sequence
    }
    #[must_use]
    pub const fn result_digest(self) -> [u8; 32] {
        self.result_digest
    }

    /// Returns the immutable cumulative limits governing every page and
    /// reconnect of this query snapshot.
    #[must_use]
    pub const fn cumulative_budget(self) -> crate::QueryBudget {
        self.cumulative_budget
    }

    /// Returns the number of authenticated resume operations represented by
    /// this execution state.
    #[must_use]
    pub const fn resume_count(self) -> u64 {
        self.resume_count
    }

    /// Returns the number of result batches replayed after an ambiguous
    /// delivery. The current native stream reports this conservatively until
    /// the delivery acknowledgement boundary is observed.
    #[must_use]
    pub const fn repeated_batch_count(self) -> u64 {
        self.repeated_batch_count
    }

    #[must_use]
    /// Returns the effective limit that stopped execution, if the terminal was
    /// caused by a query budget.
    pub const fn limiting_budget(self) -> Option<QueryBudgetDimension> {
        self.limiting_budget
    }

    #[must_use]
    /// Reports whether execution required less-effective pruning and exact
    /// post-decode fallback evaluation.
    pub const fn reduced_pruning(self) -> bool {
        self.reduced_pruning
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryIncomplete {
    failure: QueryFailure,
    stats: QueryStats,
}

impl QueryIncomplete {
    pub(crate) const fn new(failure: QueryFailure, stats: QueryStats) -> Self {
        Self {
            stats: stats.with_limiting_budget(failure.limiting_budget()),
            failure,
        }
    }
    #[must_use]
    pub const fn code(&self) -> QueryFailureCode {
        self.failure.code()
    }
    #[must_use]
    pub const fn stats(&self) -> QueryStats {
        self.stats
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QueryTerminal {
    Complete(QueryStats),
    Continued(QueryCursor),
    Incomplete(QueryIncomplete),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QueryEvent {
    Header(QueryHeader),
    Batch(QueryBatch),
    Terminal(QueryTerminal),
}
