use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::{QueryBudgetDimension, QueryCursor, QueryFailure, QueryFailureCode};
use positron_kernel::TransferredResourceReservation;

use super::{CorrelationOutcome, QueryHeader, QueryRecord};

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
    _reservation: Option<TransferredResourceReservation>,
}

/// The move-owned correlation result sidecar. Its `Vec` allocation is made
/// while query memory is still reserved, then shared without copying rows.
#[derive(Debug)]
pub(crate) struct CorrelationOutcomes {
    outcomes: Vec<CorrelationOutcome>,
    _reservation: TransferredResourceReservation,
}

impl PartialEq for CorrelationOutcomes {
    fn eq(&self, other: &Self) -> bool {
        self.outcomes == other.outcomes
    }
}

impl Eq for CorrelationOutcomes {}

impl CorrelationOutcomes {
    pub(crate) const fn new(
        outcomes: Vec<CorrelationOutcome>,
        reservation: TransferredResourceReservation,
    ) -> Self {
        Self {
            outcomes,
            _reservation: reservation,
        }
    }

    pub(crate) fn get(&self, index: usize) -> Option<CorrelationOutcome> {
        self.outcomes.get(index).copied()
    }

    pub(crate) fn len(&self) -> usize {
        self.outcomes.len()
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &CorrelationOutcome> {
        self.outcomes.iter()
    }
}

/// `ArcInner` retains two atomics before its payload. Keeping this separate
/// makes the ownership-transfer allocation visible to both memory budgets.
pub(crate) const fn correlation_outcomes_arc_bytes() -> u64 {
    (std::mem::size_of::<CorrelationOutcomes>()
        + (2 * std::mem::size_of::<std::sync::atomic::AtomicUsize>())) as u64
}

impl BatchMemoryClaim {
    pub(crate) fn new(account: Arc<BatchMemoryAccount>, bytes: u64) -> Arc<Self> {
        Arc::new(Self {
            account,
            bytes,
            _reservation: None,
        })
    }

    pub(crate) fn new_with_reservation(
        account: Arc<BatchMemoryAccount>,
        bytes: u64,
        reservation: TransferredResourceReservation,
    ) -> Arc<Self> {
        Arc::new(Self {
            account,
            bytes,
            _reservation: Some(reservation),
        })
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
    correlations: Option<Arc<CorrelationOutcomes>>,
    prior_digest: [u8; 32],
    digest: [u8; 32],
    claim: Option<Arc<BatchMemoryClaim>>,
}

impl QueryBatch {
    pub(crate) fn new(
        sequence: u64,
        records: Vec<QueryRecord>,
        correlations: Option<Vec<CorrelationOutcome>>,
        correlation_reservation: Option<TransferredResourceReservation>,
        prior_digest: [u8; 32],
        digest: [u8; 32],
    ) -> Result<Self, QueryFailure> {
        let correlations = match (correlations, correlation_reservation) {
            (Some(outcomes), Some(reservation)) => {
                Some(Arc::new(CorrelationOutcomes::new(outcomes, reservation)))
            },
            (None, None) => None,
            (Some(_), None) | (None, Some(_)) => {
                return Err(QueryFailure::new(QueryFailureCode::Internal));
            },
        };
        Ok(Self {
            sequence,
            records: Arc::from(records.into_boxed_slice()),
            correlations,
            prior_digest,
            digest,
            claim: None,
        })
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
            correlations: None,
            prior_digest,
            digest,
            claim: Some(claim),
        }
    }
    #[must_use]
    pub fn records(&self) -> &[QueryRecord] {
        &self.records
    }

    /// Returns the explicit Log-to-Trace outcome for the row at `index`.
    ///
    /// Ordinary Log Store batches have no correlation sidecar and return
    /// `None` for every index.
    #[must_use]
    pub fn correlation_outcome(&self, index: usize) -> Option<CorrelationOutcome> {
        self.correlations
            .as_deref()
            .and_then(|outcomes| outcomes.get(index))
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

    /// Produces the bounded, self-delimiting typed payload persisted by a
    /// durable export. This is deliberately distinct from the batch digest:
    /// callers need the actual rows, while the digest commits their logical
    /// query result.
    pub(crate) fn canonical_export_bytes(&self) -> Result<Vec<u8>, QueryFailure> {
        const MAGIC: &[u8; 8] = b"POSQBT01";
        let count = u32::try_from(self.records.len())
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(MAGIC.len() + 8 + 32 + 32 + 4)
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        output.extend_from_slice(MAGIC);
        output.extend_from_slice(&self.sequence.to_be_bytes());
        output.extend_from_slice(&self.prior_digest);
        output.extend_from_slice(&self.digest);
        output.extend_from_slice(&count.to_be_bytes());
        for record in self.records.iter() {
            record.append_export_encoding(&mut output)?;
        }
        if let Some(correlations) = &self.correlations {
            let correlation_count = u32::try_from(correlations.len())
                .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
            output
                .try_reserve_exact(1 + 4)
                .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
            output.push(1);
            output.extend_from_slice(&correlation_count.to_be_bytes());
            for outcome in correlations.iter() {
                append_correlation_export_encoding(&mut output, outcome)?;
            }
        } else {
            output
                .try_reserve_exact(1)
                .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
            output.push(0);
        }
        Ok(output)
    }
}

fn append_correlation_export_encoding(
    output: &mut Vec<u8>,
    outcome: &CorrelationOutcome,
) -> Result<(), QueryFailure> {
    let (tag, trace, span) = match outcome {
        CorrelationOutcome::MissingLogTraceId => {
            output
                .try_reserve_exact(1)
                .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
            output.push(0);
            return Ok(());
        },
        CorrelationOutcome::MissingTraceTarget { trace_id, span_id } => (1, trace_id, span_id),
        CorrelationOutcome::Matched { trace_id, span_id } => (2, trace_id, span_id),
        CorrelationOutcome::Ambiguous { trace_id, span_id } => (3, trace_id, span_id),
    };
    output
        .try_reserve_exact(1 + 16 + 1 + usize::from(span.is_some()) * 8)
        .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
    output.push(tag);
    output.extend_from_slice(trace);
    match span {
        Some(span) => {
            output.push(1);
            output.extend_from_slice(span);
        },
        None => output.push(0),
    }
    Ok(())
}

impl Clone for QueryBatch {
    fn clone(&self) -> Self {
        Self {
            sequence: self.sequence,
            records: Arc::clone(&self.records),
            correlations: self.correlations.clone(),
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
            && self.correlations == other.correlations
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

    /// Appends the fixed-size terminal statistics retained beside a durable
    /// export manifest. The output format is private to the Query module.
    pub(crate) fn append_durable_export_encoding(
        self,
        output: &mut Vec<u8>,
    ) -> Result<(), QueryFailure> {
        const BYTES: usize = 179;
        output
            .try_reserve_exact(BYTES)
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        for value in [
            self.records,
            self.scanned_bytes,
            self.decoded_records,
            self.output_bytes,
            self.memory_peak_bytes,
            self.cpu_work_units,
            self.wall_seconds,
        ] {
            output.extend_from_slice(&value.to_be_bytes());
        }
        match self.last_sequence {
            Some(sequence) => {
                output.push(1);
                output.extend_from_slice(&sequence.to_be_bytes());
            },
            None => {
                output.push(0);
                output.extend_from_slice(&0_u64.to_be_bytes());
            },
        }
        output.extend_from_slice(&self.result_digest);
        for value in [
            self.cumulative_budget.scanned_bytes(),
            self.cumulative_budget.decoded_records(),
            self.cumulative_budget.output_rows(),
            self.cumulative_budget.output_bytes(),
            self.cumulative_budget.memory_bytes(),
            self.cumulative_budget.cpu_work_units(),
            self.cumulative_budget.wall_seconds(),
            self.cumulative_budget.maximum_time_range_nanoseconds(),
            self.resume_count,
            self.repeated_batch_count,
        ] {
            output.extend_from_slice(&value.to_be_bytes());
        }
        output.push(encode_budget_dimension(self.limiting_budget));
        output.push(u8::from(self.reduced_pruning));
        Ok(())
    }

    pub(crate) fn from_durable_export_encoding(
        bytes: &[u8],
        offset: &mut usize,
    ) -> Result<Self, QueryFailure> {
        let records = read_export_u64(bytes, offset)?;
        let scanned_bytes = read_export_u64(bytes, offset)?;
        let decoded_records = read_export_u64(bytes, offset)?;
        let output_bytes = read_export_u64(bytes, offset)?;
        let memory_peak_bytes = read_export_u64(bytes, offset)?;
        let cpu_work_units = read_export_u64(bytes, offset)?;
        let wall_seconds = read_export_u64(bytes, offset)?;
        let last_sequence = match read_export_byte(bytes, offset)? {
            0 => {
                let _reserved = read_export_u64(bytes, offset)?;
                None
            },
            1 => Some(read_export_u64(bytes, offset)?),
            _ => return Err(QueryFailure::new(QueryFailureCode::MalformedPersistentData)),
        };
        let result_digest = read_export_array(bytes, offset)?;
        let budget_scanned_bytes = read_export_u64(bytes, offset)?;
        let budget_decoded_records = read_export_u64(bytes, offset)?;
        let budget_output_rows = read_export_u64(bytes, offset)?;
        let budget_output_bytes = read_export_u64(bytes, offset)?;
        let budget_memory_bytes = read_export_u64(bytes, offset)?;
        let budget_cpu_work_units = read_export_u64(bytes, offset)?;
        let budget_wall_seconds = read_export_u64(bytes, offset)?;
        let maximum_time_range_nanoseconds = read_export_u64(bytes, offset)?;
        let budget = crate::QueryBudget::new(
            budget_scanned_bytes,
            budget_decoded_records,
            budget_output_rows,
            budget_output_bytes,
            budget_memory_bytes,
            budget_wall_seconds,
        )?
        .with_cpu_work_units(budget_cpu_work_units)?
        .with_maximum_time_range_nanoseconds(maximum_time_range_nanoseconds)?;
        let resume_count = read_export_u64(bytes, offset)?;
        let repeated_batch_count = read_export_u64(bytes, offset)?;
        let limiting_budget = decode_budget_dimension(read_export_byte(bytes, offset)?)?;
        let reduced_pruning = match read_export_byte(bytes, offset)? {
            0 => false,
            1 => true,
            _ => return Err(QueryFailure::new(QueryFailureCode::MalformedPersistentData)),
        };
        Ok(Self {
            records,
            scanned_bytes,
            decoded_records,
            output_bytes,
            memory_peak_bytes,
            cpu_work_units,
            wall_seconds,
            last_sequence,
            result_digest,
            cumulative_budget: budget,
            resume_count,
            repeated_batch_count,
            limiting_budget,
            reduced_pruning,
        })
    }
}

fn encode_budget_dimension(value: Option<QueryBudgetDimension>) -> u8 {
    match value {
        None => 0,
        Some(QueryBudgetDimension::ScannedBytes) => 1,
        Some(QueryBudgetDimension::DecodedRecords) => 2,
        Some(QueryBudgetDimension::OutputRows) => 3,
        Some(QueryBudgetDimension::OutputBytes) => 4,
        Some(QueryBudgetDimension::MemoryBytes) => 5,
        Some(QueryBudgetDimension::CpuWorkUnits) => 6,
        Some(QueryBudgetDimension::WallSeconds) => 7,
        Some(QueryBudgetDimension::MaximumTimeRangeNanoseconds) => 8,
    }
}

fn decode_budget_dimension(value: u8) -> Result<Option<QueryBudgetDimension>, QueryFailure> {
    match value {
        0 => Ok(None),
        1 => Ok(Some(QueryBudgetDimension::ScannedBytes)),
        2 => Ok(Some(QueryBudgetDimension::DecodedRecords)),
        3 => Ok(Some(QueryBudgetDimension::OutputRows)),
        4 => Ok(Some(QueryBudgetDimension::OutputBytes)),
        5 => Ok(Some(QueryBudgetDimension::MemoryBytes)),
        6 => Ok(Some(QueryBudgetDimension::CpuWorkUnits)),
        7 => Ok(Some(QueryBudgetDimension::WallSeconds)),
        8 => Ok(Some(QueryBudgetDimension::MaximumTimeRangeNanoseconds)),
        _ => Err(QueryFailure::new(QueryFailureCode::MalformedPersistentData)),
    }
}

fn read_export_byte(bytes: &[u8], offset: &mut usize) -> Result<u8, QueryFailure> {
    let byte = *bytes
        .get(*offset)
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::MalformedPersistentData))?;
    *offset = offset
        .checked_add(1)
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::MalformedPersistentData))?;
    Ok(byte)
}

fn read_export_array<const N: usize>(
    bytes: &[u8],
    offset: &mut usize,
) -> Result<[u8; N], QueryFailure> {
    let end = offset
        .checked_add(N)
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::MalformedPersistentData))?;
    let slice = bytes
        .get(*offset..end)
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::MalformedPersistentData))?;
    let value = slice
        .try_into()
        .map_err(|_| QueryFailure::new(QueryFailureCode::MalformedPersistentData))?;
    *offset = end;
    Ok(value)
}

fn read_export_u64(bytes: &[u8], offset: &mut usize) -> Result<u64, QueryFailure> {
    Ok(u64::from_be_bytes(read_export_array(bytes, offset)?))
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

#[cfg(test)]
mod tests {
    use super::QueryStats;
    use crate::QueryBudget;

    #[test]
    fn durable_export_stats_round_trip_distinct_cpu_and_wall_limits() {
        let budget = QueryBudget::new(101, 102, 103, 104, 105, 107)
            .expect("valid wall limit")
            .with_cpu_work_units(106)
            .expect("valid cpu limit")
            .with_maximum_time_range_nanoseconds(108)
            .expect("valid time range");
        let stats = QueryStats {
            records: 1,
            scanned_bytes: 2,
            decoded_records: 3,
            output_bytes: 4,
            memory_peak_bytes: 5,
            cpu_work_units: 6,
            wall_seconds: 7,
            last_sequence: Some(8),
            result_digest: [9; 32],
            cumulative_budget: budget,
            resume_count: 10,
            repeated_batch_count: 11,
            limiting_budget: None,
            reduced_pruning: false,
        };
        let mut bytes = Vec::new();
        stats
            .append_durable_export_encoding(&mut bytes)
            .expect("bounded encoding");
        let mut offset = 0;
        let recovered = QueryStats::from_durable_export_encoding(&bytes, &mut offset)
            .expect("exact durable decoding");

        assert_eq!(offset, bytes.len());
        assert_eq!(recovered, stats);
        assert_eq!(recovered.cumulative_budget().cpu_work_units(), 106);
        assert_eq!(recovered.cumulative_budget().wall_seconds(), 107);
    }
}
