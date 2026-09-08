use crate::{
    CorrelationOutcome, QueryBudgetDimension, QueryFailure, QueryFailureCode, QueryRecord,
};

/// Canonical conservative slot charge for every simultaneously retained typed query record.
pub(crate) const QUERY_RECORD_SLOT_BYTES: u64 = 192;
pub(crate) const GROUP_ENTRY_BYTES: u64 = 128;
pub(crate) const GROUP_VALUE_SLOT_BYTES: u64 = 96;

const _: () = assert!(
    std::mem::size_of::<QueryRecord>() <= QUERY_RECORD_SLOT_BYTES as usize,
    "the canonical query-record slot charge must cover every retained row"
);

pub(crate) struct QueryMemory {
    limit: u64,
    current: u64,
    peak: u64,
}

impl QueryMemory {
    pub(crate) const fn new(limit: u64) -> Self {
        Self {
            limit,
            current: 0,
            peak: 0,
        }
    }

    pub(crate) fn acquire(&mut self, bytes: u64) -> Result<(), QueryFailure> {
        let next = self
            .current
            .checked_add(bytes)
            .ok_or_else(|| QueryFailure::budget_exhausted(QueryBudgetDimension::MemoryBytes))?;
        if next > self.limit {
            return Err(QueryFailure::budget_exhausted(
                QueryBudgetDimension::MemoryBytes,
            ));
        }
        self.current = next;
        self.peak = self.peak.max(next);
        Ok(())
    }

    pub(crate) fn release(&mut self, bytes: u64) -> Result<(), QueryFailure> {
        self.current = self
            .current
            .checked_sub(bytes)
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
        Ok(())
    }

    pub(crate) const fn peak(&self) -> u64 {
        self.peak
    }
}

#[derive(Debug)]
pub(crate) struct RecordBuffer {
    records: Vec<QueryRecord>,
    correlations: Option<Vec<CorrelationOutcome>>,
    slot_bytes: u64,
    dynamic_bytes: u64,
}

impl RecordBuffer {
    pub(crate) fn allocate(
        capacity: usize,
        has_correlation: bool,
        memory: &mut QueryMemory,
    ) -> Result<Self, QueryFailure> {
        let record_slots = u64::try_from(capacity)
            .ok()
            .and_then(|count| count.checked_mul(QUERY_RECORD_SLOT_BYTES))
            .ok_or_else(|| QueryFailure::budget_exhausted(QueryBudgetDimension::MemoryBytes))?;
        let correlation_slots = correlation_slot_bytes(capacity)?;
        let slot_bytes = if has_correlation {
            record_slots
                .checked_add(correlation_slots)
                .ok_or_else(|| QueryFailure::budget_exhausted(QueryBudgetDimension::MemoryBytes))?
        } else {
            record_slots
        };
        memory.acquire(slot_bytes)?;
        let mut records = Vec::new();
        if records.try_reserve_exact(capacity).is_err() {
            memory.release(slot_bytes)?;
            return Err(QueryFailure::new(QueryFailureCode::ResourceExhausted));
        }
        let correlations = if has_correlation {
            let mut correlations = Vec::new();
            if correlations.try_reserve_exact(capacity).is_err() {
                memory.release(slot_bytes)?;
                return Err(QueryFailure::new(QueryFailureCode::ResourceExhausted));
            }
            Some(correlations)
        } else {
            None
        };
        Ok(Self {
            records,
            correlations,
            slot_bytes,
            dynamic_bytes: 0,
        })
    }

    pub(crate) fn push_acquired(
        &mut self,
        record: QueryRecord,
        dynamic_bytes: u64,
        correlation: Option<CorrelationOutcome>,
    ) -> Result<(), QueryFailure> {
        match (&mut self.correlations, correlation) {
            (Some(outcomes), Some(outcome)) => outcomes.push(outcome),
            (None, None) => {},
            _ => return Err(QueryFailure::new(QueryFailureCode::Internal)),
        }
        self.records.push(record);
        self.dynamic_bytes = self
            .dynamic_bytes
            .checked_add(dynamic_bytes)
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
        Ok(())
    }

    pub(crate) fn correlation_outcomes(&self) -> Option<&[CorrelationOutcome]> {
        self.correlations.as_deref()
    }

    pub(crate) const fn has_correlation(&self) -> bool {
        self.correlations.is_some()
    }

    pub(crate) fn swap(&mut self, first: usize, second: usize) -> Result<(), QueryFailure> {
        if first >= self.records.len() || second >= self.records.len() {
            return Err(QueryFailure::new(QueryFailureCode::Internal));
        }
        self.records.swap(first, second);
        if let Some(outcomes) = &mut self.correlations {
            outcomes.swap(first, second);
        }
        Ok(())
    }

    pub(crate) fn as_slice(&self) -> &[QueryRecord] {
        &self.records
    }

    pub(crate) fn len(&self) -> usize {
        self.records.len()
    }

    pub(crate) fn into_parts(
        self,
    ) -> (Vec<QueryRecord>, Option<Vec<CorrelationOutcome>>, u64, u64) {
        (
            self.records,
            self.correlations,
            self.slot_bytes,
            self.dynamic_bytes,
        )
    }
}

pub(crate) fn correlation_slot_bytes(capacity: usize) -> Result<u64, QueryFailure> {
    u64::try_from(capacity)
        .ok()
        .and_then(|count| {
            count.checked_mul(u64::try_from(std::mem::size_of::<CorrelationOutcome>()).ok()?)
        })
        .ok_or_else(|| QueryFailure::budget_exhausted(QueryBudgetDimension::MemoryBytes))
}

pub(crate) fn correlation_retained_bytes(capacity: usize) -> Result<u64, QueryFailure> {
    correlation_slot_bytes(capacity)?
        .checked_add(crate::stream::correlation_outcomes_arc_bytes())
        .ok_or_else(|| QueryFailure::budget_exhausted(QueryBudgetDimension::MemoryBytes))
}

#[cfg(test)]
mod tests {
    use super::QueryMemory;
    use crate::QueryFailureCode;

    #[test]
    fn releasing_more_than_the_live_query_memory_is_an_internal_failure() {
        let mut memory = QueryMemory::new(8);
        memory.acquire(8).expect("bounded acquisition should fit");
        assert_eq!(
            memory
                .release(9)
                .expect_err("release cannot underflow")
                .code(),
            QueryFailureCode::Internal
        );
    }
}
