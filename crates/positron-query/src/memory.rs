use crate::{QueryFailure, QueryFailureCode, QueryRecord};

/// Canonical conservative slot charge for every simultaneously retained typed query record.
pub(crate) const QUERY_RECORD_SLOT_BYTES: u64 = 128;
pub(crate) const GROUP_ENTRY_BYTES: u64 = 640;
pub(crate) const GROUP_VALUE_SLOT_BYTES: u64 = 32;

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
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::BudgetExhausted))?;
        if next > self.limit {
            return Err(QueryFailure::new(QueryFailureCode::BudgetExhausted));
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
}

pub(crate) struct RecordBuffer {
    records: Vec<QueryRecord>,
    slot_bytes: u64,
    dynamic_bytes: u64,
}

impl RecordBuffer {
    pub(crate) fn allocate(
        capacity: usize,
        memory: &mut QueryMemory,
    ) -> Result<Self, QueryFailure> {
        let slot_bytes = u64::try_from(capacity)
            .ok()
            .and_then(|count| count.checked_mul(QUERY_RECORD_SLOT_BYTES))
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::BudgetExhausted))?;
        memory.acquire(slot_bytes)?;
        let mut records = Vec::new();
        if records.try_reserve_exact(capacity).is_err() {
            memory.release(slot_bytes)?;
            return Err(QueryFailure::new(QueryFailureCode::ResourceExhausted));
        }
        Ok(Self {
            records,
            slot_bytes,
            dynamic_bytes: 0,
        })
    }

    pub(crate) fn push_acquired(
        &mut self,
        record: QueryRecord,
        dynamic_bytes: u64,
    ) -> Result<(), QueryFailure> {
        self.records.push(record);
        self.dynamic_bytes = self
            .dynamic_bytes
            .checked_add(dynamic_bytes)
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
        Ok(())
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [QueryRecord] {
        &mut self.records
    }

    pub(crate) fn len(&self) -> usize {
        self.records.len()
    }

    pub(crate) fn into_parts(self) -> (Vec<QueryRecord>, u64, u64) {
        (self.records, self.slot_bytes, self.dynamic_bytes)
    }
}
