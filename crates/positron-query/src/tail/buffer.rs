use crate::memory::QUERY_RECORD_SLOT_BYTES;
use crate::{QueryFailure, QueryFailureCode, QueryRecord};

const MAX_BYTES: u64 = 16 * 1_048_576;

pub(crate) struct TailBuffer {
    batch: Option<Vec<QueryRecord>>,
    rows: usize,
    bytes: u64,
    max_rows: usize,
    max_bytes: u64,
    memory_limit: u64,
    memory_used: u64,
    memory_peak: u64,
}

impl TailBuffer {
    pub(crate) fn new(
        max_rows: usize,
        max_bytes: u64,
        memory_limit: u64,
    ) -> Result<Self, QueryFailure> {
        if max_rows == 0 || max_rows > 1_024 || max_bytes == 0 || max_bytes > MAX_BYTES {
            return Err(QueryFailure::new(QueryFailureCode::InvalidBudget));
        }
        Ok(Self {
            batch: None,
            rows: 0,
            bytes: 0,
            max_rows,
            max_bytes,
            memory_limit,
            memory_used: 0,
            memory_peak: 0,
        })
    }

    pub(crate) fn push(&mut self, batch: Vec<QueryRecord>) -> Result<(), QueryFailure> {
        let rows = batch.len();
        if rows == 0 || self.batch.is_some() || rows > self.max_rows.saturating_sub(self.rows) {
            return Err(QueryFailure::new(
                QueryFailureCode::ResourceAdmissionRefused,
            ));
        }
        let dynamic = batch.iter().try_fold(0_u64, |total, record| {
            total
                .checked_add(record.retained_dynamic_bytes()?)
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::ResourceExhausted))
        })?;
        let bytes = rows
            .checked_mul(
                usize::try_from(QUERY_RECORD_SLOT_BYTES)
                    .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?,
            )
            .and_then(|value| u64::try_from(value).ok())
            .and_then(|value| value.checked_add(dynamic))
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        let next = self
            .bytes
            .checked_add(bytes)
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        if next > self.max_bytes {
            return Err(QueryFailure::new(
                QueryFailureCode::ResourceAdmissionRefused,
            ));
        }
        let next_memory = self
            .memory_used
            .checked_add(bytes)
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        if next_memory > self.memory_limit {
            return Err(QueryFailure::new(
                QueryFailureCode::ResourceAdmissionRefused,
            ));
        }
        self.rows = self
            .rows
            .checked_add(rows)
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        self.bytes = next;
        self.memory_used = next_memory;
        self.memory_peak = self.memory_peak.max(next_memory);
        self.batch = Some(batch);
        Ok(())
    }

    pub(crate) fn reserve_queue_bytes(&mut self, bytes: u64) -> Result<u64, QueryFailure> {
        let next_memory = self
            .memory_used
            .checked_add(bytes)
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        if next_memory > self.memory_limit {
            return Err(QueryFailure::budget_exhausted(
                crate::QueryBudgetDimension::MemoryBytes,
            ));
        }
        self.memory_used = next_memory;
        self.memory_peak = self.memory_peak.max(next_memory);
        Ok(bytes)
    }

    pub(crate) fn release_queue(&mut self, bytes: u64) -> Result<(), QueryFailure> {
        self.memory_used = self
            .memory_used
            .checked_sub(bytes)
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
        Ok(())
    }

    pub(crate) fn pop(&mut self) -> Option<Vec<QueryRecord>> {
        let batch = self.batch.take()?;
        if self.rows >= batch.len() {
            self.rows -= batch.len();
        } else {
            self.rows = 0;
        }
        let bytes = batch
            .len()
            .checked_mul(usize::try_from(QUERY_RECORD_SLOT_BYTES).ok()?)
            .and_then(|value| u64::try_from(value).ok());
        let dynamic = batch
            .iter()
            .try_fold(0_u64, |total, record| {
                total
                    .checked_add(record.retained_dynamic_bytes().map_err(|_| ())?)
                    .ok_or(())
            })
            .ok();
        if let (Some(bytes), Some(dynamic)) = (bytes, dynamic)
            && let Some(bytes) = bytes.checked_add(dynamic)
        {
            if self.bytes >= bytes {
                self.bytes -= bytes;
            } else {
                self.bytes = 0;
            }
            if self.memory_used >= bytes {
                self.memory_used -= bytes;
            } else {
                self.memory_used = 0;
            }
        } else {
            self.bytes = 0;
            self.memory_used = 0;
        }
        Some(batch)
    }

    pub(crate) fn front_cloned(&self) -> Option<Vec<QueryRecord>> {
        self.batch.clone()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.batch.is_none()
    }

    pub(crate) const fn memory_peak(&self) -> u64 {
        self.memory_peak
    }

    pub(crate) fn clear(&mut self) {
        self.batch = None;
        self.rows = 0;
        self.bytes = 0;
        self.memory_used = 0;
    }
}

#[cfg(test)]
mod accounting_tests {
    use super::{MAX_BYTES, TailBuffer};
    use crate::stream::QueryRecord;

    #[test]
    fn pop_reconciles_underflow_and_overflowed_dynamic_accounting() {
        let mut buffer = TailBuffer::new(2, MAX_BYTES, MAX_BYTES).expect("bounded buffer");
        buffer
            .push(vec![QueryRecord::count_record(1)])
            .expect("record fits in the buffer");
        buffer.rows = 0;
        buffer.bytes = 0;
        buffer.memory_used = 0;
        assert!(buffer.pop().is_some());

        let mut buffer = TailBuffer::new(2, MAX_BYTES, MAX_BYTES).expect("bounded buffer");
        buffer.batch = Some(vec![
            QueryRecord::count_record(1).test_with_retained_bytes(u64::MAX, 1),
        ]);
        buffer.rows = 1;
        buffer.bytes = 1;
        assert!(buffer.pop().is_some());
        assert_eq!(buffer.bytes, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_BYTES, TailBuffer};
    use crate::QueryFailureCode;
    use crate::memory::QUERY_RECORD_SLOT_BYTES;

    #[test]
    fn invalid_windows_and_empty_batches_are_refused() {
        for (rows, bytes) in [(0, 1), (1, 0), (1_025, 1), (1, MAX_BYTES + 1)] {
            assert!(matches!(
                TailBuffer::new(rows, bytes, MAX_BYTES),
                Err(failure) if failure.code() == QueryFailureCode::InvalidBudget
            ));
        }
        let mut buffer = TailBuffer::new(1, 1, 1).expect("valid bounded window");
        assert_eq!(
            buffer
                .push(Vec::new())
                .expect_err("empty batches are not deliverable")
                .code(),
            QueryFailureCode::ResourceAdmissionRefused
        );
    }

    #[test]
    fn retained_slots_are_bounded_before_the_next_batch() {
        let mut buffer = TailBuffer::new(2, MAX_BYTES, QUERY_RECORD_SLOT_BYTES).expect("window");
        assert_eq!(
            buffer
                .push(vec![
                    crate::stream::QueryRecord::count_record(1),
                    crate::stream::QueryRecord::count_record(2),
                ])
                .expect_err("two retained slots exceed one-slot memory admission")
                .code(),
            QueryFailureCode::ResourceAdmissionRefused
        );
        buffer
            .push(vec![crate::stream::QueryRecord::count_record(1)])
            .expect("one retained slot fits");
        assert_eq!(buffer.memory_peak(), QUERY_RECORD_SLOT_BYTES);
        assert_eq!(buffer.pop().expect("retained batch").len(), 1);
        assert_eq!(buffer.memory_used, 0);
    }

    #[test]
    fn queue_reservation_and_release_are_checked_against_memory() {
        let mut buffer = TailBuffer::new(1, MAX_BYTES, 1).expect("window");
        assert_eq!(
            buffer
                .reserve_queue_bytes(2)
                .expect_err("queue reservation exceeds memory")
                .code(),
            QueryFailureCode::BudgetExhausted
        );
        assert_eq!(
            buffer
                .release_queue(1)
                .expect_err("release cannot underflow memory")
                .code(),
            QueryFailureCode::Internal
        );
        buffer.reserve_queue_bytes(1).expect("one byte fits");
        assert_eq!(buffer.memory_peak(), 1);
        buffer.release_queue(1).expect("reserved byte released");
        assert_eq!(buffer.memory_used, 0);
    }

    #[test]
    fn push_checks_existing_batch_byte_window_and_memory_window() {
        let record = crate::stream::QueryRecord::count_record(1);
        let mut buffer = TailBuffer::new(1, MAX_BYTES, MAX_BYTES).expect("window");
        buffer
            .push(vec![record.clone()])
            .expect("record fits in the buffer");
        assert_eq!(
            buffer
                .push(vec![record.clone()])
                .expect_err("a second batch cannot be retained")
                .code(),
            QueryFailureCode::ResourceAdmissionRefused
        );

        let mut bytes = TailBuffer::new(1, QUERY_RECORD_SLOT_BYTES - 1, MAX_BYTES)
            .expect("window below one retained slot");
        assert_eq!(
            bytes
                .push(vec![record.clone()])
                .expect_err("retained bytes exceed the window")
                .code(),
            QueryFailureCode::ResourceAdmissionRefused
        );

        let mut memory = TailBuffer::new(1, MAX_BYTES, QUERY_RECORD_SLOT_BYTES - 1)
            .expect("memory window below one retained slot");
        assert_eq!(
            memory
                .push(vec![record])
                .expect_err("retained bytes exceed memory")
                .code(),
            QueryFailureCode::ResourceAdmissionRefused
        );
    }
}
