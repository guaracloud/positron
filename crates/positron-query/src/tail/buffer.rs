use std::collections::VecDeque;

use crate::{QueryFailure, QueryFailureCode, QueryRecord};

const MAX_BYTES: u64 = 16 * 1_048_576;

pub(crate) struct TailBuffer {
    batches: VecDeque<Vec<QueryRecord>>,
    rows: usize,
    bytes: u64,
    max_rows: usize,
    max_bytes: u64,
}

impl TailBuffer {
    pub(crate) fn new(max_rows: usize, max_bytes: u64) -> Result<Self, QueryFailure> {
        if max_rows == 0 || max_rows > 1_024 || max_bytes == 0 || max_bytes > MAX_BYTES {
            return Err(QueryFailure::new(QueryFailureCode::InvalidBudget));
        }
        let mut batches = VecDeque::new();
        batches
            .try_reserve_exact(max_rows)
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        Ok(Self {
            batches,
            rows: 0,
            bytes: 0,
            max_rows,
            max_bytes,
        })
    }

    pub(crate) fn push(&mut self, batch: Vec<QueryRecord>) -> Result<(), QueryFailure> {
        let rows = batch.len();
        if rows == 0 || rows > self.max_rows.saturating_sub(self.rows) {
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
            .checked_mul(std::mem::size_of::<QueryRecord>())
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
        self.rows = self
            .rows
            .checked_add(rows)
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        self.bytes = next;
        self.batches.push_back(batch);
        Ok(())
    }

    pub(crate) fn pop(&mut self) -> Option<Vec<QueryRecord>> {
        let batch = self.batches.pop_front()?;
        if self.rows >= batch.len() {
            self.rows -= batch.len();
        } else {
            self.rows = 0;
        }
        let bytes = batch
            .len()
            .checked_mul(std::mem::size_of::<QueryRecord>())
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
        } else {
            self.bytes = 0;
        }
        Some(batch)
    }

    pub(crate) fn front_cloned(&self) -> Option<Vec<QueryRecord>> {
        self.batches.front().cloned()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.batches.is_empty()
    }

    pub(crate) fn clear(&mut self) {
        self.batches.clear();
        self.rows = 0;
        self.bytes = 0;
    }
}

#[cfg(test)]
mod accounting_tests {
    use super::{MAX_BYTES, TailBuffer};
    use crate::stream::QueryRecord;

    #[test]
    fn pop_reconciles_underflow_and_overflowed_dynamic_accounting() {
        let mut buffer = TailBuffer::new(2, MAX_BYTES).expect("bounded buffer");
        buffer
            .push(vec![QueryRecord::count_record(1)])
            .expect("record fits in the buffer");
        buffer.rows = 0;
        buffer.bytes = 0;
        assert!(buffer.pop().is_some());

        let mut buffer = TailBuffer::new(2, MAX_BYTES).expect("bounded buffer");
        buffer.batches.push_back(vec![
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

    #[test]
    fn invalid_windows_and_empty_batches_are_refused() {
        for (rows, bytes) in [(0, 1), (1, 0), (1_025, 1), (1, MAX_BYTES + 1)] {
            assert!(matches!(
                TailBuffer::new(rows, bytes),
                Err(failure) if failure.code() == QueryFailureCode::InvalidBudget
            ));
        }
        let mut buffer = TailBuffer::new(1, 1).expect("valid bounded window");
        assert_eq!(
            buffer
                .push(Vec::new())
                .expect_err("empty batches are not deliverable")
                .code(),
            QueryFailureCode::ResourceAdmissionRefused
        );
    }
}
