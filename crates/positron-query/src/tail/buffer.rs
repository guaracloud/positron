use std::sync::Arc;

use crate::memory::QUERY_RECORD_SLOT_BYTES;
use crate::stream::{BatchMemoryAccount, BatchMemoryClaim};
use crate::{QueryFailure, QueryFailureCode, QueryRecord};
use positron_kernel::{
    OperationToken, ResourceAmounts, ResourceDimension, ResourceGovernor,
    TransferredResourceReservation, WorkClaim, WorkKind,
};

const MAX_BYTES: u64 = 16 * 1_048_576;

pub(crate) struct TailBuffer<'kernel> {
    batch: Option<BufferedBatch>,
    rows: usize,
    bytes: u64,
    max_rows: usize,
    max_bytes: u64,
    memory_used: u64,
    memory_peak: u64,
    account: Arc<BatchMemoryAccount>,
    governor: Option<ResourceGovernor<'kernel>>,
    operation: Option<OperationToken>,
    queue_claims: Vec<QueueClaim>,
    queue_bytes: u64,
}

struct BufferedBatch {
    records: Arc<[QueryRecord]>,
    claim: Arc<BatchMemoryClaim>,
}

struct QueueClaim {
    bytes: u64,
    _reservation: Option<TransferredResourceReservation>,
}

impl<'kernel> TailBuffer<'kernel> {
    pub(crate) fn new(
        governor: ResourceGovernor<'kernel>,
        operation: OperationToken,
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
            memory_used: 0,
            memory_peak: 0,
            account: Arc::new(BatchMemoryAccount::new(memory_limit)),
            governor: Some(governor),
            operation: Some(operation),
            queue_claims: Vec::new(),
            queue_bytes: 0,
        })
    }

    #[cfg(test)]
    fn new_for_test(
        max_rows: usize,
        max_bytes: u64,
        memory_limit: u64,
    ) -> Result<TailBuffer<'static>, QueryFailure> {
        if max_rows == 0 || max_rows > 1_024 || max_bytes == 0 || max_bytes > MAX_BYTES {
            return Err(QueryFailure::new(QueryFailureCode::InvalidBudget));
        }
        Ok(TailBuffer {
            batch: None,
            rows: 0,
            bytes: 0,
            max_rows,
            max_bytes,
            memory_used: 0,
            memory_peak: 0,
            account: Arc::new(BatchMemoryAccount::new(memory_limit)),
            governor: None,
            operation: None,
            queue_claims: Vec::new(),
            queue_bytes: 0,
        })
    }

    fn reserve_governor_memory(
        &self,
        bytes: u64,
    ) -> Result<Option<TransferredResourceReservation>, QueryFailure> {
        let (Some(governor), Some(operation)) = (self.governor, self.operation) else {
            return Ok(None);
        };
        let amounts = ResourceAmounts::only(ResourceDimension::MemoryBytes, bytes)
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        let claim =
            WorkClaim::authenticated_child(operation, WorkKind::InteractiveQueryTail, amounts)
                .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
        governor
            .reserve(claim)
            .map(|reservation| reservation.transfer())
            .map(Some)
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceAdmissionRefused))
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
        let reservation = self.reserve_governor_memory(bytes)?;
        if let Err(failure) = self.account.reserve(
            bytes,
            QueryFailure::new(QueryFailureCode::ResourceAdmissionRefused),
        ) {
            drop(reservation);
            return Err(failure);
        }
        self.rows = self
            .rows
            .checked_add(rows)
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        self.bytes = next;
        self.memory_used = self.account.used();
        self.memory_peak = self.memory_peak.max(self.account.peak());
        let records = Arc::from(batch.into_boxed_slice());
        let claim = match reservation {
            Some(reservation) => BatchMemoryClaim::new_with_reservation(
                Arc::clone(&self.account),
                bytes,
                reservation,
            ),
            None => BatchMemoryClaim::new(Arc::clone(&self.account), bytes),
        };
        self.batch = Some(BufferedBatch { records, claim });
        Ok(())
    }

    pub(crate) fn reserve_queue_bytes(&mut self, bytes: u64) -> Result<u64, QueryFailure> {
        if bytes == 0 {
            return Ok(0);
        }
        let next = self
            .queue_bytes
            .checked_add(bytes)
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        let reservation = self.reserve_governor_memory(bytes)?;
        if let Err(failure) = self.account.reserve(
            bytes,
            QueryFailure::budget_exhausted(crate::QueryBudgetDimension::MemoryBytes),
        ) {
            drop(reservation);
            return Err(failure);
        }
        if let Err(_) = self.queue_claims.try_reserve(1) {
            self.account.release(bytes);
            drop(reservation);
            return Err(QueryFailure::new(QueryFailureCode::ResourceExhausted));
        }
        self.queue_claims.push(QueueClaim {
            bytes,
            _reservation: reservation,
        });
        self.queue_bytes = next;
        self.memory_used = self.account.used();
        self.memory_peak = self.memory_peak.max(self.account.peak());
        Ok(bytes)
    }

    pub(crate) fn release_queue(&mut self, bytes: u64) -> Result<(), QueryFailure> {
        if bytes == 0 {
            return Ok(());
        }
        if self.account.used() < bytes {
            return Err(QueryFailure::new(QueryFailureCode::Internal));
        }
        if self.queue_bytes < bytes {
            return Err(QueryFailure::new(QueryFailureCode::Internal));
        }
        if self.queue_bytes == bytes {
            self.queue_claims.clear();
            self.queue_bytes = 0;
        } else {
            let Some(index) = self
                .queue_claims
                .iter()
                .position(|claim| claim.bytes == bytes)
            else {
                return Err(QueryFailure::new(QueryFailureCode::Internal));
            };
            self.queue_claims.swap_remove(index);
            self.queue_bytes = self
                .queue_bytes
                .checked_sub(bytes)
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
        }
        self.account.release(bytes);
        self.memory_used = self.account.used();
        Ok(())
    }

    pub(crate) fn pop(&mut self) -> Option<Arc<[QueryRecord]>> {
        let batch = self.batch.take()?;
        if self.rows >= batch.records.len() {
            self.rows -= batch.records.len();
        } else {
            self.rows = 0;
        }
        if self.bytes >= batch.claim.bytes() {
            self.bytes -= batch.claim.bytes();
        } else {
            self.bytes = 0;
        }
        let records = Arc::clone(&batch.records);
        drop(batch);
        self.memory_used = self.account.used();
        Some(records)
    }

    pub(crate) fn front_shared(&self) -> Option<(Arc<[QueryRecord]>, Arc<BatchMemoryClaim>)> {
        let batch = self.batch.as_ref()?;
        Some((Arc::clone(&batch.records), Arc::clone(&batch.claim)))
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.batch.is_none()
    }

    pub(crate) fn memory_peak(&self) -> u64 {
        self.memory_peak.max(self.account.peak())
    }

    pub(crate) fn clear(&mut self) {
        self.batch = None;
        self.queue_claims.clear();
        self.queue_bytes = 0;
        self.rows = 0;
        self.bytes = 0;
        self.memory_used = self.account.used();
    }
}

#[cfg(test)]
mod accounting_tests {
    use std::sync::Arc;

    use super::{MAX_BYTES, TailBuffer};
    use crate::stream::{BatchMemoryClaim, QueryRecord};
    use crate::{QueryFailure, QueryFailureCode};

    #[test]
    fn pop_reconciles_underflow_and_overflowed_dynamic_accounting() {
        let mut buffer = TailBuffer::new_for_test(2, MAX_BYTES, MAX_BYTES).expect("bounded buffer");
        buffer
            .push(vec![QueryRecord::count_record(1)])
            .expect("record fits in the buffer");
        buffer.rows = 0;
        buffer.bytes = 0;
        buffer.memory_used = 0;
        assert!(buffer.pop().is_some());

        let mut buffer = TailBuffer::new_for_test(2, MAX_BYTES, MAX_BYTES).expect("bounded buffer");
        buffer
            .account
            .reserve(1, QueryFailure::new(QueryFailureCode::Internal))
            .expect("manual claim fits");
        buffer.batch = Some(super::BufferedBatch {
            records: Arc::from(
                vec![QueryRecord::count_record(1).test_with_retained_bytes(u64::MAX, 1)]
                    .into_boxed_slice(),
            ),
            claim: BatchMemoryClaim::new(Arc::clone(&buffer.account), 1),
        });
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
                TailBuffer::new_for_test(rows, bytes, MAX_BYTES),
                Err(failure) if failure.code() == QueryFailureCode::InvalidBudget
            ));
        }
        let mut buffer = TailBuffer::new_for_test(1, 1, 1).expect("valid bounded window");
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
        let mut buffer =
            TailBuffer::new_for_test(2, MAX_BYTES, QUERY_RECORD_SLOT_BYTES).expect("window");
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
        let mut buffer = TailBuffer::new_for_test(1, MAX_BYTES, 1).expect("window");
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
        let mut buffer = TailBuffer::new_for_test(1, MAX_BYTES, MAX_BYTES).expect("window");
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

        let mut bytes = TailBuffer::new_for_test(1, QUERY_RECORD_SLOT_BYTES - 1, MAX_BYTES)
            .expect("window below one retained slot");
        assert_eq!(
            bytes
                .push(vec![record.clone()])
                .expect_err("retained bytes exceed the window")
                .code(),
            QueryFailureCode::ResourceAdmissionRefused
        );

        let mut memory = TailBuffer::new_for_test(1, MAX_BYTES, QUERY_RECORD_SLOT_BYTES - 1)
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
