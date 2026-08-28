use super::session::PendingBatch;
use super::{TailPosition, TailSession, TailTerminal};
use crate::execution::{ScanAfter, execute_scan};
use crate::execution_support::{QueryScanObserver, query_record};
use crate::memory::QueryMemory;
use crate::{QueryBudgetDimension, QueryFailure, QueryFailureCode, QueryRecord};
use std::{cmp::Ordering, collections::VecDeque};
pub(super) struct TailCandidate {
    pub(super) record: QueryRecord,
    pub(super) position: TailPosition,
}
impl TailSession<'_, '_, '_, '_> {
    pub(super) fn fill_sources(&mut self, limit: usize) -> Result<(), QueryFailure> {
        let mut queue_memory = 0_u64;
        let result = self.fill_sources_inner(limit, &mut queue_memory);
        let cleanup = self.buffer.release_queue(queue_memory);
        match (result, cleanup) {
            (Err(failure), Ok(())) => Err(failure),
            (Ok(()), Ok(())) => Ok(()),
            (Ok(()), Err(failure)) => Err(failure),
            (Err(failure), Err(cleanup)) => Err(crate::failure::stronger_failure(failure, cleanup)),
        }
    }
    fn fill_sources_inner(
        &mut self,
        limit: usize,
        queue_memory: &mut u64,
    ) -> Result<(), QueryFailure> {
        let output_remaining = self
            .query
            .budget
            .output_rows()
            .checked_sub(self.output_rows)
            .ok_or_else(|| {
                QueryFailure::budget_exhausted(crate::QueryBudgetDimension::OutputRows)
            })?;
        let limit = limit.min(usize::try_from(output_remaining).unwrap_or(usize::MAX));
        if limit == 0 {
            return Err(QueryFailure::budget_exhausted(
                crate::QueryBudgetDimension::OutputRows,
            ));
        }
        if !self.historical_frontiers.is_empty() {
            return self.fill_historical_sources(limit, queue_memory);
        }
        let mut snapshots = Vec::new();
        snapshots
            .try_reserve_exact(self.sources.readers().len())
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        for reader in self.sources.readers() {
            snapshots.push(
                reader
                    .snapshot()
                    .map_err(crate::execution_support::map_ledger_failure)?,
            );
        }
        let source_count = snapshots.len();
        let mut source_batches = Vec::new();
        source_batches
            .try_reserve_exact(source_count)
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        let mut source_progress = Vec::new();
        source_progress
            .try_reserve_exact(source_count)
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        let mut positions = Vec::new();
        positions
            .try_reserve_exact(source_count)
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        for snapshot in snapshots {
            let shard = snapshot.scope().shard_id();
            let after = self
                .state
                .positions()
                .iter()
                .find(|position| position.shard() == shard)
                .copied()
                .ok_or_else(super::internal)?;
            let after = if self.state.record_bound() {
                ScanAfter::Record(after.position(), after.ordinal())
            } else {
                ScanAfter::Position(after.position())
            };
            let (mut source_records, position, _) =
                self.materialize_snapshot(&snapshot, after, snapshot.frontier(), limit)?;
            self.sort_candidates(&mut source_records)?;
            let slots = u64::try_from(source_records.len())
                .ok()
                .and_then(|count| count.checked_mul(crate::memory::QUERY_RECORD_SLOT_BYTES))
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
            let dynamic = source_records.iter().try_fold(0_u64, |total, candidate| {
                total
                    .checked_add(candidate.record.retained_dynamic_bytes()?)
                    .ok_or_else(|| QueryFailure::new(QueryFailureCode::ResourceExhausted))
            })?;
            let mut queue = VecDeque::new();
            queue
                .try_reserve_exact(source_records.len())
                .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
            let reserved = self.buffer.reserve_queue_bytes(
                slots
                    .checked_add(dynamic)
                    .ok_or_else(|| QueryFailure::new(QueryFailureCode::ResourceExhausted))?,
            )?;
            *queue_memory = queue_memory
                .checked_add(reserved)
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
            queue.extend(source_records);
            source_progress.push((position, queue.front().is_some()));
            source_batches.push(queue);
        }
        let mut records = Vec::new();
        records
            .try_reserve_exact(limit)
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        let mut selected_shards = Vec::new();
        selected_shards
            .try_reserve_exact(source_count)
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        selected_shards.resize(source_count, false);
        while records.len() < limit {
            let mut best: Option<usize> = None;
            for (source_index, queue) in source_batches.iter().enumerate() {
                if queue.front().is_none() {
                    continue;
                }
                let better = match best {
                    Some(best_index) => {
                        let left = queue.front().ok_or_else(super::internal)?;
                        let right = source_batches
                            .get(best_index)
                            .ok_or_else(super::internal)?
                            .front()
                            .ok_or_else(super::internal)?;
                        self.compare_candidates_cooperatively(left, right, self.tail_ordering())?
                            == Ordering::Less
                    },
                    None => true,
                };
                if better {
                    best = Some(source_index);
                }
            }
            let Some(source_index) = best else {
                break;
            };
            let candidate = source_batches
                .get_mut(source_index)
                .ok_or_else(super::internal)?
                .pop_front()
                .ok_or_else(super::internal)?;
            *selected_shards
                .get_mut(source_index)
                .ok_or_else(super::internal)? = true;
            self.update_position(&mut positions, candidate.position)?;
            records.push(candidate.record);
        }
        for (source_index, (scanned, had_candidates)) in source_progress.into_iter().enumerate() {
            if source_batches
                .get(source_index)
                .ok_or_else(super::internal)?
                .is_empty()
                && let Some(scanned) = scanned
                && (!had_candidates
                    || *selected_shards
                        .get(source_index)
                        .ok_or_else(super::internal)?)
            {
                self.update_position(&mut positions, scanned)?;
            }
        }
        if records.is_empty() {
            if self.replay_delivery.is_some() {
                return Err(QueryFailure::new(QueryFailureCode::StoreUnavailable));
            }
            if !positions.is_empty() {
                self.advance_positions(&positions, false)?;
            }
            return Ok(());
        }
        let rows = u64::try_from(records.len())
            .map_err(|_| QueryFailure::budget_exhausted(QueryBudgetDimension::OutputRows))?;
        let bytes = crate::execution_support::output_bytes_for_records(
            self.service,
            &records,
            &mut self.cpu_work_units,
            self.query.budget.cpu_work_units(),
            &self.query.cancellation,
        )?;
        let next_rows = self
            .output_rows
            .checked_add(rows)
            .ok_or_else(|| QueryFailure::budget_exhausted(QueryBudgetDimension::OutputRows))?;
        if next_rows > self.query.budget.output_rows() {
            return Err(QueryFailure::budget_exhausted(
                QueryBudgetDimension::OutputRows,
            ));
        }
        let next_bytes = self
            .output_bytes
            .checked_add(bytes)
            .ok_or_else(|| QueryFailure::budget_exhausted(QueryBudgetDimension::OutputBytes))?;
        if next_bytes > self.query.budget.output_bytes() {
            return Err(QueryFailure::budget_exhausted(
                QueryBudgetDimension::OutputBytes,
            ));
        }
        let mut digest_memory = QueryMemory::new(self.runtime_memory_limit);
        let mut digest_observer = crate::execution_support::QueryValueObserver::new(
            self.service,
            &mut self.cpu_work_units,
            self.query.budget.cpu_work_units(),
            self.query.cancellation.clone(),
            crate::QueryWorkStage::Output,
        );
        let digest = crate::execution_support::batch_digest(
            &self.service.ledger.control_tokens(),
            crate::execution_support::BatchDigestInput {
                prior: self.prior_digest,
                sequence: self.next_sequence,
                plan: &self.query.plan,
                records: &records,
                cancellation: &self.query.cancellation,
                observer: &mut digest_observer,
            },
            &mut digest_memory,
        )?;
        self.record_memory_peak(digest_memory.peak())?;
        if let Err(failure) = self.buffer.push(records) {
            if failure.code() == QueryFailureCode::ResourceAdmissionRefused {
                self.terminal_after_progress_failure(TailTerminal::ConsumerLagged {
                    cursor: Some(self.cursor.clone()),
                    stats: self.terminal_stats(),
                });
                return Ok(());
            }
            return Err(failure);
        }
        self.record_memory_peak(self.buffer.memory_peak())?;
        self.pending_batch = Some(PendingBatch {
            positions,
            digest,
            rows,
            bytes,
            historical_complete: false,
            historical_key: None,
        });
        self.publish_delivery_cursor(digest)?;
        Ok(())
    }
    pub(super) fn materialize_snapshot(
        &mut self,
        snapshot: &positron_kernel::LedgerSnapshot<'_>,
        after: ScanAfter,
        frontier: positron_domain::routing::CommitPosition,
        limit: usize,
    ) -> Result<(Vec<TailCandidate>, Option<TailPosition>, bool), QueryFailure> {
        let mut state =
            crate::execution_state::tail_state(&self.query, snapshot, self.state.expiry());
        state.physical_scanned_bytes = self.scanned_bytes;
        state.physical_decoded_records = self.decoded_records;
        state.physical_cpu_work_units = self.cpu_work_units;
        let scan_limit = positron_signals::ScanLimit::new(limit)
            .map_err(crate::execution_support::map_store_failure)?;
        let mut observer = QueryScanObserver::new(
            self.service.work_meter.as_ref(),
            self.query.cancellation.clone(),
            state.physical_cpu_work_units,
            state.budget.cpu_work_units(),
            state.physical_scanned_bytes,
            state.budget.scanned_bytes(),
            state.physical_decoded_records,
            state.budget.decoded_records(),
        );
        let scan = match execute_scan(
            self.service.governor,
            state.tenant,
            snapshot,
            Some(after),
            frontier,
            scan_limit,
            state.budget.scanned_bytes(),
            None,
            None,
            None,
            &self.query.cancellation,
            &mut observer,
        ) {
            Ok(scan) => scan,
            Err(failure) => {
                observer.harvest(&mut state);
                self.scanned_bytes = state.physical_scanned_bytes;
                self.decoded_records = state.physical_decoded_records;
                self.cpu_work_units = state.physical_cpu_work_units;
                return Err(failure);
            },
        };
        observer.harvest(&mut state);
        self.scanned_bytes = state.physical_scanned_bytes;
        self.decoded_records = state.physical_decoded_records;
        self.cpu_work_units = state.physical_cpu_work_units;
        let scan_complete = scan.complete();
        if scan.scanned_bytes_limited() {
            self.limiting_budget = Some(QueryBudgetDimension::ScannedBytes);
        }
        self.reduced_pruning |= scan.reduced_pruning();
        let scanned_retained_bytes = scan.retained_size_bytes();
        let mut memory = QueryMemory::new(self.runtime_memory_limit);
        memory.acquire(scanned_retained_bytes)?;
        let mut records = Vec::new();
        records
            .try_reserve_exact(limit)
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        let mut record_positions = Vec::new();
        record_positions
            .try_reserve_exact(limit)
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        let mut transferred_body_bytes = 0_u64;
        let mut last_scanned = None;
        let shard = snapshot.scope().shard_id();
        for mut record in scan.into_records() {
            if state.cancellation.is_cancelled() {
                return Err(QueryFailure::new(QueryFailureCode::Cancelled));
            }
            let operator_count = state.plan.operator_count();
            if operator_count > 0 {
                let units = self
                    .service
                    .work_units(crate::QueryWorkStage::Operators)?
                    .checked_mul(operator_count)
                    .ok_or_else(|| {
                        QueryFailure::budget_exhausted(QueryBudgetDimension::CpuWorkUnits)
                    })?;
                state.physical_cpu_work_units = state
                    .physical_cpu_work_units
                    .checked_add(units)
                    .ok_or_else(|| {
                        QueryFailure::budget_exhausted(QueryBudgetDimension::CpuWorkUnits)
                    })?;
                if state.physical_cpu_work_units > state.budget.cpu_work_units() {
                    self.cpu_work_units = state.physical_cpu_work_units;
                    return Err(QueryFailure::budget_exhausted(
                        QueryBudgetDimension::CpuWorkUnits,
                    ));
                }
            }
            last_scanned = Some(TailPosition::with_ordinal(
                shard,
                record.commit_position(),
                record.record_ordinal(),
            ));
            let record =
                match query_record(self.service, &mut state, &mut record, false, &mut memory) {
                    Ok(record) => record,
                    Err(failure) => {
                        self.cpu_work_units = state.physical_cpu_work_units;
                        self.record_memory_peak(memory.peak())?;
                        return Err(failure);
                    },
                };
            if let Some(record) = record {
                transferred_body_bytes = transferred_body_bytes
                    .checked_add(record.body_retained_bytes())
                    .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
                records.push(if self.replay {
                    record.mark_replayed()
                } else {
                    record
                });
                record_positions.push(last_scanned.ok_or_else(super::internal)?);
            }
            if records.len() >= limit {
                break;
            }
        }
        self.record_memory_peak(memory.peak())?;
        let released_scan_bytes = if self.query.plan.transform().is_some() {
            scanned_retained_bytes
        } else {
            scanned_retained_bytes
                .checked_sub(transferred_body_bytes)
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?
        };
        memory.release(released_scan_bytes)?;
        if records.is_empty() {
            self.cpu_work_units = state.physical_cpu_work_units;
            return Ok((Vec::new(), last_scanned, scan_complete));
        }
        self.cpu_work_units = state.physical_cpu_work_units;
        let mut candidates = Vec::new();
        candidates
            .try_reserve_exact(records.len())
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        for (record, position) in records.into_iter().zip(record_positions) {
            candidates.push(TailCandidate { record, position });
        }
        Ok((candidates, last_scanned, scan_complete))
    }
}
