use std::cmp::Ordering;
use std::collections::VecDeque;

use super::{TailPosition, TailSession, TailTerminal};
use crate::execution::{ScanAfter, execute_scan};
use crate::execution_support::{QueryScanObserver, query_record};
use crate::memory::QueryMemory;
use crate::{QueryBudgetDimension, QueryFailure, QueryFailureCode, QueryRecord};

pub(super) struct TailCandidate {
    pub(super) record: QueryRecord,
    pub(super) position: TailPosition,
}

impl TailSession<'_, '_, '_, '_> {
    pub(super) fn fill_sources(&mut self, limit: usize) -> Result<(), QueryFailure> {
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
        let snapshots = self
            .sources
            .readers()
            .iter()
            .map(|reader| {
                reader
                    .snapshot()
                    .map_err(crate::execution_support::map_ledger_failure)
            })
            .collect::<Result<Vec<_>, _>>()?;
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
        let historical = !self.historical_frontiers.is_empty();
        let mut all_sources_complete = true;
        for snapshot in snapshots {
            let shard = snapshot.scope().shard_id();
            let handoff_frontier = self
                .historical_frontiers
                .iter()
                .find(|position| position.shard() == shard)
                .map(|position| position.position());
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
            let (source_records, position, complete) = self.materialize_snapshot(
                &snapshot,
                after,
                handoff_frontier.unwrap_or_else(|| snapshot.frontier()),
                limit,
            )?;
            all_sources_complete &= complete;
            let mut source_records = source_records;
            source_records.sort_by(|left, right| self.compare_candidates(left, right));
            let had_candidates = !source_records.is_empty();
            let mut queue = VecDeque::new();
            queue
                .try_reserve_exact(source_records.len())
                .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
            queue.extend(source_records);
            source_batches.push(queue);
            source_progress.push((position, had_candidates));
        }
        let mut records = Vec::new();
        records
            .try_reserve_exact(limit)
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        let mut selected_shards = Vec::new();
        selected_shards
            .try_reserve_exact(source_count)
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        while records.len() < limit {
            let mut best: Option<usize> = None;
            for (source_index, queue) in source_batches.iter().enumerate() {
                if queue.front().is_none() {
                    continue;
                }
                let better = match best {
                    Some(best_index) => {
                        let left = queue.front().ok_or_else(super::internal)?;
                        let right = source_batches[best_index]
                            .front()
                            .ok_or_else(super::internal)?;
                        self.charge_merge_comparison()?;
                        self.compare_candidates(left, right) == Ordering::Less
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
            let candidate = source_batches[source_index]
                .pop_front()
                .ok_or_else(super::internal)?;
            if !selected_shards.contains(&source_index) {
                selected_shards.push(source_index);
            }
            update_position(&mut positions, candidate.position);
            records.push(candidate.record);
        }
        for (source_index, (scanned, had_candidates)) in source_progress.into_iter().enumerate() {
            if source_batches[source_index].is_empty()
                && let Some(scanned) = scanned
                && (!had_candidates || selected_shards.contains(&source_index))
            {
                update_position(&mut positions, scanned);
            }
        }
        if historical && records.len() < limit && all_sources_complete {
            self.historical_frontiers.clear();
        }
        if records.is_empty() {
            if !positions.is_empty() {
                self.advance_positions(&positions)?;
            }
            return Ok(());
        }
        let mut digest_memory = QueryMemory::new(self.query.budget.memory_bytes());
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
        if self.buffer.push(records).is_err() {
            self.terminal_after_progress_failure(TailTerminal::ConsumerLagged(Some(
                self.cursor.clone(),
            )));
            return Ok(());
        }
        self.pending_batches.push_back((positions, digest));
        Ok(())
    }

    fn materialize_snapshot(
        &mut self,
        snapshot: &positron_kernel::LedgerSnapshot<'_>,
        after: ScanAfter,
        frontier: positron_domain::routing::CommitPosition,
        limit: usize,
    ) -> Result<(Vec<TailCandidate>, Option<TailPosition>, bool), QueryFailure> {
        let _reservation = self
            .service
            .reserve_query(snapshot.scope().tenant_id(), self.query.budget)?;
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
        let scanned_retained_bytes = scan.retained_size_bytes();
        let mut memory = QueryMemory::new(state.budget.memory_bytes());
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
        let released_scan_bytes = if self.query.plan.transform().is_some() {
            scanned_retained_bytes
        } else {
            scanned_retained_bytes
                .checked_sub(transferred_body_bytes)
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?
        };
        memory.release(released_scan_bytes)?;
        if records.is_empty() {
            return Ok((Vec::new(), last_scanned, scan_complete));
        }
        state.physical_output_rows = self.output_rows;
        state.physical_output_bytes = self.output_bytes;
        let output_result = crate::execution_support::charge_output(
            self.service,
            &mut state,
            &records,
            &self.query.cancellation,
            false,
        );
        self.cpu_work_units = state.physical_cpu_work_units;
        self.output_rows = state.physical_output_rows;
        self.output_bytes = state.physical_output_bytes;
        output_result?;
        let candidates = records
            .into_iter()
            .zip(record_positions)
            .map(|(record, position)| TailCandidate { record, position })
            .collect();
        Ok((candidates, last_scanned, scan_complete))
    }

    fn compare_candidates(&self, left: &TailCandidate, right: &TailCandidate) -> Ordering {
        crate::execution_support::compare_records(
            &left.record,
            &right.record,
            self.query.plan.ordering(),
        )
        .then_with(|| left.position.shard().cmp(&right.position.shard()))
    }

    fn charge_merge_comparison(&mut self) -> Result<(), QueryFailure> {
        let units = self.service.work_units(crate::QueryWorkStage::Operators)?;
        self.cpu_work_units = self
            .cpu_work_units
            .checked_add(units)
            .ok_or_else(|| QueryFailure::budget_exhausted(QueryBudgetDimension::CpuWorkUnits))?;
        if self.cpu_work_units > self.query.budget.cpu_work_units() {
            return Err(QueryFailure::budget_exhausted(
                QueryBudgetDimension::CpuWorkUnits,
            ));
        }
        Ok(())
    }
}

fn update_position(positions: &mut Vec<TailPosition>, candidate: TailPosition) {
    if let Some(existing) = positions
        .iter_mut()
        .find(|position| position.shard() == candidate.shard())
    {
        if candidate > *existing {
            *existing = candidate;
        }
    } else {
        positions.push(candidate);
    }
}
