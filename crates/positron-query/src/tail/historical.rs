use super::materialize::TailCandidate;
use super::session::PendingBatch;
use super::{TailPosition, TailSession, TailTerminal};
use crate::memory::QueryMemory;
use crate::result_key::HistoricalTotalKey;
use crate::{QueryBudgetDimension, QueryFailure, QueryFailureCode, QueryRecord};

fn candidate_memory(candidate: &TailCandidate) -> Result<u64, QueryFailure> {
    let dynamic = candidate.record.retained_dynamic_bytes()?;
    dynamic
        .checked_add(crate::memory::QUERY_RECORD_SLOT_BYTES)
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::ResourceExhausted))
}

impl<'service, 'kernel, 'catalog, 'ledger> TailSession<'service, 'kernel, 'catalog, 'ledger> {
    pub(super) fn fill_historical_sources(
        &mut self,
        limit: usize,
        queue_memory: &mut u64,
    ) -> Result<(), QueryFailure> {
        let mut candidates = Vec::new();
        candidates
            .try_reserve_exact(limit)
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        let mut complete = true;
        let mut window_overflow = false;
        let mut grants = Vec::new();
        grants
            .try_reserve_exact(self.sources.readers().len())
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        if self
            .sources
            .readers()
            .iter()
            .any(|reader| reader.scope() == self.service.ledger.scope())
        {
            grants.push(self._lease.take().ok_or_else(super::internal)?);
        }
        grants.append(&mut self.source_lease_grants);
        if grants.len() != self.sources.readers().len() {
            self.restore_historical_grants(grants);
            return Err(super::internal());
        }
        let scan_result = (|| -> Result<(), QueryFailure> {
            for grant in &grants {
                let snapshot = grant.snapshot();
                let shard = snapshot.scope().shard_id();
                let marker = self
                    .state
                    .historical_markers()
                    .and_then(|markers| {
                        self.state
                            .positions()
                            .iter()
                            .position(|position| position.shard() == shard)
                            .and_then(|index| markers.get(index))
                    })
                    .copied()
                    .ok_or_else(super::internal)?;
                let mut after = crate::execution::ScanAfter::Position(marker.lower_bound());
                loop {
                    let (source_records, last_scanned, source_complete) = self
                        .materialize_snapshot(
                            snapshot,
                            after,
                            marker.handoff_frontier(),
                            limit.min(super::MAX_TAIL_BATCH_ROWS),
                        )?;
                    for candidate in source_records {
                        if let Some(key) = self.state.historical_key() {
                            let candidate_key = HistoricalTotalKey::from_record(
                                &candidate.record,
                                candidate.position.shard(),
                            );
                            if self.compare_history_keys_cooperatively(
                                candidate_key,
                                key,
                                self.query.plan.ordering(),
                            )? != std::cmp::Ordering::Greater
                            {
                                continue;
                            }
                        }
                        let candidate_bytes = candidate_memory(&candidate)?;
                        let reserved = self.buffer.reserve_queue_bytes(candidate_bytes)?;
                        *queue_memory = queue_memory.checked_add(reserved).ok_or_else(|| {
                            QueryFailure::new(QueryFailureCode::ResourceExhausted)
                        })?;
                        let (accepted, evicted) =
                            self.insert_historical_candidate(&mut candidates, candidate, limit)?;
                        if let Some(evicted) = evicted {
                            window_overflow = true;
                            let released = candidate_memory(&evicted)?;
                            self.buffer.release_queue(released)?;
                            *queue_memory = queue_memory
                                .checked_sub(released)
                                .ok_or_else(super::internal)?;
                        }
                        if !accepted {
                            window_overflow = true;
                            self.buffer.release_queue(candidate_bytes)?;
                            *queue_memory = queue_memory
                                .checked_sub(candidate_bytes)
                                .ok_or_else(super::internal)?;
                        }
                    }
                    if source_complete {
                        break;
                    }
                    let Some(last_scanned) = last_scanned else {
                        complete = false;
                        break;
                    };
                    after = crate::execution::ScanAfter::Record(
                        last_scanned.position(),
                        last_scanned.ordinal(),
                    );
                }
            }
            Ok(())
        })();
        self.restore_historical_grants(grants);
        scan_result?;
        if !complete {
            let dimension = (self.limiting_budget == Some(QueryBudgetDimension::ScannedBytes)
                || self.scanned_bytes >= self.query.budget.scanned_bytes())
            .then_some(QueryBudgetDimension::ScannedBytes)
            .or(
                (self.decoded_records >= self.query.budget.decoded_records())
                    .then_some(QueryBudgetDimension::DecodedRecords),
            )
            .unwrap_or(QueryBudgetDimension::DecodedRecords);
            return Err(QueryFailure::budget_exhausted(dimension));
        }
        let historical_complete = complete && !window_overflow;
        if candidates.is_empty() {
            self.advance_positions(&self.historical_frontiers.clone(), true)?;
            self.historical_frontiers.clear();
            return Ok(());
        }
        let mut records = Vec::new();
        let mut positions = Vec::new();
        records
            .try_reserve_exact(candidates.len())
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        positions
            .try_reserve_exact(self.state.positions().len())
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        positions.extend_from_slice(self.state.positions());
        let mut last_key = None;
        for candidate in candidates {
            last_key = Some(HistoricalTotalKey::from_record(
                &candidate.record,
                candidate.position.shard(),
            ));
            records.push(candidate.record);
        }
        let candidate_memory = std::mem::take(queue_memory);
        self.buffer.release_queue(candidate_memory)?;
        self.deliver_records(records, positions, historical_complete, last_key)
    }

    fn restore_historical_grants(
        &mut self,
        mut grants: Vec<positron_kernel::SnapshotLeaseGrant<'kernel>>,
    ) {
        if let Some(index) = grants
            .iter()
            .position(|grant| grant.snapshot().scope() == self.service.ledger.scope())
        {
            self._lease = Some(grants.swap_remove(index));
        }
        self.source_lease_grants = grants;
    }

    fn insert_historical_candidate(
        &mut self,
        candidates: &mut Vec<TailCandidate>,
        candidate: TailCandidate,
        limit: usize,
    ) -> Result<(bool, Option<TailCandidate>), QueryFailure> {
        let mut insertion = candidates.len();
        for (index, existing) in candidates.iter().enumerate() {
            if self.compare_candidates_cooperatively(&candidate, existing, self.tail_ordering())?
                == std::cmp::Ordering::Less
            {
                insertion = index;
                break;
            }
        }
        if insertion == candidates.len() && candidates.len() >= limit {
            return Ok((false, None));
        }
        if candidates.len() < limit {
            candidates.insert(insertion, candidate);
            Ok((true, None))
        } else {
            let evicted = candidates.pop();
            candidates.insert(insertion, candidate);
            Ok((true, evicted))
        }
    }

    fn deliver_records(
        &mut self,
        records: Vec<QueryRecord>,
        positions: Vec<TailPosition>,
        historical_complete: bool,
        historical_key: Option<HistoricalTotalKey>,
    ) -> Result<(), QueryFailure> {
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
            historical_complete,
            historical_key,
        });
        self.publish_delivery_cursor(digest)?;
        Ok(())
    }
}
