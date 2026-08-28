use super::TailSession;
use super::materialize::TailCandidate;
use crate::result_key::HistoricalTotalKey;
use crate::{QueryBudgetDimension, QueryFailure, QueryFailureCode};

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
}
