use super::{TailPosition, TailSession, TailTerminal};
use crate::execution::execute_scan;
use crate::execution_support::{QueryScanObserver, query_record};
use crate::memory::QueryMemory;
use crate::{QueryFailure, QueryFailureCode};

impl TailSession<'_, '_, '_, '_> {
    pub(super) fn fill_sources(&mut self, limit: usize) -> Result<(), QueryFailure> {
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
        let mut records = Vec::new();
        let mut positions = Vec::new();
        for snapshot in snapshots {
            let shard = snapshot.scope().shard_id();
            let after = self
                .state
                .positions()
                .iter()
                .find(|position| position.shard() == shard)
                .map_or(
                    positron_domain::routing::CommitPosition::origin(),
                    |position| position.position(),
                );
            let (mut source_records, position) =
                self.materialize_snapshot(&snapshot, after, limit)?;
            records.append(&mut source_records);
            if let Some(position) = position {
                positions.push(position);
            }
        }
        if records.is_empty() {
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
            self.terminal = Some(TailTerminal::ConsumerLagged(Some(self.cursor.clone())));
            return Ok(());
        }
        self.pending_batches.push_back((positions, digest));
        Ok(())
    }

    fn materialize_snapshot(
        &mut self,
        snapshot: &positron_kernel::LedgerSnapshot<'_>,
        after: positron_domain::routing::CommitPosition,
        limit: usize,
    ) -> Result<(Vec<crate::stream::QueryRecord>, Option<TailPosition>), QueryFailure> {
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
        let scan = execute_scan(
            self.service.governor,
            state.tenant,
            snapshot,
            Some(after),
            snapshot.frontier(),
            scan_limit,
            state.budget.scanned_bytes(),
            None,
            None,
            None,
            &self.query.cancellation,
            &mut observer,
        )?;
        observer.harvest(&mut state);
        self.scanned_bytes = state.physical_scanned_bytes;
        self.decoded_records = state.physical_decoded_records;
        self.cpu_work_units = state.physical_cpu_work_units;
        let mut memory = QueryMemory::new(state.budget.memory_bytes());
        let mut records = Vec::new();
        records
            .try_reserve_exact(limit)
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        let mut last = None;
        let shard = snapshot.scope().shard_id();
        for mut record in scan.into_records() {
            if let Some(record) =
                query_record(self.service, &mut state, &mut record, false, &mut memory)?
            {
                last = Some(TailPosition::with_ordinal(
                    shard,
                    record.commit_position(),
                    record.record_ordinal(),
                ));
                records.push(if self.replay {
                    record.mark_replayed()
                } else {
                    record
                });
            }
            if records.len() >= limit {
                break;
            }
        }
        if records.is_empty() {
            return Ok((records, None));
        }
        state.physical_output_rows = self.output_rows;
        state.physical_output_bytes = self.output_bytes;
        crate::execution_support::charge_output(
            self.service,
            &mut state,
            &records,
            &self.query.cancellation,
            false,
        )?;
        self.output_rows = state.physical_output_rows;
        self.output_bytes = state.physical_output_bytes;
        let position = last.ok_or_else(super::internal)?;
        Ok((records, Some(position)))
    }
}
