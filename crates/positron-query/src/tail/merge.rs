use std::cmp::Ordering;

use super::materialize::TailCandidate;
use super::{TailPosition, TailSession};
use crate::plan::OrderSpec;
use crate::result_key::HistoricalTotalKey;
use crate::{QueryBudgetDimension, QueryFailure, QueryFailureCode};

#[derive(Clone, Copy)]
pub(super) enum TailOrdering {
    Historical(OrderSpec),
    CommitVector,
}

impl TailSession<'_, '_, '_, '_> {
    pub(super) fn sort_candidates(
        &mut self,
        candidates: &mut [TailCandidate],
    ) -> Result<(), QueryFailure> {
        for index in 1..candidates.len() {
            let mut current = index;
            while current > 0 {
                if self.compare_candidates_cooperatively(
                    &candidates[current - 1],
                    &candidates[current],
                    self.tail_ordering(),
                )? != Ordering::Greater
                {
                    break;
                }
                candidates.swap(current - 1, current);
                current -= 1;
            }
        }
        Ok(())
    }

    pub(super) fn charge_merge_comparison(&mut self) -> Result<(), QueryFailure> {
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

    pub(super) fn compare_candidates_cooperatively(
        &mut self,
        left: &TailCandidate,
        right: &TailCandidate,
        ordering: TailOrdering,
    ) -> Result<Ordering, QueryFailure> {
        if self.query.cancellation.is_cancelled() {
            return Err(QueryFailure::new(QueryFailureCode::Cancelled));
        }
        self.charge_merge_comparison()?;
        if self.query.cancellation.is_cancelled() {
            return Err(QueryFailure::new(QueryFailureCode::Cancelled));
        }
        let result = compare_candidates(left, right, ordering);
        if self.query.cancellation.is_cancelled() {
            return Err(QueryFailure::new(QueryFailureCode::Cancelled));
        }
        Ok(result)
    }
}

impl TailSession<'_, '_, '_, '_> {
    pub(super) fn update_position(
        &mut self,
        positions: &mut Vec<TailPosition>,
        candidate: TailPosition,
    ) -> Result<(), QueryFailure> {
        for position in positions.iter_mut() {
            if self.query.cancellation.is_cancelled() {
                return Err(QueryFailure::new(QueryFailureCode::Cancelled));
            }
            self.charge_merge_comparison()?;
            if position.shard() == candidate.shard() {
                if candidate > *position {
                    *position = candidate;
                }
                return Ok(());
            }
        }
        positions
            .try_reserve(1)
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        positions.push(candidate);
        Ok(())
    }
}

pub(super) fn compare_candidates(
    left: &TailCandidate,
    right: &TailCandidate,
    ordering: TailOrdering,
) -> Ordering {
    match ordering {
        TailOrdering::Historical(ordering) => {
            HistoricalTotalKey::from_record(&left.record, left.position.shard()).compare(
                HistoricalTotalKey::from_record(&right.record, right.position.shard()),
                ordering,
            )
        },
        TailOrdering::CommitVector => left
            .position
            .position()
            .cmp(&right.position.position())
            .then_with(|| left.position.ordinal().cmp(&right.position.ordinal()))
            .then_with(|| left.position.shard().cmp(&right.position.shard())),
    }
}

impl TailSession<'_, '_, '_, '_> {
    pub(super) fn tail_ordering(&self) -> TailOrdering {
        if self.historical_frontiers.is_empty() {
            TailOrdering::CommitVector
        } else {
            TailOrdering::Historical(self.query.plan.ordering())
        }
    }
}
