use std::cmp::Ordering;

use super::materialize::TailCandidate;
use super::{TailPosition, TailSession};
use crate::plan::OrderSpec;
use crate::{QueryBudgetDimension, QueryFailure, QueryFailureCode};

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
                    self.query.plan.ordering(),
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
        ordering: OrderSpec,
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

pub(super) fn compare_candidates(
    left: &TailCandidate,
    right: &TailCandidate,
    ordering: OrderSpec,
) -> Ordering {
    crate::execution_support::compare_records(&left.record, &right.record, ordering)
        .then_with(|| left.position.shard().cmp(&right.position.shard()))
}

pub(super) fn update_position(
    positions: &mut Vec<TailPosition>,
    candidate: TailPosition,
) -> Result<(), QueryFailure> {
    if let Some(existing) = positions
        .iter_mut()
        .find(|position| position.shard() == candidate.shard())
    {
        if candidate > *existing {
            *existing = candidate;
        }
    } else {
        positions
            .try_reserve(1)
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        positions.push(candidate);
    }
    Ok(())
}
