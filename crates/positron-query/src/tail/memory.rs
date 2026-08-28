use crate::{PlannedQuery, QueryFailure, QueryFailureCode};

pub(super) struct TailMemoryBudget {
    pub(super) retained_bytes: u64,
    pub(super) execution_limit: u64,
}

pub(super) fn tail_memory_budget(
    query: &PlannedQuery<'_>,
) -> Result<TailMemoryBudget, QueryFailure> {
    let source_bytes = u64::try_from(query.source.len())
        .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
    let retained_bytes = query
        .plan
        .retained_memory_bytes()?
        .checked_add(source_bytes)
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
    let execution_limit = query
        .budget
        .memory_bytes()
        .checked_sub(retained_bytes)
        .ok_or_else(|| QueryFailure::budget_exhausted(crate::QueryBudgetDimension::MemoryBytes))?;
    Ok(TailMemoryBudget {
        retained_bytes,
        execution_limit,
    })
}
