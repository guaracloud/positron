use crate::cursor::CursorState;
use crate::{QueryFailure, QueryFailureCode};

pub(super) fn plan_memory(state: &CursorState) -> Result<u64, QueryFailure> {
    let source = u64::try_from(state.source.as_ref().map_or(0, |source| source.len()))
        .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
    state
        .plan
        .retained_memory_bytes()?
        .checked_add(source)
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))
}
