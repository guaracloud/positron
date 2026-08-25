use crate::cursor::CursorState;
use crate::{QueryFailure, QueryFailureCode, QueryService};

impl<'kernel, 'catalog, 'ledger> QueryService<'kernel, 'catalog, 'ledger> {
    pub(super) fn observe_state(&self, state: &mut CursorState) -> Result<bool, QueryFailure> {
        let now = self.now()?;
        if now < state.last_observed_at {
            return Err(QueryFailure::new(QueryFailureCode::Internal));
        }
        let elapsed = now - state.last_observed_at;
        state.physical_elapsed_wall_seconds = state
            .physical_elapsed_wall_seconds
            .checked_add(elapsed)
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
        state.last_observed_at = now;
        Ok(now >= state.expiry)
    }
}
