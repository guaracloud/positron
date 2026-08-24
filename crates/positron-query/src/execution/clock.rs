use crate::cursor::CursorState;
use crate::{QueryFailure, QueryFailureCode, QueryService};

impl<'kernel, 'catalog, 'ledger> QueryService<'kernel, 'catalog, 'ledger> {
    pub(super) fn observe_state(&self, state: &mut CursorState) -> Result<bool, QueryFailure> {
        let now = self.now()?;
        if now < state.last_observed_at {
            return Err(QueryFailure::new(QueryFailureCode::Internal));
        }
        state.last_observed_at = now;
        state.elapsed_wall_seconds = now.saturating_sub(state.started_at);
        Ok(now >= state.expiry)
    }
}
