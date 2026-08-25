use positron_kernel::ControlTokenProtector;

use crate::cursor::{self, CursorState};
use crate::{QueryEvent, QueryFailure, QueryHeader, ResultLease, ResultSnapshot};

pub(super) fn initial_header(
    protector: &ControlTokenProtector<'_>,
    state: &CursorState,
    pagination: bool,
) -> Result<QueryEvent, QueryFailure> {
    let initial_cursor = pagination
        .then(|| cursor::encode(protector, state.clone()))
        .transpose()?;
    let header = QueryHeader::new(
        &state.plan,
        state.budget,
        ResultSnapshot::new(
            state.catalog_identity,
            state.catalog_generation,
            state.frontier,
        ),
        ResultLease::new(state.lease_identity, state.expiry),
        initial_cursor,
    )?;
    Ok(QueryEvent::Header(header))
}
