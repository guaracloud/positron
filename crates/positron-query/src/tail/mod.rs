mod buffer;
mod cursor;
mod session;

pub use cursor::{TailCursor, TailCursorState, TailPosition};
pub use session::{TailEvent, TailSession, TailStart, TailTerminal};

use crate::{QueryFailure, QueryFailureCode};

pub(crate) const MAX_TAIL_BATCH_ROWS: usize = 1_024;

pub(crate) const fn internal() -> QueryFailure {
    QueryFailure::new(QueryFailureCode::Internal)
}
