mod buffer;
mod cursor;
mod materialize;
mod session;
mod source;

pub use cursor::{TailCursor, TailCursorState, TailPosition};
pub use session::{TailEvent, TailSession, TailStart, TailTerminal};
pub use source::TailSourceSet;

use crate::{QueryFailure, QueryFailureCode};

pub(crate) const MAX_TAIL_BATCH_ROWS: usize = 1_024;

pub(crate) const fn internal() -> QueryFailure {
    QueryFailure::new(QueryFailureCode::Internal)
}
