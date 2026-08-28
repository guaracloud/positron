mod admission;
mod buffer;
mod cursor;
#[cfg(fuzzing)]
mod fuzz;
mod historical;
mod history;
mod lease;
mod materialize;
mod memory;
mod merge;
mod session;
mod source;
mod terminal;

#[cfg(feature = "test-support")]
pub use cursor::fail_next_encode;
pub use cursor::{TailCursor, TailCursorState, TailPosition};
pub use session::{TailEvent, TailSession, TailStart};
pub use source::TailSourceSet;
pub use terminal::{TailStats, TailTerminal};

#[cfg(fuzzing)]
pub(super) use fuzz::fuzz_tail_cursor;

use crate::{QueryFailure, QueryFailureCode};

pub(crate) const MAX_TAIL_BATCH_ROWS: usize = 1_024;

pub(crate) const fn internal() -> QueryFailure {
    QueryFailure::new(QueryFailureCode::Internal)
}

#[cfg(test)]
mod tests {
    use super::internal;
    use crate::QueryFailureCode;

    #[test]
    fn missing_tail_state_is_internal() {
        assert_eq!(internal().code(), QueryFailureCode::Internal);
    }
}
