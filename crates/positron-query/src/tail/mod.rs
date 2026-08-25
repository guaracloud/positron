mod admission;
mod buffer;
mod cursor;
mod lease;
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

#[cfg(test)]
mod tests {
    use super::internal;
    use crate::QueryFailureCode;

    #[test]
    fn missing_tail_state_is_internal() {
        assert_eq!(internal().code(), QueryFailureCode::Internal);
    }
}
