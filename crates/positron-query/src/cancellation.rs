use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Cooperative cancellation shared by query planning, execution, and result delivery.
///
/// A transport may retain this handle to propagate disconnects or expired deadlines while
/// bounded query operators are running. Cancellation is permanent for the query lifecycle.
#[derive(Clone, Debug)]
pub struct QueryCancellation {
    cancelled: Arc<AtomicBool>,
}

impl QueryCancellation {
    pub(crate) fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

impl positron_signals::ScanCancellation for QueryCancellation {
    fn is_cancelled(&self) -> bool {
        self.is_cancelled()
    }
}
