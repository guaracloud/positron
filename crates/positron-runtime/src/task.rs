use std::error::Error;
use std::fmt::{Display, Formatter};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::{HealthState, ServiceHandle};

#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskRole {
    Control,
    Operations,
    Api,
    OtlpGrpc,
    OtlpHttp,
    LokiPush,
}

#[derive(Clone, Debug)]
pub struct TaskCancellation {
    cancelled: Arc<AtomicBool>,
}

impl TaskCancellation {
    pub(crate) fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    pub(crate) fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

impl positron_signals::ScanCancellation for TaskCancellation {
    fn is_cancelled(&self) -> bool {
        self.is_cancelled()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskJoinOutcome {
    Joined,
    DeadlineExpired,
    SecondSignal,
}

pub trait RegisteredTask {
    fn spawn(
        self: Box<Self>,
        cancellation: TaskCancellation,
        health: HealthState,
        services: Option<ServiceHandle>,
    ) -> Result<Box<dyn RunningTask>, TaskFailure>;
}

pub trait RunningTask {
    fn poll_join(&mut self) -> Result<Option<TaskJoinOutcome>, TaskFailure>;
    fn join(&mut self) -> Result<TaskJoinOutcome, TaskFailure>;
    fn abort(&mut self) -> Result<(), TaskFailure>;
}

pub trait TaskRegistrar {
    fn register(&self, role: TaskRole) -> Result<Box<dyn RegisteredTask>, TaskFailure>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskFailure {
    RegistrationUnavailable,
    SpawnUnavailable,
    JoinUnavailable,
    AbortUnavailable,
}

impl Display for TaskFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("runtime task failed")
    }
}

impl Error for TaskFailure {}
