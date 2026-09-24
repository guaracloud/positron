//! Generation-local worker readiness coordination.

use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::{ListenerFailure, ListenerGenerationActivation, TaskCancellation, TaskFailure};

pub(super) struct ActivationGate {
    state: Mutex<ActivationState>,
    changed: Condvar,
}

struct ActivationState {
    open: bool,
    parked: usize,
    serving: usize,
}

impl ActivationGate {
    pub(super) fn new() -> Self {
        Self {
            state: Mutex::new(ActivationState {
                open: false,
                parked: 0,
                serving: 0,
            }),
            changed: Condvar::new(),
        }
    }

    pub(super) fn park_then_wait(
        &self,
        cancellation: &TaskCancellation,
    ) -> Result<(), TaskFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| TaskFailure::SpawnUnavailable)?;
        state.parked = state.parked.saturating_add(1);
        self.changed.notify_all();
        while !state.open && !cancellation.is_cancelled() {
            let (next, _) = self
                .changed
                .wait_timeout(state, Duration::from_millis(10))
                .map_err(|_| TaskFailure::SpawnUnavailable)?;
            state = next;
        }
        Ok(())
    }

    pub(super) fn mark_serving(&self) -> Result<(), TaskFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| TaskFailure::SpawnUnavailable)?;
        state.serving = state.serving.saturating_add(1);
        self.changed.notify_all();
        Ok(())
    }

    pub(super) fn wait_parked(&self, count: usize) -> Result<(), ListenerFailure> {
        self.wait_for(count, |state| state.parked)
    }

    fn open_and_wait_serving(&self, count: usize) -> Result<(), ListenerFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ListenerFailure::BindUnavailable)?;
        state.open = true;
        self.changed.notify_all();
        let deadline = Instant::now() + Duration::from_secs(2);
        while state.serving < count {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return Err(ListenerFailure::BindUnavailable);
            };
            let (next, timeout) = self
                .changed
                .wait_timeout(state, remaining)
                .map_err(|_| ListenerFailure::BindUnavailable)?;
            state = next;
            if timeout.timed_out() && state.serving < count {
                return Err(ListenerFailure::BindUnavailable);
            }
        }
        Ok(())
    }

    fn wait_for(
        &self,
        count: usize,
        observed: impl Fn(&ActivationState) -> usize,
    ) -> Result<(), ListenerFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ListenerFailure::BindUnavailable)?;
        let deadline = Instant::now() + Duration::from_secs(2);
        while observed(&state) < count {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return Err(ListenerFailure::BindUnavailable);
            };
            let (next, timeout) = self
                .changed
                .wait_timeout(state, remaining)
                .map_err(|_| ListenerFailure::BindUnavailable)?;
            state = next;
            if timeout.timed_out() && observed(&state) < count {
                return Err(ListenerFailure::BindUnavailable);
            }
        }
        Ok(())
    }
}

pub(super) struct NativeGenerationActivation {
    pub(super) gate: Arc<ActivationGate>,
    pub(super) task_count: usize,
}

impl ListenerGenerationActivation for NativeGenerationActivation {
    fn activate_and_wait_ready(&self) -> Result<(), ListenerFailure> {
        self.gate.open_and_wait_serving(self.task_count)
    }
}
