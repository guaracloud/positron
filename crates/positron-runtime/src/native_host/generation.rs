//! Generation-local worker readiness coordination.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::{ListenerFailure, ListenerGenerationActivation, TaskCancellation, TaskFailure};

pub(super) struct ActivationGate {
    state: Mutex<ActivationState>,
    admitting: AtomicBool,
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
            admitting: AtomicBool::new(false),
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

    pub(super) fn mark_ready(&self) -> Result<(), TaskFailure> {
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

    fn open_and_wait_ready(&self, count: usize) -> Result<(), ListenerFailure> {
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

    pub(super) fn wait_for_admission(&self, cancellation: &TaskCancellation) {
        while !self.admitting.load(Ordering::Acquire) && !cancellation.is_cancelled() {
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn open_admission(&self) {
        self.admitting.store(true, Ordering::Release);
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
    fn prepare_and_wait_ready(&self) -> Result<(), ListenerFailure> {
        self.gate.open_and_wait_ready(self.task_count)
    }

    fn open_admission(&self) {
        self.gate.open_admission();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use super::ActivationGate;
    use crate::TaskCancellation;

    #[test]
    fn prepared_worker_cannot_admit_until_the_handoff_opens_its_gate()
    -> Result<(), Box<dyn std::error::Error>> {
        let gate = Arc::new(ActivationGate::new());
        let cancellation = TaskCancellation::new();
        let admitted = Arc::new(AtomicBool::new(false));
        let worker_gate = Arc::clone(&gate);
        let worker_cancellation = cancellation.clone();
        let worker_admitted = Arc::clone(&admitted);
        let worker = std::thread::spawn(move || -> Result<(), crate::TaskFailure> {
            worker_gate.park_then_wait(&worker_cancellation)?;
            worker_gate.mark_ready()?;
            worker_gate.wait_for_admission(&worker_cancellation);
            if !worker_cancellation.is_cancelled() {
                worker_admitted.store(true, Ordering::Release);
            }
            Ok(())
        });

        gate.wait_parked(1)?;
        gate.open_and_wait_ready(1)?;
        std::thread::sleep(Duration::from_millis(10));
        assert!(
            !admitted.load(Ordering::Acquire),
            "readiness must not admit a successor before the old generation closes"
        );
        gate.open_admission();
        worker.join().map_err(|_| "prepared worker panicked")??;
        assert!(admitted.load(Ordering::Acquire));
        Ok(())
    }
}
