use super::*;

pub(super) struct IngestDrainGate {
    state: Mutex<IngestDrainState>,
    changed: Condvar,
    #[cfg(test)]
    transition_observer: Mutex<Option<std::sync::mpsc::Sender<()>>>,
}

const LIFECYCLE_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

struct IngestDrainState {
    lifecycle_transitioning: bool,
    in_flight: u64,
}

/// Cancels and drains active query executions before restrictive lifecycle publication.
pub(super) struct QueryDrainGate {
    state: Mutex<QueryDrainState>,
    changed: Condvar,
    #[cfg(test)]
    transition_observer: Mutex<Option<std::sync::mpsc::Sender<()>>>,
}

struct QueryDrainState {
    closing: bool,
    next_id: u64,
    active: Vec<(u64, QueryCancellation)>,
}

impl QueryDrainGate {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(QueryDrainState {
                closing: false,
                next_id: 0,
                active: Vec::new(),
            }),
            changed: Condvar::new(),
            #[cfg(test)]
            transition_observer: Mutex::new(None),
        })
    }

    pub(super) fn enter(
        self: &Arc<Self>,
        cancellation: QueryCancellation,
    ) -> Result<QueryDrainPermit, BootstrapFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        if state.closing {
            return Err(BootstrapFailure::new(
                BootstrapFailureCode::ResourceUnavailable,
            ));
        }
        let id = state.next_id;
        state.next_id = state
            .next_id
            .checked_add(1)
            .ok_or_else(|| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        state
            .active
            .try_reserve(1)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        state.active.push((id, cancellation));
        Ok(QueryDrainPermit {
            gate: Arc::clone(self),
            id,
        })
    }

    pub(super) fn cancel_and_drain(
        self: &Arc<Self>,
    ) -> Result<QueryLifecycleDrainPermit, BootstrapFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        let deadline = Instant::now()
            .checked_add(LIFECYCLE_DRAIN_TIMEOUT)
            .ok_or_else(|| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        while state.closing {
            let (next, timed_out) = wait_for_query_drain(&self.changed, state, deadline)?;
            if timed_out {
                return Err(BootstrapFailure::new(
                    BootstrapFailureCode::ResourceUnavailable,
                ));
            }
            state = next;
        }
        state.closing = true;
        #[cfg(test)]
        if let Some(observer) = self
            .transition_observer
            .lock()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?
            .clone()
        {
            let _ = observer.send(());
        }
        for (_, cancellation) in &state.active {
            cancellation.cancel();
        }
        while !state.active.is_empty() {
            let (next, timed_out) = wait_for_query_drain(&self.changed, state, deadline)?;
            state = next;
            if timed_out {
                state.closing = false;
                self.changed.notify_all();
                return Err(BootstrapFailure::new(
                    BootstrapFailureCode::ResourceUnavailable,
                ));
            }
        }
        Ok(QueryLifecycleDrainPermit {
            gate: Arc::clone(self),
        })
    }

    #[cfg(test)]
    pub(super) fn install_transition_observer(
        &self,
        observer: std::sync::mpsc::Sender<()>,
    ) -> Result<(), BootstrapFailure> {
        *self
            .transition_observer
            .lock()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))? =
            Some(observer);
        Ok(())
    }
}

fn wait_for_query_drain<'gate>(
    changed: &'gate Condvar,
    state: std::sync::MutexGuard<'gate, QueryDrainState>,
    deadline: Instant,
) -> Result<(std::sync::MutexGuard<'gate, QueryDrainState>, bool), BootstrapFailure> {
    let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
        return Ok((state, true));
    };
    let (state, timed_out) = changed
        .wait_timeout(state, remaining)
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
    Ok((state, timed_out.timed_out()))
}

pub(crate) struct QueryDrainPermit {
    gate: Arc<QueryDrainGate>,
    id: u64,
}

impl Drop for QueryDrainPermit {
    fn drop(&mut self) {
        let mut state = match self.gate.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(index) = state.active.iter().position(|(id, _)| *id == self.id) {
            state.active.remove(index);
        }
        self.gate.changed.notify_all();
    }
}

pub(super) struct QueryLifecycleDrainPermit {
    gate: Arc<QueryDrainGate>,
}

impl Drop for QueryLifecycleDrainPermit {
    fn drop(&mut self) {
        let mut state = match self.gate.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.closing = false;
        self.gate.changed.notify_all();
    }
}

impl IngestDrainGate {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(IngestDrainState {
                lifecycle_transitioning: false,
                in_flight: 0,
            }),
            changed: Condvar::new(),
            #[cfg(test)]
            transition_observer: Mutex::new(None),
        })
    }

    pub(super) fn enter(self: &Arc<Self>) -> Result<IngestDrainPermit, BootstrapFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        if state.lifecycle_transitioning {
            return Err(BootstrapFailure::new(
                BootstrapFailureCode::ResourceUnavailable,
            ));
        }
        state.in_flight = state
            .in_flight
            .checked_add(1)
            .ok_or_else(|| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        Ok(IngestDrainPermit {
            gate: Arc::clone(self),
        })
    }

    pub(super) fn close_and_drain(
        self: &Arc<Self>,
    ) -> Result<LifecycleDrainPermit, BootstrapFailure> {
        let deadline = Instant::now()
            .checked_add(LIFECYCLE_DRAIN_TIMEOUT)
            .ok_or_else(|| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        self.close_and_drain_before(deadline)
    }

    pub(super) fn close_and_drain_before(
        self: &Arc<Self>,
        deadline: Instant,
    ) -> Result<LifecycleDrainPermit, BootstrapFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        while state.lifecycle_transitioning {
            let (next, timed_out) = wait_for_lifecycle_drain(&self.changed, state, deadline)?;
            if timed_out {
                return Err(BootstrapFailure::new(
                    BootstrapFailureCode::ResourceUnavailable,
                ));
            }
            state = next;
        }
        state.lifecycle_transitioning = true;
        #[cfg(test)]
        if let Some(observer) = self
            .transition_observer
            .lock()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?
            .clone()
        {
            let _ = observer.send(());
        }
        while state.in_flight != 0 {
            let (next, timed_out) = wait_for_lifecycle_drain(&self.changed, state, deadline)?;
            state = next;
            if timed_out {
                state.lifecycle_transitioning = false;
                self.changed.notify_all();
                return Err(BootstrapFailure::new(
                    BootstrapFailureCode::ResourceUnavailable,
                ));
            }
        }
        Ok(LifecycleDrainPermit {
            gate: Arc::clone(self),
        })
    }

    #[cfg(test)]
    pub(super) fn install_transition_observer(
        &self,
        observer: std::sync::mpsc::Sender<()>,
    ) -> Result<(), BootstrapFailure> {
        *self
            .transition_observer
            .lock()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))? =
            Some(observer);
        Ok(())
    }
}

fn wait_for_lifecycle_drain<'gate>(
    changed: &'gate Condvar,
    state: std::sync::MutexGuard<'gate, IngestDrainState>,
    deadline: Instant,
) -> Result<(std::sync::MutexGuard<'gate, IngestDrainState>, bool), BootstrapFailure> {
    let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
        return Ok((state, true));
    };
    let (state, timed_out) = changed
        .wait_timeout(state, remaining)
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
    Ok((state, timed_out.timed_out()))
}

pub(crate) struct IngestDrainPermit {
    gate: Arc<IngestDrainGate>,
}

impl Drop for IngestDrainPermit {
    fn drop(&mut self) {
        let mut state = match self.gate.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.in_flight = state.in_flight.saturating_sub(1);
        self.gate.changed.notify_all();
    }
}

pub(super) struct LifecycleDrainPermit {
    gate: Arc<IngestDrainGate>,
}

impl Drop for LifecycleDrainPermit {
    fn drop(&mut self) {
        let mut state = match self.gate.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.lifecycle_transitioning = false;
        self.gate.changed.notify_all();
    }
}

/// Serializes a tenant's lifecycle validation, drain, and publication sequence.
pub(super) struct LifecycleMutationGate {
    active: Mutex<bool>,
    changed: Condvar,
}

impl LifecycleMutationGate {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            active: Mutex::new(false),
            changed: Condvar::new(),
        })
    }

    pub(super) fn acquire(self: &Arc<Self>) -> Result<LifecycleMutationPermit, BootstrapFailure> {
        let deadline = Instant::now()
            .checked_add(LIFECYCLE_DRAIN_TIMEOUT)
            .ok_or_else(|| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        let mut active = self
            .active
            .lock()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
        while *active {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return Err(BootstrapFailure::new(
                    BootstrapFailureCode::ResourceUnavailable,
                ));
            };
            let (next, timed_out) = self
                .changed
                .wait_timeout(active, remaining)
                .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
            if timed_out.timed_out() {
                return Err(BootstrapFailure::new(
                    BootstrapFailureCode::ResourceUnavailable,
                ));
            }
            active = next;
        }
        *active = true;
        Ok(LifecycleMutationPermit {
            gate: Arc::clone(self),
        })
    }
}

pub(super) struct LifecycleMutationPermit {
    gate: Arc<LifecycleMutationGate>,
}

impl Drop for LifecycleMutationPermit {
    fn drop(&mut self) {
        let mut active = match self.gate.active.lock() {
            Ok(active) => active,
            Err(poisoned) => poisoned.into_inner(),
        };
        *active = false;
        self.gate.changed.notify_all();
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elapsed_lifecycle_drain_deadline_restores_admission() {
        let gate = IngestDrainGate::new();
        let held = gate.enter().expect("initial admission");

        let failure = match gate.close_and_drain_before(Instant::now()) {
            Ok(_) => panic!("an already elapsed deadline cannot publish a lifecycle closure"),
            Err(failure) => failure,
        };
        assert_eq!(failure.code(), BootstrapFailureCode::ResourceUnavailable);

        let later = gate.enter().expect("failed drain reopens admission");
        drop(later);
        drop(held);
    }
}
