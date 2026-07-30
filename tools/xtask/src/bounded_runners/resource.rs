//! Bounded resource queue, reservation ledger, and pressure model.

use std::collections::VecDeque;

use crate::error::XtaskError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ReservationOutcome {
    Granted,
    HardPressure,
}

pub(super) struct ReservationLedger {
    capacity: usize,
    pub(super) in_use: usize,
}

impl ReservationLedger {
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            capacity,
            in_use: 0,
        }
    }

    pub(super) fn reserve(&mut self) -> ReservationOutcome {
        if self.in_use >= self.capacity {
            ReservationOutcome::HardPressure
        } else {
            self.in_use += 1;
            ReservationOutcome::Granted
        }
    }

    pub(super) fn release(&mut self) -> Result<(), XtaskError> {
        self.in_use = self.in_use.checked_sub(1).ok_or_else(|| {
            XtaskError::invalid(
                "bounded reservation ledger",
                "release occurred without a held reservation",
            )
        })?;
        Ok(())
    }
}

pub(super) struct BoundedWorkQueue {
    capacity: usize,
    entries: VecDeque<usize>,
}

impl BoundedWorkQueue {
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: VecDeque::with_capacity(capacity),
        }
    }

    pub(super) fn enqueue(&mut self, task: usize) -> Result<(), XtaskError> {
        if self.entries.len() >= self.capacity {
            return Err(XtaskError::invalid(
                "bounded work queue",
                "overload was rejected before unreserved queue growth",
            ));
        }
        self.entries.push_back(task);
        Ok(())
    }

    pub(super) fn dequeue(&mut self) -> Result<usize, XtaskError> {
        self.entries.pop_front().ok_or_else(|| {
            XtaskError::invalid(
                "bounded work queue",
                "deterministic schedule dequeued an empty queue",
            )
        })
    }

    pub(super) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
