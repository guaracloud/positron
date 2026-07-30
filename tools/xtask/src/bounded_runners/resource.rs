//! Bounded resource queue, reservation ledger, and pressure model.

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
    entries: Vec<Option<usize>>,
    head: usize,
    tail: usize,
    len: usize,
}

impl BoundedWorkQueue {
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: vec![None; capacity],
            head: 0,
            tail: 0,
            len: 0,
        }
    }

    pub(super) fn enqueue(&mut self, task: usize) -> Result<(), XtaskError> {
        if self.len >= self.capacity {
            return Err(XtaskError::invalid(
                "bounded work queue",
                "overload was rejected before unreserved queue growth",
            ));
        }
        let slot = self.entries.get_mut(self.tail).ok_or_else(|| {
            XtaskError::invalid(
                "bounded work queue",
                "bounded queue tail escaped its fixed storage",
            )
        })?;
        if slot.replace(task).is_some() {
            return Err(XtaskError::invalid(
                "bounded work queue",
                "bounded queue attempted to overwrite retained work",
            ));
        }
        self.tail = advance(self.tail, self.capacity)?;
        self.len = self.len.checked_add(1).ok_or_else(|| {
            XtaskError::invalid(
                "bounded work queue",
                "bounded queue length cannot be represented",
            )
        })?;
        Ok(())
    }

    pub(super) fn dequeue(&mut self) -> Result<usize, XtaskError> {
        if self.len == 0 {
            return Err(XtaskError::invalid(
                "bounded work queue",
                "deterministic schedule dequeued an empty queue",
            ));
        }
        let task = self
            .entries
            .get_mut(self.head)
            .and_then(Option::take)
            .ok_or_else(|| {
                XtaskError::invalid(
                    "bounded work queue",
                    "bounded queue head omitted retained work",
                )
            })?;
        self.head = advance(self.head, self.capacity)?;
        self.len = self.len.checked_sub(1).ok_or_else(|| {
            XtaskError::invalid("bounded work queue", "bounded queue length underflowed")
        })?;
        Ok(task)
    }

    pub(super) fn is_empty(&self) -> bool {
        self.len == 0
    }
}

fn advance(index: usize, capacity: usize) -> Result<usize, XtaskError> {
    let next = index.checked_add(1).ok_or_else(|| {
        XtaskError::invalid("bounded work queue", "bounded queue index overflowed")
    })?;
    Ok(if next == capacity { 0 } else { next })
}
