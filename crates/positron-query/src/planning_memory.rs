use crate::plan::{FilterPredicate, LogicalPlan, ProjectionColumn};
use crate::{QueryBudgetDimension, QueryFailure, QueryFailureCode};
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
struct PlanningMemoryState {
    limit: u64,
    current: AtomicU64,
    peak: AtomicU64,
    retained: AtomicU64,
}
#[derive(Clone)]
pub(crate) struct PlanningMemory {
    state: Arc<PlanningMemoryState>,
}
pub(crate) struct PlanningReservation {
    state: Arc<PlanningMemoryState>,
    bytes: u64,
}
impl PlanningMemory {
    pub(crate) fn new(limit: u64) -> Self {
        Self {
            state: Arc::new(PlanningMemoryState {
                limit,
                current: AtomicU64::new(0),
                peak: AtomicU64::new(0),
                retained: AtomicU64::new(0),
            }),
        }
    }

    pub(crate) fn reserve(&self, bytes: u64) -> Result<PlanningReservation, QueryFailure> {
        let mut current = self.state.current.load(Ordering::Acquire);
        loop {
            let next = current
                .checked_add(bytes)
                .ok_or_else(|| QueryFailure::budget_exhausted(QueryBudgetDimension::MemoryBytes))?;
            if next > self.state.limit {
                return Err(QueryFailure::budget_exhausted(
                    QueryBudgetDimension::MemoryBytes,
                ));
            }
            match self.state.current.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.state.peak.fetch_max(next, Ordering::AcqRel);
                    break;
                },
                Err(observed) => current = observed,
            }
        }
        Ok(PlanningReservation {
            state: Arc::clone(&self.state),
            bytes,
        })
    }

    pub(crate) fn reserve_vec<T>(
        &self,
        capacity: usize,
    ) -> Result<PlanningReservation, QueryFailure> {
        let bytes = u64::try_from(capacity)
            .ok()
            .and_then(|capacity| capacity.checked_mul(std::mem::size_of::<T>() as u64))
            .ok_or_else(|| QueryFailure::budget_exhausted(QueryBudgetDimension::MemoryBytes))?;
        self.reserve(bytes)
    }

    #[allow(deprecated)]
    pub(crate) fn retain_reservation(
        &self,
        mut reservation: PlanningReservation,
        bytes: u64,
    ) -> Result<(), QueryFailure> {
        reservation.reconcile(bytes)?;
        self.state
            .retained
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |retained| {
                retained.checked_add(bytes)
            })
            .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
        reservation.disarm();
        Ok(())
    }

    pub(crate) fn take_retained(&self) -> PlanningReservation {
        PlanningReservation {
            state: Arc::clone(&self.state),
            bytes: self.state.retained.swap(0, Ordering::AcqRel),
        }
    }

    #[cfg(test)]
    pub(crate) fn release_retained(&self, bytes: u64) -> Result<(), QueryFailure> {
        let mut retained = self.state.retained.load(Ordering::Acquire);
        loop {
            let remaining = retained
                .checked_sub(bytes)
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
            match self.state.retained.compare_exchange_weak(
                retained,
                remaining,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.state.current.fetch_sub(bytes, Ordering::AcqRel);
                    return Ok(());
                },
                Err(observed) => retained = observed,
            }
        }
    }
}

impl PlanningReservation {
    fn disarm(&mut self) {
        self.bytes = 0;
    }

    pub(crate) fn bytes(&self) -> u64 {
        self.bytes
    }

    pub(crate) fn reconcile(&mut self, bytes: u64) -> Result<(), QueryFailure> {
        if bytes > self.bytes {
            let additional = bytes - self.bytes;
            let reservation = Arc::clone(&self.state);
            let mut current = reservation.current.load(Ordering::Acquire);
            loop {
                let next = current.checked_add(additional).ok_or_else(|| {
                    QueryFailure::budget_exhausted(QueryBudgetDimension::MemoryBytes)
                })?;
                if next > reservation.limit {
                    return Err(QueryFailure::budget_exhausted(
                        QueryBudgetDimension::MemoryBytes,
                    ));
                }
                match reservation.current.compare_exchange_weak(
                    current,
                    next,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => {
                        reservation.peak.fetch_max(next, Ordering::AcqRel);
                        break;
                    },
                    Err(observed) => current = observed,
                }
            }
        } else {
            self.state
                .current
                .fetch_sub(self.bytes - bytes, Ordering::AcqRel);
        }
        self.bytes = bytes;
        Ok(())
    }

    pub(crate) fn release_bytes(&mut self, bytes: u64) -> Result<(), QueryFailure> {
        let remaining = self
            .bytes
            .checked_sub(bytes)
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
        self.reconcile(remaining)
    }

    pub(crate) fn merge(&mut self, other: Self) -> Result<(), QueryFailure> {
        let bytes = self
            .bytes
            .checked_add(other.bytes)
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
        std::mem::forget(other);
        self.bytes = bytes;
        Ok(())
    }
}

impl Drop for PlanningReservation {
    fn drop(&mut self) {
        self.state.current.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

pub(crate) struct PlanningVec<T> {
    values: Vec<T>,
    memory: PlanningMemory,
    reservation: PlanningReservation,
}

impl<T> PlanningVec<T> {
    pub(crate) fn with_capacity(
        memory: &PlanningMemory,
        capacity: usize,
    ) -> Result<Self, QueryFailure> {
        let reservation = memory.reserve_vec::<T>(capacity)?;
        let mut values = Vec::new();
        if values.try_reserve_exact(capacity).is_err() {
            return Err(QueryFailure::new(QueryFailureCode::ResourceExhausted));
        }
        let actual = u64::try_from(values.capacity())
            .ok()
            .and_then(|capacity| capacity.checked_mul(std::mem::size_of::<T>() as u64))
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
        let mut reservation = reservation;
        reservation.reconcile(actual)?;
        Ok(Self {
            values,
            memory: memory.clone(),
            reservation,
        })
    }

    pub(crate) fn push(&mut self, value: T) -> Result<(), QueryFailure> {
        if self.values.len() == self.values.capacity() {
            let additional = self.values.capacity().max(1);
            let reservation = self.memory.reserve_vec::<T>(additional)?;
            if self.values.try_reserve_exact(additional).is_err() {
                return Err(QueryFailure::new(QueryFailureCode::ResourceExhausted));
            }
            self.reservation.merge(reservation)?;
            let actual = u64::try_from(self.values.capacity())
                .ok()
                .and_then(|capacity| capacity.checked_mul(std::mem::size_of::<T>() as u64))
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
            self.reservation.reconcile(actual)?;
        }
        self.values.push(value);
        Ok(())
    }

    pub(crate) fn as_slice(&self) -> &[T] {
        &self.values
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [T] {
        &mut self.values
    }

    pub(crate) fn len(&self) -> usize {
        self.values.len()
    }

    pub(crate) fn memory(&self) -> PlanningMemory {
        self.memory.clone()
    }

    pub(crate) fn into_vec(self) -> Vec<T> {
        self.values
    }

    pub(crate) fn into_vec_with_reservation(self) -> (Vec<T>, PlanningReservation) {
        (self.values, self.reservation)
    }
}

impl<T: PartialEq> PartialEq for PlanningVec<T> {
    fn eq(&self, other: &Self) -> bool {
        self.values == other.values
    }
}

impl<T: Eq> Eq for PlanningVec<T> {}

impl<T: std::fmt::Debug> std::fmt::Debug for PlanningVec<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.values.fmt(formatter)
    }
}

impl<T> Deref for PlanningVec<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl<T> DerefMut for PlanningVec<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut_slice()
    }
}

pub(crate) fn split_ascii_whitespace<'source>(
    source: &'source str,
    memory: &PlanningMemory,
) -> Result<PlanningVec<&'source str>, QueryFailure> {
    let capacity = source.split_ascii_whitespace().count();
    let mut tokens = PlanningVec::with_capacity(memory, capacity)?;
    for token in source.split_ascii_whitespace() {
        tokens.push(token)?;
    }
    Ok(tokens)
}
const MAX_PLAN_COLUMNS: usize = 5;

pub(crate) fn retained_plan_bytes(plan: &LogicalPlan) -> Result<u64, QueryFailure> {
    let mut bytes = u64::try_from(std::mem::size_of::<LogicalPlan>())
        .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
    bytes = add_capacity(
        bytes,
        MAX_PLAN_COLUMNS,
        std::mem::size_of::<ProjectionColumn>(),
    )?;
    bytes = projection_memory(bytes, plan.projection())?;
    if let Some(aggregate) = plan.aggregate() {
        bytes = add_capacity(
            bytes,
            MAX_PLAN_COLUMNS,
            std::mem::size_of::<ProjectionColumn>(),
        )?;
        bytes = projection_memory(bytes, aggregate.group_by())?;
    }
    if let Some(filter) = plan.filter() {
        bytes = bytes
            .checked_add(128)
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
        bytes = match filter {
            FilterPredicate::BodyEquals(value) => add_usize(
                bytes,
                value
                    .retained_heap_bytes()
                    .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?,
            )?,
            FilterPredicate::BodyContains(value) => bytes
                .checked_add(value.source_memory_bytes()?)
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?,
            FilterPredicate::BodyRegex(value) => bytes
                .checked_add(value.source_memory_bytes()?)
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?,
            FilterPredicate::AttributeEquals(query) => add_usize(
                bytes,
                query
                    .retained_memory_bytes()
                    .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?,
            )?,
        };
    }
    Ok(bytes)
}

fn add_usize(bytes: u64, value: usize) -> Result<u64, QueryFailure> {
    add_capacity(bytes, value, 1)
}

fn add_capacity(bytes: u64, capacity: usize, slot_bytes: usize) -> Result<u64, QueryFailure> {
    let capacity =
        u64::try_from(capacity).map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
    let slot_bytes =
        u64::try_from(slot_bytes).map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
    bytes
        .checked_add(
            capacity
                .checked_mul(slot_bytes)
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?,
        )
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))
}

fn projection_memory(mut bytes: u64, columns: &[ProjectionColumn]) -> Result<u64, QueryFailure> {
    for column in columns {
        if let ProjectionColumn::Attribute(path) = column {
            bytes = path_memory(bytes, path)?;
        }
    }
    Ok(bytes)
}

pub(crate) fn path_memory(
    mut bytes: u64,
    path: &positron_signals::SchemaPath,
) -> Result<u64, QueryFailure> {
    bytes = add_capacity(
        bytes,
        positron_signals::SchemaPath::system_max_segments(),
        std::mem::size_of::<String>(),
    )?;
    for segment in path.segments() {
        bytes = bytes
            .checked_add(
                u64::try_from(segment.capacity())
                    .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?,
            )
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
    }
    Ok(bytes)
}

#[cfg(test)]
#[path = "planning_memory_tests.rs"]
mod tests;
