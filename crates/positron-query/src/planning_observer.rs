use crate::planning_memory::PlanningReservation;
use crate::{QueryFailure, QueryFailureCode};

pub(crate) struct PlanningValueObserver {
    reservation: PlanningReservation,
}

impl PlanningValueObserver {
    pub(crate) fn new(reservation: PlanningReservation) -> Self {
        Self { reservation }
    }

    pub(crate) fn into_reservation(self) -> PlanningReservation {
        self.reservation
    }
}

impl positron_domain::value::NativeValueObserver for PlanningValueObserver {
    type Error = QueryFailure;

    fn observe_structure(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn observe_payload(&mut self, _payload: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }

    fn observe_allocation(&mut self, bytes: usize) -> Result<(), Self::Error> {
        let bytes =
            u64::try_from(bytes).map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
        let additional = self.reservation.bytes().checked_add(bytes).ok_or_else(|| {
            QueryFailure::budget_exhausted(crate::QueryBudgetDimension::MemoryBytes)
        })?;
        self.reservation.reconcile(additional)
    }

    fn release_allocation(&mut self, bytes: usize) -> Result<(), Self::Error> {
        let bytes =
            u64::try_from(bytes).map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
        self.reservation.release_bytes(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocation_growth_overflow_is_a_bounded_memory_failure() {
        let memory = crate::planning_memory::PlanningMemory::new(u64::MAX);
        let reservation = memory.reserve(u64::MAX).expect("maximum reservation");
        let mut observer = PlanningValueObserver::new(reservation);
        let failure =
            positron_domain::value::NativeValueObserver::observe_allocation(&mut observer, 1)
                .expect_err("overflow must fail");
        assert_eq!(
            failure.limiting_budget(),
            Some(crate::QueryBudgetDimension::MemoryBytes)
        );
    }
}
