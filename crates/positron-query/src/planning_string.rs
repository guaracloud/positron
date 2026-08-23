use crate::planning_memory::{PlanningMemory, PlanningReservation};
use crate::{QueryFailure, QueryFailureCode};

pub(crate) struct PlanningString {
    value: String,
    memory: PlanningMemory,
    reservation: PlanningReservation,
}

impl PlanningString {
    pub(crate) fn copy(source: &str, memory: &PlanningMemory) -> Result<Self, QueryFailure> {
        let mut value = Self::with_capacity(source.len(), memory)?;
        value.push_str(source)?;
        Ok(value)
    }

    pub(crate) fn with_capacity(
        capacity: usize,
        memory: &PlanningMemory,
    ) -> Result<Self, QueryFailure> {
        let bytes =
            u64::try_from(capacity).map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
        let reservation = memory.reserve(bytes)?;
        let mut value = String::new();
        if value.try_reserve_exact(capacity).is_err() {
            return Err(QueryFailure::new(QueryFailureCode::ResourceExhausted));
        }
        let actual = u64::try_from(value.capacity())
            .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
        let mut reservation = reservation;
        reservation.reconcile(actual)?;
        Ok(Self {
            value,
            memory: memory.clone(),
            reservation,
        })
    }

    pub(crate) fn push_str(&mut self, source: &str) -> Result<(), QueryFailure> {
        let required = self
            .value
            .len()
            .checked_add(source.len())
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        if required > self.value.capacity() {
            let additional = required - self.value.capacity();
            let reservation = self.memory.reserve(
                u64::try_from(additional)
                    .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?,
            )?;
            if self.value.try_reserve_exact(additional).is_err() {
                return Err(QueryFailure::new(QueryFailureCode::ResourceExhausted));
            }
            self.reservation.merge(reservation)?;
            let actual = u64::try_from(self.value.capacity())
                .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
            self.reservation.reconcile(actual)?;
        }
        self.value.push_str(source);
        Ok(())
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.value
    }

    pub(crate) fn into_parts(self) -> Result<(String, PlanningReservation, u64), QueryFailure> {
        let bytes = u64::try_from(self.value.capacity())
            .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
        let Self {
            value,
            reservation,
            memory: _,
        } = self;
        Ok((value, reservation, bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn growth_reconciles_the_owned_capacity() {
        let memory = PlanningMemory::new(64);
        let mut value = PlanningString::with_capacity(0, &memory).expect("empty string");
        value.push_str("growth").expect("growth");
        assert_eq!(value.as_str(), "growth");
        let (value, reservation, capacity) = value.into_parts().expect("owned parts");
        assert_eq!(value, "growth");
        assert_eq!(reservation.bytes(), capacity);
        drop(reservation);
        assert_eq!(memory.take_retained().bytes(), 0);
    }

    #[test]
    fn growth_refusal_keeps_the_existing_reservation_unchanged() {
        let memory = PlanningMemory::new(0);
        let mut value = PlanningString::with_capacity(0, &memory).expect("empty string");
        let failure = value.push_str("growth").expect_err("growth budget");
        assert_eq!(failure.code(), QueryFailureCode::BudgetExhausted);
        assert_eq!(memory.take_retained().bytes(), 0);
    }

    #[test]
    fn allocator_refusal_rolls_back_the_initial_reservation() {
        let memory = PlanningMemory::new(u64::MAX);
        let failure = match PlanningString::with_capacity(usize::MAX, &memory) {
            Ok(_) => panic!("impossible allocation succeeded"),
            Err(failure) => failure,
        };
        assert_eq!(failure.code(), QueryFailureCode::ResourceExhausted);
        assert_eq!(memory.take_retained().bytes(), 0);
    }
}
