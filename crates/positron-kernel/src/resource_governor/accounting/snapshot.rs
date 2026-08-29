use super::*;

impl GovernorInner {
    pub(in crate::resource_governor) fn snapshot(
        &self,
    ) -> Result<AccountingSnapshot, GovernorFailure> {
        let state = match self.state.try_lock() {
            Ok(mut state) => {
                self.drain_pending(&mut state);
                if self.drop_ledger.pending_fence.swap(false, Ordering::AcqRel) {
                    state.lifecycle = GovernorLifecycle::Fenced;
                }
                state
            },
            Err(TryLockError::WouldBlock) => {
                return Err(GovernorFailure::GovernorContended {
                    pressure: self.last_pressure(),
                });
            },
            Err(TryLockError::Poisoned(poisoned)) => {
                let mut state = poisoned.into_inner();
                self.drain_pending(&mut state);
                state.lifecycle = GovernorLifecycle::Fenced;
                state
            },
        };
        self.snapshot_from(&state)
    }

    pub(in crate::resource_governor) fn snapshot_from(
        &self,
        state: &AccountingState,
    ) -> Result<AccountingSnapshot, GovernorFailure> {
        let contention = self.contention_count.load(Ordering::Acquire);
        let mut rejection_counts = state.rejection_counts;
        let contention_slot = rejection_counts
            .get_mut(AdmissionFailureCode::GovernorContended.index())
            .ok_or_else(|| {
                self.drop_ledger
                    .pending_fence
                    .store(true, Ordering::Release);
                GovernorFailure::InternalFenced
            })?;
        *contention_slot = contention;
        let rejection_count = rejection_counts
            .iter()
            .try_fold(0_u64, |total, count| total.checked_add(*count))
            .ok_or_else(|| {
                self.drop_ledger
                    .pending_fence
                    .store(true, Ordering::Release);
                GovernorFailure::InternalFenced
            })?;
        let throttle_counts = std::array::from_fn(|index| {
            AdmissionFailureCode::from_index(index)
                .filter(|code| code.is_throttle())
                .and_then(|_| rejection_counts.get(index).copied())
                .unwrap_or(0)
        });
        Ok(AccountingSnapshot {
            outstanding: state.outstanding,
            maximum_outstanding: self.maximum_outstanding,
            reserve_consumption: state.total_usage.excess_over(self.ordinary_ceiling),
            pool_capacities: self.pool_capacities,
            pool_usage: state.pool_usage,
            disk_pressure: state.disk_pressure,
            pressure_transition_count: state.pressure_transition_count,
            lifecycle: state.lifecycle,
            total_usage: state.total_usage,
            outstanding_ordinary: state.outstanding_ordinary,
            outstanding_recovery: state.outstanding_recovery,
            outstanding_uninterruptible: state.outstanding_uninterruptible,
            class_counts: state.class_counts,
            rejection_count,
            rejection_counts,
            throttle_counts,
            effective_capacity: self.raw_effective,
            bootstrap_overhead: self.bootstrap_overhead,
            ordinary_capacity: self.ordinary_ceiling,
            recovery_reserve: self.recovery_reserve,
            recovery_shared_capacity: self.recovery_shared_capacity,
            recovery_shared_usage: state.recovery_pool_usage.shared(),
            recovery_pool_capacities: self.recovery_pool_capacities,
            recovery_pool_usage: state.recovery_pool_usage,
            usable_disk_bytes: state.usable_disk_bytes,
        })
    }
}
