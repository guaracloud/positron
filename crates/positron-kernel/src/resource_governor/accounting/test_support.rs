use super::{AdmissionFailureCode, GovernorConfiguration, GovernorInner, Ordering};

impl GovernorConfiguration {
    pub(in crate::resource_governor) fn payload_addresses_for_test(&self) -> [usize; 13] {
        [
            self.tenant_quotas.as_ptr() as usize,
            self.tenant_fair_capacities.as_ptr() as usize,
            self.recovery_tenant_shared_fair.as_ptr() as usize,
            self.recovery_tenant_pool_fair.as_ptr() as usize,
            self.state.ordinary_tenant_usage.as_ptr() as usize,
            self.state.recovery_tenant_usage.as_ptr() as usize,
            self.state.recovery_tenant_pool_usage.as_ptr() as usize,
            self.state.ordinary_tenant_pool_usage.as_ptr() as usize,
            self.state.tenant_outstanding.as_ptr() as usize,
            self.slot_signals.as_ptr() as usize,
            self.pending_words.as_ptr() as usize,
            self.state.grant_records.as_ptr() as usize,
            self.state.free_slots.as_ptr() as usize,
        ]
    }
}

impl GovernorInner {
    pub(in crate::resource_governor) fn payload_addresses_for_test(&self) -> [usize; 13] {
        let state = self.state.lock().expect("test lock is healthy");
        [
            self.tenant_quotas.as_ptr() as usize,
            self.tenant_fair_capacities.as_ptr() as usize,
            self.recovery_tenant_shared_fair.as_ptr() as usize,
            self.recovery_tenant_pool_fair.as_ptr() as usize,
            state.ordinary_tenant_usage.as_ptr() as usize,
            state.recovery_tenant_usage.as_ptr() as usize,
            state.recovery_tenant_pool_usage.as_ptr() as usize,
            state.ordinary_tenant_pool_usage.as_ptr() as usize,
            state.tenant_outstanding.as_ptr() as usize,
            self.drop_ledger.slot_signals.as_ptr() as usize,
            self.drop_ledger.pending_words.as_ptr() as usize,
            state.grant_records.as_ptr() as usize,
            state.free_slots.as_ptr() as usize,
        ]
    }

    pub(in crate::resource_governor) fn poison_for_test(&self) {
        let _guard = self.state.lock().expect("test lock starts healthy");
        panic!("intentional governor mutex poison");
    }

    pub(in crate::resource_governor) fn corrupt_outstanding_for_test(&self) {
        self.state
            .lock()
            .expect("test lock starts healthy")
            .outstanding = 0;
    }

    pub(in crate::resource_governor) fn set_telemetry_for_test(
        &self,
        reason: AdmissionFailureCode,
        total: u64,
        reason_count: u64,
        throttle_count: u64,
    ) {
        let mut state = self.state.lock().expect("test lock starts healthy");
        state.rejection_counts = [0; AdmissionFailureCode::COUNT];
        let value = reason_count.max(total).max(throttle_count);
        if reason == AdmissionFailureCode::GovernorContended {
            self.contention_count.store(value, Ordering::Release);
        } else if let Some(slot) = state.rejection_counts.get_mut(reason.index()) {
            *slot = value;
        }
    }
}
