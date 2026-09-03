use positron_domain::identity::TenantAttribution;
use positron_domain::value::ValueLimitProfile;
use positron_kernel::{ResourceAmounts, ResourceReservation};
use positron_signals::SpanObservation;

use super::{MAX_RETAINED_BYTES, TraceReceiveFailure, bounds};

/// One tenant-bound native span batch after protocol mapping.
#[derive(Debug)]
pub struct NativeSpanBatch<'authority> {
    pub(crate) attribution: TenantAttribution,
    pub(crate) records: Vec<SpanObservation>,
    pub(crate) rejections: [usize; 3],
    pub(crate) value_limit_profile: ValueLimitProfile,
    pub(crate) decoded_bytes: u64,
    pub(crate) capacity: Option<ResourceReservation<'authority>>,
    pub(crate) receiver: crate::PolicyReceiver,
}

impl<'authority> NativeSpanBatch<'authority> {
    #[cfg(test)]
    pub(crate) fn new(
        attribution: TenantAttribution,
        records: Vec<SpanObservation>,
        value_limit_profile: ValueLimitProfile,
        decoded_bytes: u64,
        capacity: Option<ResourceReservation<'authority>>,
        receiver: crate::PolicyReceiver,
    ) -> Result<Self, TraceReceiveFailure> {
        Self::new_with_rejections(
            attribution,
            records,
            value_limit_profile,
            decoded_bytes,
            capacity,
            receiver,
            [0; 3],
        )
    }

    pub(crate) fn new_with_rejections(
        attribution: TenantAttribution,
        records: Vec<SpanObservation>,
        value_limit_profile: ValueLimitProfile,
        decoded_bytes: u64,
        capacity: Option<ResourceReservation<'authority>>,
        receiver: crate::PolicyReceiver,
        rejections: [usize; 3],
    ) -> Result<Self, TraceReceiveFailure> {
        let mut batch = Self {
            attribution,
            records,
            rejections,
            value_limit_profile,
            decoded_bytes,
            capacity,
            receiver,
        };
        batch.resize_after_decode()?;
        Ok(batch)
    }

    #[must_use]
    pub const fn attribution(&self) -> TenantAttribution {
        self.attribution
    }

    #[must_use]
    pub fn records(&self) -> &[SpanObservation] {
        &self.records
    }

    #[must_use]
    pub(crate) const fn rejections(&self) -> [usize; 3] {
        self.rejections
    }

    #[must_use]
    pub const fn value_limit_profile(&self) -> ValueLimitProfile {
        self.value_limit_profile
    }

    #[must_use]
    pub const fn receiver(&self) -> crate::PolicyReceiver {
        self.receiver
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        TenantAttribution,
        Vec<SpanObservation>,
        ValueLimitProfile,
        Option<ResourceReservation<'authority>>,
        crate::PolicyReceiver,
    ) {
        (
            self.attribution,
            self.records,
            self.value_limit_profile,
            self.capacity,
            self.receiver,
        )
    }

    fn resize_after_decode(&mut self) -> Result<(), TraceReceiveFailure> {
        let record_count = u64::try_from(self.records.len())
            .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?;
        let retained_peak = bounds::retained_native_batch_bytes(&self.records)?;
        if retained_peak > MAX_RETAINED_BYTES {
            return Err(TraceReceiveFailure::ValueLimitExceeded);
        }
        let amounts =
            ResourceAmounts::new([retained_peak, 1, 1, 0, record_count, 0, 0, 0, 1, 1, 0]);
        if let Some(capacity) = self.capacity.as_mut() {
            capacity
                .try_resize(amounts)
                .map_err(|_| TraceReceiveFailure::CapacityUnavailable)?;
        }
        self.decoded_bytes = retained_peak;
        Ok(())
    }
}
