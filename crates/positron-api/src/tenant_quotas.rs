//! Checked wire types for the canonical tenant-quota update operation.

pub use crate::api_keys::ApiKeyTransport as TenantQuotaTransport;
pub use crate::api_keys::protobuf::{
    TenantQuotaUpdateRequest as WireRequest, TenantQuotaUpdateResponse,
};

pub const HTTP_PATH: &str = "/v1/tenant-quotas:update";

mod client {
    include!(concat!(env!("OUT_DIR"), "/tenant_quota_service_client.rs"));
}
pub use client::{TenantQuotaServiceClient, TenantQuotaServiceClientFailure};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TenantQuotaWireFailure;

impl std::fmt::Display for TenantQuotaWireFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("invalid tenant quota wire request")
    }
}

impl std::error::Error for TenantQuotaWireFailure {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TenantQuotaResources {
    pub memory_bytes: u64,
    pub queue_slots: u64,
    pub task_slots: u64,
    pub buffer_cache_bytes: u64,
    pub batch_items: u64,
    pub lease_slots: u64,
    pub retry_slots: u64,
    pub io_permits: u64,
    pub cpu_work_units: u64,
    pub file_descriptors: u64,
    pub disk_headroom_bytes: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct TenantQuotaUpdateRequest(WireRequest);

impl TenantQuotaUpdateRequest {
    #[must_use]
    pub fn new(
        tenant: String,
        expected_generation: u64,
        idempotency_key: String,
        weight: u32,
        resources: TenantQuotaResources,
    ) -> Self {
        Self(WireRequest {
            tenant,
            expected_generation,
            idempotency_key,
            weight,
            memory_bytes: resources.memory_bytes,
            queue_slots: resources.queue_slots,
            task_slots: resources.task_slots,
            buffer_cache_bytes: resources.buffer_cache_bytes,
            batch_items: resources.batch_items,
            lease_slots: resources.lease_slots,
            retry_slots: resources.retry_slots,
            io_permits: resources.io_permits,
            cpu_work_units: resources.cpu_work_units,
            file_descriptors: resources.file_descriptors,
            disk_headroom_bytes: resources.disk_headroom_bytes,
        })
    }
    pub fn decode(body: &[u8]) -> Result<Self, TenantQuotaWireFailure> {
        if body.len() > 1024 {
            return Err(TenantQuotaWireFailure);
        }
        let request = Self(serde_json::from_slice(body).map_err(|_| TenantQuotaWireFailure)?);
        request.validate()?;
        Ok(request)
    }

    pub fn tenant(&self) -> &str {
        &self.0.tenant
    }

    pub const fn expected_generation(&self) -> u64 {
        self.0.expected_generation
    }

    pub fn idempotency_key(&self) -> &str {
        &self.0.idempotency_key
    }

    pub const fn weight(&self) -> u32 {
        self.0.weight
    }

    pub const fn resources(&self) -> TenantQuotaResources {
        TenantQuotaResources {
            memory_bytes: self.0.memory_bytes,
            queue_slots: self.0.queue_slots,
            task_slots: self.0.task_slots,
            buffer_cache_bytes: self.0.buffer_cache_bytes,
            batch_items: self.0.batch_items,
            lease_slots: self.0.lease_slots,
            retry_slots: self.0.retry_slots,
            io_permits: self.0.io_permits,
            cpu_work_units: self.0.cpu_work_units,
            file_descriptors: self.0.file_descriptors,
            disk_headroom_bytes: self.0.disk_headroom_bytes,
        }
    }

    pub const fn resource_values(&self) -> [u64; 11] {
        [
            self.0.memory_bytes,
            self.0.queue_slots,
            self.0.task_slots,
            self.0.buffer_cache_bytes,
            self.0.batch_items,
            self.0.lease_slots,
            self.0.retry_slots,
            self.0.io_permits,
            self.0.cpu_work_units,
            self.0.file_descriptors,
            self.0.disk_headroom_bytes,
        ]
    }

    pub fn validate(&self) -> Result<(), TenantQuotaWireFailure> {
        if !identifier(&self.0.tenant)
            || !identifier(&self.0.idempotency_key)
            || self.0.expected_generation == 0
            || self.0.weight == 0
            || self.0.weight > u32::from(u16::MAX)
            || [
                self.0.memory_bytes,
                self.0.queue_slots,
                self.0.task_slots,
                self.0.buffer_cache_bytes,
                self.0.batch_items,
                self.0.lease_slots,
                self.0.retry_slots,
                self.0.io_permits,
                self.0.cpu_work_units,
                self.0.file_descriptors,
                self.0.disk_headroom_bytes,
            ]
            .contains(&0)
        {
            return Err(TenantQuotaWireFailure);
        }
        Ok(())
    }

    fn encode(&self) -> Result<Vec<u8>, TenantQuotaWireFailure> {
        self.validate()?;
        serde_json::to_vec(&self.0).map_err(|_| TenantQuotaWireFailure)
    }
}

fn identifier(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_digit() || matches!(b, b'a'..=b'f')
            }
        })
        && value.bytes().any(|b| matches!(b,b'1'..=b'9'|b'a'..=b'f'))
}
