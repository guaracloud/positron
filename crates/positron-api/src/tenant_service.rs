//! Checked public input and output for system tenant-registry administration.

use serde::{Deserialize, Serialize};

pub use crate::api_keys::ApiKeyTransport as TenantServiceTransport;
pub use crate::tenant_lifecycle::TenantLifecycleState;

pub const CREATE_HTTP_PATH: &str = "/v1/tenants:create";
pub const INSPECT_HTTP_PATH: &str = "/v1/tenants:inspect";
pub const LIST_HTTP_PATH: &str = "/v1/tenants:list";
pub const UPDATE_DISPLAY_NAME_HTTP_PATH: &str = "/v1/tenants:update-display-name";
pub const MAX_REQUEST_BYTES: usize = 2048;
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;
mod client {
    include!(concat!(env!("OUT_DIR"), "/tenant_service_client.rs"));
}
pub use client::{TenantServiceClient, TenantServiceClientFailure};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TenantServiceWireFailure;

impl std::fmt::Display for TenantServiceWireFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("invalid tenant service wire message")
    }
}
impl std::error::Error for TenantServiceWireFailure {}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TenantCreateRequest {
    tenant: String,
    slug: String,
    display_name: String,
    retention_seconds: u64,
    weight: u32,
    memory_bytes: u64,
    queue_slots: u64,
    task_slots: u64,
    buffer_cache_bytes: u64,
    batch_items: u64,
    lease_slots: u64,
    retry_slots: u64,
    io_permits: u64,
    cpu_work_units: u64,
    file_descriptors: u64,
    disk_headroom_bytes: u64,
    idempotency_key: String,
}

impl TenantCreateRequest {
    #[must_use]
    pub fn new(
        tenant: String,
        slug: String,
        display_name: String,
        retention_seconds: u64,
        weight: u32,
        resources: [u64; 11],
        idempotency_key: String,
    ) -> Self {
        Self {
            tenant,
            slug,
            display_name,
            retention_seconds,
            weight,
            memory_bytes: resources[0],
            queue_slots: resources[1],
            task_slots: resources[2],
            buffer_cache_bytes: resources[3],
            batch_items: resources[4],
            lease_slots: resources[5],
            retry_slots: resources[6],
            io_permits: resources[7],
            cpu_work_units: resources[8],
            file_descriptors: resources[9],
            disk_headroom_bytes: resources[10],
            idempotency_key,
        }
    }
    pub fn decode(body: &[u8]) -> Result<Self, TenantServiceWireFailure> {
        decode(body)
    }
    pub fn encode(&self) -> Result<Vec<u8>, TenantServiceWireFailure> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| TenantServiceWireFailure)
    }
    pub fn tenant(&self) -> &str {
        &self.tenant
    }
    pub fn slug(&self) -> &str {
        &self.slug
    }
    pub fn display_name(&self) -> &str {
        &self.display_name
    }
    pub const fn retention_seconds(&self) -> u64 {
        self.retention_seconds
    }
    pub const fn weight(&self) -> u32 {
        self.weight
    }
    pub const fn resources(&self) -> [u64; 11] {
        [
            self.memory_bytes,
            self.queue_slots,
            self.task_slots,
            self.buffer_cache_bytes,
            self.batch_items,
            self.lease_slots,
            self.retry_slots,
            self.io_permits,
            self.cpu_work_units,
            self.file_descriptors,
            self.disk_headroom_bytes,
        ]
    }
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }
    pub fn validate(&self) -> Result<(), TenantServiceWireFailure> {
        if !identifier(&self.tenant)
            || !slug(&self.slug)
            || self.display_name.is_empty()
            || self.display_name.len() > 128
            || self.retention_seconds == 0
            || self.weight == 0
            || self.weight > u32::from(u16::MAX)
            || self.resources().contains(&0)
            || !identifier(&self.idempotency_key)
        {
            return Err(TenantServiceWireFailure);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TenantInspectRequest {
    tenant: String,
}
impl TenantInspectRequest {
    #[must_use]
    pub fn new(tenant: String) -> Self {
        Self { tenant }
    }
    pub fn decode(body: &[u8]) -> Result<Self, TenantServiceWireFailure> {
        decode(body)
    }
    pub fn encode(&self) -> Result<Vec<u8>, TenantServiceWireFailure> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| TenantServiceWireFailure)
    }
    pub fn tenant(&self) -> &str {
        &self.tenant
    }
    pub fn validate(&self) -> Result<(), TenantServiceWireFailure> {
        if identifier(&self.tenant) {
            Ok(())
        } else {
            Err(TenantServiceWireFailure)
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TenantListRequest {}
impl TenantListRequest {
    #[must_use]
    pub const fn new() -> Self {
        Self {}
    }
    pub fn decode(body: &[u8]) -> Result<Self, TenantServiceWireFailure> {
        decode(body)
    }
    pub fn encode(&self) -> Result<Vec<u8>, TenantServiceWireFailure> {
        serde_json::to_vec(self).map_err(|_| TenantServiceWireFailure)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TenantDisplayNameUpdateRequest {
    tenant: String,
    expected_display_generation: u64,
    display_name: String,
    idempotency_key: String,
}
impl TenantDisplayNameUpdateRequest {
    #[must_use]
    pub fn new(
        tenant: String,
        expected_display_generation: u64,
        display_name: String,
        idempotency_key: String,
    ) -> Self {
        Self {
            tenant,
            expected_display_generation,
            display_name,
            idempotency_key,
        }
    }
    pub fn decode(body: &[u8]) -> Result<Self, TenantServiceWireFailure> {
        decode(body)
    }
    pub fn encode(&self) -> Result<Vec<u8>, TenantServiceWireFailure> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| TenantServiceWireFailure)
    }
    pub fn tenant(&self) -> &str {
        &self.tenant
    }
    pub const fn expected_display_generation(&self) -> u64 {
        self.expected_display_generation
    }
    pub fn display_name(&self) -> &str {
        &self.display_name
    }
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }
    pub fn validate(&self) -> Result<(), TenantServiceWireFailure> {
        if identifier(&self.tenant)
            && self.expected_display_generation != 0
            && !self.display_name.is_empty()
            && self.display_name.len() <= 128
            && identifier(&self.idempotency_key)
        {
            Ok(())
        } else {
            Err(TenantServiceWireFailure)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TenantDescriptor {
    pub tenant: String,
    pub slug: String,
    pub display_name: String,
    pub retention_seconds: u64,
    pub display_generation: u64,
    pub retention_generation: u64,
    pub lifecycle: TenantLifecycleState,
}
impl TenantDescriptor {
    pub fn decode(body: &[u8]) -> Result<Self, TenantServiceWireFailure> {
        decode_response(body)
    }
    pub fn validate(&self) -> Result<(), TenantServiceWireFailure> {
        if identifier(&self.tenant)
            && slug(&self.slug)
            && !self.display_name.is_empty()
            && self.display_name.len() <= 128
            && self.retention_seconds != 0
            && self.display_generation != 0
            && self.retention_generation != 0
        {
            Ok(())
        } else {
            Err(TenantServiceWireFailure)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TenantCreateResponse {
    pub tenant: String,
    pub resource_generation: u64,
    pub audit_position: u64,
}
impl TenantCreateResponse {
    pub fn decode(body: &[u8]) -> Result<Self, TenantServiceWireFailure> {
        decode_response(body)
    }
    pub fn encode(&self) -> Result<Vec<u8>, TenantServiceWireFailure> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| TenantServiceWireFailure)
    }
    pub fn validate(&self) -> Result<(), TenantServiceWireFailure> {
        if identifier(&self.tenant) && self.resource_generation != 0 && self.audit_position != 0 {
            Ok(())
        } else {
            Err(TenantServiceWireFailure)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TenantInspectResponse {
    pub tenant: TenantDescriptor,
}
impl TenantInspectResponse {
    pub fn decode(body: &[u8]) -> Result<Self, TenantServiceWireFailure> {
        decode_response(body)
    }
    pub fn encode(&self) -> Result<Vec<u8>, TenantServiceWireFailure> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| TenantServiceWireFailure)
    }
    pub fn validate(&self) -> Result<(), TenantServiceWireFailure> {
        self.tenant.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TenantListResponse {
    pub tenants: Vec<TenantDescriptor>,
}
impl TenantListResponse {
    pub fn decode(body: &[u8]) -> Result<Self, TenantServiceWireFailure> {
        decode_response(body)
    }
    pub fn encode(&self) -> Result<Vec<u8>, TenantServiceWireFailure> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| TenantServiceWireFailure)
    }
    pub fn validate(&self) -> Result<(), TenantServiceWireFailure> {
        if self.tenants.len() > 1024 {
            return Err(TenantServiceWireFailure);
        }
        for tenant in &self.tenants {
            tenant.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TenantDisplayNameUpdateResponse {
    pub tenant: String,
    pub display_generation: u64,
    pub audit_position: u64,
}
impl TenantDisplayNameUpdateResponse {
    pub fn decode(body: &[u8]) -> Result<Self, TenantServiceWireFailure> {
        decode_response(body)
    }
    pub fn encode(&self) -> Result<Vec<u8>, TenantServiceWireFailure> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| TenantServiceWireFailure)
    }
    pub fn validate(&self) -> Result<(), TenantServiceWireFailure> {
        if identifier(&self.tenant) && self.display_generation != 0 && self.audit_position != 0 {
            Ok(())
        } else {
            Err(TenantServiceWireFailure)
        }
    }
}

fn decode<T>(body: &[u8]) -> Result<T, TenantServiceWireFailure>
where
    T: for<'a> Deserialize<'a> + TenantWireValidate,
{
    if body.len() > MAX_REQUEST_BYTES {
        return Err(TenantServiceWireFailure);
    }
    let value: T = serde_json::from_slice(body).map_err(|_| TenantServiceWireFailure)?;
    value.validate_wire()?;
    Ok(value)
}
fn decode_response<T>(body: &[u8]) -> Result<T, TenantServiceWireFailure>
where
    T: for<'a> Deserialize<'a> + TenantWireValidate,
{
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(TenantServiceWireFailure);
    }
    let value: T = serde_json::from_slice(body).map_err(|_| TenantServiceWireFailure)?;
    value.validate_wire()?;
    Ok(value)
}
trait TenantWireValidate {
    fn validate_wire(&self) -> Result<(), TenantServiceWireFailure>;
}
macro_rules! validated { ($($type:ty),+ $(,)?) => { $(impl TenantWireValidate for $type { fn validate_wire(&self) -> Result<(), TenantServiceWireFailure> { self.validate() } })+ }; }
validated!(
    TenantCreateRequest,
    TenantInspectRequest,
    TenantDescriptor,
    TenantCreateResponse,
    TenantInspectResponse,
    TenantListResponse,
    TenantDisplayNameUpdateRequest,
    TenantDisplayNameUpdateResponse
);
impl TenantWireValidate for TenantListRequest {
    fn validate_wire(&self) -> Result<(), TenantServiceWireFailure> {
        Ok(())
    }
}
fn identifier(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
            }
        })
        && value
            .bytes()
            .any(|byte| matches!(byte, b'1'..=b'9' | b'a'..=b'f'))
}
fn slug(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}
