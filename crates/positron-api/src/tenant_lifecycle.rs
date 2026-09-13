//! Checked public input and output for one tenant lifecycle transition.

use serde::{Deserialize, Serialize};

pub use crate::api_keys::ApiKeyTransport as TenantLifecycleTransport;

mod client {
    include!(concat!(
        env!("OUT_DIR"),
        "/tenant_lifecycle_service_client.rs"
    ));
}
pub use client::{TenantLifecycleServiceClient, TenantLifecycleServiceClientFailure};

pub const HTTP_PATH: &str = "/v1/tenant-lifecycle:transition";
pub const MAX_REQUEST_BYTES: usize = 1024;
pub const MAX_RESPONSE_BYTES: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantLifecycleState {
    Active,
    ReadOnly,
    Suspended,
    Purging,
    Purged,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TenantLifecycleWireFailure;

impl std::fmt::Display for TenantLifecycleWireFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("invalid tenant lifecycle wire message")
    }
}

impl std::error::Error for TenantLifecycleWireFailure {}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TenantLifecycleTransitionRequest {
    tenant: String,
    target: TenantLifecycleState,
    expected_generation: u64,
    idempotency_key: String,
}

impl TenantLifecycleTransitionRequest {
    #[must_use]
    pub fn new(
        tenant: String,
        target: TenantLifecycleState,
        expected_generation: u64,
        idempotency_key: String,
    ) -> Self {
        Self {
            tenant,
            target,
            expected_generation,
            idempotency_key,
        }
    }

    pub fn decode(body: &[u8]) -> Result<Self, TenantLifecycleWireFailure> {
        if body.len() > MAX_REQUEST_BYTES {
            return Err(TenantLifecycleWireFailure);
        }
        let request: Self = serde_json::from_slice(body).map_err(|_| TenantLifecycleWireFailure)?;
        request.validate()?;
        Ok(request)
    }

    #[must_use]
    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    #[must_use]
    pub const fn target(&self) -> TenantLifecycleState {
        self.target
    }

    #[must_use]
    pub const fn expected_generation(&self) -> u64 {
        self.expected_generation
    }

    #[must_use]
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    pub fn validate(&self) -> Result<(), TenantLifecycleWireFailure> {
        if !identifier(&self.tenant)
            || !identifier(&self.idempotency_key)
            || self.expected_generation == 0
        {
            return Err(TenantLifecycleWireFailure);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, TenantLifecycleWireFailure> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| TenantLifecycleWireFailure)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TenantLifecycleTransitionResponse {
    pub tenant: String,
    pub from: TenantLifecycleState,
    pub to: TenantLifecycleState,
    pub lifecycle_generation: u64,
    pub audit_position: u64,
    pub audit_ingest_time_unix_seconds: u64,
}

impl TenantLifecycleTransitionResponse {
    pub fn decode(body: &[u8]) -> Result<Self, TenantLifecycleWireFailure> {
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(TenantLifecycleWireFailure);
        }
        let response: Self =
            serde_json::from_slice(body).map_err(|_| TenantLifecycleWireFailure)?;
        if !identifier(&response.tenant)
            || response.lifecycle_generation == 0
            || response.audit_position == 0
            || response.audit_ingest_time_unix_seconds == 0
        {
            return Err(TenantLifecycleWireFailure);
        }
        Ok(response)
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
