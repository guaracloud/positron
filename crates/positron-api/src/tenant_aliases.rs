//! Checked public input and output for one immutable external tenant-alias binding.

use serde::{Deserialize, Serialize};

pub use crate::api_keys::ApiKeyTransport as TenantAliasTransport;

mod client {
    include!(concat!(env!("OUT_DIR"), "/tenant_alias_service_client.rs"));
}
pub use client::{TenantAliasServiceClient, TenantAliasServiceClientFailure};

pub const HTTP_PATH: &str = "/v1/tenant-aliases:bind";
pub const MAX_REQUEST_BYTES: usize = 1024;
pub const MAX_RESPONSE_BYTES: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TenantAliasWireFailure;

impl std::fmt::Display for TenantAliasWireFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("invalid tenant alias wire message")
    }
}

impl std::error::Error for TenantAliasWireFailure {}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TenantAliasBindRequest {
    tenant: String,
    external_alias: String,
    expected_generation: u64,
    idempotency_key: String,
}

impl TenantAliasBindRequest {
    #[must_use]
    pub fn new(
        tenant: String,
        external_alias: String,
        expected_generation: u64,
        idempotency_key: String,
    ) -> Self {
        Self {
            tenant,
            external_alias,
            expected_generation,
            idempotency_key,
        }
    }

    pub fn decode(body: &[u8]) -> Result<Self, TenantAliasWireFailure> {
        if body.len() > MAX_REQUEST_BYTES {
            return Err(TenantAliasWireFailure);
        }
        let request: Self = serde_json::from_slice(body).map_err(|_| TenantAliasWireFailure)?;
        request.validate()?;
        Ok(request)
    }

    pub fn encode(&self) -> Result<Vec<u8>, TenantAliasWireFailure> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| TenantAliasWireFailure)
    }

    #[must_use]
    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    #[must_use]
    pub fn external_alias(&self) -> &str {
        &self.external_alias
    }

    #[must_use]
    pub const fn expected_generation(&self) -> u64 {
        self.expected_generation
    }

    #[must_use]
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    pub fn validate(&self) -> Result<(), TenantAliasWireFailure> {
        if !uuid(&self.tenant)
            || !uuid(&self.idempotency_key)
            || self.expected_generation == 0
            || self.external_alias.is_empty()
            || self.external_alias.len() > 128
            || !self
                .external_alias
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(TenantAliasWireFailure);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TenantAliasBindResponse {
    pub tenant: String,
    pub alias_generation: u64,
    pub audit_position: u64,
    pub audit_ingest_time_unix_seconds: u64,
}

impl TenantAliasBindResponse {
    pub fn decode(body: &[u8]) -> Result<Self, TenantAliasWireFailure> {
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(TenantAliasWireFailure);
        }
        let response: Self = serde_json::from_slice(body).map_err(|_| TenantAliasWireFailure)?;
        if !uuid(&response.tenant)
            || response.alias_generation == 0
            || response.audit_position == 0
            || response.audit_ingest_time_unix_seconds == 0
        {
            return Err(TenantAliasWireFailure);
        }
        Ok(response)
    }
}

fn uuid(value: &str) -> bool {
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
