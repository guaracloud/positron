//! Checked public input and redacted evidence for tenant retention administration.

use serde::{Deserialize, Serialize};

pub use crate::api_keys::ApiKeyTransport as TenantRetentionTransport;

mod client {
    include!(concat!(
        env!("OUT_DIR"),
        "/tenant_retention_service_client.rs"
    ));
}
pub use client::{TenantRetentionServiceClient, TenantRetentionServiceClientFailure};

pub const PREVIEW_HTTP_PATH: &str = "/v1/tenant-retention:preview";
pub const UPDATE_HTTP_PATH: &str = "/v1/tenant-retention:update";
pub const MAX_REQUEST_BYTES: usize = 2048;
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TenantRetentionWireFailure;

impl std::fmt::Display for TenantRetentionWireFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("invalid tenant retention wire message")
    }
}
impl std::error::Error for TenantRetentionWireFailure {}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TenantRetentionPreviewRequest {
    tenant: String,
    proposed_retention_seconds: u64,
}
impl TenantRetentionPreviewRequest {
    #[must_use]
    pub fn new(tenant: String, proposed_retention_seconds: u64) -> Self {
        Self {
            tenant,
            proposed_retention_seconds,
        }
    }
    pub fn decode(body: &[u8]) -> Result<Self, TenantRetentionWireFailure> {
        decode(body)
    }
    pub fn encode(&self) -> Result<Vec<u8>, TenantRetentionWireFailure> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| TenantRetentionWireFailure)
    }
    #[must_use]
    pub fn tenant(&self) -> &str {
        &self.tenant
    }
    #[must_use]
    pub const fn proposed_retention_seconds(&self) -> u64 {
        self.proposed_retention_seconds
    }
    pub fn validate(&self) -> Result<(), TenantRetentionWireFailure> {
        if uuid(&self.tenant) && self.proposed_retention_seconds != 0 {
            Ok(())
        } else {
            Err(TenantRetentionWireFailure)
        }
    }
}

/// A caller can submit this opaque digest only after receiving it from a
/// retention preview. The server recomputes the preview; it never trusts
/// caller supplied impact estimates.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TenantRetentionUpdateRequest {
    tenant: String,
    proposed_retention_seconds: u64,
    expected_generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    confirmation_digest: Option<String>,
    idempotency_key: String,
}
impl TenantRetentionUpdateRequest {
    #[must_use]
    pub fn new(
        tenant: String,
        proposed_retention_seconds: u64,
        expected_generation: u64,
        confirmation_digest: Option<String>,
        idempotency_key: String,
    ) -> Self {
        Self {
            tenant,
            proposed_retention_seconds,
            expected_generation,
            confirmation_digest,
            idempotency_key,
        }
    }
    pub fn decode(body: &[u8]) -> Result<Self, TenantRetentionWireFailure> {
        decode(body)
    }
    pub fn encode(&self) -> Result<Vec<u8>, TenantRetentionWireFailure> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| TenantRetentionWireFailure)
    }
    #[must_use]
    pub fn tenant(&self) -> &str {
        &self.tenant
    }
    #[must_use]
    pub const fn proposed_retention_seconds(&self) -> u64 {
        self.proposed_retention_seconds
    }
    #[must_use]
    pub const fn expected_generation(&self) -> u64 {
        self.expected_generation
    }
    #[must_use]
    pub fn confirmation_digest(&self) -> Option<&str> {
        self.confirmation_digest.as_deref()
    }
    #[must_use]
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }
    pub fn validate(&self) -> Result<(), TenantRetentionWireFailure> {
        if uuid(&self.tenant)
            && self.proposed_retention_seconds != 0
            && self.expected_generation != 0
            && uuid(&self.idempotency_key)
            && self.confirmation_digest.as_deref().is_none_or(hex_digest)
        {
            Ok(())
        } else {
            Err(TenantRetentionWireFailure)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionReclamation {
    None,
    At,
    BlockedByDurableLease,
    BlockedByInProcessSnapshot,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionScopeImpact {
    pub signal: String,
    pub shard: u32,
    pub catalog_identity: String,
    pub catalog_generation: u64,
    pub evaluated_at_unix_nanos: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub affected_start_unix_nanos: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub affected_end_unix_nanos: Option<i64>,
    pub affected_bytes: u64,
    pub immediately_reclaimable_bytes: u64,
    pub deferred_active_segment_bytes: u64,
    pub deferred_mixed_sealed_segment_bytes: u64,
    pub earliest_reclamation: RetentionReclamation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub earliest_reclamation_unix_nanos: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TenantRetentionPreviewResponse {
    pub tenant: String,
    pub retention_generation: u64,
    pub proposed_retention_seconds: u64,
    pub catalog_identity: String,
    pub catalog_generation: u64,
    pub confirmation_digest: String,
    pub scopes: Vec<RetentionScopeImpact>,
}
impl TenantRetentionPreviewResponse {
    pub fn decode(body: &[u8]) -> Result<Self, TenantRetentionWireFailure> {
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(TenantRetentionWireFailure);
        }
        let value: Self = serde_json::from_slice(body).map_err(|_| TenantRetentionWireFailure)?;
        value.validate()?;
        Ok(value)
    }
    pub fn encode(&self) -> Result<Vec<u8>, TenantRetentionWireFailure> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| TenantRetentionWireFailure)
    }
    pub fn validate(&self) -> Result<(), TenantRetentionWireFailure> {
        if !uuid(&self.tenant)
            || self.retention_generation == 0
            || self.proposed_retention_seconds == 0
            || !hex_digest(&self.catalog_identity)
            || self.catalog_generation == 0
            || !hex_digest(&self.confirmation_digest)
            || self.scopes.len() > 1024
        {
            return Err(TenantRetentionWireFailure);
        }
        for scope in &self.scopes {
            if !matches!(scope.signal.as_str(), "logs" | "traces")
                || !hex_digest(&scope.catalog_identity)
                || scope.catalog_generation == 0
                || (scope.affected_start_unix_nanos.is_some()
                    != scope.affected_end_unix_nanos.is_some())
                || scope
                    .affected_start_unix_nanos
                    .zip(scope.affected_end_unix_nanos)
                    .is_some_and(|(start, end)| start > end)
                || matches!(
                    scope.earliest_reclamation,
                    RetentionReclamation::At | RetentionReclamation::BlockedByDurableLease
                ) != scope.earliest_reclamation_unix_nanos.is_some()
                || matches!(
                    scope.earliest_reclamation,
                    RetentionReclamation::None | RetentionReclamation::BlockedByInProcessSnapshot
                ) && scope.earliest_reclamation_unix_nanos.is_some()
            {
                return Err(TenantRetentionWireFailure);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TenantRetentionUpdateResponse {
    pub tenant: String,
    pub retention_generation: u64,
    pub audit_position: u64,
    pub audit_ingest_time_unix_seconds: u64,
}
impl TenantRetentionUpdateResponse {
    pub fn decode(body: &[u8]) -> Result<Self, TenantRetentionWireFailure> {
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(TenantRetentionWireFailure);
        }
        let value: Self = serde_json::from_slice(body).map_err(|_| TenantRetentionWireFailure)?;
        if uuid(&value.tenant)
            && value.retention_generation != 0
            && value.audit_position != 0
            && value.audit_ingest_time_unix_seconds != 0
        {
            Ok(value)
        } else {
            Err(TenantRetentionWireFailure)
        }
    }
    pub fn encode(&self) -> Result<Vec<u8>, TenantRetentionWireFailure> {
        if uuid(&self.tenant)
            && self.retention_generation != 0
            && self.audit_position != 0
            && self.audit_ingest_time_unix_seconds != 0
        {
            serde_json::to_vec(self).map_err(|_| TenantRetentionWireFailure)
        } else {
            Err(TenantRetentionWireFailure)
        }
    }
}

fn decode<T>(body: &[u8]) -> Result<T, TenantRetentionWireFailure>
where
    T: for<'de> Deserialize<'de> + Validate,
{
    if body.len() > MAX_REQUEST_BYTES {
        return Err(TenantRetentionWireFailure);
    }
    let value: T = serde_json::from_slice(body).map_err(|_| TenantRetentionWireFailure)?;
    value.validate()?;
    Ok(value)
}
trait Validate {
    fn validate(&self) -> Result<(), TenantRetentionWireFailure>;
}
impl Validate for TenantRetentionPreviewRequest {
    fn validate(&self) -> Result<(), TenantRetentionWireFailure> {
        Self::validate(self)
    }
}
impl Validate for TenantRetentionUpdateRequest {
    fn validate(&self) -> Result<(), TenantRetentionWireFailure> {
        Self::validate(self)
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
fn hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
