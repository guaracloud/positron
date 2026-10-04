//! Bounded, authenticated Maintenance Coordinator inspection wire types.

use serde::{Deserialize, Serialize};

pub use crate::api_keys::ApiKeyTransport as MaintenanceTransport;

mod client {
    include!(concat!(env!("OUT_DIR"), "/maintenance_service_client.rs"));
}
pub use client::{MaintenanceServiceClient, MaintenanceServiceClientFailure};

pub const STATUS_HTTP_PATH: &str = "/v1/maintenance:status";
pub const EXPLAIN_HTTP_PATH: &str = "/v1/maintenance:explain";
pub const RUN_HTTP_PATH: &str = "/v1/maintenance:run";
pub const MAX_REQUEST_BYTES: usize = 128;
pub const MAX_RUN_REQUEST_BYTES: usize = 256;
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;
pub const MAX_TASKS: usize = 128;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceStatusRequest {}

impl MaintenanceStatusRequest {
    pub fn decode(body: &[u8]) -> Result<Self, MaintenanceWireFailure> {
        if body.len() > MAX_REQUEST_BYTES {
            return Err(MaintenanceWireFailure);
        }
        serde_json::from_slice(body).map_err(|_| MaintenanceWireFailure)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceExplainRequest {
    pub identity: String,
}

/// A bounded operator request for the coordinator to prepare one already
/// sealed source scope. The server chooses the authenticated retention bucket
/// and derives every task precondition and reservation from Catalog state.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceRunRequest {
    class: String,
    tenant: String,
    signal: String,
    shard: u32,
    idempotency_key: String,
}

impl MaintenanceRunRequest {
    #[must_use]
    pub fn new(
        class: String,
        tenant: String,
        signal: String,
        shard: u32,
        idempotency_key: String,
    ) -> Self {
        Self {
            class,
            tenant,
            signal,
            shard,
            idempotency_key,
        }
    }

    pub fn decode(body: &[u8]) -> Result<Self, MaintenanceWireFailure> {
        if body.len() > MAX_RUN_REQUEST_BYTES {
            return Err(MaintenanceWireFailure);
        }
        let request: Self = serde_json::from_slice(body).map_err(|_| MaintenanceWireFailure)?;
        request.validate()?;
        Ok(request)
    }

    pub fn encode(&self) -> Result<Vec<u8>, MaintenanceWireFailure> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| MaintenanceWireFailure)
    }

    #[must_use]
    pub fn class(&self) -> &str {
        &self.class
    }

    #[must_use]
    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    #[must_use]
    pub fn signal(&self) -> &str {
        &self.signal
    }

    #[must_use]
    pub const fn shard(&self) -> u32 {
        self.shard
    }

    #[must_use]
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    pub fn validate(&self) -> Result<(), MaintenanceWireFailure> {
        if self.class != "compaction"
            || !identifier(&self.tenant)
            || !matches!(self.signal.as_str(), "logs" | "traces")
            || self.shard == 0
            || !identifier(&self.idempotency_key)
        {
            return Err(MaintenanceWireFailure);
        }
        Ok(())
    }
}

impl MaintenanceExplainRequest {
    pub fn decode(body: &[u8]) -> Result<Self, MaintenanceWireFailure> {
        if body.len() > MAX_REQUEST_BYTES {
            return Err(MaintenanceWireFailure);
        }
        let request: Self = serde_json::from_slice(body).map_err(|_| MaintenanceWireFailure)?;
        if request.identity.len() != 32
            || !request
                .identity
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(MaintenanceWireFailure);
        }
        Ok(request)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceTaskStatus {
    pub identity: String,
    pub class: String,
    pub scope: String,
    pub phase: String,
    pub submitted_at_unix_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_sequence: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pause_until_unix_seconds: Option<u64>,
    pub cancellation_requested: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceStatusResponse {
    pub tasks: Vec<MaintenanceTaskStatus>,
    pub queued: u32,
    pub running: u32,
    pub deferred: u32,
    pub terminal: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceExplainResponse {
    pub task: MaintenanceTaskStatus,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceRunResponse {
    pub task: MaintenanceTaskStatus,
}

impl MaintenanceRunResponse {
    pub fn decode(body: &[u8]) -> Result<Self, MaintenanceWireFailure> {
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(MaintenanceWireFailure);
        }
        let response: Self = serde_json::from_slice(body).map_err(|_| MaintenanceWireFailure)?;
        MaintenanceStatusResponse {
            tasks: vec![response.task.clone()],
            queued: u32::from(response.task.phase == "queued"),
            running: u32::from(response.task.phase == "running"),
            deferred: u32::from(response.task.phase == "deferred"),
            terminal: u32::from(matches!(
                response.task.phase.as_str(),
                "cancelled" | "succeeded" | "failed"
            )),
        }
        .validate()?;
        Ok(response)
    }

    pub fn encode(&self) -> Result<Vec<u8>, MaintenanceWireFailure> {
        Self::decode(&serde_json::to_vec(self).map_err(|_| MaintenanceWireFailure)?)?;
        serde_json::to_vec(self).map_err(|_| MaintenanceWireFailure)
    }
}

impl MaintenanceExplainResponse {
    pub fn encode(&self) -> Result<Vec<u8>, MaintenanceWireFailure> {
        let response = MaintenanceStatusResponse {
            tasks: vec![self.task.clone()],
            queued: u32::from(self.task.phase == "queued"),
            running: u32::from(self.task.phase == "running"),
            deferred: u32::from(self.task.phase == "deferred"),
            terminal: u32::from(matches!(
                self.task.phase.as_str(),
                "cancelled" | "succeeded" | "failed"
            )),
        };
        response.validate()?;
        serde_json::to_vec(self).map_err(|_| MaintenanceWireFailure)
    }
}

impl MaintenanceStatusResponse {
    pub fn decode(body: &[u8]) -> Result<Self, MaintenanceWireFailure> {
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(MaintenanceWireFailure);
        }
        let response: Self = serde_json::from_slice(body).map_err(|_| MaintenanceWireFailure)?;
        response.validate()?;
        Ok(response)
    }
    pub fn encode(&self) -> Result<Vec<u8>, MaintenanceWireFailure> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| MaintenanceWireFailure)?;
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(MaintenanceWireFailure);
        }
        Ok(bytes)
    }

    pub fn validate(&self) -> Result<(), MaintenanceWireFailure> {
        if self.tasks.len() > MAX_TASKS
            || self.tasks.iter().any(|task| {
                task.identity.len() != 32
                    || !task.identity.bytes().all(|byte| byte.is_ascii_hexdigit())
                    || task.class.is_empty()
                    || task.class.len() > 64
                    || task.scope.is_empty()
                    || task.scope.len() > 128
                    || !matches!(
                        task.phase.as_str(),
                        "queued" | "running" | "deferred" | "cancelled" | "succeeded" | "failed"
                    )
                    || task.checkpoint_sequence == Some(0)
                    || task.pause_until_unix_seconds == Some(0)
            })
        {
            return Err(MaintenanceWireFailure);
        }
        let total = u32::try_from(self.tasks.len()).map_err(|_| MaintenanceWireFailure)?;
        if self
            .queued
            .checked_add(self.running)
            .and_then(|total| total.checked_add(self.deferred))
            .and_then(|total| total.checked_add(self.terminal))
            != Some(total)
        {
            return Err(MaintenanceWireFailure);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaintenanceWireFailure;

impl std::fmt::Display for MaintenanceWireFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("invalid maintenance wire message")
    }
}

impl std::error::Error for MaintenanceWireFailure {}

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
