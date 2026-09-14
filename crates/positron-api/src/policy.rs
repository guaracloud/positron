//! Checked public input for non-mutating policy validation.

use serde::{Deserialize, Serialize};

pub use crate::api_keys::ApiKeyTransport as PolicyPreviewTransport;

mod client {
    include!(concat!(
        env!("OUT_DIR"),
        "/policy_preview_service_client.rs"
    ));
}
pub use client::{
    MAX_REQUEST_BYTES, PolicyPreviewServiceClient, PolicyPreviewServiceClientFailure,
};
mod test_client {
    include!(concat!(env!("OUT_DIR"), "/policy_test_service_client.rs"));
}
pub use test_client::{
    MAX_TEST_REQUEST_BYTES, PolicyTestServiceClient, PolicyTestServiceClientFailure,
};
mod diff_client {
    include!(concat!(env!("OUT_DIR"), "/policy_diff_service_client.rs"));
}
pub use diff_client::{
    MAX_DIFF_REQUEST_BYTES, PolicyDiffServiceClient, PolicyDiffServiceClientFailure,
};
mod explain_client {
    include!(concat!(
        env!("OUT_DIR"),
        "/policy_explain_service_client.rs"
    ));
}
pub use explain_client::{
    MAX_EXPLAIN_REQUEST_BYTES, PolicyExplainServiceClient, PolicyExplainServiceClientFailure,
};
mod activate_client {
    include!(concat!(
        env!("OUT_DIR"),
        "/policy_activate_service_client.rs"
    ));
}
pub use activate_client::{
    MAX_ACTIVATE_REQUEST_BYTES, PolicyActivateServiceClient, PolicyActivateServiceClientFailure,
};

pub const HTTP_VALIDATE_PATH: &str = "/v1/policies:validate";
pub const HTTP_TEST_PATH: &str = "/v1/policies:test";
pub const HTTP_DIFF_PATH: &str = "/v1/policies:diff";
pub const HTTP_EXPLAIN_PATH: &str = "/v1/policies:explain";
pub const HTTP_ACTIVATE_PATH: &str = "/v1/policies:activate";
/// One generation change plus at most two semantic changes for each of the
/// 64 rules accepted by the canonical preview policy.
pub const MAX_DIFF_SEMANTIC_CHANGES: usize = 129;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyPreviewRequest {
    policy_json: String,
}

impl PolicyPreviewRequest {
    #[must_use]
    pub fn new(policy_json: String) -> Self {
        Self { policy_json }
    }

    pub fn decode(body: &[u8]) -> Result<Self, PolicyPreviewServiceClientFailure> {
        if body.len() > MAX_REQUEST_BYTES {
            return Err(PolicyPreviewServiceClientFailure::InvalidRequest);
        }
        let request: Self = serde_json::from_slice(body)
            .map_err(|_| PolicyPreviewServiceClientFailure::InvalidRequest)?;
        if request.policy_json.is_empty() || request.policy_json.len() > MAX_REQUEST_BYTES {
            return Err(PolicyPreviewServiceClientFailure::InvalidRequest);
        }
        Ok(request)
    }
    #[must_use]
    pub fn policy_json(&self) -> &str {
        &self.policy_json
    }

    pub fn validate(&self) -> Result<(), PolicyPreviewServiceClientFailure> {
        if self.policy_json.is_empty() || self.policy_json.len() > MAX_REQUEST_BYTES {
            return Err(PolicyPreviewServiceClientFailure::InvalidRequest);
        }
        Ok(())
    }

    fn encode(&self) -> Result<Vec<u8>, PolicyPreviewServiceClientFailure> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| PolicyPreviewServiceClientFailure::InvalidRequest)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyValidateResponse {
    pub policy_generation: u64,
    pub policy_digest: String,
    pub rule_count: u32,
}

impl PolicyValidateResponse {
    pub fn decode(body: &[u8]) -> Result<Self, PolicyPreviewServiceClientFailure> {
        let response: Self = serde_json::from_slice(body)
            .map_err(|_| PolicyPreviewServiceClientFailure::Transport)?;
        if response.policy_generation == 0
            || response.rule_count > 4096
            || response.policy_digest.len() != 64
            || !response
                .policy_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(PolicyPreviewServiceClientFailure::Transport);
        }
        Ok(response)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyTestRequest {
    policy_json: String,
    candidate_json: String,
}

impl PolicyTestRequest {
    #[must_use]
    pub fn new(policy_json: String, candidate_json: String) -> Self {
        Self {
            policy_json,
            candidate_json,
        }
    }
    pub fn decode(body: &[u8]) -> Result<Self, PolicyTestServiceClientFailure> {
        if body.len() > MAX_TEST_REQUEST_BYTES {
            return Err(PolicyTestServiceClientFailure::InvalidRequest);
        }
        let request: Self = serde_json::from_slice(body)
            .map_err(|_| PolicyTestServiceClientFailure::InvalidRequest)?;
        request.validate()?;
        Ok(request)
    }
    #[must_use]
    pub fn policy_json(&self) -> &str {
        &self.policy_json
    }
    #[must_use]
    pub fn candidate_json(&self) -> &str {
        &self.candidate_json
    }
    pub fn validate(&self) -> Result<(), PolicyTestServiceClientFailure> {
        if self.policy_json.is_empty() || self.candidate_json.is_empty() {
            return Err(PolicyTestServiceClientFailure::InvalidRequest);
        }
        let encoded =
            serde_json::to_vec(self).map_err(|_| PolicyTestServiceClientFailure::InvalidRequest)?;
        if encoded.len() > MAX_TEST_REQUEST_BYTES {
            return Err(PolicyTestServiceClientFailure::InvalidRequest);
        }
        Ok(())
    }
    fn encode(&self) -> Result<Vec<u8>, PolicyTestServiceClientFailure> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| PolicyTestServiceClientFailure::InvalidRequest)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyTestResponse {
    pub policy_generation: u64,
    pub policy_digest: String,
    pub accepted: bool,
    pub applied_rule_count: u32,
}
impl PolicyTestResponse {
    fn decode(body: &[u8]) -> Result<Self, PolicyTestServiceClientFailure> {
        let response: Self =
            serde_json::from_slice(body).map_err(|_| PolicyTestServiceClientFailure::Transport)?;
        if response.policy_generation == 0
            || response.policy_digest.len() != 64
            || !response
                .policy_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || response.applied_rule_count > 4096
        {
            return Err(PolicyTestServiceClientFailure::Transport);
        }
        Ok(response)
    }
}

pub type PolicyExplainRequest = PolicyTestRequest;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyExplainResponse {
    pub policy_generation: u64,
    pub policy_digest: String,
    pub outcome: String,
    pub explanation: String,
}

impl PolicyExplainResponse {
    pub fn decode(body: &[u8]) -> Result<Self, PolicyTestServiceClientFailure> {
        let response: Self =
            serde_json::from_slice(body).map_err(|_| PolicyTestServiceClientFailure::Transport)?;
        if response.policy_generation == 0
            || !valid_digest(&response.policy_digest)
            || !matches!(response.outcome.as_str(), "accepted" | "rejected")
            || response.explanation.is_empty()
            || response.explanation.len() > 4096
        {
            return Err(PolicyTestServiceClientFailure::Transport);
        }
        Ok(response)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyActivateRequest {
    policy_json: String,
    expected_generation: u64,
    idempotency_key: String,
}

impl PolicyActivateRequest {
    #[must_use]
    pub fn new(policy_json: String, expected_generation: u64, idempotency_key: String) -> Self {
        Self {
            policy_json,
            expected_generation,
            idempotency_key,
        }
    }
    pub fn decode(body: &[u8]) -> Result<Self, PolicyActivateServiceClientFailure> {
        if body.len() > MAX_ACTIVATE_REQUEST_BYTES {
            return Err(PolicyActivateServiceClientFailure::InvalidRequest);
        }
        let request: Self = serde_json::from_slice(body)
            .map_err(|_| PolicyActivateServiceClientFailure::InvalidRequest)?;
        request.validate()?;
        Ok(request)
    }
    #[must_use]
    pub fn policy_json(&self) -> &str {
        &self.policy_json
    }
    #[must_use]
    pub const fn expected_generation(&self) -> u64 {
        self.expected_generation
    }
    #[must_use]
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }
    pub fn validate(&self) -> Result<(), PolicyActivateServiceClientFailure> {
        if self.policy_json.is_empty()
            || self.expected_generation == 0
            || !canonical_uuid(&self.idempotency_key)
        {
            return Err(PolicyActivateServiceClientFailure::InvalidRequest);
        }
        if serde_json::to_vec(self)
            .map_err(|_| PolicyActivateServiceClientFailure::InvalidRequest)?
            .len()
            > MAX_ACTIVATE_REQUEST_BYTES
        {
            return Err(PolicyActivateServiceClientFailure::InvalidRequest);
        }
        Ok(())
    }
    fn encode(&self) -> Result<Vec<u8>, PolicyActivateServiceClientFailure> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| PolicyActivateServiceClientFailure::InvalidRequest)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyActivateResponse {
    pub resource_generation: u64,
    pub policy_digest: String,
    pub audit_position: u64,
}

impl PolicyActivateResponse {
    fn decode(body: &[u8]) -> Result<Self, PolicyActivateServiceClientFailure> {
        let response: Self = serde_json::from_slice(body)
            .map_err(|_| PolicyActivateServiceClientFailure::Transport)?;
        if response.resource_generation == 0
            || response.audit_position == 0
            || !valid_digest(&response.policy_digest)
        {
            return Err(PolicyActivateServiceClientFailure::Transport);
        }
        Ok(response)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDiffRequest {
    before_policy_json: String,
    after_policy_json: String,
}

impl PolicyDiffRequest {
    #[must_use]
    pub fn new(before_policy_json: String, after_policy_json: String) -> Self {
        Self {
            before_policy_json,
            after_policy_json,
        }
    }
    pub fn decode(body: &[u8]) -> Result<Self, PolicyDiffServiceClientFailure> {
        if body.len() > MAX_DIFF_REQUEST_BYTES {
            return Err(PolicyDiffServiceClientFailure::InvalidRequest);
        }
        let request: Self = serde_json::from_slice(body)
            .map_err(|_| PolicyDiffServiceClientFailure::InvalidRequest)?;
        request.validate()?;
        Ok(request)
    }
    #[must_use]
    pub fn before_policy_json(&self) -> &str {
        &self.before_policy_json
    }
    #[must_use]
    pub fn after_policy_json(&self) -> &str {
        &self.after_policy_json
    }
    pub fn validate(&self) -> Result<(), PolicyDiffServiceClientFailure> {
        if self.before_policy_json.is_empty() || self.after_policy_json.is_empty() {
            return Err(PolicyDiffServiceClientFailure::InvalidRequest);
        }
        if serde_json::to_vec(self)
            .map_err(|_| PolicyDiffServiceClientFailure::InvalidRequest)?
            .len()
            > MAX_DIFF_REQUEST_BYTES
        {
            return Err(PolicyDiffServiceClientFailure::InvalidRequest);
        }
        Ok(())
    }
    fn encode(&self) -> Result<Vec<u8>, PolicyDiffServiceClientFailure> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| PolicyDiffServiceClientFailure::InvalidRequest)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDiffResponse {
    pub before_policy_generation: u64,
    pub before_policy_digest: String,
    pub after_policy_generation: u64,
    pub after_policy_digest: String,
    pub semantic_changes: Vec<String>,
}

impl PolicyDiffResponse {
    fn decode(body: &[u8]) -> Result<Self, PolicyDiffServiceClientFailure> {
        let response: Self =
            serde_json::from_slice(body).map_err(|_| PolicyDiffServiceClientFailure::Transport)?;
        if response.before_policy_generation == 0
            || response.after_policy_generation == 0
            || !valid_digest(&response.before_policy_digest)
            || !valid_digest(&response.after_policy_digest)
            || response.semantic_changes.len() > MAX_DIFF_SEMANTIC_CHANGES
            || !response.semantic_changes.iter().all(|change| {
                matches!(
                    change.as_str(),
                    "generation_changed"
                        | "rule_added"
                        | "rule_removed"
                        | "rule_predicates_changed"
                        | "rule_action_changed"
                )
            })
        {
            return Err(PolicyDiffServiceClientFailure::Transport);
        }
        Ok(response)
    }
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn canonical_uuid(value: &str) -> bool {
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
