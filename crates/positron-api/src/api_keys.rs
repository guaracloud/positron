//! Bounded adapters around wire messages generated from `positron.v1`.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Standard Prost output generated at build time from the canonical schema.
pub mod protobuf {
    include!(concat!(env!("OUT_DIR"), "/positron.v1.rs"));
}
pub use protobuf::{ApiKeyResponse, KeyAction, KeyDescriptor, KeyScope};

pub const HTTP_PATH: &str = "/v1/api-keys:manage";
pub const MAX_REQUEST_BYTES: usize = 1024;
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// A checked request; the wire fields are owned by the generated message.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ApiKeyRequest(protobuf::ApiKeyRequest);

impl ApiKeyRequest {
    pub fn create(
        scope: KeyScope,
        expiry: Option<u64>,
        expected: u64,
        idempotency: String,
    ) -> Self {
        Self(protobuf::ApiKeyRequest {
            action: KeyAction::Create.into(),
            scope: Some(scope.into()),
            principal: None,
            expires_at_unix_seconds: expiry,
            expected_generation: Some(expected),
            idempotency_key: Some(idempotency),
        })
    }
    pub fn list() -> Self {
        Self(protobuf::ApiKeyRequest {
            action: KeyAction::List.into(),
            ..Default::default()
        })
    }
    pub fn inspect(principal: String) -> Self {
        let mut request = Self::list();
        request.0.action = KeyAction::ScopeInspect.into();
        request.0.principal = Some(principal);
        request
    }
    pub fn mutation(
        action: KeyAction,
        principal: String,
        expected: u64,
        idempotency: String,
    ) -> Result<Self, KeyWireFailure> {
        if !matches!(action, KeyAction::Rotate | KeyAction::Revoke) {
            return Err(KeyWireFailure);
        }
        Ok(Self(protobuf::ApiKeyRequest {
            action: action.into(),
            principal: Some(principal),
            expected_generation: Some(expected),
            idempotency_key: Some(idempotency),
            ..Default::default()
        }))
    }
    pub fn action(&self) -> KeyAction {
        self.0.action()
    }
    pub fn scope(&self) -> Option<KeyScope> {
        self.0
            .scope
            .and_then(|scope| KeyScope::try_from(scope).ok())
    }
    pub fn principal(&self) -> Option<&str> {
        self.0.principal.as_deref()
    }
    pub const fn expiry(&self) -> Option<u64> {
        self.0.expires_at_unix_seconds
    }
    pub const fn expected_generation(&self) -> Option<u64> {
        self.0.expected_generation
    }
    pub fn idempotency_key(&self) -> Option<&str> {
        self.0.idempotency_key.as_deref()
    }
    pub fn encode(&self) -> Result<Vec<u8>, KeyWireFailure> {
        self.validate()?;
        serde_json::to_vec(&self.0).map_err(|_| KeyWireFailure)
    }
    pub fn decode(body: &[u8]) -> Result<Self, KeyWireFailure> {
        if body.len() > MAX_REQUEST_BYTES {
            return Err(KeyWireFailure);
        }
        let request = Self(serde_json::from_slice(body).map_err(|_| KeyWireFailure)?);
        request.validate()?;
        Ok(request)
    }
    fn validate(&self) -> Result<(), KeyWireFailure> {
        let action = self.action();
        let mutation = matches!(
            action,
            KeyAction::Create | KeyAction::Rotate | KeyAction::Revoke
        );
        if action == KeyAction::Unspecified
            || self.scope() == Some(KeyScope::Unspecified)
            || mutation != self.0.expected_generation.is_some()
            || mutation != self.0.idempotency_key.is_some()
            || self.0.expected_generation == Some(0)
            || self
                .0
                .idempotency_key
                .as_ref()
                .is_some_and(|value| !identifier(value))
            || self
                .0
                .principal
                .as_ref()
                .is_some_and(|value| !identifier(value))
            || matches!(
                action,
                KeyAction::Rotate | KeyAction::Revoke | KeyAction::ScopeInspect
            ) != self.0.principal.is_some()
            || (action == KeyAction::Create) != self.0.scope.is_some()
            || (action != KeyAction::Create && self.0.expires_at_unix_seconds.is_some())
            || self.0.expires_at_unix_seconds == Some(0)
        {
            return Err(KeyWireFailure);
        }
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

impl Drop for ApiKeyResponse {
    fn drop(&mut self) {
        if let Some(secret) = self.secret.as_mut() {
            secret.zeroize();
        }
    }
}
impl std::fmt::Debug for ApiKeyResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ApiKeyResponse { <redacted> }")
    }
}
impl ApiKeyResponse {
    pub fn encode(&self) -> Result<Vec<u8>, KeyWireFailure> {
        serde_json::to_vec(self).map_err(|_| KeyWireFailure)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, KeyWireFailure> {
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(KeyWireFailure);
        }
        serde_json::from_slice(bytes).map_err(|_| KeyWireFailure)
    }
}

// Protobuf enums are stored as integers by Prost. These adapters retain the
// canonical HTTP mapping's closed snake_case enum representation.
mod action_json {
    use super::*;
    pub fn serialize<S: serde::Serializer>(value: &i32, serializer: S) -> Result<S::Ok, S::Error> {
        KeyAction::try_from(*value)
            .map_err(serde::ser::Error::custom)?
            .serialize(serializer)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<i32, D::Error> {
        KeyAction::deserialize(deserializer).map(Into::into)
    }
}
mod scope_json {
    use super::*;
    pub fn serialize<S: serde::Serializer>(value: &i32, serializer: S) -> Result<S::Ok, S::Error> {
        KeyScope::try_from(*value)
            .map_err(serde::ser::Error::custom)?
            .serialize(serializer)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<i32, D::Error> {
        KeyScope::deserialize(deserializer).map(Into::into)
    }
}
mod optional_scope_json {
    use super::*;
    pub fn serialize<S: serde::Serializer>(
        value: &Option<i32>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        value
            .map(KeyScope::try_from)
            .transpose()
            .map_err(serde::ser::Error::custom)?
            .serialize(serializer)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<i32>, D::Error> {
        Option::<KeyScope>::deserialize(deserializer).map(|scope| scope.map(Into::into))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyWireFailure;
impl std::fmt::Display for KeyWireFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("invalid API-key request or response")
    }
}
impl std::error::Error for KeyWireFailure {}
