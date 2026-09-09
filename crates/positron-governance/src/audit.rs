mod rotation;
mod schema_checkpoint;

use std::fmt::{Display, Formatter};

use positron_domain::identity::{ExternalTenantAlias, PrincipalId, Scope, TenantId, TenantSlug};
use positron_kernel::GovernanceAuditRecord;

use crate::identity::IdentityFailure;
use crate::{AdministrativeIdempotencyKey, ResourceGeneration};

pub use rotation::{CatalogRootRotationAuditEntry, CatalogRootRotationStage};

const MAGIC_V1: [u8; 8] = *b"POSAUD01";
const MAGIC_V2: [u8; 8] = *b"POSAUD02";
const ROOT_ROTATION_MAGIC: &[u8] = b"catalog-root-rotation-v1\0";
const POLICY_ACTIVATION_MAGIC: [u8; 8] = *b"POSPOL02";
const KEY_LIFECYCLE_MAGIC: [u8; 8] = *b"POSKEY01";
const LISTENER_TRANSPORT_MAGIC: [u8; 8] = *b"POSTPT01";

/// Bounded, non-secret metadata for the initial instance operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitialAuditMetadata {
    non_interactive: bool,
    tenant_slug: TenantSlug,
    external_alias: Option<ExternalTenantAlias>,
}

impl InitialAuditMetadata {
    #[must_use]
    pub const fn initialization_mode(&self) -> &'static str {
        if self.non_interactive {
            "non-interactive"
        } else {
            "interactive"
        }
    }

    #[must_use]
    pub fn tenant_slug(&self) -> &str {
        self.tenant_slug.as_str()
    }

    #[must_use]
    pub fn external_tenant_alias(&self) -> Option<&str> {
        self.external_alias
            .as_ref()
            .map(ExternalTenantAlias::as_str)
    }
}

/// Closed Administration-owned meaning for exactly one committed kernel audit position.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GovernanceAuditEntry {
    Initialization(InitializationAuditEntry),
    CatalogRootRotation(CatalogRootRotationAuditEntry),
    IngestPolicyActivation(IngestPolicyActivationAuditEntry),
    SchemaCheckpoint(SchemaCheckpointAuditEntry),
    ApiKeyLifecycle(ApiKeyLifecycleAuditEntry),
    ListenerTransport(ListenerTransportAuditEntry),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiKeyLifecycleAuditEntry {
    position: u64,
    action: ApiKeyLifecycleAction,
    actor: PrincipalId,
    principal: PrincipalId,
    target: PrincipalId,
    scope: Scope,
    expires_at_unix_seconds: Option<u64>,
    expected_generation: ResourceGeneration,
    generation: ResourceGeneration,
    idempotency_key: AdministrativeIdempotencyKey,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApiKeyLifecycleAction {
    Create,
    Rotate,
    Revoke,
}

/// Redacted evidence that the active API listener uses the explicit plaintext
/// transport opt-out.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListenerTransportAuditEntry {
    position: u64,
    instance: [u8; 16],
}

impl ListenerTransportAuditEntry {
    #[must_use]
    pub const fn new(position: u64, instance: [u8; 16]) -> Self {
        Self { position, instance }
    }

    #[must_use]
    pub const fn position(&self) -> u64 {
        self.position
    }

    #[must_use]
    pub const fn instance_id(&self) -> [u8; 16] {
        self.instance
    }

    #[must_use]
    pub const fn action(&self) -> &'static str {
        "listener.api-transport.plaintext-opt-out"
    }

    #[must_use]
    pub const fn outcome(&self) -> &'static str {
        "active"
    }
}

pub(crate) fn plaintext_api_transport_audit_intent(instance: [u8; 16]) -> Vec<u8> {
    let mut intent = Vec::with_capacity(LISTENER_TRANSPORT_MAGIC.len() + instance.len());
    intent.extend_from_slice(&LISTENER_TRANSPORT_MAGIC);
    intent.extend_from_slice(&instance);
    intent
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IngestPolicyActivationAuditEntry {
    position: u64,
    idempotency_key: AdministrativeIdempotencyKey,
    principal: PrincipalId,
    tenant: TenantId,
    expected_generation: ResourceGeneration,
    generation: ResourceGeneration,
    digest: [u8; 32],
    request_digest: [u8; 32],
}

impl IngestPolicyActivationAuditEntry {
    #[must_use]
    pub const fn position(&self) -> u64 {
        self.position
    }
    #[must_use]
    pub const fn idempotency_key(&self) -> AdministrativeIdempotencyKey {
        self.idempotency_key
    }
    #[must_use]
    pub const fn principal_id(&self) -> PrincipalId {
        self.principal
    }
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant
    }
    #[must_use]
    pub const fn expected_generation(&self) -> ResourceGeneration {
        self.expected_generation
    }
    #[must_use]
    pub const fn generation(&self) -> ResourceGeneration {
        self.generation
    }
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
    #[must_use]
    pub const fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }
}

/// Typed, bounded meaning of the committed instance initialization audit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitializationAuditEntry {
    position: u64,
    ingest_time_unix_seconds: u64,
    principal: PrincipalId,
    tenant: Option<TenantId>,
    action: String,
    target: [u8; 16],
    outcome: String,
    request_id: [u8; 16],
    metadata: InitialAuditMetadata,
}

impl GovernanceAuditEntry {
    /// Decodes every supported committed schema without weakening the closed
    /// failure for unknown or malformed records.
    pub fn decode(record: &GovernanceAuditRecord) -> Result<Self, IdentityFailure> {
        Self::decode_fields(
            record.position(),
            record.transaction().to_bytes(),
            record.intent(),
        )
    }

    #[must_use]
    pub const fn position(&self) -> u64 {
        match self {
            Self::Initialization(entry) => entry.position(),
            Self::CatalogRootRotation(entry) => entry.position(),
            Self::IngestPolicyActivation(entry) => entry.position,
            Self::SchemaCheckpoint(entry) => entry.position(),
            Self::ApiKeyLifecycle(entry) => entry.position,
            Self::ListenerTransport(entry) => entry.position,
        }
    }

    #[must_use]
    pub fn action(&self) -> &str {
        match self {
            Self::Initialization(entry) => entry.action(),
            Self::CatalogRootRotation(entry) => entry.action(),
            Self::IngestPolicyActivation(_) => "ingest-policy.activate",
            Self::SchemaCheckpoint(_) => "schema-checkpoint.replace",
            Self::ApiKeyLifecycle(entry) => match entry.action {
                ApiKeyLifecycleAction::Create => "api-key.create",
                ApiKeyLifecycleAction::Rotate => "api-key.rotate",
                ApiKeyLifecycleAction::Revoke => "api-key.revoke",
            },
            Self::ListenerTransport(entry) => entry.action(),
        }
    }

    #[must_use]
    pub fn outcome(&self) -> &str {
        match self {
            Self::Initialization(entry) => entry.outcome(),
            Self::CatalogRootRotation(entry) => entry.outcome(),
            Self::IngestPolicyActivation(_) => "succeeded",
            Self::SchemaCheckpoint(_) => "succeeded",
            Self::ApiKeyLifecycle(_) => "succeeded",
            Self::ListenerTransport(entry) => entry.outcome(),
        }
    }

    #[must_use]
    pub const fn as_initialization(&self) -> Option<&InitializationAuditEntry> {
        match self {
            Self::Initialization(entry) => Some(entry),
            Self::CatalogRootRotation(_)
            | Self::IngestPolicyActivation(_)
            | Self::SchemaCheckpoint(_)
            | Self::ApiKeyLifecycle(_)
            | Self::ListenerTransport(_) => None,
        }
    }

    #[must_use]
    pub const fn as_catalog_root_rotation(&self) -> Option<&CatalogRootRotationAuditEntry> {
        match self {
            Self::CatalogRootRotation(entry) => Some(entry),
            Self::Initialization(_)
            | Self::IngestPolicyActivation(_)
            | Self::SchemaCheckpoint(_)
            | Self::ApiKeyLifecycle(_)
            | Self::ListenerTransport(_) => None,
        }
    }

    #[must_use]
    pub const fn as_schema_checkpoint(&self) -> Option<&SchemaCheckpointAuditEntry> {
        match self {
            Self::SchemaCheckpoint(entry) => Some(entry),
            Self::Initialization(_)
            | Self::CatalogRootRotation(_)
            | Self::IngestPolicyActivation(_)
            | Self::ApiKeyLifecycle(_)
            | Self::ListenerTransport(_) => None,
        }
    }

    #[must_use]
    pub const fn as_api_key_lifecycle(&self) -> Option<&ApiKeyLifecycleAuditEntry> {
        match self {
            Self::ApiKeyLifecycle(entry) => Some(entry),
            Self::Initialization(_)
            | Self::CatalogRootRotation(_)
            | Self::IngestPolicyActivation(_)
            | Self::SchemaCheckpoint(_)
            | Self::ListenerTransport(_) => None,
        }
    }

    #[must_use]
    pub const fn as_listener_transport(&self) -> Option<&ListenerTransportAuditEntry> {
        match self {
            Self::ListenerTransport(entry) => Some(entry),
            Self::Initialization(_)
            | Self::CatalogRootRotation(_)
            | Self::IngestPolicyActivation(_)
            | Self::SchemaCheckpoint(_)
            | Self::ApiKeyLifecycle(_) => None,
        }
    }

    pub(crate) fn decode_fields(
        position: u64,
        transaction_id: [u8; 16],
        intent: &[u8],
    ) -> Result<Self, IdentityFailure> {
        if intent.starts_with(MAGIC_V1.as_slice()) || intent.starts_with(MAGIC_V2.as_slice()) {
            return InitializationAuditEntry::decode_intent(position, intent)
                .map(Self::Initialization);
        }
        if intent.starts_with(ROOT_ROTATION_MAGIC) {
            return CatalogRootRotationAuditEntry::decode_intent(position, transaction_id, intent)
                .map(Self::CatalogRootRotation);
        }
        if intent.starts_with(&POLICY_ACTIVATION_MAGIC) {
            let mut cursor = Cursor::new(intent);
            if cursor.take_array::<8>()? != POLICY_ACTIVATION_MAGIC {
                return Err(IdentityFailure);
            }
            let idempotency_key = AdministrativeIdempotencyKey::new(cursor.take_array()?)
                .map_err(|_| IdentityFailure)?;
            if idempotency_key.to_bytes() != transaction_id {
                return Err(IdentityFailure);
            }
            let principal =
                PrincipalId::from_bytes(cursor.take_array()?).map_err(|_| IdentityFailure)?;
            let tenant = TenantId::from_bytes(cursor.take_array()?).map_err(|_| IdentityFailure)?;
            let expected_generation =
                ResourceGeneration::new(cursor.take_u64()?).map_err(|_| IdentityFailure)?;
            let generation =
                ResourceGeneration::new(cursor.take_u64()?).map_err(|_| IdentityFailure)?;
            let digest = cursor.take_array()?;
            let request_digest = cursor.take_array()?;
            if expected_generation.get().checked_add(1) != Some(generation.get())
                || digest.iter().all(|byte| *byte == 0)
                || request_digest.iter().all(|byte| *byte == 0)
                || !cursor.is_empty()
            {
                return Err(IdentityFailure);
            }
            return Ok(Self::IngestPolicyActivation(
                IngestPolicyActivationAuditEntry {
                    position,
                    idempotency_key,
                    principal,
                    tenant,
                    expected_generation,
                    generation,
                    digest,
                    request_digest,
                },
            ));
        }
        if intent.starts_with(&schema_checkpoint::MAGIC) {
            return SchemaCheckpointAuditEntry::decode_intent(position, transaction_id, intent)
                .map(Self::SchemaCheckpoint);
        }
        if intent.starts_with(&LISTENER_TRANSPORT_MAGIC) {
            if intent.len() != LISTENER_TRANSPORT_MAGIC.len() + 16
                || intent.get(..8) != Some(LISTENER_TRANSPORT_MAGIC.as_slice())
                || intent.get(8..) != Some(transaction_id.as_slice())
                || transaction_id.iter().all(|byte| *byte == 0)
            {
                return Err(IdentityFailure);
            }
            return Ok(Self::ListenerTransport(ListenerTransportAuditEntry::new(
                position,
                transaction_id,
            )));
        }
        if intent.starts_with(&KEY_LIFECYCLE_MAGIC) {
            let fields = 9;
            let action = match *intent.get(8).ok_or(IdentityFailure)? {
                1 => ApiKeyLifecycleAction::Create,
                2 => ApiKeyLifecycleAction::Rotate,
                3 => ApiKeyLifecycleAction::Revoke,
                _ => return Err(IdentityFailure),
            };
            if intent.len() != fields + 89
                || intent.get(..8) != Some(KEY_LIFECYCLE_MAGIC.as_slice())
                || intent.get(fields + 73..fields + 89) != Some(transaction_id.as_slice())
            {
                return Err(IdentityFailure);
            }
            let actor = PrincipalId::from_bytes(
                intent
                    .get(fields..fields + 16)
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or(IdentityFailure)?,
            )
            .map_err(|_| IdentityFailure)?;
            let principal = PrincipalId::from_bytes(
                intent
                    .get(fields + 16..fields + 32)
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or(IdentityFailure)?,
            )
            .map_err(|_| IdentityFailure)?;
            let target = PrincipalId::from_bytes(
                intent
                    .get(fields + 32..fields + 48)
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or(IdentityFailure)?,
            )
            .map_err(|_| IdentityFailure)?;
            let scope = match *intent.get(fields + 48).ok_or(IdentityFailure)? {
                1 => Scope::Ingest,
                2 => Scope::Query,
                3 => Scope::TenantAdministration,
                _ => return Err(IdentityFailure),
            };
            let expires_at_unix_seconds = match intent
                .get(fields + 49..fields + 57)
                .and_then(|bytes| bytes.try_into().ok())
                .map(u64::from_be_bytes)
                .ok_or(IdentityFailure)?
            {
                0 => None,
                value => Some(value),
            };
            let expected_generation = ResourceGeneration::new(
                intent
                    .get(fields + 57..fields + 65)
                    .and_then(|bytes| bytes.try_into().ok())
                    .map(u64::from_be_bytes)
                    .ok_or(IdentityFailure)?,
            )
            .map_err(|_| IdentityFailure)?;
            let generation = ResourceGeneration::new(
                intent
                    .get(fields + 65..fields + 73)
                    .and_then(|bytes| bytes.try_into().ok())
                    .map(u64::from_be_bytes)
                    .ok_or(IdentityFailure)?,
            )
            .map_err(|_| IdentityFailure)?;
            if expected_generation.get().checked_add(1) != Some(generation.get()) {
                return Err(IdentityFailure);
            }
            return Ok(Self::ApiKeyLifecycle(ApiKeyLifecycleAuditEntry {
                position,
                action,
                actor,
                principal,
                target,
                scope,
                expires_at_unix_seconds,
                expected_generation,
                generation,
                idempotency_key: AdministrativeIdempotencyKey::new(transaction_id)
                    .map_err(|_| IdentityFailure)?,
            }));
        }
        Err(IdentityFailure)
    }
}

impl ApiKeyLifecycleAuditEntry {
    #[must_use]
    pub const fn actor_id(&self) -> PrincipalId {
        self.actor
    }

    #[must_use]
    pub const fn principal_id(&self) -> PrincipalId {
        self.principal
    }

    #[must_use]
    pub const fn target_principal_id(&self) -> PrincipalId {
        self.target
    }

    #[must_use]
    pub const fn scope(&self) -> Scope {
        self.scope
    }

    #[must_use]
    pub const fn action(&self) -> ApiKeyLifecycleAction {
        self.action
    }

    #[must_use]
    pub const fn expires_at_unix_seconds(&self) -> Option<u64> {
        self.expires_at_unix_seconds
    }

    #[must_use]
    pub const fn expected_generation(&self) -> ResourceGeneration {
        self.expected_generation
    }

    #[must_use]
    pub const fn generation(&self) -> ResourceGeneration {
        self.generation
    }

    #[must_use]
    pub const fn idempotency_key(&self) -> AdministrativeIdempotencyKey {
        self.idempotency_key
    }
}

pub use schema_checkpoint::{SchemaCheckpointAuditEntry, schema_checkpoint_audit_intent};

impl Display for GovernanceAuditEntry {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "governance audit position {}: {} {}",
            self.position(),
            self.action(),
            self.outcome()
        )
    }
}

impl InitializationAuditEntry {
    pub(crate) fn decode_intent(position: u64, encoded: &[u8]) -> Result<Self, IdentityFailure> {
        let mut cursor = Cursor::new(encoded);
        let magic = cursor.take_array::<8>()?;
        if magic != MAGIC_V1 && magic != MAGIC_V2 {
            return Err(IdentityFailure);
        }
        let ingest_time_unix_seconds = cursor.take_u64()?;
        if ingest_time_unix_seconds == 0 {
            return Err(IdentityFailure);
        }
        let principal =
            PrincipalId::from_bytes(cursor.take_array()?).map_err(|_| IdentityFailure)?;
        let tenant = match cursor.take_u8()? {
            0 => None,
            1 => Some(TenantId::from_bytes(cursor.take_array()?).map_err(|_| IdentityFailure)?),
            _ => return Err(IdentityFailure),
        };
        let action = cursor.take_text_u8(128)?.to_owned();
        if action != "instance.initialize" || cursor.take_u8()? != 1 {
            return Err(IdentityFailure);
        }
        let target = cursor.take_array()?;
        if target.iter().all(|byte| *byte == 0) {
            return Err(IdentityFailure);
        }
        let outcome = cursor.take_text_u8(64)?.to_owned();
        let request_id = cursor.take_array()?;
        if outcome != "succeeded" || request_id.iter().all(|byte| *byte == 0) {
            return Err(IdentityFailure);
        }
        let non_interactive = match cursor.take_u8()? {
            0 => false,
            1 => true,
            _ => return Err(IdentityFailure),
        };
        let tenant_slug =
            TenantSlug::parse_canonical(cursor.take_text_u8(63)?).map_err(|_| IdentityFailure)?;
        let external_alias = if magic == MAGIC_V2 {
            Some(
                ExternalTenantAlias::parse(cursor.take_text_u8(128)?)
                    .map_err(|_| IdentityFailure)?,
            )
        } else {
            None
        };
        if !cursor.is_empty() {
            return Err(IdentityFailure);
        }
        Ok(Self {
            position,
            ingest_time_unix_seconds,
            principal,
            tenant,
            action,
            target,
            outcome,
            request_id,
            metadata: InitialAuditMetadata {
                non_interactive,
                tenant_slug,
                external_alias,
            },
        })
    }

    #[must_use]
    pub const fn position(&self) -> u64 {
        self.position
    }
    #[must_use]
    pub const fn ingest_time_unix_seconds(&self) -> u64 {
        self.ingest_time_unix_seconds
    }
    #[must_use]
    pub const fn principal_id(&self) -> PrincipalId {
        self.principal
    }
    #[must_use]
    pub const fn tenant_id(&self) -> Option<TenantId> {
        self.tenant
    }
    #[must_use]
    pub fn action(&self) -> &str {
        &self.action
    }
    #[must_use]
    pub const fn target(&self) -> [u8; 16] {
        self.target
    }
    #[must_use]
    pub fn outcome(&self) -> &str {
        &self.outcome
    }
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }
    #[must_use]
    pub const fn metadata(&self) -> &InitialAuditMetadata {
        &self.metadata
    }
}

struct Cursor<'a> {
    remaining: &'a [u8],
}

impl<'a> Cursor<'a> {
    const fn new(remaining: &'a [u8]) -> Self {
        Self { remaining }
    }
    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], IdentityFailure> {
        let (value, rest) = self.remaining.split_at_checked(N).ok_or(IdentityFailure)?;
        self.remaining = rest;
        value.try_into().map_err(|_| IdentityFailure)
    }
    fn take_u8(&mut self) -> Result<u8, IdentityFailure> {
        Ok(self.take_array::<1>()?[0])
    }
    fn take_u64(&mut self) -> Result<u64, IdentityFailure> {
        self.take_array().map(u64::from_be_bytes)
    }
    fn take_text_u8(&mut self, maximum: usize) -> Result<&'a str, IdentityFailure> {
        let length = usize::from(self.take_u8()?);
        if length > maximum {
            return Err(IdentityFailure);
        }
        let (value, rest) = self
            .remaining
            .split_at_checked(length)
            .ok_or(IdentityFailure)?;
        self.remaining = rest;
        std::str::from_utf8(value).map_err(|_| IdentityFailure)
    }
    const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}

#[cfg(test)]
#[path = "audit/tests.rs"]
mod tests;
