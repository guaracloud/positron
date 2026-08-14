mod rotation;
mod schema_checkpoint;

use std::fmt::{Display, Formatter};

use positron_domain::identity::{PrincipalId, TenantId, TenantSlug};
use positron_kernel::GovernanceAuditRecord;

use crate::identity::IdentityFailure;
use crate::{AdministrativeIdempotencyKey, ResourceGeneration};

pub use rotation::{CatalogRootRotationAuditEntry, CatalogRootRotationStage};

const MAGIC: [u8; 8] = *b"POSAUD01";
const ROOT_ROTATION_MAGIC: &[u8] = b"catalog-root-rotation-v1\0";
const POLICY_ACTIVATION_MAGIC: [u8; 8] = *b"POSPOL02";

/// Bounded, non-secret metadata for the initial instance operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitialAuditMetadata {
    non_interactive: bool,
    tenant_slug: TenantSlug,
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
}

/// Closed Administration-owned meaning for exactly one committed kernel audit position.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GovernanceAuditEntry {
    Initialization(InitializationAuditEntry),
    CatalogRootRotation(CatalogRootRotationAuditEntry),
    IngestPolicyActivation(IngestPolicyActivationAuditEntry),
    SchemaCheckpoint(SchemaCheckpointAuditEntry),
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
        }
    }

    #[must_use]
    pub fn action(&self) -> &str {
        match self {
            Self::Initialization(entry) => entry.action(),
            Self::CatalogRootRotation(entry) => entry.action(),
            Self::IngestPolicyActivation(_) => "ingest-policy.activate",
            Self::SchemaCheckpoint(_) => "schema-checkpoint.replace",
        }
    }

    #[must_use]
    pub fn outcome(&self) -> &str {
        match self {
            Self::Initialization(entry) => entry.outcome(),
            Self::CatalogRootRotation(entry) => entry.outcome(),
            Self::IngestPolicyActivation(_) => "succeeded",
            Self::SchemaCheckpoint(_) => "succeeded",
        }
    }

    #[must_use]
    pub const fn as_initialization(&self) -> Option<&InitializationAuditEntry> {
        match self {
            Self::Initialization(entry) => Some(entry),
            Self::CatalogRootRotation(_)
            | Self::IngestPolicyActivation(_)
            | Self::SchemaCheckpoint(_) => None,
        }
    }

    #[must_use]
    pub const fn as_catalog_root_rotation(&self) -> Option<&CatalogRootRotationAuditEntry> {
        match self {
            Self::CatalogRootRotation(entry) => Some(entry),
            Self::Initialization(_)
            | Self::IngestPolicyActivation(_)
            | Self::SchemaCheckpoint(_) => None,
        }
    }

    #[must_use]
    pub const fn as_schema_checkpoint(&self) -> Option<&SchemaCheckpointAuditEntry> {
        match self {
            Self::SchemaCheckpoint(entry) => Some(entry),
            Self::Initialization(_)
            | Self::CatalogRootRotation(_)
            | Self::IngestPolicyActivation(_) => None,
        }
    }

    pub(crate) fn decode_fields(
        position: u64,
        transaction_id: [u8; 16],
        intent: &[u8],
    ) -> Result<Self, IdentityFailure> {
        if intent.starts_with(MAGIC.as_slice()) {
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
        Err(IdentityFailure)
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
        if cursor.take_array::<8>()? != MAGIC {
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
