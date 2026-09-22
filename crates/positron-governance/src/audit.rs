mod codec;
mod rotation;
mod schema_checkpoint;

use std::fmt::{Display, Formatter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use positron_domain::identity::{ExternalTenantAlias, PrincipalId, Scope, TenantId, TenantSlug};
use positron_domain::lifecycle::TenantLifecycleState;
use positron_kernel::GovernanceAuditRecord;
use sha2::{Digest, Sha256};

use crate::identity::IdentityFailure;
use crate::tenant_profile_administration::TENANT_DISPLAY_MAGIC;
use crate::{
    AdministrativeIdempotencyKey, DurableOperationKind, DurableOperationPhase,
    DurableOperationRequest, DurableOperationStatus, OperationId, ResourceGeneration,
};

pub use rotation::{CatalogRootRotationAuditEntry, CatalogRootRotationStage};

const MAGIC_V1: [u8; 8] = *b"POSAUD01";
const MAGIC_V2: [u8; 8] = *b"POSAUD02";
const ROOT_ROTATION_MAGIC: &[u8] = b"catalog-root-rotation-v1\0";
const POLICY_ACTIVATION_MAGIC: [u8; 8] = *b"POSPOL02";
const TENANT_QUOTA_MAGIC: [u8; 8] = *b"POSQUO01";
const KEY_LIFECYCLE_MAGIC: [u8; 8] = *b"POSKEY01";
const KEY_LIFECYCLE_V2_MAGIC: [u8; 8] = *b"POSKEY02";
const KEY_LIFECYCLE_V3_MAGIC: [u8; 8] = *b"POSKEY03";
const LISTENER_TRANSPORT_MAGIC: [u8; 8] = *b"POSTPT01";
const LISTENER_TRANSPORT_V2_MAGIC: [u8; 8] = *b"POSTPT02";
const LISTENER_TRANSPORT_REQUEST_DOMAIN: &[u8] = b"positron.listener-transport.request.v1\0";
const TENANT_LIFECYCLE_MAGIC: [u8; 8] = *b"POSTEN01";
const TENANT_LIFECYCLE_V2_MAGIC: [u8; 8] = *b"POSTEN02";
const TENANT_CREATION_MAGIC: [u8; 8] = *b"POSTNA01";
const FORMAT_MIGRATION_MAGIC: [u8; 8] = *b"POSFMT01";
const TENANT_ALIAS_MAGIC: [u8; 8] = *b"POSALI01";
const TENANT_RETENTION_MAGIC: [u8; 8] = *b"POSTRT01";
const SYSTEM_AUDIT_RETENTION_MAGIC: [u8; 8] = *b"POSAR001";
const DURABLE_OPERATION_AUDIT_MAGIC: [u8; 8] = *b"POSOPA02";
const DURABLE_OPERATION_AUDIT_MAGIC_V3: [u8; 8] = *b"POSOPA03";
const DURABLE_OPERATION_AUDIT_MAGIC_V4: [u8; 8] = *b"POSOPA04";
const DURABLE_OPERATION_AUDIT_MAGIC_V1: [u8; 8] = *b"POSOPA01";

/// Extracts a terminal receipt's idempotency key only after its owning codec
/// has recognized the supported receipt version and key location. Callers use
/// the key solely to locate a candidate; the Catalog object identity then
/// proves the complete typed terminal result.
pub(crate) fn terminal_receipt_key(
    bytes: &[u8],
    versions: &[([u8; 8], usize, usize)],
) -> Result<Option<[u8; 16]>, ()> {
    let Some((_, encoded_bytes, key_offset)) = versions
        .iter()
        .find(|(magic, _, _)| bytes.starts_with(magic))
    else {
        return Ok(None);
    };
    if bytes.len() != *encoded_bytes {
        return Err(());
    }
    let key: [u8; 16] = bytes
        .get(*key_offset..key_offset.saturating_add(16))
        .and_then(|value| value.try_into().ok())
        .ok_or(())?;
    if key.iter().all(|byte| *byte == 0) {
        return Err(());
    }
    Ok(Some(key))
}

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
    TenantQuotaUpdate(TenantQuotaUpdateAuditEntry),
    TenantDisplayNameUpdate(TenantDisplayNameUpdateAuditEntry),
    SchemaCheckpoint(SchemaCheckpointAuditEntry),
    ApiKeyLifecycle(ApiKeyLifecycleAuditEntry),
    ListenerTransport(ListenerTransportAuditEntry),
    TenantLifecycle(TenantLifecycleAuditEntry),
    TenantCreation(TenantCreationAuditEntry),
    CatalogFormatMigration(CatalogFormatMigrationAuditEntry),
    TenantAliasBinding(TenantAliasBindingAuditEntry),
    TenantRetentionUpdate(TenantRetentionUpdateAuditEntry),
    SystemAuditRetentionUpdate(SystemAuditRetentionUpdateAuditEntry),
    DurableOperation(DurableOperationAuditEntry),
}

/// Redacted jointly committed evidence for one durable-operation state transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableOperationAuditEntry {
    position: u64,
    operation_id: OperationId,
    actor: Option<PrincipalId>,
    applicable_tenant: Option<TenantId>,
    action: DurableOperationKind,
    outcome: DurableOperationStatus,
    phase: DurableOperationPhase,
    request_id: Option<AdministrativeIdempotencyKey>,
    cancellation_request_id: Option<AdministrativeIdempotencyKey>,
    accepted_generation: Option<u64>,
    progress_percent: Option<u8>,
    revision: u64,
}

impl DurableOperationAuditEntry {
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    #[must_use]
    pub const fn acting_principal(&self) -> Option<PrincipalId> {
        self.actor
    }

    #[must_use]
    pub const fn applicable_tenant(&self) -> Option<TenantId> {
        self.applicable_tenant
    }

    #[must_use]
    pub const fn action(&self) -> DurableOperationKind {
        self.action
    }

    #[must_use]
    pub const fn target(&self) -> OperationId {
        self.operation_id
    }

    #[must_use]
    pub const fn outcome(&self) -> DurableOperationStatus {
        self.outcome
    }

    #[must_use]
    pub const fn request_id(&self) -> Option<AdministrativeIdempotencyKey> {
        self.request_id
    }

    #[must_use]
    pub const fn cancellation_request_id(&self) -> Option<AdministrativeIdempotencyKey> {
        self.cancellation_request_id
    }

    #[must_use]
    pub const fn accepted_generation(&self) -> Option<u64> {
        self.accepted_generation
    }

    #[must_use]
    pub const fn progress_percent(&self) -> Option<u8> {
        self.progress_percent
    }
}

/// Redacted evidence for a system-controlled Governance Audit retention update.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemAuditRetentionUpdateAuditEntry {
    position: u64,
    ingest_time_unix_seconds: u64,
    actor: PrincipalId,
    expected_generation: ResourceGeneration,
    generation: ResourceGeneration,
    retained_record_limit: u64,
    request_digest: [u8; 32],
    idempotency_key: AdministrativeIdempotencyKey,
}

pub(crate) struct SystemAuditRetentionAuditIntent {
    pub(crate) ingest_time_unix_seconds: u64,
    pub(crate) idempotency_key: AdministrativeIdempotencyKey,
    pub(crate) actor: PrincipalId,
    pub(crate) expected_generation: ResourceGeneration,
    pub(crate) generation: ResourceGeneration,
    pub(crate) retained_record_limit: u64,
    pub(crate) request_digest: [u8; 32],
}

impl SystemAuditRetentionAuditIntent {
    pub(crate) fn encode(self) -> Vec<u8> {
        let mut intent = Vec::with_capacity(104);
        intent.extend_from_slice(&SYSTEM_AUDIT_RETENTION_MAGIC);
        intent.extend_from_slice(&self.ingest_time_unix_seconds.to_be_bytes());
        intent.extend_from_slice(&self.idempotency_key.to_bytes());
        intent.extend_from_slice(&self.actor.to_bytes());
        intent.extend_from_slice(&self.expected_generation.get().to_be_bytes());
        intent.extend_from_slice(&self.generation.get().to_be_bytes());
        intent.extend_from_slice(&self.retained_record_limit.to_be_bytes());
        intent.extend_from_slice(&self.request_digest);
        intent
    }
}

/// Redacted evidence for a retention successor. The duration and impact
/// evidence remain bound only by the request digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TenantRetentionUpdateAuditEntry {
    position: u64,
    ingest_time_unix_seconds: u64,
    actor: PrincipalId,
    tenant: TenantId,
    expected_generation: ResourceGeneration,
    generation: ResourceGeneration,
    request_digest: [u8; 32],
    idempotency_key: AdministrativeIdempotencyKey,
}

/// Redacted immutable-alias binding evidence. The alias text is intentionally
/// omitted; its canonical request digest is the idempotency binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TenantAliasBindingAuditEntry {
    position: u64,
    ingest_time_unix_seconds: u64,
    actor: PrincipalId,
    tenant: TenantId,
    expected_generation: ResourceGeneration,
    generation: ResourceGeneration,
    request_digest: [u8; 32],
    idempotency_key: AdministrativeIdempotencyKey,
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
    request_digest: Option<[u8; 32]>,
    tenant: Option<TenantId>,
}

/// Redacted evidence for one committed tenant registry entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TenantCreationAuditEntry {
    position: u64,
    idempotency_key: AdministrativeIdempotencyKey,
    actor: PrincipalId,
    tenant: TenantId,
    expected_generation: ResourceGeneration,
    generation: ResourceGeneration,
    request_digest: [u8; 32],
}

/// Redacted evidence for the one-way catalog representation publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogFormatMigrationAuditEntry {
    position: u64,
    idempotency_key: AdministrativeIdempotencyKey,
    actor: PrincipalId,
    from: u32,
    to: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApiKeyLifecycleAction {
    Create,
    Rotate,
    Revoke,
}

/// Redacted evidence for one durable tenant lifecycle transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TenantLifecycleAuditEntry {
    position: u64,
    ingest_time_unix_seconds: u64,
    actor: PrincipalId,
    tenant: TenantId,
    from: TenantLifecycleState,
    to: TenantLifecycleState,
    expected_generation: ResourceGeneration,
    generation: ResourceGeneration,
    idempotency_key: AdministrativeIdempotencyKey,
    request_digest: Option<[u8; 32]>,
}

/// Redacted evidence that the active API listener uses the explicit plaintext
/// transport opt-out.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListenerTransportAuditEntry {
    position: u64,
    instance: [u8; 16],
    listener_target: Option<SocketAddr>,
    configuration_provenance: Option<ListenerTransportConfigurationProvenance>,
    request_id: Option<[u8; 16]>,
    request_digest: Option<[u8; 32]>,
}

impl ListenerTransportAuditEntry {
    #[must_use]
    pub const fn new(position: u64, instance: [u8; 16]) -> Self {
        Self {
            position,
            instance,
            listener_target: None,
            configuration_provenance: None,
            request_id: None,
            request_digest: None,
        }
    }

    #[must_use]
    pub(crate) const fn bound(
        position: u64,
        instance: [u8; 16],
        listener_target: SocketAddr,
        configuration_provenance: ListenerTransportConfigurationProvenance,
        request_id: [u8; 16],
        request_digest: [u8; 32],
    ) -> Self {
        Self {
            position,
            instance,
            listener_target: Some(listener_target),
            configuration_provenance: Some(configuration_provenance),
            request_id: Some(request_id),
            request_digest: Some(request_digest),
        }
    }

    #[must_use]
    pub const fn position(&self) -> u64 {
        self.position
    }

    #[must_use]
    pub const fn instance_id(&self) -> [u8; 16] {
        self.instance
    }

    /// Returns the exact listener target for current bound records.
    /// Legacy records retain their original, unbound representation.
    #[must_use]
    pub const fn listener_target(&self) -> Option<SocketAddr> {
        self.listener_target
    }

    /// Returns the resolved Configuration Contract source for current bound
    /// records. Legacy records retain no fabricated source identity.
    #[must_use]
    pub const fn configuration_provenance(
        &self,
    ) -> Option<ListenerTransportConfigurationProvenance> {
        self.configuration_provenance
    }

    /// Returns the deterministic request identity for current bound records.
    #[must_use]
    pub const fn request_id(&self) -> Option<[u8; 16]> {
        self.request_id
    }

    /// Returns the canonical binding digest for current bound records.
    #[must_use]
    pub const fn request_digest(&self) -> Option<[u8; 32]> {
        self.request_digest
    }

    #[must_use]
    pub const fn is_configuration_file_intent(&self) -> bool {
        matches!(
            self.configuration_provenance,
            Some(ListenerTransportConfigurationProvenance::ConfigurationFile)
        )
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

/// The only accepted Configuration Contract source for the plaintext
/// startup-only opt-out.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ListenerTransportConfigurationProvenance {
    ConfigurationFile,
}

impl ListenerTransportConfigurationProvenance {
    const fn code(self) -> u8 {
        match self {
            Self::ConfigurationFile => 1,
        }
    }

    const fn from_code(code: u8) -> Result<Self, IdentityFailure> {
        match code {
            1 => Ok(Self::ConfigurationFile),
            _ => Err(IdentityFailure),
        }
    }
}

/// A closed startup-only intent from the Configuration Contract. It is not a
/// public administration request and accepts no caller-controlled identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ListenerTransportAuditRequest {
    listener_target: SocketAddr,
    configuration_provenance: ListenerTransportConfigurationProvenance,
}

impl ListenerTransportAuditRequest {
    #[must_use]
    pub const fn configuration_file(listener_target: SocketAddr) -> Self {
        Self {
            listener_target,
            configuration_provenance: ListenerTransportConfigurationProvenance::ConfigurationFile,
        }
    }

    #[must_use]
    pub const fn listener_target(self) -> SocketAddr {
        self.listener_target
    }

    #[must_use]
    pub const fn configuration_provenance(self) -> ListenerTransportConfigurationProvenance {
        self.configuration_provenance
    }

    #[must_use]
    pub fn digest_for(self, instance: [u8; 16]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(LISTENER_TRANSPORT_REQUEST_DOMAIN);
        hasher.update(instance);
        hasher.update([self.configuration_provenance.code()]);
        hasher.update(listener_target_bytes(self.listener_target));
        hasher.finalize().into()
    }

    #[must_use]
    pub fn transaction_id_for(self, instance: [u8; 16]) -> [u8; 16] {
        let digest = self.digest_for(instance);
        let mut request_id = [0_u8; 16];
        request_id.copy_from_slice(&digest[..16]);
        if request_id.iter().all(|byte| *byte == 0) {
            request_id[0] = 1;
        }
        request_id
    }
}

pub(crate) fn plaintext_api_transport_audit_intent_v2(
    instance: [u8; 16],
    request: ListenerTransportAuditRequest,
) -> Vec<u8> {
    let digest = request.digest_for(instance);
    let request_id = request.transaction_id_for(instance);
    let mut intent = Vec::with_capacity(76);
    intent.extend_from_slice(&LISTENER_TRANSPORT_V2_MAGIC);
    intent.extend_from_slice(&instance);
    intent.extend_from_slice(&listener_target_bytes(request.listener_target()));
    intent.push(request.configuration_provenance().code());
    intent.extend_from_slice(&request_id);
    intent.extend_from_slice(&digest);
    intent
}

fn listener_target_bytes(target: SocketAddr) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(19);
    match target.ip() {
        IpAddr::V4(address) => {
            encoded.push(4);
            encoded.extend_from_slice(&address.octets());
        },
        IpAddr::V6(address) => {
            encoded.push(6);
            encoded.extend_from_slice(&address.octets());
        },
    }
    encoded.extend_from_slice(&target.port().to_be_bytes());
    encoded
}

fn decode_listener_target(cursor: &mut Cursor<'_>) -> Result<SocketAddr, IdentityFailure> {
    let address = match cursor.take_u8()? {
        4 => IpAddr::V4(Ipv4Addr::from(cursor.take_array::<4>()?)),
        6 => IpAddr::V6(Ipv6Addr::from(cursor.take_array::<16>()?)),
        _ => return Err(IdentityFailure),
    };
    Ok(SocketAddr::new(
        address,
        u16::from_be_bytes(cursor.take_array()?),
    ))
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

/// Redacted evidence for one durably published tenant quota successor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TenantQuotaUpdateAuditEntry {
    position: u64,
    idempotency_key: AdministrativeIdempotencyKey,
    principal: PrincipalId,
    tenant: TenantId,
    expected_generation: ResourceGeneration,
    generation: ResourceGeneration,
    weight: u32,
    resources: [u64; 11],
    request_digest: [u8; 32],
}

/// Redacted evidence for one display-name successor. The label itself is
/// bound only through the request digest and is never copied into audit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TenantDisplayNameUpdateAuditEntry {
    position: u64,
    idempotency_key: AdministrativeIdempotencyKey,
    principal: PrincipalId,
    tenant: TenantId,
    expected_generation: ResourceGeneration,
    generation: ResourceGeneration,
    request_digest: [u8; 32],
}

impl TenantDisplayNameUpdateAuditEntry {
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
    pub const fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }
}

impl TenantCreationAuditEntry {
    #[must_use]
    pub const fn position(&self) -> u64 {
        self.position
    }
    #[must_use]
    pub const fn idempotency_key(&self) -> AdministrativeIdempotencyKey {
        self.idempotency_key
    }
    #[must_use]
    pub const fn actor_id(&self) -> PrincipalId {
        self.actor
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
    pub const fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }
}

impl CatalogFormatMigrationAuditEntry {
    #[must_use]
    pub const fn position(&self) -> u64 {
        self.position
    }
    #[must_use]
    pub const fn idempotency_key(&self) -> AdministrativeIdempotencyKey {
        self.idempotency_key
    }
    #[must_use]
    pub const fn actor_id(&self) -> PrincipalId {
        self.actor
    }
    #[must_use]
    pub const fn from(&self) -> u32 {
        self.from
    }
    #[must_use]
    pub const fn to(&self) -> u32 {
        self.to
    }
}

impl TenantAliasBindingAuditEntry {
    #[must_use]
    pub const fn position(&self) -> u64 {
        self.position
    }
    #[must_use]
    pub const fn ingest_time_unix_seconds(&self) -> u64 {
        self.ingest_time_unix_seconds
    }
    #[must_use]
    pub const fn actor_id(&self) -> PrincipalId {
        self.actor
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
    pub const fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }
    #[must_use]
    pub const fn idempotency_key(&self) -> AdministrativeIdempotencyKey {
        self.idempotency_key
    }
}

impl TenantQuotaUpdateAuditEntry {
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
    pub const fn weight(&self) -> u32 {
        self.weight
    }
    #[must_use]
    pub const fn resources(&self) -> [u64; 11] {
        self.resources
    }
    #[must_use]
    pub const fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }
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
            Self::TenantQuotaUpdate(entry) => entry.position,
            Self::TenantDisplayNameUpdate(entry) => entry.position,
            Self::SchemaCheckpoint(entry) => entry.position(),
            Self::ApiKeyLifecycle(entry) => entry.position,
            Self::ListenerTransport(entry) => entry.position,
            Self::TenantLifecycle(entry) => entry.position,
            Self::TenantCreation(entry) => entry.position,
            Self::CatalogFormatMigration(entry) => entry.position,
            Self::TenantAliasBinding(entry) => entry.position,
            Self::TenantRetentionUpdate(entry) => entry.position,
            Self::SystemAuditRetentionUpdate(entry) => entry.position,
            Self::DurableOperation(entry) => entry.position,
        }
    }

    /// Returns the explicit tenant scope carried by this redacted record.
    /// System-wide and legacy records without a tenant field never become
    /// visible through a tenant-scoped inspection.
    #[must_use]
    pub const fn tenant_id(&self) -> Option<TenantId> {
        match self {
            Self::Initialization(entry) => entry.tenant_id(),
            Self::CatalogRootRotation(_) => None,
            Self::IngestPolicyActivation(entry) => Some(entry.tenant),
            Self::TenantQuotaUpdate(entry) => Some(entry.tenant),
            Self::TenantDisplayNameUpdate(entry) => Some(entry.tenant),
            Self::SchemaCheckpoint(entry) => Some(entry.tenant_id()),
            Self::ApiKeyLifecycle(entry) => entry.tenant_id(),
            Self::ListenerTransport(_) => None,
            Self::TenantLifecycle(entry) => Some(entry.tenant),
            Self::TenantCreation(entry) => Some(entry.tenant),
            Self::CatalogFormatMigration(_) => None,
            Self::TenantAliasBinding(entry) => Some(entry.tenant),
            Self::TenantRetentionUpdate(entry) => Some(entry.tenant),
            Self::SystemAuditRetentionUpdate(_) => None,
            Self::DurableOperation(_) => None,
        }
    }

    #[must_use]
    pub fn action(&self) -> &str {
        match self {
            Self::Initialization(entry) => entry.action(),
            Self::CatalogRootRotation(entry) => entry.action(),
            Self::IngestPolicyActivation(_) => "ingest-policy.activate",
            Self::TenantQuotaUpdate(_) => "tenant-quota.update",
            Self::TenantDisplayNameUpdate(_) => "tenant.display-name.update",
            Self::SchemaCheckpoint(_) => "schema-checkpoint.replace",
            Self::ApiKeyLifecycle(entry) => match entry.action {
                ApiKeyLifecycleAction::Create => "api-key.create",
                ApiKeyLifecycleAction::Rotate => "api-key.rotate",
                ApiKeyLifecycleAction::Revoke => "api-key.revoke",
            },
            Self::ListenerTransport(entry) => entry.action(),
            Self::TenantLifecycle(_) => "tenant.lifecycle.transition",
            Self::TenantCreation(_) => "tenant.create",
            Self::CatalogFormatMigration(_) => "catalog.format.migrate",
            Self::TenantAliasBinding(_) => "tenant.alias.bind",
            Self::TenantRetentionUpdate(_) => "tenant.retention.update",
            Self::SystemAuditRetentionUpdate(_) => "system.audit-retention.update",
            Self::DurableOperation(_) => "durable-operation.transition",
        }
    }

    #[must_use]
    pub fn outcome(&self) -> &str {
        match self {
            Self::Initialization(entry) => entry.outcome(),
            Self::CatalogRootRotation(entry) => entry.outcome(),
            Self::IngestPolicyActivation(_) => "succeeded",
            Self::TenantQuotaUpdate(_) => "succeeded",
            Self::TenantDisplayNameUpdate(_) => "succeeded",
            Self::SchemaCheckpoint(_) => "succeeded",
            Self::ApiKeyLifecycle(_) => "succeeded",
            Self::ListenerTransport(entry) => entry.outcome(),
            Self::TenantLifecycle(_) => "succeeded",
            Self::TenantCreation(_) => "succeeded",
            Self::CatalogFormatMigration(_) => "succeeded",
            Self::TenantAliasBinding(_) => "succeeded",
            Self::TenantRetentionUpdate(_) => "succeeded",
            Self::SystemAuditRetentionUpdate(_) => "succeeded",
            Self::DurableOperation(entry) => match entry.outcome {
                DurableOperationStatus::Failed => "failed",
                DurableOperationStatus::Cancelled => "cancelled",
                _ => "succeeded",
            },
        }
    }

    #[must_use]
    pub const fn as_initialization(&self) -> Option<&InitializationAuditEntry> {
        match self {
            Self::Initialization(entry) => Some(entry),
            Self::CatalogRootRotation(_)
            | Self::IngestPolicyActivation(_)
            | Self::TenantQuotaUpdate(_)
            | Self::TenantDisplayNameUpdate(_)
            | Self::SchemaCheckpoint(_)
            | Self::ApiKeyLifecycle(_)
            | Self::ListenerTransport(_)
            | Self::TenantLifecycle(_)
            | Self::TenantCreation(_)
            | Self::CatalogFormatMigration(_)
            | Self::TenantAliasBinding(_)
            | Self::TenantRetentionUpdate(_)
            | Self::SystemAuditRetentionUpdate(_)
            | Self::DurableOperation(_) => None,
        }
    }

    #[must_use]
    pub const fn as_catalog_root_rotation(&self) -> Option<&CatalogRootRotationAuditEntry> {
        match self {
            Self::CatalogRootRotation(entry) => Some(entry),
            Self::Initialization(_)
            | Self::IngestPolicyActivation(_)
            | Self::TenantQuotaUpdate(_)
            | Self::TenantDisplayNameUpdate(_)
            | Self::SchemaCheckpoint(_)
            | Self::ApiKeyLifecycle(_)
            | Self::ListenerTransport(_)
            | Self::TenantLifecycle(_)
            | Self::TenantCreation(_)
            | Self::CatalogFormatMigration(_)
            | Self::TenantAliasBinding(_)
            | Self::TenantRetentionUpdate(_)
            | Self::SystemAuditRetentionUpdate(_)
            | Self::DurableOperation(_) => None,
        }
    }

    #[must_use]
    pub const fn as_schema_checkpoint(&self) -> Option<&SchemaCheckpointAuditEntry> {
        match self {
            Self::SchemaCheckpoint(entry) => Some(entry),
            Self::Initialization(_)
            | Self::CatalogRootRotation(_)
            | Self::IngestPolicyActivation(_)
            | Self::TenantQuotaUpdate(_)
            | Self::TenantDisplayNameUpdate(_)
            | Self::ApiKeyLifecycle(_)
            | Self::ListenerTransport(_)
            | Self::TenantLifecycle(_)
            | Self::TenantCreation(_)
            | Self::CatalogFormatMigration(_)
            | Self::TenantAliasBinding(_)
            | Self::TenantRetentionUpdate(_)
            | Self::SystemAuditRetentionUpdate(_)
            | Self::DurableOperation(_) => None,
        }
    }

    #[must_use]
    pub const fn as_api_key_lifecycle(&self) -> Option<&ApiKeyLifecycleAuditEntry> {
        match self {
            Self::ApiKeyLifecycle(entry) => Some(entry),
            Self::Initialization(_)
            | Self::CatalogRootRotation(_)
            | Self::IngestPolicyActivation(_)
            | Self::TenantQuotaUpdate(_)
            | Self::TenantDisplayNameUpdate(_)
            | Self::SchemaCheckpoint(_)
            | Self::ListenerTransport(_)
            | Self::TenantLifecycle(_)
            | Self::TenantCreation(_)
            | Self::CatalogFormatMigration(_)
            | Self::TenantAliasBinding(_)
            | Self::TenantRetentionUpdate(_)
            | Self::SystemAuditRetentionUpdate(_)
            | Self::DurableOperation(_) => None,
        }
    }

    #[must_use]
    pub const fn as_listener_transport(&self) -> Option<&ListenerTransportAuditEntry> {
        match self {
            Self::ListenerTransport(entry) => Some(entry),
            Self::Initialization(_)
            | Self::CatalogRootRotation(_)
            | Self::IngestPolicyActivation(_)
            | Self::TenantQuotaUpdate(_)
            | Self::TenantDisplayNameUpdate(_)
            | Self::SchemaCheckpoint(_)
            | Self::ApiKeyLifecycle(_)
            | Self::TenantLifecycle(_)
            | Self::TenantCreation(_)
            | Self::CatalogFormatMigration(_)
            | Self::TenantAliasBinding(_)
            | Self::TenantRetentionUpdate(_)
            | Self::SystemAuditRetentionUpdate(_)
            | Self::DurableOperation(_) => None,
        }
    }

    #[must_use]
    pub const fn as_tenant_lifecycle(&self) -> Option<&TenantLifecycleAuditEntry> {
        match self {
            Self::TenantLifecycle(entry) => Some(entry),
            Self::Initialization(_)
            | Self::CatalogRootRotation(_)
            | Self::IngestPolicyActivation(_)
            | Self::TenantQuotaUpdate(_)
            | Self::TenantDisplayNameUpdate(_)
            | Self::SchemaCheckpoint(_)
            | Self::ApiKeyLifecycle(_)
            | Self::ListenerTransport(_)
            | Self::TenantCreation(_)
            | Self::CatalogFormatMigration(_)
            | Self::TenantAliasBinding(_)
            | Self::TenantRetentionUpdate(_)
            | Self::SystemAuditRetentionUpdate(_)
            | Self::DurableOperation(_) => None,
        }
    }

    #[must_use]
    pub const fn as_tenant_quota_update(&self) -> Option<&TenantQuotaUpdateAuditEntry> {
        match self {
            Self::TenantQuotaUpdate(entry) => Some(entry),
            Self::Initialization(_)
            | Self::CatalogRootRotation(_)
            | Self::IngestPolicyActivation(_)
            | Self::TenantDisplayNameUpdate(_)
            | Self::SchemaCheckpoint(_)
            | Self::ApiKeyLifecycle(_)
            | Self::ListenerTransport(_)
            | Self::TenantLifecycle(_)
            | Self::TenantCreation(_)
            | Self::CatalogFormatMigration(_)
            | Self::TenantAliasBinding(_)
            | Self::TenantRetentionUpdate(_)
            | Self::SystemAuditRetentionUpdate(_)
            | Self::DurableOperation(_) => None,
        }
    }

    #[must_use]
    pub const fn as_tenant_display_name_update(
        &self,
    ) -> Option<&TenantDisplayNameUpdateAuditEntry> {
        match self {
            Self::TenantDisplayNameUpdate(entry) => Some(entry),
            Self::Initialization(_)
            | Self::CatalogRootRotation(_)
            | Self::IngestPolicyActivation(_)
            | Self::TenantQuotaUpdate(_)
            | Self::SchemaCheckpoint(_)
            | Self::ApiKeyLifecycle(_)
            | Self::ListenerTransport(_)
            | Self::TenantLifecycle(_)
            | Self::TenantCreation(_)
            | Self::CatalogFormatMigration(_)
            | Self::TenantAliasBinding(_)
            | Self::TenantRetentionUpdate(_)
            | Self::SystemAuditRetentionUpdate(_)
            | Self::DurableOperation(_) => None,
        }
    }

    #[must_use]
    pub const fn as_tenant_retention_update(&self) -> Option<&TenantRetentionUpdateAuditEntry> {
        match self {
            Self::TenantRetentionUpdate(entry) => Some(entry),
            Self::Initialization(_)
            | Self::CatalogRootRotation(_)
            | Self::IngestPolicyActivation(_)
            | Self::TenantQuotaUpdate(_)
            | Self::TenantDisplayNameUpdate(_)
            | Self::SchemaCheckpoint(_)
            | Self::ApiKeyLifecycle(_)
            | Self::ListenerTransport(_)
            | Self::TenantLifecycle(_)
            | Self::TenantCreation(_)
            | Self::CatalogFormatMigration(_)
            | Self::TenantAliasBinding(_) => None,
            Self::SystemAuditRetentionUpdate(_) | Self::DurableOperation(_) => None,
        }
    }

    #[must_use]
    pub const fn as_system_audit_retention_update(
        &self,
    ) -> Option<&SystemAuditRetentionUpdateAuditEntry> {
        match self {
            Self::SystemAuditRetentionUpdate(entry) => Some(entry),
            _ => None,
        }
    }
}

impl SystemAuditRetentionUpdateAuditEntry {
    #[must_use]
    pub const fn position(&self) -> u64 {
        self.position
    }
    #[must_use]
    pub const fn actor_id(&self) -> PrincipalId {
        self.actor
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
    pub const fn retained_record_limit(&self) -> u64 {
        self.retained_record_limit
    }
    #[must_use]
    pub const fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }
    #[must_use]
    pub const fn idempotency_key(&self) -> AdministrativeIdempotencyKey {
        self.idempotency_key
    }
}

impl TenantRetentionUpdateAuditEntry {
    #[must_use]
    pub const fn position(&self) -> u64 {
        self.position
    }
    #[must_use]
    pub const fn ingest_time_unix_seconds(&self) -> u64 {
        self.ingest_time_unix_seconds
    }
    #[must_use]
    pub const fn actor_id(&self) -> PrincipalId {
        self.actor
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
    pub const fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }
    #[must_use]
    pub const fn idempotency_key(&self) -> AdministrativeIdempotencyKey {
        self.idempotency_key
    }
}

impl TenantLifecycleAuditEntry {
    #[must_use]
    pub const fn position(&self) -> u64 {
        self.position
    }
    #[must_use]
    pub const fn ingest_time_unix_seconds(&self) -> u64 {
        self.ingest_time_unix_seconds
    }
    #[must_use]
    pub const fn actor_id(&self) -> PrincipalId {
        self.actor
    }
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant
    }
    #[must_use]
    pub const fn from(&self) -> TenantLifecycleState {
        self.from
    }
    #[must_use]
    pub const fn to(&self) -> TenantLifecycleState {
        self.to
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

    /// Returns the canonical request binding for current durable records.
    /// Legacy v1 records intentionally decode without rewriting their bytes.
    #[must_use]
    pub const fn request_digest(&self) -> Option<[u8; 32]> {
        self.request_digest
    }
}

pub(crate) struct TenantLifecycleAuditIntent {
    pub(crate) ingest_time_unix_seconds: u64,
    pub(crate) idempotency_key: AdministrativeIdempotencyKey,
    pub(crate) actor: PrincipalId,
    pub(crate) tenant: TenantId,
    pub(crate) from: TenantLifecycleState,
    pub(crate) to: TenantLifecycleState,
    pub(crate) expected_generation: ResourceGeneration,
    pub(crate) generation: ResourceGeneration,
    pub(crate) request_digest: [u8; 32],
}

impl TenantLifecycleAuditIntent {
    pub(crate) fn encode(self) -> Vec<u8> {
        let mut intent = Vec::with_capacity(114);
        intent.extend_from_slice(&TENANT_LIFECYCLE_V2_MAGIC);
        intent.extend_from_slice(&self.ingest_time_unix_seconds.to_be_bytes());
        intent.extend_from_slice(&self.idempotency_key.to_bytes());
        intent.extend_from_slice(&self.actor.to_bytes());
        intent.extend_from_slice(&self.tenant.to_bytes());
        intent.push(lifecycle_state_code(self.from));
        intent.push(lifecycle_state_code(self.to));
        intent.extend_from_slice(&self.expected_generation.get().to_be_bytes());
        intent.extend_from_slice(&self.generation.get().to_be_bytes());
        intent.extend_from_slice(&self.request_digest);
        intent
    }
}

const fn lifecycle_state_code(state: TenantLifecycleState) -> u8 {
    match state {
        TenantLifecycleState::Active => 1,
        TenantLifecycleState::ReadOnly => 2,
        TenantLifecycleState::Suspended => 3,
        TenantLifecycleState::Purging => 4,
        TenantLifecycleState::Purged => 5,
    }
}

const fn lifecycle_state(code: u8) -> Result<TenantLifecycleState, IdentityFailure> {
    match code {
        1 => Ok(TenantLifecycleState::Active),
        2 => Ok(TenantLifecycleState::ReadOnly),
        3 => Ok(TenantLifecycleState::Suspended),
        4 => Ok(TenantLifecycleState::Purging),
        5 => Ok(TenantLifecycleState::Purged),
        _ => Err(IdentityFailure),
    }
}

impl ApiKeyLifecycleAuditEntry {
    #[must_use]
    pub const fn position(&self) -> u64 {
        self.position
    }

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

    /// Returns the canonical request binding for current durable records.
    /// Legacy v1 records intentionally decode without rewriting their bytes.
    #[must_use]
    pub const fn request_digest(&self) -> Option<[u8; 32]> {
        self.request_digest
    }

    /// The tenant explicitly bound into current API-key lifecycle evidence.
    /// Legacy records omit this binding and remain system-only readable.
    #[must_use]
    pub const fn tenant_id(&self) -> Option<TenantId> {
        self.tenant
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
