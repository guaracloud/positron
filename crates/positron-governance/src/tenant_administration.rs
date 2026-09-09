use std::error::Error;
use std::fmt::{Display, Formatter};

use positron_domain::identity::{PrincipalId, Scope, TenantId, TenantSlug};
use positron_kernel::{
    AuditIntent, BootstrapKeyCustody, Catalog, CatalogFailureCode, CatalogObject, CatalogProposal,
    CatalogReadView, CatalogSnapshot, PreparedTransactionResolution, TransactionId,
};
use positron_policy::IngestPolicy;
use sha2::{Digest, Sha256};

use crate::{AdministrativeIdempotencyKey, AuthorizedContext, ResourceGeneration};

const TENANT_RECORD_MAGIC: [u8; 8] = *b"POSTNR01";
const TENANT_RECEIPT_MAGIC: [u8; 8] = *b"POSTRR01";
const TENANT_AUDIT_MAGIC: [u8; 8] = *b"POSTNA01";
const TENANT_REGISTRY_V1_MAGIC: [u8; 8] = *b"POSTRG01";
const TENANT_REGISTRY_V2_MAGIC: [u8; 8] = *b"POSTRG02";

struct TenantRegistry {
    generation: ResourceGeneration,
    tenants: Vec<TenantId>,
}

/// Public redacted outcome of a tenant creation publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TenantCreation {
    tenant: TenantId,
    generation: ResourceGeneration,
    audit_position: u64,
}

impl TenantCreation {
    #[must_use]
    pub const fn tenant_id(self) -> TenantId {
        self.tenant
    }
    #[must_use]
    pub const fn resource_generation(self) -> ResourceGeneration {
        self.generation
    }
    #[must_use]
    pub const fn audit_position(self) -> u64 {
        self.audit_position
    }
}

/// Bounded tenant creation input. Tenant credentials are intentionally absent:
/// a system administrator creates registry state but never receives data-plane
/// authority for the new tenant.
#[derive(Clone)]
pub struct TenantCreateRequest {
    actor: AuthorizedContext,
    tenant: TenantId,
    slug: TenantSlug,
    display_name: String,
    retention_seconds: u64,
    weight: u32,
    resources: [u64; 11],
    expected: ResourceGeneration,
    idempotency: AdministrativeIdempotencyKey,
}

impl TenantCreateRequest {
    #[must_use]
    pub fn new(
        actor: AuthorizedContext,
        tenant: TenantId,
        slug: TenantSlug,
        display_name: &str,
        retention_seconds: u64,
        weight: u32,
        resources: [u64; 11],
        expected: ResourceGeneration,
        idempotency: AdministrativeIdempotencyKey,
    ) -> Self {
        Self {
            actor,
            tenant,
            slug,
            display_name: display_name.to_owned(),
            retention_seconds,
            weight,
            resources,
            expected,
            idempotency,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TenantAdministrationFailure {
    Unauthorized,
    InvalidInput,
    DuplicateTenant,
    StaleGeneration,
    IdempotencyConflict,
    PersistenceUnavailable,
}
impl Display for TenantAdministrationFailure {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("tenant administration failed")
    }
}
impl Error for TenantAdministrationFailure {}

/// Administration owns validation and idempotency; Catalog alone publishes.
pub struct TenantAdministration;

impl TenantAdministration {
    /// Reconstructs only the bounded admission limits from authenticated
    /// tenant registry records during instance reopen. The caller keeps the
    /// resulting live registration in the governor authority.
    pub fn registered_tenant_quotas(
        snapshot: &CatalogSnapshot,
    ) -> Result<Vec<(TenantId, [u64; 11])>, TenantAdministrationFailure> {
        let mut quotas = Vec::new();
        for identity in snapshot.object_identities() {
            let bytes = snapshot
                .object(identity)
                .map_err(map_catalog)?
                .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
            if is_tenant_record(bytes) {
                let record = tenant_record(bytes)?;
                quotas.push((record.tenant, record.resources));
            }
        }
        Ok(quotas)
    }

    /// The initial Catalog publication establishes the independent tenant
    /// registry generation at one.  It is deliberately not coupled to any
    /// individual tenant's quota or policy generation.
    pub fn initial_registry(
        instance: positron_kernel::InstanceId,
        default_tenant: TenantId,
    ) -> Result<CatalogObject, TenantAdministrationFailure> {
        registry_object(
            instance,
            ResourceGeneration::new(1).map_err(|_| TenantAdministrationFailure::InvalidInput)?,
            &[default_tenant],
        )
    }

    /// Rewrites a V1 registry representation into the Epoch-2 immutable
    /// membership directory. Mutable default-tenant authority remains in the
    /// one authenticated governance object; this directory owns only tenant
    /// membership and never duplicates its mutable fields.
    pub fn epoch_two_registry(
        snapshot: &CatalogSnapshot,
    ) -> Result<CatalogObject, TenantAdministrationFailure> {
        let (_, governance) = snapshot.governance_object().map_err(map_catalog)?;
        let mut registry = registry(snapshot)?.unwrap_or(TenantRegistry {
            generation: ResourceGeneration::new(1)
                .map_err(|_| TenantAdministrationFailure::InvalidInput)?,
            tenants: Vec::new(),
        });
        if !registry.tenants.contains(&governance.tenant()) {
            registry.tenants.push(governance.tenant());
        }
        for identity in snapshot.object_identities() {
            let bytes = snapshot
                .object(identity)
                .map_err(map_catalog)?
                .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
            if is_tenant_record(bytes) {
                let record = tenant_record(bytes)?;
                if !registry.tenants.contains(&record.tenant) {
                    registry.tenants.push(record.tenant);
                }
            }
        }
        registry_object(
            positron_kernel::InstanceId::new(governance.instance()).map_err(map_catalog)?,
            registry.generation,
            &registry.tenants,
        )
    }

    /// Returns the authenticated immutable tenant membership directory. V1
    /// remains a singleton reader path; V2 requires the explicit directory.
    pub fn registered_tenant_ids(
        snapshot: &CatalogSnapshot,
    ) -> Result<Vec<TenantId>, TenantAdministrationFailure> {
        if snapshot.format_epoch() == Some(positron_kernel::FormatEpoch::CATALOG_V1) {
            let (_, governance) = snapshot.governance_object().map_err(map_catalog)?;
            return Ok(vec![governance.tenant()]);
        }
        let registry =
            registry(snapshot)?.ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
        if registry.tenants.is_empty() {
            return Err(TenantAdministrationFailure::PersistenceUnavailable);
        }
        let (_, governance) = snapshot.governance_object().map_err(map_catalog)?;
        let mut states = vec![governance.tenant()];
        for identity in snapshot.object_identities() {
            let bytes = snapshot
                .object(identity)
                .map_err(map_catalog)?
                .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
            if is_tenant_record(bytes) {
                let record = tenant_record(bytes)?;
                if states.contains(&record.tenant) {
                    return Err(TenantAdministrationFailure::PersistenceUnavailable);
                }
                states.push(record.tenant);
            }
        }
        if registry.tenants.len() != states.len()
            || registry
                .tenants
                .iter()
                .any(|tenant| !states.contains(tenant))
        {
            return Err(TenantAdministrationFailure::PersistenceUnavailable);
        }
        Ok(registry.tenants)
    }

    /// Resolves an exact committed retry from an authenticated read view before
    /// callers acquire a governor enrollment permit or the Catalog writer.
    pub fn replay_from_view(
        view: &CatalogReadView,
        administrator: PrincipalId,
        request: TenantCreateRequest,
    ) -> Result<Option<TenantCreation>, TenantAdministrationFailure> {
        validate_request(administrator, &request)?;
        let Some(replay) = replay_snapshot(view.snapshot(), &request)? else {
            return Ok(None);
        };
        let audit_position = view
            .governance_audit_records()
            .iter()
            .find(|record| {
                record.transaction().to_bytes() == request.idempotency.to_bytes()
                    && record.intent().starts_with(&TENANT_AUDIT_MAGIC)
            })
            .map(positron_kernel::GovernanceAuditRecord::position)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
        Ok(Some(TenantCreation {
            audit_position,
            ..replay
        }))
    }

    pub fn create(
        catalog: &Catalog<'_>,
        keys: &BootstrapKeyCustody,
        instance: positron_kernel::InstanceId,
        administrator: PrincipalId,
        request: TenantCreateRequest,
    ) -> Result<TenantCreation, TenantAdministrationFailure> {
        validate_request(administrator, &request)?;
        let snapshot = catalog.pin().map_err(map_catalog)?;
        if let Some(replay) = replay_snapshot(&snapshot, &request)? {
            return Ok(replay);
        }
        let digest = request_digest(&request);
        let transaction =
            TransactionId::new(request.idempotency.to_bytes()).map_err(map_catalog)?;
        match catalog
            .resume_prepared(transaction, digest)
            .map_err(map_catalog)?
        {
            PreparedTransactionResolution::Absent => {},
            PreparedTransactionResolution::Unavailable => {
                return Err(TenantAdministrationFailure::PersistenceUnavailable);
            },
            PreparedTransactionResolution::Resumed(commit) => {
                let replay = replay_snapshot(&catalog.pin().map_err(map_catalog)?, &request)?
                    .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
                let audit_position = commit
                    .governance_audit_record()
                    .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?
                    .position();
                return Ok(TenantCreation {
                    audit_position,
                    ..replay
                });
            },
        }
        let mut registry =
            registry(&snapshot)?.ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
        if registry.generation != request.expected {
            return Err(TenantAdministrationFailure::StaleGeneration);
        }
        let generation = ResourceGeneration::new(
            request
                .expected
                .get()
                .checked_add(1)
                .ok_or(TenantAdministrationFailure::InvalidInput)?,
        )
        .map_err(|_| TenantAdministrationFailure::InvalidInput)?;
        let mut objects = Vec::new();
        for identity in snapshot.object_identities() {
            let bytes = snapshot
                .object(identity)
                .map_err(map_catalog)?
                .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
            if is_registry(bytes) {
                continue;
            }
            if is_tenant_record(bytes) {
                let record = tenant_record(bytes)?;
                if record.tenant == request.tenant || record.slug == request.slug.as_str() {
                    return Err(TenantAdministrationFailure::DuplicateTenant);
                }
            }
            objects.push(CatalogObject::new(bytes.to_vec()).map_err(map_catalog)?);
        }
        registry.tenants.push(request.tenant);
        objects.push(registry_object(instance, generation, &registry.tenants)?);
        let envelope = keys
            .provision_tenant_key_envelope(
                instance,
                request.tenant,
                keys.random_identifier()
                    .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?,
                1,
            )
            .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
        objects.push(
            CatalogObject::new(encode_record(instance, &request, &envelope)?)
                .map_err(map_catalog)?,
        );
        let policy = IngestPolicy::preserving(1)
            .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?
            .activated_object(request.tenant)
            .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
        objects.push(CatalogObject::new(policy.into_bytes()).map_err(map_catalog)?);
        objects.push(
            CatalogObject::new(encode_receipt(&request, generation, digest))
                .map_err(map_catalog)?,
        );
        let commit = catalog
            .commit_prepared(
                snapshot.identity(),
                CatalogProposal::new(
                    TransactionId::new(request.idempotency.to_bytes()).map_err(map_catalog)?,
                    snapshot
                        .format_epoch()
                        .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?,
                    objects,
                )
                .map_err(map_catalog)?,
                AuditIntent::new(encode_audit(&request, generation, digest))
                    .map_err(map_catalog)?,
                digest,
            )
            .map_err(map_catalog)?;
        let audit_position = commit
            .governance_audit_record()
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?
            .position();
        Ok(TenantCreation {
            tenant: request.tenant,
            generation,
            audit_position,
        })
    }
}

pub(crate) fn is_registry(bytes: &[u8]) -> bool {
    bytes.starts_with(&TENANT_REGISTRY_V1_MAGIC) || bytes.starts_with(&TENANT_REGISTRY_V2_MAGIC)
}

fn registry(
    snapshot: &CatalogSnapshot,
) -> Result<Option<TenantRegistry>, TenantAdministrationFailure> {
    let mut found = None;
    for identity in snapshot.object_identities() {
        let bytes = snapshot
            .object(identity)
            .map_err(map_catalog)?
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
        if is_registry(bytes) {
            if found.is_some() {
                return Err(TenantAdministrationFailure::PersistenceUnavailable);
            }
            let generation = generation_at(bytes, 24)?;
            let tenants = if bytes.starts_with(&TENANT_REGISTRY_V1_MAGIC) {
                if bytes.len() != 32 {
                    return Err(TenantAdministrationFailure::PersistenceUnavailable);
                }
                Vec::new()
            } else {
                let count = usize::from(u16::from_be_bytes(
                    bytes
                        .get(32..34)
                        .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?
                        .try_into()
                        .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?,
                ));
                let expected = 34_usize
                    .checked_add(
                        count
                            .checked_mul(16)
                            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?,
                    )
                    .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
                if bytes.len() != expected || count == 0 {
                    return Err(TenantAdministrationFailure::PersistenceUnavailable);
                }
                let mut tenants = Vec::with_capacity(count);
                for index in 0..count {
                    let offset = 34_usize
                        .checked_add(
                            index
                                .checked_mul(16)
                                .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?,
                        )
                        .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
                    let tenant = TenantId::from_bytes(
                        bytes
                            .get(offset..offset + 16)
                            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?
                            .try_into()
                            .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?,
                    )
                    .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
                    if tenants.contains(&tenant) {
                        return Err(TenantAdministrationFailure::PersistenceUnavailable);
                    }
                    tenants.push(tenant);
                }
                tenants
            };
            found = Some(TenantRegistry {
                generation,
                tenants,
            });
        }
    }
    Ok(found)
}

fn registry_object(
    instance: positron_kernel::InstanceId,
    generation: ResourceGeneration,
    tenants: &[TenantId],
) -> Result<CatalogObject, TenantAdministrationFailure> {
    if tenants.is_empty() || tenants.len() > u16::MAX as usize {
        return Err(TenantAdministrationFailure::InvalidInput);
    }
    let mut encoded = Vec::with_capacity(34 + tenants.len() * 16);
    encoded.extend_from_slice(&TENANT_REGISTRY_V2_MAGIC);
    encoded.extend_from_slice(&instance.to_bytes());
    encoded.extend_from_slice(&generation.get().to_be_bytes());
    encoded.extend_from_slice(&(tenants.len() as u16).to_be_bytes());
    for tenant in tenants {
        encoded.extend_from_slice(&tenant.to_bytes());
    }
    CatalogObject::new(encoded).map_err(map_catalog)
}

fn is_tenant_record(bytes: &[u8]) -> bool {
    bytes.starts_with(&TENANT_RECORD_MAGIC)
}
struct TenantRecord<'a> {
    tenant: TenantId,
    slug: &'a str,
    resources: [u64; 11],
}
fn tenant_record(bytes: &[u8]) -> Result<TenantRecord<'_>, TenantAdministrationFailure> {
    let start = 24;
    let end = start + 16;
    let raw: [u8; 16] = bytes
        .get(start..end)
        .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?
        .try_into()
        .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
    let tenant = TenantId::from_bytes(raw)
        .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
    let slug_length = usize::from(
        *bytes
            .get(end)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?,
    );
    let slug = std::str::from_utf8(
        bytes
            .get(end + 1..end + 1 + slug_length)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?,
    )
    .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
    let display_start = end
        .checked_add(1)
        .and_then(|value| value.checked_add(slug_length))
        .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
    let display_length = usize::from(
        *bytes
            .get(display_start)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?,
    );
    let quota_start = display_start
        .checked_add(1)
        .and_then(|value| value.checked_add(display_length))
        .and_then(|value| value.checked_add(8 + 8 + 4))
        .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
    let mut resources = [0_u64; 11];
    for (index, resource) in resources.iter_mut().enumerate() {
        let offset = quota_start
            .checked_add(
                index
                    .checked_mul(8)
                    .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?,
            )
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
        *resource = u64::from_be_bytes(
            bytes
                .get(offset..offset + 8)
                .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?
                .try_into()
                .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?,
        );
    }
    if resources.contains(&0) {
        return Err(TenantAdministrationFailure::PersistenceUnavailable);
    }
    Ok(TenantRecord {
        tenant,
        slug,
        resources,
    })
}
fn encode_record(
    instance: positron_kernel::InstanceId,
    request: &TenantCreateRequest,
    envelope: &[u8],
) -> Result<Vec<u8>, TenantAdministrationFailure> {
    let slug = request.slug.as_str().as_bytes();
    let display = request.display_name.as_bytes();
    let envelope_len =
        u16::try_from(envelope.len()).map_err(|_| TenantAdministrationFailure::InvalidInput)?;
    let mut encoded = Vec::with_capacity(
        8 + 16 + 16 + 1 + slug.len() + 1 + display.len() + 8 + 4 + 88 + 1 + 2 + envelope.len(),
    );
    encoded.extend_from_slice(&TENANT_RECORD_MAGIC);
    encoded.extend_from_slice(&instance.to_bytes());
    encoded.extend_from_slice(&request.tenant.to_bytes());
    encoded.push(u8::try_from(slug.len()).map_err(|_| TenantAdministrationFailure::InvalidInput)?);
    encoded.extend_from_slice(slug);
    encoded
        .push(u8::try_from(display.len()).map_err(|_| TenantAdministrationFailure::InvalidInput)?);
    encoded.extend_from_slice(display);
    encoded.extend_from_slice(&request.retention_seconds.to_be_bytes());
    encoded.extend_from_slice(&1_u64.to_be_bytes());
    encoded.extend_from_slice(&request.weight.to_be_bytes());
    for value in request.resources {
        encoded.extend_from_slice(&value.to_be_bytes());
    }
    // Active lifecycle and initial policy generation are durable tenant state.
    encoded.push(1);
    encoded.extend_from_slice(&1_u64.to_be_bytes());
    encoded.extend_from_slice(&envelope_len.to_be_bytes());
    encoded.extend_from_slice(envelope);
    Ok(encoded)
}
fn validate_request(
    administrator: PrincipalId,
    request: &TenantCreateRequest,
) -> Result<(), TenantAdministrationFailure> {
    if request.actor.principal_id() != administrator
        || request.actor.scope() != Scope::SystemAdministration
        || request.actor.tenant_attribution().is_some()
    {
        return Err(TenantAdministrationFailure::Unauthorized);
    }
    if request.display_name.is_empty()
        || request.display_name.len() > 128
        || request.retention_seconds == 0
        || request.weight == 0
        || request.weight > u32::from(u16::MAX)
        || request.resources.contains(&0)
    {
        return Err(TenantAdministrationFailure::InvalidInput);
    }
    Ok(())
}
fn replay_snapshot(
    snapshot: &CatalogSnapshot,
    request: &TenantCreateRequest,
) -> Result<Option<TenantCreation>, TenantAdministrationFailure> {
    let Some(receipt) = receipt_for(snapshot, request.idempotency)? else {
        return Ok(None);
    };
    let generation = ResourceGeneration::new(
        request
            .expected
            .get()
            .checked_add(1)
            .ok_or(TenantAdministrationFailure::InvalidInput)?,
    )
    .map_err(|_| TenantAdministrationFailure::InvalidInput)?;
    if receipt.actor != request.actor.principal_id()
        || receipt.tenant != request.tenant
        || receipt.expected != request.expected
        || receipt.generation != generation
        || receipt.digest != request_digest(request)
    {
        return Err(TenantAdministrationFailure::IdempotencyConflict);
    }
    Ok(Some(TenantCreation {
        tenant: receipt.tenant,
        generation: receipt.generation,
        audit_position: receipt.audit_position,
    }))
}
struct Receipt {
    actor: PrincipalId,
    tenant: TenantId,
    expected: ResourceGeneration,
    generation: ResourceGeneration,
    digest: [u8; 32],
    audit_position: u64,
}
fn encode_receipt(
    request: &TenantCreateRequest,
    generation: ResourceGeneration,
    digest: [u8; 32],
) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(112);
    encoded.extend_from_slice(&TENANT_RECEIPT_MAGIC);
    encoded.extend_from_slice(&request.idempotency.to_bytes());
    encoded.extend_from_slice(&request.actor.principal_id().to_bytes());
    encoded.extend_from_slice(&request.tenant.to_bytes());
    encoded.extend_from_slice(&request.expected.get().to_be_bytes());
    encoded.extend_from_slice(&generation.get().to_be_bytes());
    encoded.extend_from_slice(&digest);
    encoded.extend_from_slice(&0_u64.to_be_bytes());
    encoded
}
fn receipt_for(
    snapshot: &CatalogSnapshot,
    key: AdministrativeIdempotencyKey,
) -> Result<Option<Receipt>, TenantAdministrationFailure> {
    for identity in snapshot.object_identities() {
        let bytes = snapshot
            .object(identity)
            .map_err(map_catalog)?
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
        if bytes.starts_with(&TENANT_RECEIPT_MAGIC)
            && bytes.len() == 112
            && bytes.get(8..24) == Some(key.to_bytes().as_slice())
        {
            let actor = principal_at(bytes, 24)?;
            let tenant = tenant_at(bytes, 40)?;
            let expected = generation_at(bytes, 56)?;
            let generation = generation_at(bytes, 64)?;
            let digest: [u8; 32] = bytes
                .get(72..104)
                .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?
                .try_into()
                .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
            let audit_position = u64::from_be_bytes(
                bytes
                    .get(104..112)
                    .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?
                    .try_into()
                    .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?,
            );
            return Ok(Some(Receipt {
                actor,
                tenant,
                expected,
                generation,
                digest,
                audit_position,
            }));
        }
    }
    Ok(None)
}
fn principal_at(bytes: &[u8], at: usize) -> Result<PrincipalId, TenantAdministrationFailure> {
    PrincipalId::from_bytes(
        bytes
            .get(at..at + 16)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?
            .try_into()
            .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?,
    )
    .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)
}
fn tenant_at(bytes: &[u8], at: usize) -> Result<TenantId, TenantAdministrationFailure> {
    TenantId::from_bytes(
        bytes
            .get(at..at + 16)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?
            .try_into()
            .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?,
    )
    .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)
}
fn generation_at(
    bytes: &[u8],
    at: usize,
) -> Result<ResourceGeneration, TenantAdministrationFailure> {
    ResourceGeneration::new(u64::from_be_bytes(
        bytes
            .get(at..at + 8)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?
            .try_into()
            .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?,
    ))
    .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)
}
fn request_digest(request: &TenantCreateRequest) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(request.actor.principal_id().to_bytes());
    hasher.update(request.tenant.to_bytes());
    hasher.update(request.slug.as_str().as_bytes());
    hasher.update(request.display_name.as_bytes());
    hasher.update(request.retention_seconds.to_be_bytes());
    hasher.update(request.weight.to_be_bytes());
    for resource in request.resources {
        hasher.update(resource.to_be_bytes());
    }
    hasher.update(request.expected.get().to_be_bytes());
    hasher.update(request.idempotency.to_bytes());
    hasher.finalize().into()
}
fn encode_audit(
    request: &TenantCreateRequest,
    generation: ResourceGeneration,
    digest: [u8; 32],
) -> Vec<u8> {
    let mut audit = Vec::with_capacity(96);
    audit.extend_from_slice(&TENANT_AUDIT_MAGIC);
    audit.extend_from_slice(&request.idempotency.to_bytes());
    audit.extend_from_slice(&request.actor.principal_id().to_bytes());
    audit.extend_from_slice(&request.tenant.to_bytes());
    audit.extend_from_slice(&request.expected.get().to_be_bytes());
    audit.extend_from_slice(&generation.get().to_be_bytes());
    audit.extend_from_slice(&digest);
    audit
}
fn map_catalog(failure: positron_kernel::CatalogFailure) -> TenantAdministrationFailure {
    match failure.code() {
        CatalogFailureCode::IdempotencyConflict => TenantAdministrationFailure::IdempotencyConflict,
        _ => TenantAdministrationFailure::PersistenceUnavailable,
    }
}
