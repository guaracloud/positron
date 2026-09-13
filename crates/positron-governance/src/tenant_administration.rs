use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{Display, Formatter};

use positron_domain::identity::{PrincipalId, Scope, TenantId, TenantSlug};
use positron_domain::lifecycle::TenantLifecycleState;
use positron_kernel::{
    AuditIntent, BootstrapKeyCustody, Catalog, CatalogFailureCode, CatalogObject, CatalogProposal,
    CatalogReadView, CatalogSnapshot, PreparedTransactionResolution, TransactionId,
};
use positron_policy::IngestPolicy;
use sha2::{Digest, Sha256};

use crate::tenant_quota_record::{
    TENANT_RECORD_V3_MAGIC, is_tenant_record, tenant_record_metadata,
};
use crate::{AdministrativeIdempotencyKey, AuthorizedContext, ResourceGeneration};

const TENANT_RECEIPT_MAGIC: [u8; 8] = *b"POSTRR01";
const TENANT_AUDIT_MAGIC: [u8; 8] = *b"POSTNA01";
const TENANT_REGISTRY_V1_MAGIC: [u8; 8] = *b"POSTRG01";
const TENANT_REGISTRY_V2_MAGIC: [u8; 8] = *b"POSTRG02";

struct TenantRegistry {
    generation: ResourceGeneration,
    tenants: Vec<TenantId>,
}

/// Opaque position in one immutable tenant-registry generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TenantListContinuation {
    catalog_identity: [u8; 32],
    catalog_generation: u64,
    next_index: u16,
}

impl TenantListContinuation {
    #[must_use]
    pub fn to_bytes(self) -> [u8; 42] {
        let mut bytes = [0; 42];
        bytes[..32].copy_from_slice(&self.catalog_identity);
        bytes[32..40].copy_from_slice(&self.catalog_generation.to_be_bytes());
        bytes[40..].copy_from_slice(&self.next_index.to_be_bytes());
        bytes
    }

    pub fn from_bytes(bytes: [u8; 42]) -> Result<Self, TenantAdministrationFailure> {
        let catalog_generation = u64::from_be_bytes(
            bytes[32..40]
                .try_into()
                .map_err(|_| TenantAdministrationFailure::InvalidInput)?,
        );
        let next_index = u16::from_be_bytes(
            bytes[40..]
                .try_into()
                .map_err(|_| TenantAdministrationFailure::InvalidInput)?,
        );
        if catalog_generation == 0 || next_index == 0 {
            return Err(TenantAdministrationFailure::InvalidInput);
        }
        Ok(Self {
            catalog_identity: bytes[..32]
                .try_into()
                .map_err(|_| TenantAdministrationFailure::InvalidInput)?,
            catalog_generation,
            next_index,
        })
    }
}

/// One bounded page of authenticated tenant-registry descriptors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TenantInspectionPage {
    inspections: Vec<TenantInspection>,
    continuation: Option<TenantListContinuation>,
}

impl TenantInspectionPage {
    #[must_use]
    pub fn inspections(&self) -> &[TenantInspection] {
        &self.inspections
    }

    #[must_use]
    pub const fn continuation(&self) -> Option<TenantListContinuation> {
        self.continuation
    }
}

/// Public redacted outcome of a tenant creation publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TenantCreation {
    tenant: TenantId,
    generation: ResourceGeneration,
    audit_position: u64,
}

/// One redacted, authenticated tenant-administration view. It contains no
/// credential material or opaque key-envelope bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TenantInspection {
    tenant: TenantId,
    slug: TenantSlug,
    display_name: String,
    retention_seconds: u64,
    display_generation: ResourceGeneration,
    retention_generation: ResourceGeneration,
    lifecycle: TenantLifecycleState,
}

impl TenantInspection {
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant
    }

    #[must_use]
    pub fn slug(&self) -> &str {
        self.slug.as_str()
    }

    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    #[must_use]
    pub const fn retention_seconds(&self) -> u64 {
        self.retention_seconds
    }

    #[must_use]
    pub const fn display_generation(&self) -> ResourceGeneration {
        self.display_generation
    }

    #[must_use]
    pub const fn retention_generation(&self) -> ResourceGeneration {
        self.retention_generation
    }

    #[must_use]
    pub const fn lifecycle(&self) -> TenantLifecycleState {
        self.lifecycle
    }
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
    idempotency: AdministrativeIdempotencyKey,
}

/// Bounded durable attributes for a newly created tenant.
#[derive(Clone)]
pub struct TenantCreateConfiguration {
    slug: TenantSlug,
    display_name: String,
    retention_seconds: u64,
    weight: u32,
    resources: [u64; 11],
}

impl TenantCreateConfiguration {
    #[must_use]
    pub fn new(
        slug: TenantSlug,
        display_name: &str,
        retention_seconds: u64,
        weight: u32,
        resources: [u64; 11],
    ) -> Self {
        Self {
            slug,
            display_name: display_name.to_owned(),
            retention_seconds,
            weight,
            resources,
        }
    }

    #[must_use]
    pub const fn resources(&self) -> [u64; 11] {
        self.resources
    }

    #[must_use]
    pub const fn weight(&self) -> u32 {
        self.weight
    }
}

impl TenantCreateRequest {
    #[must_use]
    pub fn new(
        actor: AuthorizedContext,
        tenant: TenantId,
        configuration: TenantCreateConfiguration,
        idempotency: AdministrativeIdempotencyKey,
    ) -> Self {
        Self {
            actor,
            tenant,
            slug: configuration.slug,
            display_name: configuration.display_name,
            retention_seconds: configuration.retention_seconds,
            weight: configuration.weight,
            resources: configuration.resources,
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
    /// Lists redacted tenant state from one authenticated Catalog snapshot.
    /// The runtime authorizes enumeration before calling this pure decoder.
    pub fn list(
        snapshot: &CatalogSnapshot,
    ) -> Result<Vec<TenantInspection>, TenantAdministrationFailure> {
        Ok(tenant_inspections(snapshot)?.1)
    }

    /// Enumerates one fixed-size page from an immutable Catalog snapshot.
    /// A continuation from a different snapshot is explicit rather than
    /// risking a skipped, duplicated, or mixed descriptor page.
    pub fn list_page(
        snapshot: &CatalogSnapshot,
        continuation: Option<TenantListContinuation>,
        limit: usize,
    ) -> Result<TenantInspectionPage, TenantAdministrationFailure> {
        if limit == 0 || limit > 128 {
            return Err(TenantAdministrationFailure::InvalidInput);
        }
        let (_, inspections) = tenant_inspections(snapshot)?;
        let start = match continuation {
            None => 0,
            Some(continuation) => {
                if continuation.catalog_identity != snapshot.identity().to_bytes()
                    || continuation.catalog_generation != snapshot.number()
                {
                    return Err(TenantAdministrationFailure::StaleGeneration);
                }
                usize::from(continuation.next_index)
            },
        };
        if start > inspections.len() {
            return Err(TenantAdministrationFailure::InvalidInput);
        }
        let end = start
            .checked_add(limit)
            .map(|end| end.min(inspections.len()))
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
        let mut page = Vec::new();
        page.try_reserve(end - start)
            .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
        page.extend_from_slice(
            inspections
                .get(start..end)
                .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?,
        );
        let continuation = if end < inspections.len() {
            Some(TenantListContinuation {
                catalog_identity: snapshot.identity().to_bytes(),
                catalog_generation: snapshot.number(),
                next_index: u16::try_from(end)
                    .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?,
            })
        } else {
            None
        };
        Ok(TenantInspectionPage {
            inspections: page,
            continuation,
        })
    }

    /// Resolves one registered tenant from one authenticated Catalog snapshot.
    pub fn inspect(
        snapshot: &CatalogSnapshot,
        tenant: TenantId,
    ) -> Result<TenantInspection, TenantAdministrationFailure> {
        tenant_inspections(snapshot)?
            .1
            .into_iter()
            .find(|inspection| inspection.tenant == tenant)
            .ok_or(TenantAdministrationFailure::Unauthorized)
    }

    /// Reconstructs only the bounded admission limits from authenticated
    /// tenant registry records during instance reopen. The caller keeps the
    /// resulting live registration in the governor authority.
    pub fn registered_tenant_quotas(
        snapshot: &CatalogSnapshot,
    ) -> Result<Vec<(TenantId, u32, [u64; 11])>, TenantAdministrationFailure> {
        let mut quotas = Vec::new();
        for identity in snapshot.object_identities() {
            let bytes = snapshot
                .object(identity)
                .map_err(map_catalog)?
                .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
            if is_tenant_record(bytes) {
                let record = tenant_record_metadata(bytes)?;
                quotas.push((record.tenant, record.weight, record.resources));
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
                let record = tenant_record_metadata(bytes)?;
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
        Ok(tenant_inspections(snapshot)?
            .1
            .into_iter()
            .map(|inspection| inspection.tenant)
            .collect())
    }

    /// Reconstructs each registered tenant's durable lifecycle. The default
    /// lifecycle lives in POSGOV; every secondary lifecycle lives in its
    /// canonical POSTNR record.
    pub(crate) fn registered_tenant_lifecycles(
        snapshot: &CatalogSnapshot,
    ) -> Result<Vec<(TenantId, TenantLifecycleState)>, TenantAdministrationFailure> {
        let registered = Self::registered_tenant_ids(snapshot)?;
        let (_, governance) = snapshot.governance_object().map_err(map_catalog)?;
        let mut lifecycles = vec![(governance.tenant(), governance.lifecycle())];
        for identity in snapshot.object_identities() {
            let bytes = snapshot
                .object(identity)
                .map_err(map_catalog)?
                .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
            if !is_tenant_record(bytes) {
                continue;
            }
            let record = tenant_record_metadata(bytes)?;
            if record.tenant == governance.tenant()
                || !registered.contains(&record.tenant)
                || lifecycles
                    .iter()
                    .any(|(tenant, _)| *tenant == record.tenant)
            {
                return Err(TenantAdministrationFailure::PersistenceUnavailable);
            }
            lifecycles.push((record.tenant, record.lifecycle));
        }
        if lifecycles.len() != registered.len() {
            return Err(TenantAdministrationFailure::PersistenceUnavailable);
        }
        Ok(lifecycles)
    }

    /// Reconstructs only the non-default tenant envelopes whose immutable
    /// membership and durable tenant records agree in this Catalog generation.
    pub fn registered_tenant_key_envelopes(
        snapshot: &CatalogSnapshot,
    ) -> Result<Vec<(TenantId, Vec<u8>)>, TenantAdministrationFailure> {
        let tenants = Self::registered_tenant_ids(snapshot)?;
        let (_, governance) = snapshot.governance_object().map_err(map_catalog)?;
        let mut envelopes = Vec::new();
        for identity in snapshot.object_identities() {
            let bytes = snapshot
                .object(identity)
                .map_err(map_catalog)?
                .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
            if !is_tenant_record(bytes) {
                continue;
            }
            let record = tenant_record_metadata(bytes)?;
            if record.tenant == governance.tenant()
                || !tenants.contains(&record.tenant)
                || envelopes.iter().any(|(tenant, _)| *tenant == record.tenant)
            {
                return Err(TenantAdministrationFailure::PersistenceUnavailable);
            }
            envelopes.push((record.tenant, record.envelope));
        }
        if envelopes.len().checked_add(1) != Some(tenants.len()) {
            return Err(TenantAdministrationFailure::PersistenceUnavailable);
        }
        Ok(envelopes)
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
        let mut registry =
            registry(&snapshot)?.ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
        let digest = request_digest(&request);
        let transaction =
            TransactionId::new(request.idempotency.to_bytes()).map_err(map_catalog)?;
        let prepared = match catalog.resume_prepared(transaction, digest) {
            Ok(prepared) => prepared,
            Err(failure) if failure.code() == CatalogFailureCode::IdempotencyConflict => catalog
                .resume_prepared(
                    transaction,
                    legacy_request_digest(&request, registry.generation),
                )
                .map_err(map_catalog)?,
            Err(failure) => return Err(map_catalog(failure)),
        };
        match prepared {
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
        let generation = ResourceGeneration::new(
            registry
                .generation
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
                let record = tenant_record_metadata(bytes)?;
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
            CatalogObject::new(encode_receipt(
                &request,
                registry.generation,
                generation,
                digest,
            ))
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
                AuditIntent::new(encode_audit(
                    &request,
                    registry.generation,
                    generation,
                    digest,
                ))
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

fn tenant_inspections(
    snapshot: &CatalogSnapshot,
) -> Result<(TenantRegistry, Vec<TenantInspection>), TenantAdministrationFailure> {
    let (_, governance) = snapshot.governance_object().map_err(map_catalog)?;
    let default = TenantInspection {
        tenant: governance.tenant(),
        slug: governance.tenant_slug(),
        display_name: governance.display_name().to_owned(),
        retention_seconds: governance.retention_seconds(),
        display_generation: ResourceGeneration::new(governance.display_generation())
            .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?,
        retention_generation: ResourceGeneration::new(governance.retention_generation())
            .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?,
        lifecycle: governance.lifecycle(),
    };
    if snapshot.format_epoch() == Some(positron_kernel::FormatEpoch::CATALOG_V1) {
        return Ok((
            TenantRegistry {
                generation: ResourceGeneration::new(1)
                    .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?,
                tenants: vec![default.tenant],
            },
            vec![default],
        ));
    }

    let mut registry = None;
    let mut records = BTreeMap::new();
    for identity in snapshot.object_identities() {
        let bytes = snapshot
            .object(identity)
            .map_err(map_catalog)?
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
        if is_registry(bytes) {
            if registry.is_some() {
                return Err(TenantAdministrationFailure::PersistenceUnavailable);
            }
            registry = Some(decode_registry(bytes)?);
        } else if is_tenant_record(bytes) {
            let record = tenant_record_metadata(bytes)?;
            if record.tenant == default.tenant || records.insert(record.tenant, record).is_some() {
                return Err(TenantAdministrationFailure::PersistenceUnavailable);
            }
        }
    }
    let registry = registry.ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
    let registered = registry.tenants.iter().copied().collect::<BTreeSet<_>>();
    if registered.len() != registry.tenants.len()
        || !registered.contains(&default.tenant)
        || records.len().checked_add(1) != Some(registered.len())
        || records.keys().any(|tenant| !registered.contains(tenant))
    {
        return Err(TenantAdministrationFailure::PersistenceUnavailable);
    }
    let mut inspections = Vec::new();
    inspections
        .try_reserve(registry.tenants.len())
        .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
    for tenant in &registry.tenants {
        if *tenant == default.tenant {
            inspections.push(default.clone());
            continue;
        }
        let record = records
            .remove(tenant)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
        inspections.push(TenantInspection {
            tenant: record.tenant,
            slug: TenantSlug::parse_canonical(&record.slug)
                .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?,
            display_name: record.display_name,
            retention_seconds: record.retention_seconds,
            display_generation: record.display_generation,
            retention_generation: record.retention_generation,
            lifecycle: record.lifecycle,
        });
    }
    if !records.is_empty() {
        return Err(TenantAdministrationFailure::PersistenceUnavailable);
    }
    Ok((registry, inspections))
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
            found = Some(decode_registry(bytes)?);
        }
    }
    Ok(found)
}

fn decode_registry(bytes: &[u8]) -> Result<TenantRegistry, TenantAdministrationFailure> {
    let generation = generation_at(bytes, 24)?;
    if bytes.starts_with(&TENANT_REGISTRY_V1_MAGIC) {
        if bytes.len() != 32 {
            return Err(TenantAdministrationFailure::PersistenceUnavailable);
        }
        return Ok(TenantRegistry {
            generation,
            tenants: Vec::new(),
        });
    }
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
    let mut tenants = Vec::new();
    tenants
        .try_reserve(count)
        .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
    let mut unique = BTreeSet::new();
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
        if !unique.insert(tenant) {
            return Err(TenantAdministrationFailure::PersistenceUnavailable);
        }
        tenants.push(tenant);
    }
    Ok(TenantRegistry {
        generation,
        tenants,
    })
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
        8 + 16
            + 16
            + 1
            + slug.len()
            + 1
            + display.len()
            + 8
            + 4
            + 88
            + 1
            + 8
            + 8
            + 8
            + 2
            + envelope.len(),
    );
    encoded.extend_from_slice(&TENANT_RECORD_V3_MAGIC);
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
    // Active lifecycle, policy generation, and independent lifecycle, display,
    // and retention generations are durable tenant state.
    encoded.push(1);
    encoded.extend_from_slice(&1_u64.to_be_bytes());
    encoded.extend_from_slice(&1_u64.to_be_bytes());
    encoded.extend_from_slice(&1_u64.to_be_bytes());
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
    replay_receipt(
        &receipt,
        request.actor.principal_id(),
        request.tenant,
        request_digest(request),
        legacy_request_digest(request, receipt.expected),
    )?;
    Ok(Some(TenantCreation {
        tenant: receipt.tenant,
        generation: receipt.generation,
        audit_position: receipt.audit_position,
    }))
}

fn replay_receipt(
    receipt: &Receipt,
    actor: PrincipalId,
    tenant: TenantId,
    canonical_digest: [u8; 32],
    legacy_digest: [u8; 32],
) -> Result<(), TenantAdministrationFailure> {
    if receipt.expected.get().checked_add(1) != Some(receipt.generation.get()) {
        return Err(TenantAdministrationFailure::PersistenceUnavailable);
    }
    if receipt.actor != actor
        || receipt.tenant != tenant
        || (receipt.digest != canonical_digest && receipt.digest != legacy_digest)
    {
        return Err(TenantAdministrationFailure::IdempotencyConflict);
    }
    Ok(())
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
    prior_generation: ResourceGeneration,
    generation: ResourceGeneration,
    digest: [u8; 32],
) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(112);
    encoded.extend_from_slice(&TENANT_RECEIPT_MAGIC);
    encoded.extend_from_slice(&request.idempotency.to_bytes());
    encoded.extend_from_slice(&request.actor.principal_id().to_bytes());
    encoded.extend_from_slice(&request.tenant.to_bytes());
    encoded.extend_from_slice(&prior_generation.get().to_be_bytes());
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
        if let Some(receipt) = decode_receipt(bytes, key)? {
            return Ok(Some(receipt));
        }
    }
    Ok(None)
}

fn decode_receipt(
    bytes: &[u8],
    key: AdministrativeIdempotencyKey,
) -> Result<Option<Receipt>, TenantAdministrationFailure> {
    if !bytes.starts_with(&TENANT_RECEIPT_MAGIC) {
        return Ok(None);
    }
    if bytes.len() != 112 {
        return Err(TenantAdministrationFailure::PersistenceUnavailable);
    }
    if bytes.get(8..24) != Some(key.to_bytes().as_slice()) {
        return Ok(None);
    }
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
    Ok(Some(Receipt {
        actor,
        tenant,
        expected,
        generation,
        digest,
        audit_position,
    }))
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
    hasher.update(request.idempotency.to_bytes());
    hasher.finalize().into()
}

/// Verifies receipts and prepared transactions created by the retired
/// creation precondition without making that precondition part of the current
/// request contract.
fn legacy_request_digest(request: &TenantCreateRequest, expected: ResourceGeneration) -> [u8; 32] {
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
    hasher.update(expected.get().to_be_bytes());
    hasher.update(request.idempotency.to_bytes());
    hasher.finalize().into()
}
fn encode_audit(
    request: &TenantCreateRequest,
    prior_generation: ResourceGeneration,
    generation: ResourceGeneration,
    digest: [u8; 32],
) -> Vec<u8> {
    let mut audit = Vec::with_capacity(96);
    audit.extend_from_slice(&TENANT_AUDIT_MAGIC);
    audit.extend_from_slice(&request.idempotency.to_bytes());
    audit.extend_from_slice(&request.actor.principal_id().to_bytes());
    audit.extend_from_slice(&request.tenant.to_bytes());
    audit.extend_from_slice(&prior_generation.get().to_be_bytes());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_v1_creation_receipt_replays_without_the_retired_precondition() {
        let actor = PrincipalId::from_bytes([0x41; 16]).expect("principal");
        let tenant = TenantId::from_bytes([0x42; 16]).expect("tenant");
        let key = AdministrativeIdempotencyKey::new([0x43; 16]).expect("idempotency");
        let expected = ResourceGeneration::new(7).expect("prior generation");
        let generation = ResourceGeneration::new(8).expect("successor generation");
        let legacy = digest(
            actor,
            tenant,
            "legacy",
            "Legacy tenant",
            key,
            Some(expected),
        );
        let canonical = digest(actor, tenant, "legacy", "Legacy tenant", key, None);

        let mut encoded = Vec::new();
        encoded.extend_from_slice(&TENANT_RECEIPT_MAGIC);
        encoded.extend_from_slice(&key.to_bytes());
        encoded.extend_from_slice(&actor.to_bytes());
        encoded.extend_from_slice(&tenant.to_bytes());
        encoded.extend_from_slice(&expected.get().to_be_bytes());
        encoded.extend_from_slice(&generation.get().to_be_bytes());
        encoded.extend_from_slice(&legacy);
        encoded.extend_from_slice(&17_u64.to_be_bytes());

        let receipt = decode_receipt(&encoded, key)
            .expect("historical receipt decodes")
            .expect("matching receipt");
        assert_eq!(receipt.generation, generation);
        assert_eq!(receipt.audit_position, 17);
        assert!(replay_receipt(&receipt, actor, tenant, canonical, legacy).is_ok());

        let changed_legacy = digest(
            actor,
            tenant,
            "legacy",
            "Changed tenant",
            key,
            Some(expected),
        );
        assert_eq!(
            replay_receipt(&receipt, actor, tenant, canonical, changed_legacy),
            Err(TenantAdministrationFailure::IdempotencyConflict)
        );
    }

    #[test]
    fn receipt_lookup_skips_a_well_formed_record_for_a_different_idempotency_key() {
        let recorded = AdministrativeIdempotencyKey::new([0x43; 16]).expect("recorded key");
        let sought = AdministrativeIdempotencyKey::new([0x44; 16]).expect("sought key");
        let actor = PrincipalId::from_bytes([0x41; 16]).expect("principal");
        let tenant = TenantId::from_bytes([0x42; 16]).expect("tenant");
        let expected = ResourceGeneration::new(7).expect("prior generation");
        let generation = ResourceGeneration::new(8).expect("successor generation");
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&TENANT_RECEIPT_MAGIC);
        encoded.extend_from_slice(&recorded.to_bytes());
        encoded.extend_from_slice(&actor.to_bytes());
        encoded.extend_from_slice(&tenant.to_bytes());
        encoded.extend_from_slice(&expected.get().to_be_bytes());
        encoded.extend_from_slice(&generation.get().to_be_bytes());
        encoded.extend_from_slice(&[0x45; 32]);
        encoded.extend_from_slice(&17_u64.to_be_bytes());

        assert!(
            decode_receipt(&encoded, sought)
                .expect("well-formed unrelated receipt is ignored")
                .is_none()
        );
    }

    fn digest(
        actor: PrincipalId,
        tenant: TenantId,
        slug: &str,
        display_name: &str,
        key: AdministrativeIdempotencyKey,
        expected: Option<ResourceGeneration>,
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(actor.to_bytes());
        hasher.update(tenant.to_bytes());
        hasher.update(slug.as_bytes());
        hasher.update(display_name.as_bytes());
        hasher.update(2_592_000_u64.to_be_bytes());
        hasher.update(1_u32.to_be_bytes());
        for resource in [1_u64; 11] {
            hasher.update(resource.to_be_bytes());
        }
        if let Some(expected) = expected {
            hasher.update(expected.get().to_be_bytes());
        }
        hasher.update(key.to_bytes());
        hasher.finalize().into()
    }
}
