use positron_domain::{
    identity::{ExternalTenantAlias, TenantId},
    lifecycle::TenantLifecycleState,
};
use positron_kernel::{CatalogObject, CatalogSnapshot};

use crate::{ResourceGeneration, TenantAdministration, TenantAdministrationFailure};

const TENANT_RECORD_V1_MAGIC: [u8; 8] = *b"POSTNR01";
pub(crate) const TENANT_RECORD_V2_MAGIC: [u8; 8] = *b"POSTNR02";
pub(crate) const TENANT_RECORD_V3_MAGIC: [u8; 8] = *b"POSTNR03";
pub(crate) const TENANT_RECORD_V4_MAGIC: [u8; 8] = *b"POSTNR04";
const RESOURCE_COUNT: usize = 11;
const RESOURCE_BYTES: usize = RESOURCE_COUNT * std::mem::size_of::<u64>();

/// The mutable quota fields carried by one durable secondary-tenant record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TenantQuotaState {
    pub(crate) generation: ResourceGeneration,
    pub(crate) weight: u32,
    pub(crate) resources: [u64; 11],
}

/// The lifecycle fields of a canonical secondary-tenant record. Lifecycle
/// generation is deliberately independent from quota and policy generations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TenantLifecycleRecord {
    pub(crate) generation: ResourceGeneration,
    pub(crate) state: TenantLifecycleState,
}

/// The display and retention resources carried by one tenant's canonical
/// authority. They deliberately retain separate optimistic generations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TenantProfileState {
    pub(crate) display_name: String,
    pub(crate) display_generation: ResourceGeneration,
    pub(crate) retention_seconds: u64,
    pub(crate) retention_generation: ResourceGeneration,
}

/// The immutable external compatibility alias and its one-time bind generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TenantAliasRecord {
    pub(crate) generation: ResourceGeneration,
    pub(crate) alias: Option<ExternalTenantAlias>,
}

/// The immutable fields that other governance workflows read from a canonical
/// secondary-tenant record.
pub(crate) struct TenantRecordMetadata {
    pub(crate) tenant: TenantId,
    pub(crate) slug: String,
    pub(crate) display_name: String,
    pub(crate) display_generation: ResourceGeneration,
    pub(crate) retention_seconds: u64,
    pub(crate) retention_generation: ResourceGeneration,
    pub(crate) resources: [u64; 11],
    pub(crate) weight: u32,
    pub(crate) lifecycle: TenantLifecycleState,
    pub(crate) envelope: Vec<u8>,
}

struct RecordLayout {
    tenant: TenantId,
    slug: String,
    display_name: String,
    envelope: Vec<u8>,
    quota_start: usize,
    display_length_at: usize,
    display_end: usize,
    retention_at: usize,
    state: TenantQuotaState,
    lifecycle: TenantLifecycleState,
    lifecycle_generation: ResourceGeneration,
    display_generation: ResourceGeneration,
    retention_seconds: u64,
    retention_generation: ResourceGeneration,
    alias_generation: ResourceGeneration,
    external_alias: Option<ExternalTenantAlias>,
    lifecycle_at: usize,
    lifecycle_generation_at: Option<usize>,
    display_generation_at: Option<usize>,
    retention_generation_at: Option<usize>,
    alias_at: usize,
    policy_at: usize,
}

pub(crate) fn tenant_record_metadata(
    bytes: &[u8],
) -> Result<TenantRecordMetadata, TenantAdministrationFailure> {
    let record = record_layout(bytes)?;
    Ok(TenantRecordMetadata {
        tenant: record.tenant,
        slug: record.slug,
        display_name: record.display_name,
        display_generation: record.display_generation,
        retention_seconds: record.retention_seconds,
        retention_generation: record.retention_generation,
        resources: record.state.resources,
        weight: record.state.weight,
        lifecycle: record.lifecycle,
        envelope: record.envelope,
    })
}

/// Reads the one canonical secondary-tenant quota record when it exists.
///
/// The default tenant is held by the governance object and therefore returns
/// `None`. A present record must also belong to the authenticated membership
/// directory before its mutable quota fields are exposed.
pub(crate) fn tenant_quota_state(
    snapshot: &CatalogSnapshot,
    tenant: TenantId,
) -> Result<Option<TenantQuotaState>, TenantAdministrationFailure> {
    let mut state = None;
    for identity in snapshot.object_identities() {
        let bytes = snapshot
            .object(identity)
            .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
        if !is_tenant_record(bytes) {
            continue;
        }
        let record = record_layout(bytes)?;
        if record.tenant == tenant && state.replace(record.state).is_some() {
            return Err(TenantAdministrationFailure::PersistenceUnavailable);
        }
    }
    if state.is_some() && !tenant_is_registered(snapshot, tenant)? {
        return Err(TenantAdministrationFailure::Unauthorized);
    }
    Ok(state)
}

/// Replaces exactly one canonical secondary-tenant record's mutable quota
/// fields while preserving all other catalog objects and record bytes.
pub(crate) fn replace_tenant_quota_record(
    snapshot: &CatalogSnapshot,
    tenant: TenantId,
    successor: TenantQuotaState,
) -> Result<Vec<CatalogObject>, TenantAdministrationFailure> {
    if !tenant_is_registered(snapshot, tenant)? {
        return Err(TenantAdministrationFailure::Unauthorized);
    }
    let mut objects = Vec::new();
    let mut replaced = false;
    for identity in snapshot.object_identities() {
        let bytes = snapshot
            .object(identity)
            .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
        let replacement = if is_tenant_record(bytes) {
            let record = record_layout(bytes)?;
            if record.tenant == tenant {
                if replaced {
                    return Err(TenantAdministrationFailure::PersistenceUnavailable);
                }
                replaced = true;
                rewrite_quota(bytes, record, successor)?
            } else {
                bytes.to_vec()
            }
        } else {
            bytes.to_vec()
        };
        objects
            .try_reserve(1)
            .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
        objects.push(
            CatalogObject::new(replacement)
                .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?,
        );
    }
    if !replaced {
        return Err(TenantAdministrationFailure::Unauthorized);
    }
    Ok(objects)
}

/// Reads the canonical lifecycle state and generation of one registered
/// secondary tenant. A POSTNR01 record has the documented initial lifecycle
/// generation of one until its first lifecycle successor upgrades it.
pub(crate) fn tenant_lifecycle_record(
    snapshot: &CatalogSnapshot,
    tenant: TenantId,
) -> Result<Option<TenantLifecycleRecord>, TenantAdministrationFailure> {
    let mut lifecycle = None;
    for identity in snapshot.object_identities() {
        let bytes = snapshot
            .object(identity)
            .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
        if !is_tenant_record(bytes) {
            continue;
        }
        let record = record_layout(bytes)?;
        if record.tenant == tenant
            && lifecycle
                .replace(TenantLifecycleRecord {
                    generation: record.lifecycle_generation,
                    state: record.lifecycle,
                })
                .is_some()
        {
            return Err(TenantAdministrationFailure::PersistenceUnavailable);
        }
    }
    if lifecycle.is_some() && !tenant_is_registered(snapshot, tenant)? {
        return Err(TenantAdministrationFailure::Unauthorized);
    }
    Ok(lifecycle)
}

/// Replaces one secondary lifecycle record, preserving every quota, policy,
/// identity, and opaque key-envelope byte. POSTNR01 is upgraded only here.
pub(crate) fn replace_tenant_lifecycle_record(
    snapshot: &CatalogSnapshot,
    tenant: TenantId,
    successor: TenantLifecycleRecord,
) -> Result<Vec<CatalogObject>, TenantAdministrationFailure> {
    if !tenant_is_registered(snapshot, tenant)? {
        return Err(TenantAdministrationFailure::Unauthorized);
    }
    let mut objects = Vec::new();
    let mut replaced = false;
    for identity in snapshot.object_identities() {
        let bytes = snapshot
            .object(identity)
            .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
        let replacement = if is_tenant_record(bytes) {
            let record = record_layout(bytes)?;
            if record.tenant == tenant {
                if replaced {
                    return Err(TenantAdministrationFailure::PersistenceUnavailable);
                }
                replaced = true;
                rewrite_lifecycle(bytes, record, successor)?
            } else {
                bytes.to_vec()
            }
        } else {
            bytes.to_vec()
        };
        objects
            .try_reserve(1)
            .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
        objects.push(
            CatalogObject::new(replacement)
                .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?,
        );
    }
    if !replaced {
        return Err(TenantAdministrationFailure::Unauthorized);
    }
    Ok(objects)
}

pub(crate) fn tenant_profile_state(
    snapshot: &CatalogSnapshot,
    tenant: TenantId,
) -> Result<Option<TenantProfileState>, TenantAdministrationFailure> {
    let mut profile = None;
    for identity in snapshot.object_identities() {
        let bytes = snapshot
            .object(identity)
            .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
        if !is_tenant_record(bytes) {
            continue;
        }
        let record = record_layout(bytes)?;
        if record.tenant == tenant
            && profile
                .replace(TenantProfileState {
                    display_name: record.display_name,
                    display_generation: record.display_generation,
                    retention_seconds: record.retention_seconds,
                    retention_generation: record.retention_generation,
                })
                .is_some()
        {
            return Err(TenantAdministrationFailure::PersistenceUnavailable);
        }
    }
    if profile.is_some() && !tenant_is_registered(snapshot, tenant)? {
        return Err(TenantAdministrationFailure::Unauthorized);
    }
    Ok(profile)
}

pub(crate) fn replace_tenant_profile_record(
    snapshot: &CatalogSnapshot,
    tenant: TenantId,
    successor: &TenantProfileState,
) -> Result<Vec<CatalogObject>, TenantAdministrationFailure> {
    if !tenant_is_registered(snapshot, tenant)? {
        return Err(TenantAdministrationFailure::Unauthorized);
    }
    let mut objects = Vec::new();
    let mut replaced = false;
    for identity in snapshot.object_identities() {
        let bytes = snapshot
            .object(identity)
            .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
        let replacement = if is_tenant_record(bytes) {
            let record = record_layout(bytes)?;
            if record.tenant == tenant {
                if replaced {
                    return Err(TenantAdministrationFailure::PersistenceUnavailable);
                }
                replaced = true;
                rewrite_profile(bytes, record, successor)?
            } else {
                bytes.to_vec()
            }
        } else {
            bytes.to_vec()
        };
        objects
            .try_reserve(1)
            .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
        objects.push(
            CatalogObject::new(replacement)
                .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?,
        );
    }
    if !replaced {
        return Err(TenantAdministrationFailure::Unauthorized);
    }
    Ok(objects)
}

pub(crate) fn tenant_alias_record(
    snapshot: &CatalogSnapshot,
    tenant: TenantId,
) -> Result<Option<TenantAliasRecord>, TenantAdministrationFailure> {
    let mut alias = None;
    for identity in snapshot.object_identities() {
        let bytes = snapshot
            .object(identity)
            .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
        if !is_tenant_record(bytes) {
            continue;
        }
        let record = record_layout(bytes)?;
        if record.tenant == tenant
            && alias
                .replace(TenantAliasRecord {
                    generation: record.alias_generation,
                    alias: record.external_alias,
                })
                .is_some()
        {
            return Err(TenantAdministrationFailure::PersistenceUnavailable);
        }
    }
    if alias.is_some() && !tenant_is_registered(snapshot, tenant)? {
        return Err(TenantAdministrationFailure::Unauthorized);
    }
    Ok(alias)
}

/// Binds the one immutable secondary-tenant external alias. Legacy records
/// upgrade to POSTNR04 only at this first binding and retain every other byte.
pub(crate) fn replace_tenant_alias_record(
    snapshot: &CatalogSnapshot,
    tenant: TenantId,
    successor: TenantAliasRecord,
) -> Result<Vec<CatalogObject>, TenantAdministrationFailure> {
    if !tenant_is_registered(snapshot, tenant)? {
        return Err(TenantAdministrationFailure::Unauthorized);
    }
    let mut objects = Vec::new();
    let mut replaced = false;
    for identity in snapshot.object_identities() {
        let bytes = snapshot
            .object(identity)
            .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
        let replacement = if is_tenant_record(bytes) {
            let record = record_layout(bytes)?;
            if record.tenant == tenant {
                if replaced {
                    return Err(TenantAdministrationFailure::PersistenceUnavailable);
                }
                replaced = true;
                rewrite_alias(bytes, record, successor.clone())?
            } else {
                bytes.to_vec()
            }
        } else {
            bytes.to_vec()
        };
        objects
            .try_reserve(1)
            .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
        objects.push(
            CatalogObject::new(replacement)
                .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?,
        );
    }
    if !replaced {
        return Err(TenantAdministrationFailure::Unauthorized);
    }
    Ok(objects)
}

fn tenant_is_registered(
    snapshot: &CatalogSnapshot,
    tenant: TenantId,
) -> Result<bool, TenantAdministrationFailure> {
    Ok(TenantAdministration::registered_tenant_ids(snapshot)?.contains(&tenant))
}

pub(crate) fn is_tenant_record(bytes: &[u8]) -> bool {
    bytes.starts_with(&TENANT_RECORD_V1_MAGIC)
        || bytes.starts_with(&TENANT_RECORD_V2_MAGIC)
        || bytes.starts_with(&TENANT_RECORD_V3_MAGIC)
        || bytes.starts_with(&TENANT_RECORD_V4_MAGIC)
}

fn record_layout(bytes: &[u8]) -> Result<RecordLayout, TenantAdministrationFailure> {
    let version_four = bytes.starts_with(&TENANT_RECORD_V4_MAGIC);
    let version_three = bytes.starts_with(&TENANT_RECORD_V3_MAGIC) || version_four;
    let version_two = bytes.starts_with(&TENANT_RECORD_V2_MAGIC) || version_three;
    if !is_tenant_record(bytes) {
        return Err(TenantAdministrationFailure::PersistenceUnavailable);
    }
    let tenant = TenantId::from_bytes(array_at(bytes, 24)?)
        .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
    let slug_start = 40;
    let slug_length = usize::from(byte_at(bytes, slug_start)?);
    let slug_end = slug_start
        .checked_add(1)
        .and_then(|start| start.checked_add(slug_length))
        .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
    let slug = std::str::from_utf8(
        bytes
            .get(slug_start + 1..slug_end)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?,
    )
    .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
    if slug.is_empty() {
        return Err(TenantAdministrationFailure::PersistenceUnavailable);
    }
    let display_length = usize::from(byte_at(bytes, slug_end)?);
    let display_end = slug_end
        .checked_add(1)
        .and_then(|start| start.checked_add(display_length))
        .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
    let display = std::str::from_utf8(
        bytes
            .get(slug_end + 1..display_end)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?,
    )
    .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
    if display.is_empty() {
        return Err(TenantAdministrationFailure::PersistenceUnavailable);
    }
    let retention_at = display_end;
    let retention_seconds = u64_at(bytes, retention_at)?;
    if retention_seconds == 0 {
        return Err(TenantAdministrationFailure::PersistenceUnavailable);
    }
    let generation_at = retention_at
        .checked_add(8)
        .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
    let generation = ResourceGeneration::new(u64_at(bytes, generation_at)?)
        .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
    let weight_at = generation_at
        .checked_add(8)
        .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
    let weight = u32_at(bytes, weight_at)?;
    if weight == 0 || weight > u32::from(u16::MAX) {
        return Err(TenantAdministrationFailure::PersistenceUnavailable);
    }
    let resources_at = weight_at
        .checked_add(4)
        .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
    let resources_end = resources_at
        .checked_add(RESOURCE_BYTES)
        .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
    let mut resources = [0_u64; RESOURCE_COUNT];
    for (index, resource) in resources.iter_mut().enumerate() {
        let offset = resources_at
            .checked_add(
                index
                    .checked_mul(8)
                    .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?,
            )
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
        *resource = u64_at(bytes, offset)?;
    }
    if resources.contains(&0) {
        return Err(TenantAdministrationFailure::PersistenceUnavailable);
    }
    let lifecycle_at = resources_end;
    let lifecycle = lifecycle_state(byte_at(bytes, lifecycle_at)?)?;
    let policy_at = lifecycle_at
        .checked_add(1)
        .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
    ResourceGeneration::new(u64_at(bytes, policy_at)?)
        .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
    let after_policy = policy_at
        .checked_add(8)
        .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
    let (lifecycle_generation, lifecycle_generation_at, after_lifecycle) = if version_two {
        let at = after_policy;
        (
            ResourceGeneration::new(u64_at(bytes, at)?)
                .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?,
            Some(at),
            at.checked_add(8)
                .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?,
        )
    } else {
        (
            ResourceGeneration::new(1)
                .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?,
            None,
            after_policy,
        )
    };
    let (
        display_generation,
        display_generation_at,
        retention_generation,
        retention_generation_at,
        after_profile,
    ) = if version_three {
        let display_at = after_lifecycle;
        let retention_at = display_at
            .checked_add(8)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
        let after_retention = retention_at
            .checked_add(8)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
        (
            ResourceGeneration::new(u64_at(bytes, display_at)?)
                .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?,
            Some(display_at),
            ResourceGeneration::new(u64_at(bytes, retention_at)?)
                .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?,
            Some(retention_at),
            after_retention,
        )
    } else {
        (
            ResourceGeneration::new(1)
                .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?,
            None,
            ResourceGeneration::new(1)
                .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?,
            None,
            after_lifecycle,
        )
    };
    let (alias_generation, external_alias, alias_at, envelope_length_at) = if version_four {
        let alias_generation = ResourceGeneration::new(u64_at(bytes, after_profile)?)
            .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
        let alias_length_at = after_profile
            .checked_add(8)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
        let alias_length = usize::from(byte_at(bytes, alias_length_at)?);
        if alias_length == 0 {
            return Err(TenantAdministrationFailure::PersistenceUnavailable);
        }
        let alias_start = alias_length_at
            .checked_add(1)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
        let envelope_at = alias_start
            .checked_add(alias_length)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
        let alias = std::str::from_utf8(
            bytes
                .get(alias_start..envelope_at)
                .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?,
        )
        .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
        (
            alias_generation,
            Some(
                ExternalTenantAlias::parse(alias)
                    .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?,
            ),
            after_profile,
            envelope_at,
        )
    } else {
        (
            ResourceGeneration::new(1)
                .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?,
            None,
            after_profile,
            after_profile,
        )
    };
    let envelope_length = usize::from(u16_at(bytes, envelope_length_at)?);
    let envelope_start = envelope_length_at
        .checked_add(2)
        .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
    let envelope_end = envelope_start
        .checked_add(envelope_length)
        .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
    if envelope_length == 0
        || bytes.get(envelope_start..envelope_end).is_none()
        || envelope_end != bytes.len()
    {
        return Err(TenantAdministrationFailure::PersistenceUnavailable);
    }
    Ok(RecordLayout {
        tenant,
        slug: slug.to_owned(),
        display_name: display.to_owned(),
        envelope: bytes
            .get(envelope_start..envelope_end)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?
            .to_vec(),
        quota_start: generation_at,
        display_length_at: slug_end,
        display_end,
        retention_at,
        state: TenantQuotaState {
            generation,
            weight,
            resources,
        },
        lifecycle,
        lifecycle_generation,
        display_generation,
        retention_seconds,
        retention_generation,
        alias_generation,
        external_alias,
        lifecycle_at,
        lifecycle_generation_at,
        display_generation_at,
        retention_generation_at,
        alias_at,
        policy_at,
    })
}

fn lifecycle_state(code: u8) -> Result<TenantLifecycleState, TenantAdministrationFailure> {
    match code {
        1 => Ok(TenantLifecycleState::Active),
        2 => Ok(TenantLifecycleState::ReadOnly),
        3 => Ok(TenantLifecycleState::Suspended),
        4 => Ok(TenantLifecycleState::Purging),
        5 => Ok(TenantLifecycleState::Purged),
        _ => Err(TenantAdministrationFailure::PersistenceUnavailable),
    }
}

fn rewrite_quota(
    bytes: &[u8],
    record: RecordLayout,
    successor: TenantQuotaState,
) -> Result<Vec<u8>, TenantAdministrationFailure> {
    if successor.weight == 0
        || successor.weight > u32::from(u16::MAX)
        || successor.resources.contains(&0)
    {
        return Err(TenantAdministrationFailure::InvalidInput);
    }
    let mut replacement = bytes.to_vec();
    replacement
        .get_mut(record.quota_start..record.quota_start + 8)
        .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?
        .copy_from_slice(&successor.generation.get().to_be_bytes());
    replacement
        .get_mut(record.quota_start + 8..record.quota_start + 12)
        .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?
        .copy_from_slice(&successor.weight.to_be_bytes());
    for (index, resource) in successor.resources.into_iter().enumerate() {
        let start = record
            .quota_start
            .checked_add(12)
            .and_then(|start| start.checked_add(index.checked_mul(8)?))
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
        replacement
            .get_mut(start..start + 8)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?
            .copy_from_slice(&resource.to_be_bytes());
    }
    Ok(replacement)
}

fn rewrite_lifecycle(
    bytes: &[u8],
    record: RecordLayout,
    successor: TenantLifecycleRecord,
) -> Result<Vec<u8>, TenantAdministrationFailure> {
    let lifecycle = lifecycle_code(successor.state)?;
    if let Some(generation_at) = record.lifecycle_generation_at {
        let mut replacement = bytes.to_vec();
        *replacement
            .get_mut(record.lifecycle_at)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)? = lifecycle;
        replacement
            .get_mut(generation_at..generation_at + 8)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?
            .copy_from_slice(&successor.generation.get().to_be_bytes());
        return Ok(replacement);
    }
    let mut replacement = Vec::new();
    replacement
        .try_reserve_exact(
            bytes
                .len()
                .checked_add(8)
                .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?,
        )
        .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
    replacement.extend_from_slice(&TENANT_RECORD_V2_MAGIC);
    replacement.extend_from_slice(
        bytes
            .get(8..record.lifecycle_at)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?,
    );
    replacement.push(lifecycle);
    replacement.extend_from_slice(
        bytes
            .get(record.lifecycle_at + 1..record.policy_at + 8)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?,
    );
    replacement.extend_from_slice(&successor.generation.get().to_be_bytes());
    replacement.extend_from_slice(
        bytes
            .get(record.policy_at + 8..)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?,
    );
    Ok(replacement)
}

fn rewrite_profile(
    bytes: &[u8],
    record: RecordLayout,
    successor: &TenantProfileState,
) -> Result<Vec<u8>, TenantAdministrationFailure> {
    if successor.display_name.is_empty()
        || successor.display_name.len() > 128
        || successor.retention_seconds == 0
    {
        return Err(TenantAdministrationFailure::InvalidInput);
    }
    let display_length = usize::from(
        *bytes
            .get(record.display_length_at)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?,
    );
    let profile_at = record
        .lifecycle_generation_at
        .map_or(record.policy_at + 8, |at| at + 8);
    let base_capacity = bytes
        .len()
        .checked_sub(display_length)
        .and_then(|size| size.checked_add(successor.display_name.len()))
        .and_then(|size| size.checked_add(usize::from(record.display_generation_at.is_none()) * 16))
        .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
    let mut replacement = Vec::new();
    replacement
        .try_reserve_exact(base_capacity)
        .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
    replacement.extend_from_slice(if record.external_alias.is_some() {
        &TENANT_RECORD_V4_MAGIC
    } else {
        &TENANT_RECORD_V3_MAGIC
    });
    replacement.extend_from_slice(
        bytes
            .get(8..record.display_length_at)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?,
    );
    replacement.push(
        u8::try_from(successor.display_name.len())
            .map_err(|_| TenantAdministrationFailure::InvalidInput)?,
    );
    replacement.extend_from_slice(successor.display_name.as_bytes());
    replacement.extend_from_slice(
        bytes
            .get(record.display_end..profile_at)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?,
    );
    if record.lifecycle_generation_at.is_none() {
        replacement.extend_from_slice(&record.lifecycle_generation.get().to_be_bytes());
    }
    replacement.extend_from_slice(&successor.display_generation.get().to_be_bytes());
    replacement.extend_from_slice(&successor.retention_generation.get().to_be_bytes());
    let suffix_at = record
        .retention_generation_at
        .map_or(profile_at, |at| at + 8);
    replacement.extend_from_slice(
        bytes
            .get(suffix_at..)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?,
    );
    let display_delta = successor.display_name.len().abs_diff(display_length);
    let retention_at = if successor.display_name.len() >= display_length {
        record
            .retention_at
            .checked_add(display_delta)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?
    } else {
        record
            .retention_at
            .checked_sub(display_delta)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?
    };
    replacement
        .get_mut(retention_at..retention_at + 8)
        .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?
        .copy_from_slice(&successor.retention_seconds.to_be_bytes());
    Ok(replacement)
}

fn lifecycle_code(state: TenantLifecycleState) -> Result<u8, TenantAdministrationFailure> {
    match state {
        TenantLifecycleState::Active => Ok(1),
        TenantLifecycleState::ReadOnly => Ok(2),
        TenantLifecycleState::Suspended => Ok(3),
        TenantLifecycleState::Purging => Ok(4),
        TenantLifecycleState::Purged => Ok(5),
    }
}

fn rewrite_alias(
    bytes: &[u8],
    record: RecordLayout,
    successor: TenantAliasRecord,
) -> Result<Vec<u8>, TenantAdministrationFailure> {
    let alias = successor
        .alias
        .as_ref()
        .ok_or(TenantAdministrationFailure::InvalidInput)?;
    if record.external_alias.is_some() || successor.generation.get() != 2 {
        return Err(TenantAdministrationFailure::InvalidInput);
    }
    let alias_bytes = alias.as_str().as_bytes();
    let mut replacement = Vec::new();
    replacement
        .try_reserve_exact(
            bytes
                .len()
                .checked_add(9)
                .and_then(|size| size.checked_add(alias_bytes.len()))
                .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?,
        )
        .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
    replacement.extend_from_slice(&TENANT_RECORD_V4_MAGIC);
    replacement.extend_from_slice(
        bytes
            .get(8..record.alias_at)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?,
    );
    replacement.extend_from_slice(&successor.generation.get().to_be_bytes());
    replacement.push(
        u8::try_from(alias_bytes.len()).map_err(|_| TenantAdministrationFailure::InvalidInput)?,
    );
    replacement.extend_from_slice(alias_bytes);
    replacement.extend_from_slice(
        bytes
            .get(record.alias_at..)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?,
    );
    Ok(replacement)
}

#[cfg(test)]
fn replace_record_quota(
    bytes: &[u8],
    tenant: TenantId,
    successor: TenantQuotaState,
) -> Result<Vec<u8>, TenantAdministrationFailure> {
    let record = record_layout(bytes)?;
    if record.tenant != tenant {
        return Err(TenantAdministrationFailure::Unauthorized);
    }
    rewrite_quota(bytes, record, successor)
}

#[cfg(test)]
fn quota_from_record(
    bytes: &[u8],
    tenant: TenantId,
) -> Result<TenantQuotaState, TenantAdministrationFailure> {
    let record = record_layout(bytes)?;
    if record.tenant != tenant {
        return Err(TenantAdministrationFailure::Unauthorized);
    }
    Ok(record.state)
}

#[cfg(test)]
fn quota_start(bytes: &[u8]) -> Result<usize, TenantAdministrationFailure> {
    Ok(record_layout(bytes)?.quota_start)
}

#[cfg(test)]
fn quota_end(bytes: &[u8]) -> Result<usize, TenantAdministrationFailure> {
    record_layout(bytes)?
        .quota_start
        .checked_add(8 + 4 + RESOURCE_BYTES)
        .ok_or(TenantAdministrationFailure::PersistenceUnavailable)
}

fn byte_at(bytes: &[u8], offset: usize) -> Result<u8, TenantAdministrationFailure> {
    bytes
        .get(offset)
        .copied()
        .ok_or(TenantAdministrationFailure::PersistenceUnavailable)
}

fn array_at(bytes: &[u8], offset: usize) -> Result<[u8; 16], TenantAdministrationFailure> {
    bytes
        .get(offset..offset + 16)
        .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?
        .try_into()
        .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)
}

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, TenantAdministrationFailure> {
    bytes
        .get(offset..offset + 2)
        .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?
        .try_into()
        .map(u16::from_be_bytes)
        .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, TenantAdministrationFailure> {
    bytes
        .get(offset..offset + 4)
        .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?
        .try_into()
        .map(u32::from_be_bytes)
        .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, TenantAdministrationFailure> {
    bytes
        .get(offset..offset + 8)
        .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?
        .try_into()
        .map(u64::from_be_bytes)
        .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use positron_domain::lifecycle::TenantLifecycleState;

    #[test]
    fn metadata_decodes_every_persisted_lifecycle_and_rejects_unknown_codes() {
        let tenant = TenantId::from_bytes([2; 16]).expect("tenant");
        for (code, lifecycle) in [
            (1, TenantLifecycleState::Active),
            (2, TenantLifecycleState::ReadOnly),
            (3, TenantLifecycleState::Suspended),
            (4, TenantLifecycleState::Purging),
            (5, TenantLifecycleState::Purged),
        ] {
            let record = tenant_record_with_lifecycle(tenant, [1; 11], code);
            assert_eq!(
                tenant_record_metadata(&record)
                    .expect("valid lifecycle record")
                    .lifecycle,
                lifecycle
            );
        }
        for code in [0, 6, u8::MAX] {
            let record = tenant_record_with_lifecycle(tenant, [1; 11], code);
            assert!(
                tenant_record_metadata(&record).is_err(),
                "lifecycle code {code} must fail closed"
            );
        }
    }

    #[test]
    fn quota_replacement_preserves_every_non_quota_secondary_tenant_field() {
        let tenant = TenantId::from_bytes([2; 16]).expect("tenant");
        let original = tenant_record(tenant, [1; 11]);
        let successor = TenantQuotaState {
            generation: ResourceGeneration::new(2).expect("generation"),
            weight: 7,
            resources: [3; 11],
        };

        let replacement = replace_record_quota(&original, tenant, successor)
            .expect("replace canonical tenant quota");

        assert_eq!(
            quota_from_record(&replacement, tenant).expect("read replacement"),
            successor
        );
        assert_eq!(
            &replacement[..quota_start(&original).expect("quota offset")],
            &original[..quota_start(&original).expect("quota offset")]
        );
        assert_eq!(
            &replacement[quota_end(&original).expect("quota end")..],
            &original[quota_end(&original).expect("quota end")..]
        );
    }

    #[test]
    fn legacy_lifecycle_successor_upgrades_only_the_distinct_lifecycle_generation() {
        let tenant = TenantId::from_bytes([4; 16]).expect("tenant");
        let original = tenant_record(tenant, [1; 11]);
        let original_layout = record_layout(&original).expect("legacy layout");
        let original_policy_at = original_layout.policy_at;
        let original_envelope = original_layout.envelope.clone();
        let replacement = rewrite_lifecycle(
            &original,
            original_layout,
            TenantLifecycleRecord {
                generation: ResourceGeneration::new(2).expect("generation"),
                state: TenantLifecycleState::ReadOnly,
            },
        )
        .expect("lifecycle successor");
        let replacement_layout = record_layout(&replacement).expect("version two layout");

        assert!(replacement.starts_with(&TENANT_RECORD_V2_MAGIC));
        assert_eq!(replacement_layout.lifecycle, TenantLifecycleState::ReadOnly);
        assert_eq!(replacement_layout.lifecycle_generation.get(), 2);
        assert_eq!(
            &replacement[replacement_layout.policy_at..replacement_layout.policy_at + 8],
            &original[original_policy_at..original_policy_at + 8],
            "the existing policy generation remains independent"
        );
        assert_eq!(replacement_layout.envelope, original_envelope);
        assert_eq!(
            &replacement[replacement_layout.policy_at + 16..],
            &original[original_policy_at + 8..],
            "the envelope-length framing and opaque envelope remain byte-for-byte intact"
        );
    }

    #[test]
    fn quota_replacement_preserves_version_two_lifecycle_generation() {
        let tenant = TenantId::from_bytes([5; 16]).expect("tenant");
        let legacy = tenant_record(tenant, [1; 11]);
        let version_two = rewrite_lifecycle(
            &legacy,
            record_layout(&legacy).expect("legacy layout"),
            TenantLifecycleRecord {
                generation: ResourceGeneration::new(2).expect("generation"),
                state: TenantLifecycleState::ReadOnly,
            },
        )
        .expect("version two lifecycle successor");
        let replacement = replace_record_quota(
            &version_two,
            tenant,
            TenantQuotaState {
                generation: ResourceGeneration::new(2).expect("quota generation"),
                weight: 2,
                resources: [3; 11],
            },
        )
        .expect("quota successor");
        let layout = record_layout(&replacement).expect("replacement layout");

        assert_eq!(layout.lifecycle, TenantLifecycleState::ReadOnly);
        assert_eq!(layout.lifecycle_generation.get(), 2);
        assert_eq!(
            tenant_record_metadata(&replacement)
                .expect("metadata")
                .envelope,
            tenant_record_metadata(&version_two)
                .expect("original metadata")
                .envelope
        );
    }

    #[test]
    fn legacy_profile_successor_upgrades_independent_display_and_retention_generations() {
        let tenant = TenantId::from_bytes([8; 16]).expect("tenant");
        let original = tenant_record(tenant, [1; 11]);
        let original_layout = record_layout(&original).expect("legacy layout");
        let original_envelope = original_layout.envelope.clone();
        let successor = TenantProfileState {
            display_name: "Renamed tenant".to_owned(),
            display_generation: ResourceGeneration::new(2).expect("display generation"),
            retention_seconds: 86_400,
            retention_generation: ResourceGeneration::new(2).expect("retention generation"),
        };

        let replacement =
            rewrite_profile(&original, original_layout, &successor).expect("profile successor");
        let metadata = tenant_record_metadata(&replacement).expect("profile metadata");

        assert!(replacement.starts_with(&TENANT_RECORD_V3_MAGIC));
        assert_eq!(metadata.display_name, "Renamed tenant");
        assert_eq!(metadata.display_generation.get(), 2);
        assert_eq!(metadata.retention_seconds, 86_400);
        assert_eq!(metadata.retention_generation.get(), 2);
        assert_eq!(metadata.lifecycle, TenantLifecycleState::Active);
        assert_eq!(metadata.resources, [1; 11]);
        assert_eq!(metadata.envelope, original_envelope);
    }

    #[test]
    fn profile_record_alias_successor_upgrades_without_rewriting_other_authority() {
        let tenant = TenantId::from_bytes([0x81; 16]).expect("tenant");
        let legacy = tenant_record(tenant, [1; 11]);
        let profile = rewrite_profile(
            &legacy,
            record_layout(&legacy).expect("legacy layout"),
            &TenantProfileState {
                display_name: "Profile tenant".to_owned(),
                display_generation: ResourceGeneration::new(2).expect("display generation"),
                retention_seconds: 86_400,
                retention_generation: ResourceGeneration::new(2).expect("retention generation"),
            },
        )
        .expect("profile successor");
        let profile_layout = record_layout(&profile).expect("profile layout");
        let envelope = profile_layout.envelope.clone();

        let successor = rewrite_alias(
            &profile,
            profile_layout,
            TenantAliasRecord {
                generation: ResourceGeneration::new(2).expect("alias generation"),
                alias: Some(ExternalTenantAlias::parse("tenant-alias").expect("alias")),
            },
        )
        .expect("alias successor");
        let metadata = tenant_record_metadata(&successor).expect("metadata");

        assert!(successor.starts_with(&TENANT_RECORD_V4_MAGIC));
        assert_eq!(metadata.display_name, "Profile tenant");
        assert_eq!(metadata.display_generation.get(), 2);
        assert_eq!(metadata.retention_seconds, 86_400);
        assert_eq!(metadata.retention_generation.get(), 2);
        assert_eq!(
            record_layout(&successor)
                .expect("alias layout")
                .alias_generation
                .get(),
            2
        );
        assert_eq!(
            record_layout(&successor)
                .expect("alias layout")
                .external_alias
                .as_ref()
                .map(ExternalTenantAlias::as_str),
            Some("tenant-alias")
        );
        assert_eq!(metadata.envelope, envelope);
    }

    #[test]
    fn version_two_zero_lifecycle_generation_fails_closed() {
        let tenant = TenantId::from_bytes([6; 16]).expect("tenant");
        let legacy = tenant_record(tenant, [1; 11]);
        let mut version_two = rewrite_lifecycle(
            &legacy,
            record_layout(&legacy).expect("legacy layout"),
            TenantLifecycleRecord {
                generation: ResourceGeneration::new(2).expect("generation"),
                state: TenantLifecycleState::ReadOnly,
            },
        )
        .expect("version two lifecycle successor");
        let layout = record_layout(&version_two).expect("version two layout");
        let generation_at = layout
            .lifecycle_generation_at
            .expect("version two generation");
        version_two[generation_at..generation_at + 8].copy_from_slice(&0_u64.to_be_bytes());
        assert!(tenant_record_metadata(&version_two).is_err());
    }

    #[test]
    fn version_two_tenant_record_rejects_every_truncation() {
        let tenant = TenantId::from_bytes([7; 16]).expect("tenant");
        let legacy = tenant_record(tenant, [1; 11]);
        let version_two = rewrite_lifecycle(
            &legacy,
            record_layout(&legacy).expect("legacy layout"),
            TenantLifecycleRecord {
                generation: ResourceGeneration::new(2).expect("generation"),
                state: TenantLifecycleState::Suspended,
            },
        )
        .expect("version two lifecycle successor");
        for length in 0..version_two.len() {
            assert!(
                tenant_record_metadata(&version_two[..length]).is_err(),
                "version two truncation at {length} must fail closed"
            );
        }
    }

    #[test]
    fn quota_record_rejects_unknown_tenant_and_every_truncation() {
        let tenant = TenantId::from_bytes([2; 16]).expect("tenant");
        let record = tenant_record(tenant, [1; 11]);
        let other = TenantId::from_bytes([3; 16]).expect("other tenant");
        assert!(replace_record_quota(&record, other, quota_state()).is_err());
        for length in 0..record.len() {
            assert!(
                replace_record_quota(&record[..length], tenant, quota_state()).is_err(),
                "truncation at {length} must fail closed"
            );
        }
    }

    fn quota_state() -> TenantQuotaState {
        TenantQuotaState {
            generation: ResourceGeneration::new(2).expect("generation"),
            weight: 7,
            resources: [3; 11],
        }
    }

    fn tenant_record(tenant: TenantId, resources: [u64; 11]) -> Vec<u8> {
        tenant_record_with_lifecycle(tenant, resources, 1)
    }

    fn tenant_record_with_lifecycle(
        tenant: TenantId,
        resources: [u64; 11],
        lifecycle: u8,
    ) -> Vec<u8> {
        let slug = b"tenant";
        let display = b"Tenant display";
        let envelope = b"POSKE01:opaque-envelope";
        let mut record = Vec::new();
        record.extend_from_slice(b"POSTNR01");
        record.extend_from_slice(&[1; 16]);
        record.extend_from_slice(&tenant.to_bytes());
        record.push(u8::try_from(slug.len()).expect("slug bound"));
        record.extend_from_slice(slug);
        record.push(u8::try_from(display.len()).expect("display bound"));
        record.extend_from_slice(display);
        record.extend_from_slice(&2_592_000_u64.to_be_bytes());
        record.extend_from_slice(&1_u64.to_be_bytes());
        record.extend_from_slice(&1_u32.to_be_bytes());
        for resource in resources {
            record.extend_from_slice(&resource.to_be_bytes());
        }
        record.push(lifecycle);
        record.extend_from_slice(&1_u64.to_be_bytes());
        record.extend_from_slice(
            &u16::try_from(envelope.len())
                .expect("envelope bound")
                .to_be_bytes(),
        );
        record.extend_from_slice(envelope);
        record
    }
}
