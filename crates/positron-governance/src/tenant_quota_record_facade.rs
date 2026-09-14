use positron_domain::identity::TenantId;
use positron_kernel::{CatalogObject, CatalogSnapshot};

use super::*;

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
    tenant_record_state(snapshot, tenant, |record| record.state)
}

/// Replaces exactly one canonical secondary-tenant record's mutable quota
/// fields while preserving all other catalog objects and record bytes.
pub(crate) fn replace_tenant_quota_record(
    snapshot: &CatalogSnapshot,
    tenant: TenantId,
    successor: TenantQuotaState,
) -> Result<Vec<CatalogObject>, TenantAdministrationFailure> {
    replace_tenant_record(snapshot, tenant, |bytes, record| {
        rewrite_quota(bytes, record, successor)
    })
}

/// Reads the canonical lifecycle state and generation of one registered
/// secondary tenant. A POSTNR01 record has the documented initial lifecycle
/// generation of one until its first lifecycle successor upgrades it.
pub(crate) fn tenant_lifecycle_record(
    snapshot: &CatalogSnapshot,
    tenant: TenantId,
) -> Result<Option<TenantLifecycleRecord>, TenantAdministrationFailure> {
    tenant_record_state(snapshot, tenant, |record| TenantLifecycleRecord {
        generation: record.lifecycle_generation,
        state: record.lifecycle,
    })
}

/// Replaces one secondary lifecycle record, preserving every quota, policy,
/// identity, and opaque key-envelope byte. POSTNR01 is upgraded only here.
pub(crate) fn replace_tenant_lifecycle_record(
    snapshot: &CatalogSnapshot,
    tenant: TenantId,
    successor: TenantLifecycleRecord,
) -> Result<Vec<CatalogObject>, TenantAdministrationFailure> {
    replace_tenant_record(snapshot, tenant, |bytes, record| {
        rewrite_lifecycle(bytes, record, successor)
    })
}

pub(crate) fn tenant_profile_state(
    snapshot: &CatalogSnapshot,
    tenant: TenantId,
) -> Result<Option<TenantProfileState>, TenantAdministrationFailure> {
    tenant_record_state(snapshot, tenant, |record| TenantProfileState {
        display_name: record.display_name.clone(),
        display_generation: record.display_generation,
        retention_seconds: record.retention_seconds,
        retention_generation: record.retention_generation,
    })
}

pub(crate) fn replace_tenant_profile_record(
    snapshot: &CatalogSnapshot,
    tenant: TenantId,
    successor: &TenantProfileState,
) -> Result<Vec<CatalogObject>, TenantAdministrationFailure> {
    replace_tenant_record(snapshot, tenant, |bytes, record| {
        rewrite_profile(bytes, record, successor)
    })
}

pub(crate) fn tenant_alias_record(
    snapshot: &CatalogSnapshot,
    tenant: TenantId,
) -> Result<Option<TenantAliasRecord>, TenantAdministrationFailure> {
    tenant_record_state(snapshot, tenant, |record| TenantAliasRecord {
        generation: record.alias_generation,
        alias: record.external_alias.clone(),
    })
}

/// Binds the one immutable secondary-tenant external alias. Legacy records
/// upgrade to POSTNR04 only at this first binding and retain every other byte.
pub(crate) fn replace_tenant_alias_record(
    snapshot: &CatalogSnapshot,
    tenant: TenantId,
    successor: TenantAliasRecord,
) -> Result<Vec<CatalogObject>, TenantAdministrationFailure> {
    replace_tenant_record(snapshot, tenant, |bytes, record| {
        rewrite_alias(bytes, record, successor.clone())
    })
}

pub(super) fn tenant_record_state<T>(
    snapshot: &CatalogSnapshot,
    tenant: TenantId,
    select: impl Fn(&RecordLayout) -> T,
) -> Result<Option<T>, TenantAdministrationFailure> {
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
        if record.tenant == tenant && state.replace(select(&record)).is_some() {
            return Err(TenantAdministrationFailure::PersistenceUnavailable);
        }
    }
    if state.is_some() && !tenant_is_registered(snapshot, tenant)? {
        return Err(TenantAdministrationFailure::Unauthorized);
    }
    Ok(state)
}

pub(super) fn replace_tenant_record(
    snapshot: &CatalogSnapshot,
    tenant: TenantId,
    mut rewrite: impl FnMut(&[u8], RecordLayout) -> Result<Vec<u8>, TenantAdministrationFailure>,
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
                rewrite(bytes, record)?
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

pub(super) fn tenant_is_registered(
    snapshot: &CatalogSnapshot,
    tenant: TenantId,
) -> Result<bool, TenantAdministrationFailure> {
    Ok(TenantAdministration::registered_tenant_ids(snapshot)?.contains(&tenant))
}
