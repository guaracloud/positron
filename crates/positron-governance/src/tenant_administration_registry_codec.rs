use std::collections::BTreeSet;

use positron_domain::identity::TenantId;
use positron_kernel::{CatalogObject, CatalogSnapshot};

use super::{TenantAdministrationFailure, generation_at, map_catalog};
use crate::ResourceGeneration;

const TENANT_REGISTRY_V1_MAGIC: [u8; 8] = *b"POSTRG01";
pub(super) const TENANT_REGISTRY_V2_MAGIC: [u8; 8] = *b"POSTRG02";

pub(super) struct TenantRegistry {
    pub(super) generation: ResourceGeneration,
    pub(super) tenants: Vec<TenantId>,
}

pub(crate) fn is_registry(bytes: &[u8]) -> bool {
    bytes.starts_with(&TENANT_REGISTRY_V1_MAGIC) || bytes.starts_with(&TENANT_REGISTRY_V2_MAGIC)
}

pub(super) fn registry(
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

pub(super) fn decode_registry(bytes: &[u8]) -> Result<TenantRegistry, TenantAdministrationFailure> {
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

pub(super) fn registry_object(
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
