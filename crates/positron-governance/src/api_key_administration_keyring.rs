use positron_domain::identity::{PrincipalId, TenantId};
use positron_kernel::{
    AuditIntent, Catalog, CatalogCredential, CatalogObject, CatalogProposal, CatalogSnapshot,
    TransactionId,
};

use super::{
    ApiKeyAdministrationFailure, ApiKeyLifecycleAction, MutationAudit, TENANT_KEYRING_MAGIC,
    map_catalog,
};
pub(super) struct TenantKeyring {
    pub(super) generation: u64,
    pub(super) credentials: Vec<CatalogCredential>,
}

pub(super) fn tenant_keyring(
    snapshot: &CatalogSnapshot,
    tenant: TenantId,
) -> Result<TenantKeyring, ApiKeyAdministrationFailure> {
    Ok(
        find_tenant_keyring(snapshot, tenant)?.unwrap_or(TenantKeyring {
            generation: 1,
            credentials: Vec::new(),
        }),
    )
}

pub(super) fn find_tenant_keyring(
    snapshot: &CatalogSnapshot,
    tenant: TenantId,
) -> Result<Option<TenantKeyring>, ApiKeyAdministrationFailure> {
    let mut found = None;
    for identity in snapshot.object_identities() {
        let bytes = snapshot
            .object(identity)
            .map_err(map_catalog)?
            .ok_or(ApiKeyAdministrationFailure::PersistenceUnavailable)?;
        if !bytes.starts_with(&TENANT_KEYRING_MAGIC) {
            continue;
        }
        let decoded = decode_tenant_keyring(bytes)?;
        if decoded.0 != tenant {
            continue;
        }
        if found.replace(decoded.1).is_some() {
            return Err(ApiKeyAdministrationFailure::PersistenceUnavailable);
        }
    }
    Ok(found)
}

pub(super) fn decode_tenant_keyring(
    bytes: &[u8],
) -> Result<(TenantId, TenantKeyring), ApiKeyAdministrationFailure> {
    let tenant = TenantId::from_bytes(
        bytes
            .get(8..24)
            .ok_or(ApiKeyAdministrationFailure::PersistenceUnavailable)?
            .try_into()
            .map_err(|_| ApiKeyAdministrationFailure::PersistenceUnavailable)?,
    )
    .map_err(|_| ApiKeyAdministrationFailure::PersistenceUnavailable)?;
    let generation = u64::from_be_bytes(
        bytes
            .get(24..32)
            .ok_or(ApiKeyAdministrationFailure::PersistenceUnavailable)?
            .try_into()
            .map_err(|_| ApiKeyAdministrationFailure::PersistenceUnavailable)?,
    );
    if generation == 0 {
        return Err(ApiKeyAdministrationFailure::PersistenceUnavailable);
    }
    let count = usize::from(u16::from_be_bytes(
        bytes
            .get(32..34)
            .ok_or(ApiKeyAdministrationFailure::PersistenceUnavailable)?
            .try_into()
            .map_err(|_| ApiKeyAdministrationFailure::PersistenceUnavailable)?,
    ));
    if count == 0 || count > 128 || bytes.len() != 34 + count * 90 {
        return Err(ApiKeyAdministrationFailure::PersistenceUnavailable);
    }
    let mut credentials = Vec::new();
    credentials
        .try_reserve_exact(count)
        .map_err(|_| ApiKeyAdministrationFailure::CapacityExceeded)?;
    for index in 0..count {
        let offset = 34 + index * 90;
        let principal = PrincipalId::from_bytes(
            bytes
                .get(offset..offset + 16)
                .ok_or(ApiKeyAdministrationFailure::PersistenceUnavailable)?
                .try_into()
                .map_err(|_| ApiKeyAdministrationFailure::PersistenceUnavailable)?,
        )
        .map_err(|_| ApiKeyAdministrationFailure::PersistenceUnavailable)?;
        let scope = bytes
            .get(offset + 16)
            .copied()
            .ok_or(ApiKeyAdministrationFailure::PersistenceUnavailable)?;
        let active = match bytes.get(offset + 17).copied() {
            Some(0) => false,
            Some(1) => true,
            _ => return Err(ApiKeyAdministrationFailure::PersistenceUnavailable),
        };
        let expiry = u64::from_be_bytes(
            bytes
                .get(offset + 18..offset + 26)
                .ok_or(ApiKeyAdministrationFailure::PersistenceUnavailable)?
                .try_into()
                .map_err(|_| ApiKeyAdministrationFailure::PersistenceUnavailable)?,
        );
        let salt: [u8; 32] = bytes
            .get(offset + 26..offset + 58)
            .ok_or(ApiKeyAdministrationFailure::PersistenceUnavailable)?
            .try_into()
            .map_err(|_| ApiKeyAdministrationFailure::PersistenceUnavailable)?;
        let hash: [u8; 32] = bytes
            .get(offset + 58..offset + 90)
            .ok_or(ApiKeyAdministrationFailure::PersistenceUnavailable)?
            .try_into()
            .map_err(|_| ApiKeyAdministrationFailure::PersistenceUnavailable)?;
        let credential = CatalogCredential::new(
            principal,
            scope,
            active,
            (expiry != 0).then_some(expiry),
            salt,
            hash,
        )
        .map_err(map_catalog)?;
        if credentials
            .iter()
            .any(|prior: &CatalogCredential| prior.principal() == credential.principal())
        {
            return Err(ApiKeyAdministrationFailure::PersistenceUnavailable);
        }
        credentials.push(credential);
    }
    Ok((
        tenant,
        TenantKeyring {
            generation,
            credentials,
        },
    ))
}

pub(super) fn encode_tenant_keyring(
    tenant: TenantId,
    generation: u64,
    credentials: &[CatalogCredential],
) -> Result<Vec<u8>, ApiKeyAdministrationFailure> {
    if generation == 0 || credentials.is_empty() || credentials.len() > 128 {
        return Err(ApiKeyAdministrationFailure::CredentialUnavailable);
    }
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(34 + credentials.len() * 90)
        .map_err(|_| ApiKeyAdministrationFailure::CapacityExceeded)?;
    encoded.extend_from_slice(&TENANT_KEYRING_MAGIC);
    encoded.extend_from_slice(&tenant.to_bytes());
    encoded.extend_from_slice(&generation.to_be_bytes());
    encoded.extend_from_slice(
        &u16::try_from(credentials.len())
            .map_err(|_| ApiKeyAdministrationFailure::CapacityExceeded)?
            .to_be_bytes(),
    );
    for credential in credentials {
        encoded.extend_from_slice(&credential.principal().to_bytes());
        encoded.push(credential.scope_code());
        encoded.push(u8::from(credential.is_active()));
        encoded.extend_from_slice(
            &credential
                .expires_at_unix_seconds()
                .unwrap_or(0)
                .to_be_bytes(),
        );
        let (salt, hash) = credential.salted_hash();
        encoded.extend_from_slice(&salt);
        encoded.extend_from_slice(&hash);
    }
    Ok(encoded)
}

pub(super) fn commit_tenant_keyring(
    catalog: &Catalog<'_>,
    snapshot: &CatalogSnapshot,
    tenant: TenantId,
    replacement: Vec<u8>,
    audit_fields: MutationAudit,
    request_digest: [u8; 32],
) -> Result<(), ApiKeyAdministrationFailure> {
    let mut objects = Vec::new();
    for object_id in snapshot.object_identities() {
        let bytes = snapshot
            .object(object_id)
            .map_err(map_catalog)?
            .ok_or(ApiKeyAdministrationFailure::PersistenceUnavailable)?;
        if bytes.starts_with(&TENANT_KEYRING_MAGIC) && decode_tenant_keyring(bytes)?.0 == tenant {
            continue;
        }
        objects.push(CatalogObject::new(bytes.to_vec()).map_err(map_catalog)?);
    }
    objects.push(CatalogObject::new(replacement).map_err(map_catalog)?);
    let mut audit = Vec::with_capacity(98);
    audit.extend_from_slice(b"POSKEY01");
    audit.push(match audit_fields.action {
        ApiKeyLifecycleAction::Create => 1,
        ApiKeyLifecycleAction::Rotate => 2,
        ApiKeyLifecycleAction::Revoke => 3,
    });
    audit.extend_from_slice(&audit_fields.actor.to_bytes());
    audit.extend_from_slice(&audit_fields.principal.to_bytes());
    audit.extend_from_slice(&audit_fields.target.to_bytes());
    audit.push(audit_fields.scope);
    audit.extend_from_slice(
        &audit_fields
            .expires_at_unix_seconds
            .unwrap_or(0)
            .to_be_bytes(),
    );
    audit.extend_from_slice(&audit_fields.expected.get().to_be_bytes());
    audit.extend_from_slice(&audit_fields.generation.get().to_be_bytes());
    audit.extend_from_slice(&audit_fields.idempotency.to_bytes());
    catalog
        .commit_prepared(
            snapshot.identity(),
            CatalogProposal::new(
                TransactionId::new(audit_fields.idempotency.to_bytes()).map_err(map_catalog)?,
                snapshot
                    .format_epoch()
                    .ok_or(ApiKeyAdministrationFailure::PersistenceUnavailable)?,
                objects,
            )
            .map_err(map_catalog)?,
            AuditIntent::new(audit).map_err(map_catalog)?,
            request_digest,
        )
        .map_err(map_catalog)?;
    Ok(())
}
