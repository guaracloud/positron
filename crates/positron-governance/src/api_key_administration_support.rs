//! Shared API-key lifecycle validation and secret-safe support.

use super::*;

pub(super) fn authorizes(administrator: PrincipalId, actor: AuthorizedContext) -> bool {
    actor.principal_id() == administrator
        && actor.scope() == Scope::SystemAdministration
        && actor.tenant_attribution().is_none()
}

pub(super) fn ensure_registered_tenant(
    snapshot: &CatalogSnapshot,
    tenant: TenantId,
) -> Result<(), ApiKeyAdministrationFailure> {
    if TenantAdministration::registered_tenant_ids(snapshot)
        .map_err(|_| ApiKeyAdministrationFailure::CredentialUnavailable)?
        .contains(&tenant)
    {
        Ok(())
    } else {
        Err(ApiKeyAdministrationFailure::CredentialUnavailable)
    }
}

pub(super) fn descriptors(
    credentials: &[CatalogCredential],
    generation: u64,
) -> Result<Vec<ApiKeyDescriptor>, ApiKeyAdministrationFailure> {
    let generation = ResourceGeneration::new(generation)
        .map_err(|_| ApiKeyAdministrationFailure::PersistenceUnavailable)?;
    let mut descriptors = Vec::new();
    descriptors
        .try_reserve_exact(credentials.len())
        .map_err(|_| ApiKeyAdministrationFailure::CapacityExceeded)?;
    for credential in credentials {
        descriptors.push(ApiKeyDescriptor {
            principal: credential.principal(),
            scope: scope_from_code(credential.scope_code())
                .ok_or(ApiKeyAdministrationFailure::PersistenceUnavailable)?,
            active: credential.is_active(),
            expires_at_unix_seconds: credential.expires_at_unix_seconds(),
            generation,
        });
    }
    Ok(descriptors)
}

pub(super) fn next_generation(
    current: u64,
    expected: ResourceGeneration,
) -> Result<u64, ApiKeyAdministrationFailure> {
    if current != expected.get() {
        return Err(ApiKeyAdministrationFailure::StaleGeneration);
    }
    expected
        .get()
        .checked_add(1)
        .ok_or(ApiKeyAdministrationFailure::CapacityExceeded)
}

pub(super) fn credentials_with_capacity(
    current: &[CatalogCredential],
) -> Result<Vec<CatalogCredential>, ApiKeyAdministrationFailure> {
    if current.len() >= 128 {
        return Err(ApiKeyAdministrationFailure::CapacityExceeded);
    }
    let mut credentials = current.to_vec();
    credentials
        .try_reserve(1)
        .map_err(|_| ApiKeyAdministrationFailure::CapacityExceeded)?;
    Ok(credentials)
}

pub(super) fn active_tenant_credential(
    keyring: &TenantKeyring,
    principal: PrincipalId,
) -> Result<&CatalogCredential, ApiKeyAdministrationFailure> {
    keyring
        .credentials
        .iter()
        .find(|credential| {
            credential.principal() == principal
                && credential.is_active()
                && credential.scope_code() != 4
        })
        .ok_or(ApiKeyAdministrationFailure::CredentialUnavailable)
}

pub(super) fn tenant_key_replay(
    catalog: &Catalog<'_>,
    request: ApiKeyCreateRequest,
) -> Result<ApiKeyCreation, ApiKeyAdministrationFailure> {
    let snapshot = catalog.pin().map_err(map_catalog)?;
    replay_tenant_creation(catalog, &snapshot, request)?
        .ok_or(ApiKeyAdministrationFailure::IdempotencyConflict)
}

pub(super) fn replay_tenant_creation(
    catalog: &Catalog<'_>,
    snapshot: &CatalogSnapshot,
    request: ApiKeyCreateRequest,
) -> Result<Option<ApiKeyCreation>, ApiKeyAdministrationFailure> {
    let tenant = request
        .tenant
        .ok_or(ApiKeyAdministrationFailure::IdempotencyConflict)?;
    let keyring = tenant_keyring(snapshot, tenant)?;
    let Some(audit) = replay_entry(catalog, request.idempotency)? else {
        return Ok(None);
    };
    if audit.action() != ApiKeyLifecycleAction::Create
        || audit.actor_id() != request.actor.principal_id()
        || audit.scope() != request.scope
        || audit.expires_at_unix_seconds() != request.expires_at_unix_seconds
        || audit.expected_generation() != request.expected
    {
        return Err(ApiKeyAdministrationFailure::IdempotencyConflict);
    }
    if !keyring.credentials.iter().any(|credential| {
        credential.principal() == audit.principal_id()
            && scope_from_code(credential.scope_code()) == Some(request.scope)
            && credential.expires_at_unix_seconds() == request.expires_at_unix_seconds
    }) {
        return Err(ApiKeyAdministrationFailure::PersistenceUnavailable);
    }
    Ok(Some(ApiKeyCreation {
        principal: audit.principal_id(),
        secret: None,
    }))
}

pub(super) fn credential_material(
    key: &BootstrapKeyCustody,
) -> Result<CredentialMaterial, ApiKeyAdministrationFailure> {
    let principal = PrincipalId::from_bytes(
        key.random_identifier()
            .map_err(|_| ApiKeyAdministrationFailure::PersistenceUnavailable)?,
    )
    .map_err(|_| ApiKeyAdministrationFailure::PersistenceUnavailable)?;
    let salt = key
        .random_secret()
        .map_err(|_| ApiKeyAdministrationFailure::PersistenceUnavailable)?;
    let raw_secret = key
        .random_secret()
        .map_err(|_| ApiKeyAdministrationFailure::PersistenceUnavailable)?;
    let raw_secret = Zeroizing::new(*raw_secret);
    let hash = key
        .salted_secret_hash(salt.as_ref(), &raw_secret)
        .map_err(|_| ApiKeyAdministrationFailure::PersistenceUnavailable)?;
    Ok(CredentialMaterial {
        principal,
        salt: *salt,
        raw_secret,
        hash,
    })
}

pub(super) struct CredentialMaterial {
    pub(super) principal: PrincipalId,
    pub(super) salt: [u8; 32],
    pub(super) raw_secret: Zeroizing<[u8; 32]>,
    pub(super) hash: [u8; 32],
}

pub(super) fn scope_code(scope: Scope) -> Option<u8> {
    match scope {
        Scope::Ingest => Some(1),
        Scope::Query => Some(2),
        Scope::TenantAdministration => Some(3),
        Scope::SystemAdministration => None,
    }
}

pub(super) fn scope_from_code(scope: u8) -> Option<Scope> {
    match scope {
        1 => Some(Scope::Ingest),
        2 => Some(Scope::Query),
        3 => Some(Scope::TenantAdministration),
        4 => Some(Scope::SystemAdministration),
        _ => None,
    }
}

pub(super) fn format_secret(secret: &[u8; 32]) -> String {
    let mut rendered = String::with_capacity(68);
    rendered.push_str("pos_");
    for byte in secret {
        rendered.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
        rendered.push(char::from(b"0123456789abcdef"[usize::from(byte & 15)]));
    }
    rendered
}

pub(super) fn map_catalog(failure: positron_kernel::CatalogFailure) -> ApiKeyAdministrationFailure {
    match failure.code() {
        CatalogFailureCode::StaleGeneration => ApiKeyAdministrationFailure::StaleGeneration,
        CatalogFailureCode::IdempotencyConflict => ApiKeyAdministrationFailure::IdempotencyConflict,
        CatalogFailureCode::LimitExceeded | CatalogFailureCode::ResourceAdmissionRefused => {
            ApiKeyAdministrationFailure::CapacityExceeded
        },
        CatalogFailureCode::StorageUnavailable
        | CatalogFailureCode::ConcurrentWriter
        | CatalogFailureCode::InvalidInput
        | CatalogFailureCode::IntegrityCorruption
        | CatalogFailureCode::AuthenticationFailed
        | CatalogFailureCode::UnsupportedFormat => {
            ApiKeyAdministrationFailure::PersistenceUnavailable
        },
    }
}
