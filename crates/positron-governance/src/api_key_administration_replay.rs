use positron_domain::identity::PrincipalId;
use positron_kernel::Catalog;

use super::*;

pub(super) fn replay_creation(
    catalog: &Catalog<'_>,
    idempotency: AdministrativeIdempotencyKey,
    actor: PrincipalId,
    scope: Scope,
    expires_at_unix_seconds: Option<u64>,
    expected: ResourceGeneration,
    credentials: &[CatalogCredential],
) -> Result<Option<ApiKeyCreation>, ApiKeyAdministrationFailure> {
    let snapshot = catalog.pin().map_err(map_catalog)?;
    if let Some(receipt) = find(&snapshot, idempotency)? {
        let digest =
            create_request_digest(idempotency, actor, scope, expires_at_unix_seconds, expected)?;
        if receipt.tenant.is_some()
            || receipt.action != ApiKeyLifecycleAction::Create
            || receipt.actor != actor
            || receipt.scope
                != scope_code(scope).ok_or(ApiKeyAdministrationFailure::Unauthorized)?
            || receipt.expires_at_unix_seconds != expires_at_unix_seconds
            || receipt.expected != expected
            || receipt.request_digest != digest
        {
            return Err(ApiKeyAdministrationFailure::IdempotencyConflict);
        }
        return Ok(Some(ApiKeyCreation {
            principal: receipt.principal,
            secret: None,
        }));
    }
    let Some(lifecycle) = replay_entry(catalog, idempotency)? else {
        return Ok(None);
    };
    let scope_code = scope_code(scope).ok_or(ApiKeyAdministrationFailure::Unauthorized)?;
    let request_matches = lifecycle.actor_id() == actor
        && lifecycle.scope() == scope
        && lifecycle.expires_at_unix_seconds() == expires_at_unix_seconds
        && lifecycle.expected_generation() == expected
        && lifecycle.action() == ApiKeyLifecycleAction::Create;
    let request_digest =
        create_request_digest(idempotency, actor, scope, expires_at_unix_seconds, expected)?;
    if !request_matches
        || lifecycle
            .request_digest()
            .is_some_and(|actual| actual != request_digest)
    {
        return Err(ApiKeyAdministrationFailure::IdempotencyConflict);
    }
    let published = credentials.iter().any(|credential| {
        credential.principal() == lifecycle.principal_id()
            && credential.scope_code() == scope_code
            && credential.expires_at_unix_seconds() == expires_at_unix_seconds
    });
    if !published {
        // A pre-publication Catalog fault may leave no durable successor. Its
        // audit reservation is not an operation outcome, so let Catalog's
        // ordinary retry path decide the same request rather than claiming a
        // redacted success that has no credential.
        return Ok(None);
    }
    Ok(Some(ApiKeyCreation {
        principal: lifecycle.principal_id(),
        secret: None,
    }))
}

pub(super) fn replay_rotation(
    catalog: &Catalog<'_>,
    idempotency: AdministrativeIdempotencyKey,
    actor: PrincipalId,
    predecessor: PrincipalId,
    expected: ResourceGeneration,
) -> Result<Option<ApiKeyCreation>, ApiKeyAdministrationFailure> {
    let snapshot = catalog.pin().map_err(map_catalog)?;
    if let Some(receipt) = find(&snapshot, idempotency)? {
        let digest = rotate_request_digest(
            idempotency,
            actor,
            predecessor,
            receipt.scope,
            receipt.expires_at_unix_seconds,
            expected,
        )?;
        if receipt.tenant.is_some()
            || receipt.action != ApiKeyLifecycleAction::Rotate
            || receipt.actor != actor
            || receipt.target != predecessor
            || receipt.expected != expected
            || receipt.request_digest != digest
        {
            return Err(ApiKeyAdministrationFailure::IdempotencyConflict);
        }
        return Ok(Some(ApiKeyCreation {
            principal: receipt.principal,
            secret: None,
        }));
    }
    let Some(lifecycle) = replay_entry(catalog, idempotency)? else {
        return Ok(None);
    };
    let request_digest = rotate_request_digest(
        idempotency,
        actor,
        predecessor,
        scope_code(lifecycle.scope()).ok_or(ApiKeyAdministrationFailure::PersistenceUnavailable)?,
        lifecycle.expires_at_unix_seconds(),
        expected,
    )?;
    if lifecycle.action() != ApiKeyLifecycleAction::Rotate
        || lifecycle.actor_id() != actor
        || lifecycle.target_principal_id() != predecessor
        || lifecycle.expected_generation() != expected
        || lifecycle
            .request_digest()
            .is_some_and(|actual| actual != request_digest)
    {
        return Err(ApiKeyAdministrationFailure::IdempotencyConflict);
    }
    Ok(Some(ApiKeyCreation {
        principal: lifecycle.principal_id(),
        secret: None,
    }))
}

pub(super) fn replay_tenant_rotation(
    catalog: &Catalog<'_>,
    keyring: &TenantKeyring,
    tenant: TenantId,
    idempotency: AdministrativeIdempotencyKey,
    actor: PrincipalId,
    predecessor: PrincipalId,
    expected: ResourceGeneration,
) -> Result<Option<ApiKeyCreation>, ApiKeyAdministrationFailure> {
    let snapshot = catalog.pin().map_err(map_catalog)?;
    if let Some(receipt) = find(&snapshot, idempotency)? {
        let digest = tenant_rotate_request_digest(
            idempotency,
            actor,
            tenant,
            predecessor,
            receipt.scope,
            receipt.expires_at_unix_seconds,
            expected,
        );
        if receipt.tenant != Some(tenant)
            || receipt.action != ApiKeyLifecycleAction::Rotate
            || receipt.actor != actor
            || receipt.target != predecessor
            || receipt.expected != expected
            || receipt.request_digest != digest
        {
            return Err(ApiKeyAdministrationFailure::IdempotencyConflict);
        }
        return Ok(Some(ApiKeyCreation {
            principal: receipt.principal,
            secret: None,
        }));
    }
    let Some(lifecycle) = replay_entry(catalog, idempotency)? else {
        return Ok(None);
    };
    if lifecycle.action() != ApiKeyLifecycleAction::Rotate
        || lifecycle.actor_id() != actor
        || lifecycle.target_principal_id() != predecessor
        || lifecycle.expected_generation() != expected
        || !keyring
            .credentials
            .iter()
            .any(|credential| credential.principal() == lifecycle.principal_id())
    {
        return Err(ApiKeyAdministrationFailure::IdempotencyConflict);
    }
    Ok(Some(ApiKeyCreation {
        principal: lifecycle.principal_id(),
        secret: None,
    }))
}

pub(super) fn replay_revocation(
    catalog: &Catalog<'_>,
    idempotency: AdministrativeIdempotencyKey,
    actor: PrincipalId,
    principal: PrincipalId,
    expected: ResourceGeneration,
) -> Result<bool, ApiKeyAdministrationFailure> {
    let snapshot = catalog.pin().map_err(map_catalog)?;
    if let Some(receipt) = find(&snapshot, idempotency)? {
        let digest = revoke_request_digest(
            idempotency,
            actor,
            principal,
            receipt.scope,
            receipt.expires_at_unix_seconds,
            expected,
        );
        if receipt.tenant.is_some()
            || receipt.action != ApiKeyLifecycleAction::Revoke
            || receipt.actor != actor
            || receipt.target != principal
            || receipt.expected != expected
            || receipt.request_digest != digest
        {
            return Err(ApiKeyAdministrationFailure::IdempotencyConflict);
        }
        return Ok(true);
    }
    let Some(lifecycle) = replay_entry(catalog, idempotency)? else {
        return Ok(false);
    };
    if lifecycle.action() != ApiKeyLifecycleAction::Revoke
        || lifecycle.actor_id() != actor
        || lifecycle.target_principal_id() != principal
        || lifecycle.expected_generation() != expected
    {
        return Err(ApiKeyAdministrationFailure::IdempotencyConflict);
    }
    Ok(true)
}

pub(super) fn replay_tenant_revocation(
    catalog: &Catalog<'_>,
    keyring: &TenantKeyring,
    tenant: TenantId,
    idempotency: AdministrativeIdempotencyKey,
    actor: PrincipalId,
    principal: PrincipalId,
    expected: ResourceGeneration,
) -> Result<bool, ApiKeyAdministrationFailure> {
    let snapshot = catalog.pin().map_err(map_catalog)?;
    if let Some(receipt) = find(&snapshot, idempotency)? {
        let digest = tenant_revoke_request_digest(
            idempotency,
            actor,
            tenant,
            principal,
            receipt.scope,
            receipt.expires_at_unix_seconds,
            expected,
        );
        if receipt.tenant != Some(tenant)
            || receipt.action != ApiKeyLifecycleAction::Revoke
            || receipt.actor != actor
            || receipt.target != principal
            || receipt.expected != expected
            || receipt.request_digest != digest
        {
            return Err(ApiKeyAdministrationFailure::IdempotencyConflict);
        }
        return Ok(true);
    }
    let Some(lifecycle) = replay_entry(catalog, idempotency)? else {
        return Ok(false);
    };
    if lifecycle.action() != ApiKeyLifecycleAction::Revoke
        || lifecycle.actor_id() != actor
        || lifecycle.target_principal_id() != principal
        || lifecycle.expected_generation() != expected
        || !keyring
            .credentials
            .iter()
            .any(|credential| credential.principal() == principal && !credential.is_active())
    {
        return Err(ApiKeyAdministrationFailure::IdempotencyConflict);
    }
    Ok(true)
}

pub(super) fn replay_entry(
    catalog: &Catalog<'_>,
    idempotency: AdministrativeIdempotencyKey,
) -> Result<Option<ApiKeyLifecycleAuditEntry>, ApiKeyAdministrationFailure> {
    let mut matching = None;
    for record in catalog.governance_audit_records().map_err(map_catalog)? {
        if record.transaction().to_bytes() != idempotency.to_bytes() {
            continue;
        }
        let entry = crate::GovernanceAuditEntry::decode(&record)
            .map_err(|_| ApiKeyAdministrationFailure::PersistenceUnavailable)?;
        let lifecycle = entry
            .as_api_key_lifecycle()
            .ok_or(ApiKeyAdministrationFailure::IdempotencyConflict)?;
        matching = Some(lifecycle.clone());
    }
    Ok(matching)
}

pub(super) fn tenant_key_rotation_replay(
    catalog: &Catalog<'_>,
    tenant: TenantId,
    idempotency: AdministrativeIdempotencyKey,
    actor: PrincipalId,
    predecessor: PrincipalId,
    expected: ResourceGeneration,
) -> Result<ApiKeyCreation, ApiKeyAdministrationFailure> {
    let snapshot = catalog.pin().map_err(map_catalog)?;
    let keyring = tenant_keyring(&snapshot, tenant)?;
    replay_tenant_rotation(
        catalog,
        &keyring,
        tenant,
        idempotency,
        actor,
        predecessor,
        expected,
    )?
    .ok_or(ApiKeyAdministrationFailure::IdempotencyConflict)
}

pub(super) fn tenant_key_revocation_replay(
    catalog: &Catalog<'_>,
    tenant: TenantId,
    idempotency: AdministrativeIdempotencyKey,
    actor: PrincipalId,
    principal: PrincipalId,
    expected: ResourceGeneration,
) -> Result<(), ApiKeyAdministrationFailure> {
    let snapshot = catalog.pin().map_err(map_catalog)?;
    let keyring = tenant_keyring(&snapshot, tenant)?;
    if replay_tenant_revocation(
        catalog,
        &keyring,
        tenant,
        idempotency,
        actor,
        principal,
        expected,
    )? {
        Ok(())
    } else {
        Err(ApiKeyAdministrationFailure::IdempotencyConflict)
    }
}
