//! Canonical API-key lifecycle request digests.

use super::*;

pub(super) fn tenant_create_request_digest(
    idempotency: AdministrativeIdempotencyKey,
    actor: PrincipalId,
    tenant: TenantId,
    scope: Scope,
    expires_at_unix_seconds: Option<u64>,
    expected: ResourceGeneration,
) -> Result<[u8; 32], ApiKeyAdministrationFailure> {
    let scope = scope_code(scope).ok_or(ApiKeyAdministrationFailure::Unauthorized)?;
    let mut digest = Sha256::new();
    digest.update(b"positron-tenant-api-key-create-request-v1");
    digest.update(idempotency.to_bytes());
    digest.update(actor.to_bytes());
    digest.update(tenant.to_bytes());
    digest.update([scope]);
    digest.update(expires_at_unix_seconds.unwrap_or(0).to_be_bytes());
    digest.update(expected.get().to_be_bytes());
    Ok(digest.finalize().into())
}

pub(super) fn tenant_rotate_request_digest(
    idempotency: AdministrativeIdempotencyKey,
    actor: PrincipalId,
    tenant: TenantId,
    predecessor: PrincipalId,
    scope: u8,
    expires_at_unix_seconds: Option<u64>,
    expected: ResourceGeneration,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"positron-tenant-api-key-rotate-request-v1");
    digest.update(idempotency.to_bytes());
    digest.update(actor.to_bytes());
    digest.update(tenant.to_bytes());
    digest.update(predecessor.to_bytes());
    digest.update([scope]);
    digest.update(expires_at_unix_seconds.unwrap_or(0).to_be_bytes());
    digest.update(expected.get().to_be_bytes());
    digest.finalize().into()
}

pub(super) fn tenant_revoke_request_digest(
    idempotency: AdministrativeIdempotencyKey,
    actor: PrincipalId,
    tenant: TenantId,
    principal: PrincipalId,
    scope: u8,
    expires_at_unix_seconds: Option<u64>,
    expected: ResourceGeneration,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"positron-tenant-api-key-revoke-request-v1");
    digest.update(idempotency.to_bytes());
    digest.update(actor.to_bytes());
    digest.update(tenant.to_bytes());
    digest.update(principal.to_bytes());
    digest.update([scope]);
    digest.update(expires_at_unix_seconds.unwrap_or(0).to_be_bytes());
    digest.update(expected.get().to_be_bytes());
    digest.finalize().into()
}

pub(super) fn create_request_digest(
    idempotency: AdministrativeIdempotencyKey,
    actor: PrincipalId,
    scope: Scope,
    expires_at_unix_seconds: Option<u64>,
    expected: ResourceGeneration,
) -> Result<[u8; 32], ApiKeyAdministrationFailure> {
    let scope = scope_code(scope).ok_or(ApiKeyAdministrationFailure::Unauthorized)?;
    let mut digest = Sha256::new();
    digest.update(b"positron-api-key-create-request-v1");
    digest.update(idempotency.to_bytes());
    digest.update(actor.to_bytes());
    digest.update([scope]);
    match expires_at_unix_seconds {
        Some(value) => {
            digest.update([1]);
            digest.update(value.to_be_bytes());
        },
        None => digest.update([0]),
    }
    digest.update(expected.get().to_be_bytes());
    Ok(digest.finalize().into())
}

pub(super) fn rotate_request_digest(
    idempotency: AdministrativeIdempotencyKey,
    actor: PrincipalId,
    predecessor: PrincipalId,
    scope: u8,
    expires_at_unix_seconds: Option<u64>,
    expected: ResourceGeneration,
) -> Result<[u8; 32], ApiKeyAdministrationFailure> {
    let mut digest = Sha256::new();
    digest.update(b"positron-api-key-rotate-request-v1");
    digest.update(idempotency.to_bytes());
    digest.update(actor.to_bytes());
    digest.update(predecessor.to_bytes());
    digest.update([scope]);
    match expires_at_unix_seconds {
        Some(value) => {
            digest.update([1]);
            digest.update(value.to_be_bytes());
        },
        None => digest.update([0]),
    }
    digest.update(expected.get().to_be_bytes());
    Ok(digest.finalize().into())
}

pub(super) fn revoke_request_digest(
    idempotency: AdministrativeIdempotencyKey,
    actor: PrincipalId,
    principal: PrincipalId,
    scope: u8,
    expires_at_unix_seconds: Option<u64>,
    expected: ResourceGeneration,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"positron-api-key-revoke-request-v1");
    digest.update(idempotency.to_bytes());
    digest.update(actor.to_bytes());
    digest.update(principal.to_bytes());
    digest.update([scope]);
    match expires_at_unix_seconds {
        Some(value) => {
            digest.update([1]);
            digest.update(value.to_be_bytes());
        },
        None => digest.update([0]),
    }
    digest.update(expected.get().to_be_bytes());
    digest.finalize().into()
}
