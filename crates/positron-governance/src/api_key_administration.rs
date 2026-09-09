use std::error::Error;
use std::fmt::{Display, Formatter};

use positron_domain::identity::{PrincipalId, Scope};
use positron_kernel::{
    AuditIntent, BootstrapKeyCustody, Catalog, CatalogCredential, CatalogFailureCode,
    CatalogObject, CatalogProposal, CatalogSnapshot, FormatEpoch, PreparedTransactionResolution,
    TransactionId,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::audit::ApiKeyLifecycleAuditEntry;
use crate::{
    AdministrativeIdempotencyKey, ApiKeyLifecycleAction, AuthorizedContext, ResourceGeneration,
};

/// One secret-safe result from a newly created or rotated API key.
pub struct ApiKeyCreation {
    principal: PrincipalId,
    secret: Option<Zeroizing<String>>,
}

/// Canonical, bounded create request bound to an administrative idempotency key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApiKeyCreateRequest {
    actor: AuthorizedContext,
    scope: Scope,
    expires_at_unix_seconds: Option<u64>,
    expected: ResourceGeneration,
    idempotency: AdministrativeIdempotencyKey,
}

/// Redacted API-key lifecycle inspection result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApiKeyDescriptor {
    principal: PrincipalId,
    scope: Scope,
    active: bool,
    expires_at_unix_seconds: Option<u64>,
    generation: ResourceGeneration,
}

impl ApiKeyDescriptor {
    #[must_use]
    pub const fn principal_id(self) -> PrincipalId {
        self.principal
    }
    #[must_use]
    pub const fn scope(self) -> Scope {
        self.scope
    }
    #[must_use]
    pub const fn is_active(self) -> bool {
        self.active
    }
    #[must_use]
    pub const fn expires_at_unix_seconds(self) -> Option<u64> {
        self.expires_at_unix_seconds
    }
    #[must_use]
    pub const fn generation(self) -> ResourceGeneration {
        self.generation
    }
}

impl ApiKeyCreateRequest {
    #[must_use]
    pub const fn new(
        actor: AuthorizedContext,
        scope: Scope,
        expires_at_unix_seconds: Option<u64>,
        expected: ResourceGeneration,
        idempotency: AdministrativeIdempotencyKey,
    ) -> Self {
        Self {
            actor,
            scope,
            expires_at_unix_seconds,
            expected,
            idempotency,
        }
    }
}

impl ApiKeyCreation {
    #[must_use]
    pub fn secret(&self) -> Option<&str> {
        self.secret.as_deref().map(String::as_str)
    }

    #[must_use]
    pub const fn principal_id(&self) -> PrincipalId {
        self.principal
    }
}

impl std::fmt::Debug for ApiKeyCreation {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ApiKeyCreation { <redacted> }")
    }
}

/// Closed outcomes for Administration-owned API-key lifecycle work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApiKeyAdministrationFailure {
    Unauthorized,
    StaleGeneration,
    IdempotencyConflict,
    CapacityExceeded,
    CredentialUnavailable,
    PersistenceUnavailable,
}

impl Display for ApiKeyAdministrationFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("API-key administration failed")
    }
}

impl Error for ApiKeyAdministrationFailure {}

/// Administration owns semantic API-key lifecycle mutation; Catalog remains
/// the only durable publication authority and Identity remains read-only.
pub struct ApiKeyAdministration;

impl ApiKeyAdministration {
    pub fn list(
        catalog: &Catalog<'_>,
        administrator: PrincipalId,
        actor: AuthorizedContext,
    ) -> Result<Vec<ApiKeyDescriptor>, ApiKeyAdministrationFailure> {
        if !authorizes(administrator, actor) {
            return Err(ApiKeyAdministrationFailure::Unauthorized);
        }
        let snapshot = catalog.pin().map_err(map_catalog)?;
        let (_, governance) = snapshot.governance_object().map_err(map_catalog)?;
        let generation = ResourceGeneration::new(governance.credential_generation())
            .map_err(|_| ApiKeyAdministrationFailure::PersistenceUnavailable)?;
        let mut descriptors = Vec::new();
        descriptors
            .try_reserve_exact(governance.credentials().len())
            .map_err(|_| ApiKeyAdministrationFailure::CapacityExceeded)?;
        for credential in governance.credentials() {
            let scope = scope_from_code(credential.scope_code())
                .ok_or(ApiKeyAdministrationFailure::PersistenceUnavailable)?;
            descriptors.push(ApiKeyDescriptor {
                principal: credential.principal(),
                scope,
                active: credential.is_active(),
                expires_at_unix_seconds: credential.expires_at_unix_seconds(),
                generation,
            });
        }
        Ok(descriptors)
    }

    pub fn create(
        catalog: &Catalog<'_>,
        key: &BootstrapKeyCustody,
        administrator: PrincipalId,
        request: ApiKeyCreateRequest,
    ) -> Result<ApiKeyCreation, ApiKeyAdministrationFailure> {
        if !authorizes(administrator, request.actor) || !request.scope.is_tenant_scoped() {
            return Err(ApiKeyAdministrationFailure::Unauthorized);
        }
        let snapshot = catalog.pin().map_err(map_catalog)?;
        let (_, governance) = snapshot.governance_object().map_err(map_catalog)?;
        if let Some(replay) = replay_creation(
            catalog,
            request.idempotency,
            request.actor.principal_id(),
            request.scope,
            request.expires_at_unix_seconds,
            request.expected,
            governance.credentials(),
        )? {
            return Ok(replay);
        }
        let request_digest = create_request_digest(
            request.idempotency,
            request.actor.principal_id(),
            request.scope,
            request.expires_at_unix_seconds,
            request.expected,
        )?;
        match catalog
            .resume_prepared(
                TransactionId::new(request.idempotency.to_bytes()).map_err(map_catalog)?,
                request_digest,
            )
            .map_err(map_catalog)?
        {
            PreparedTransactionResolution::Absent => {},
            PreparedTransactionResolution::Unavailable => {
                return Err(ApiKeyAdministrationFailure::PersistenceUnavailable);
            },
            PreparedTransactionResolution::Resumed(commit) => {
                let audit = commit
                    .governance_audit_record()
                    .ok_or(ApiKeyAdministrationFailure::PersistenceUnavailable)?;
                let entry = crate::GovernanceAuditEntry::decode(audit)
                    .map_err(|_| ApiKeyAdministrationFailure::PersistenceUnavailable)?;
                let lifecycle = entry
                    .as_api_key_lifecycle()
                    .ok_or(ApiKeyAdministrationFailure::PersistenceUnavailable)?;
                if lifecycle.actor_id() != request.actor.principal_id()
                    || lifecycle.scope() != request.scope
                    || lifecycle.expires_at_unix_seconds() != request.expires_at_unix_seconds
                    || lifecycle.expected_generation() != request.expected
                    || lifecycle.action() != ApiKeyLifecycleAction::Create
                {
                    return Err(ApiKeyAdministrationFailure::IdempotencyConflict);
                }
                return Ok(ApiKeyCreation {
                    principal: lifecycle.principal_id(),
                    secret: None,
                });
            },
        }
        let generation = next_generation(governance.credential_generation(), request.expected)?;
        let mut credentials = credentials_with_capacity(governance.credentials())?;
        let CredentialMaterial {
            principal,
            salt,
            raw_secret,
            hash,
        } = credential_material(key)?;
        let scope_code =
            scope_code(request.scope).ok_or(ApiKeyAdministrationFailure::Unauthorized)?;
        credentials.push(
            CatalogCredential::new(
                principal,
                scope_code,
                true,
                request.expires_at_unix_seconds,
                salt,
                hash,
            )
            .map_err(map_catalog)?,
        );
        let replacement = governance
            .with_credentials(generation, &credentials)
            .map_err(map_catalog)?;
        commit(
            catalog,
            &snapshot,
            replacement,
            MutationAudit {
                idempotency: request.idempotency,
                actor: request.actor.principal_id(),
                principal,
                target: principal,
                scope: scope_code,
                expires_at_unix_seconds: request.expires_at_unix_seconds,
                expected: request.expected,
                generation: ResourceGeneration::new(generation)
                    .map_err(|_| ApiKeyAdministrationFailure::PersistenceUnavailable)?,
                action: ApiKeyLifecycleAction::Create,
            },
            Some(request_digest),
        )?;
        Ok(ApiKeyCreation {
            principal,
            secret: Some(Zeroizing::new(format_secret(&raw_secret))),
        })
    }

    pub fn rotate(
        catalog: &Catalog<'_>,
        key: &BootstrapKeyCustody,
        administrator: PrincipalId,
        actor: AuthorizedContext,
        predecessor: PrincipalId,
        expected: ResourceGeneration,
        idempotency: AdministrativeIdempotencyKey,
    ) -> Result<ApiKeyCreation, ApiKeyAdministrationFailure> {
        if !authorizes(administrator, actor) {
            return Err(ApiKeyAdministrationFailure::Unauthorized);
        }
        let snapshot = catalog.pin().map_err(map_catalog)?;
        let (_, governance) = snapshot.governance_object().map_err(map_catalog)?;
        if let Some(replay) = replay_rotation(
            catalog,
            idempotency,
            actor.principal_id(),
            predecessor,
            expected,
        )? {
            return Ok(replay);
        }
        let generation = next_generation(governance.credential_generation(), expected)?;
        let predecessor = governance
            .credentials()
            .iter()
            .find(|credential| {
                credential.principal() == predecessor
                    && credential.is_active()
                    && credential.scope_code() != 4
            })
            .ok_or(ApiKeyAdministrationFailure::CredentialUnavailable)?;
        let mut credentials = credentials_with_capacity(governance.credentials())?;
        let CredentialMaterial {
            principal,
            salt,
            raw_secret,
            hash,
        } = credential_material(key)?;
        let scope = predecessor.scope_code();
        credentials.push(
            CatalogCredential::new(
                principal,
                scope,
                true,
                predecessor.expires_at_unix_seconds(),
                salt,
                hash,
            )
            .map_err(map_catalog)?,
        );
        let replacement = governance
            .with_credentials(generation, &credentials)
            .map_err(map_catalog)?;
        commit(
            catalog,
            &snapshot,
            replacement,
            MutationAudit {
                idempotency,
                actor: actor.principal_id(),
                principal,
                target: predecessor.principal(),
                scope,
                expires_at_unix_seconds: predecessor.expires_at_unix_seconds(),
                expected,
                generation: ResourceGeneration::new(generation)
                    .map_err(|_| ApiKeyAdministrationFailure::PersistenceUnavailable)?,
                action: ApiKeyLifecycleAction::Rotate,
            },
            None,
        )?;
        Ok(ApiKeyCreation {
            principal,
            secret: Some(Zeroizing::new(format_secret(&raw_secret))),
        })
    }

    pub fn revoke(
        catalog: &Catalog<'_>,
        administrator: PrincipalId,
        actor: AuthorizedContext,
        principal: PrincipalId,
        expected: ResourceGeneration,
        idempotency: AdministrativeIdempotencyKey,
    ) -> Result<(), ApiKeyAdministrationFailure> {
        if !authorizes(administrator, actor) {
            return Err(ApiKeyAdministrationFailure::Unauthorized);
        }
        let snapshot = catalog.pin().map_err(map_catalog)?;
        let (_, governance) = snapshot.governance_object().map_err(map_catalog)?;
        if replay_revocation(
            catalog,
            idempotency,
            actor.principal_id(),
            principal,
            expected,
        )? {
            return Ok(());
        }
        let generation = next_generation(governance.credential_generation(), expected)?;
        let mut credentials = governance.credentials().to_vec();
        let index = credentials
            .iter()
            .position(|credential| {
                credential.principal() == principal
                    && credential.is_active()
                    && credential.scope_code() != 4
            })
            .ok_or(ApiKeyAdministrationFailure::CredentialUnavailable)?;
        credentials[index] = credentials[index].with_active(false);
        let scope = credentials[index].scope_code();
        let replacement = governance
            .with_credentials(generation, &credentials)
            .map_err(map_catalog)?;
        commit(
            catalog,
            &snapshot,
            replacement,
            MutationAudit {
                idempotency,
                actor: actor.principal_id(),
                principal,
                target: principal,
                scope,
                expires_at_unix_seconds: credentials[index].expires_at_unix_seconds(),
                expected,
                generation: ResourceGeneration::new(generation)
                    .map_err(|_| ApiKeyAdministrationFailure::PersistenceUnavailable)?,
                action: ApiKeyLifecycleAction::Revoke,
            },
            None,
        )
    }
}

fn authorizes(administrator: PrincipalId, actor: AuthorizedContext) -> bool {
    actor.principal_id() == administrator
        && actor.scope() == Scope::SystemAdministration
        && actor.tenant_attribution().is_none()
}

fn next_generation(
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

fn credentials_with_capacity(
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

fn replay_creation(
    catalog: &Catalog<'_>,
    idempotency: AdministrativeIdempotencyKey,
    actor: PrincipalId,
    scope: Scope,
    expires_at_unix_seconds: Option<u64>,
    expected: ResourceGeneration,
    credentials: &[CatalogCredential],
) -> Result<Option<ApiKeyCreation>, ApiKeyAdministrationFailure> {
    let Some(lifecycle) = replay_entry(catalog, idempotency)? else {
        return Ok(None);
    };
    let scope_code = scope_code(scope).ok_or(ApiKeyAdministrationFailure::Unauthorized)?;
    let request_matches = lifecycle.actor_id() == actor
        && lifecycle.scope() == scope
        && lifecycle.expires_at_unix_seconds() == expires_at_unix_seconds
        && lifecycle.expected_generation() == expected
        && lifecycle.action() == ApiKeyLifecycleAction::Create;
    if !request_matches {
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

fn replay_rotation(
    catalog: &Catalog<'_>,
    idempotency: AdministrativeIdempotencyKey,
    actor: PrincipalId,
    predecessor: PrincipalId,
    expected: ResourceGeneration,
) -> Result<Option<ApiKeyCreation>, ApiKeyAdministrationFailure> {
    let Some(lifecycle) = replay_entry(catalog, idempotency)? else {
        return Ok(None);
    };
    if lifecycle.action() != ApiKeyLifecycleAction::Rotate
        || lifecycle.actor_id() != actor
        || lifecycle.target_principal_id() != predecessor
        || lifecycle.expected_generation() != expected
    {
        return Err(ApiKeyAdministrationFailure::IdempotencyConflict);
    }
    Ok(Some(ApiKeyCreation {
        principal: lifecycle.principal_id(),
        secret: None,
    }))
}

fn replay_revocation(
    catalog: &Catalog<'_>,
    idempotency: AdministrativeIdempotencyKey,
    actor: PrincipalId,
    principal: PrincipalId,
    expected: ResourceGeneration,
) -> Result<bool, ApiKeyAdministrationFailure> {
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

fn replay_entry(
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

fn credential_material(
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
    let hash = key
        .salted_secret_hash(salt.as_ref(), raw_secret.as_ref())
        .map_err(|_| ApiKeyAdministrationFailure::PersistenceUnavailable)?;
    Ok(CredentialMaterial {
        principal,
        salt: *salt,
        raw_secret: *raw_secret,
        hash,
    })
}

fn create_request_digest(
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

struct CredentialMaterial {
    principal: PrincipalId,
    salt: [u8; 32],
    raw_secret: [u8; 32],
    hash: [u8; 32],
}

fn scope_code(scope: Scope) -> Option<u8> {
    match scope {
        Scope::Ingest => Some(1),
        Scope::Query => Some(2),
        Scope::TenantAdministration => Some(3),
        Scope::SystemAdministration => None,
    }
}

fn scope_from_code(scope: u8) -> Option<Scope> {
    match scope {
        1 => Some(Scope::Ingest),
        2 => Some(Scope::Query),
        3 => Some(Scope::TenantAdministration),
        4 => Some(Scope::SystemAdministration),
        _ => None,
    }
}

fn commit(
    catalog: &Catalog<'_>,
    snapshot: &CatalogSnapshot,
    replacement: Vec<u8>,
    audit_fields: MutationAudit,
    prepared_request: Option<[u8; 32]>,
) -> Result<(), ApiKeyAdministrationFailure> {
    let mut objects = Vec::new();
    for object_id in snapshot.object_identities() {
        let bytes = snapshot
            .object(object_id)
            .map_err(map_catalog)?
            .ok_or(ApiKeyAdministrationFailure::PersistenceUnavailable)?;
        if !bytes.starts_with(b"POSGOV") {
            objects.push(CatalogObject::new(bytes.to_vec()).map_err(map_catalog)?);
        }
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
    let proposal = CatalogProposal::new(
        TransactionId::new(audit_fields.idempotency.to_bytes()).map_err(map_catalog)?,
        FormatEpoch::CATALOG_V1,
        objects,
    )
    .map_err(map_catalog)?;
    let audit = AuditIntent::new(audit).map_err(map_catalog)?;
    match prepared_request {
        Some(request_digest) => catalog
            .commit_prepared(snapshot.identity(), proposal, audit, request_digest)
            .map_err(map_catalog)?,
        None => catalog
            .commit(snapshot.identity(), proposal, Some(audit))
            .map_err(map_catalog)?,
    };
    Ok(())
}

struct MutationAudit {
    idempotency: AdministrativeIdempotencyKey,
    actor: PrincipalId,
    principal: PrincipalId,
    target: PrincipalId,
    scope: u8,
    expires_at_unix_seconds: Option<u64>,
    expected: ResourceGeneration,
    generation: ResourceGeneration,
    action: ApiKeyLifecycleAction,
}

fn format_secret(secret: &[u8; 32]) -> String {
    let mut rendered = String::with_capacity(68);
    rendered.push_str("pos_");
    for byte in secret {
        rendered.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
        rendered.push(char::from(b"0123456789abcdef"[usize::from(byte & 15)]));
    }
    rendered
}

fn map_catalog(failure: positron_kernel::CatalogFailure) -> ApiKeyAdministrationFailure {
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
