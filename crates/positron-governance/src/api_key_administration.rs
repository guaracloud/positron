use std::error::Error;
use std::fmt::{Display, Formatter};

use positron_domain::identity::{PrincipalId, Scope, TenantId};
use positron_kernel::{
    AuditIntent, BootstrapKeyCustody, Catalog, CatalogCredential, CatalogFailureCode,
    CatalogObject, CatalogProposal, CatalogSnapshot, PreparedTransactionResolution, TransactionId,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::audit::ApiKeyLifecycleAuditEntry;
use crate::{
    AdministrativeIdempotencyKey, ApiKeyLifecycleAction, AuthorizedContext, ResourceGeneration,
    TenantAdministration,
};

const TENANT_KEYRING_MAGIC: [u8; 8] = *b"POSTKC01";

pub(crate) struct TenantCredentialIdentity {
    pub(crate) tenant: TenantId,
    pub(crate) credentials: Vec<CatalogCredential>,
}

/// One secret-safe result from a newly created or rotated API key.
pub struct ApiKeyCreation {
    principal: PrincipalId,
    secret: Option<Zeroizing<String>>,
}

/// Canonical, bounded create request bound to an administrative idempotency key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApiKeyCreateRequest {
    actor: AuthorizedContext,
    tenant: Option<TenantId>,
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
            tenant: None,
            scope,
            expires_at_unix_seconds,
            expected,
            idempotency,
        }
    }

    #[must_use]
    pub const fn for_tenant(mut self, tenant: TenantId) -> Self {
        self.tenant = Some(tenant);
        self
    }
}

/// Canonical, bounded rotation request for one default or named tenant keyring.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApiKeyRotationRequest {
    actor: AuthorizedContext,
    tenant: Option<TenantId>,
    predecessor: PrincipalId,
    expected: ResourceGeneration,
    idempotency: AdministrativeIdempotencyKey,
}

impl ApiKeyRotationRequest {
    #[must_use]
    pub const fn new(
        actor: AuthorizedContext,
        predecessor: PrincipalId,
        expected: ResourceGeneration,
        idempotency: AdministrativeIdempotencyKey,
    ) -> Self {
        Self {
            actor,
            tenant: None,
            predecessor,
            expected,
            idempotency,
        }
    }

    #[must_use]
    pub const fn for_tenant(mut self, tenant: TenantId) -> Self {
        self.tenant = Some(tenant);
        self
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
    /// Creates a tenant-bound credential through the same salted-hash,
    /// Catalog-serialized API-key lifecycle authority as default-tenant keys.
    pub fn create_for_tenant(
        catalog: &Catalog<'_>,
        key: &BootstrapKeyCustody,
        administrator: PrincipalId,
        request: ApiKeyCreateRequest,
    ) -> Result<ApiKeyCreation, ApiKeyAdministrationFailure> {
        let tenant = request
            .tenant
            .ok_or(ApiKeyAdministrationFailure::Unauthorized)?;
        if !authorizes(administrator, request.actor) || !request.scope.is_tenant_scoped() {
            return Err(ApiKeyAdministrationFailure::Unauthorized);
        }
        let snapshot = catalog.pin().map_err(map_catalog)?;
        let (_, governance) = snapshot.governance_object().map_err(map_catalog)?;
        if governance.tenant() == tenant {
            return Self::create(catalog, key, administrator, request);
        }
        if !TenantAdministration::registered_tenant_ids(&snapshot)
            .map_err(|_| ApiKeyAdministrationFailure::CredentialUnavailable)?
            .contains(&tenant)
        {
            return Err(ApiKeyAdministrationFailure::CredentialUnavailable);
        }
        let request_digest = tenant_create_request_digest(
            request.idempotency,
            request.actor.principal_id(),
            tenant,
            request.scope,
            request.expires_at_unix_seconds,
            request.expected,
        )?;
        if let Some(replay) = replay_tenant_creation(catalog, &snapshot, request)? {
            return Ok(replay);
        }
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
            PreparedTransactionResolution::Resumed(_) => {
                return tenant_key_replay(catalog, request);
            },
        }
        let keyring = tenant_keyring(&snapshot, tenant)?;
        let generation = ResourceGeneration::new(keyring.generation)
            .map_err(|_| ApiKeyAdministrationFailure::PersistenceUnavailable)?;
        if generation != request.expected {
            return Err(ApiKeyAdministrationFailure::StaleGeneration);
        }
        let next = generation
            .get()
            .checked_add(1)
            .ok_or(ApiKeyAdministrationFailure::PersistenceUnavailable)?;
        let CredentialMaterial {
            principal,
            salt,
            raw_secret,
            hash,
        } = credential_material(key)?;
        let scope_code =
            scope_code(request.scope).ok_or(ApiKeyAdministrationFailure::Unauthorized)?;
        let mut credentials = credentials_with_capacity(&keyring.credentials)?;
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
        let replacement = encode_tenant_keyring(tenant, next, &credentials)?;
        commit_tenant_keyring(
            catalog,
            &snapshot,
            tenant,
            replacement,
            MutationAudit {
                idempotency: request.idempotency,
                actor: request.actor.principal_id(),
                principal,
                target: principal,
                scope: scope_code,
                expires_at_unix_seconds: request.expires_at_unix_seconds,
                expected: request.expected,
                generation: ResourceGeneration::new(next)
                    .map_err(|_| ApiKeyAdministrationFailure::PersistenceUnavailable)?,
                action: ApiKeyLifecycleAction::Create,
            },
            request_digest,
        )?;
        Ok(ApiKeyCreation {
            principal,
            secret: Some(Zeroizing::new(format_secret(&raw_secret))),
        })
    }

    pub(crate) fn tenant_credential_identities(
        snapshot: &CatalogSnapshot,
    ) -> Result<Vec<TenantCredentialIdentity>, ApiKeyAdministrationFailure> {
        let registered = TenantAdministration::registered_tenant_ids(snapshot)
            .map_err(|_| ApiKeyAdministrationFailure::PersistenceUnavailable)?;
        let (_, governance) = snapshot.governance_object().map_err(map_catalog)?;
        let mut identities = Vec::new();
        for tenant in registered {
            if let Some(keyring) = find_tenant_keyring(snapshot, tenant)? {
                if tenant == governance.tenant() {
                    return Err(ApiKeyAdministrationFailure::PersistenceUnavailable);
                }
                identities.push(TenantCredentialIdentity {
                    tenant,
                    credentials: keyring.credentials,
                });
            }
        }
        Ok(identities)
    }

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

    /// Lists redacted credentials bound to one explicit tenant. The default
    /// tenant continues to use the sole POSGOV credential authority.
    pub fn list_for_tenant(
        catalog: &Catalog<'_>,
        administrator: PrincipalId,
        actor: AuthorizedContext,
        tenant: TenantId,
    ) -> Result<Vec<ApiKeyDescriptor>, ApiKeyAdministrationFailure> {
        if !authorizes(administrator, actor) {
            return Err(ApiKeyAdministrationFailure::Unauthorized);
        }
        let snapshot = catalog.pin().map_err(map_catalog)?;
        let (_, governance) = snapshot.governance_object().map_err(map_catalog)?;
        if governance.tenant() == tenant {
            return Self::list(catalog, administrator, actor);
        }
        ensure_registered_tenant(&snapshot, tenant)?;
        let keyring = tenant_keyring(&snapshot, tenant)?;
        descriptors(&keyring.credentials, keyring.generation)
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
        request: ApiKeyRotationRequest,
    ) -> Result<ApiKeyCreation, ApiKeyAdministrationFailure> {
        if request.tenant.is_some() || !authorizes(administrator, request.actor) {
            return Err(ApiKeyAdministrationFailure::Unauthorized);
        }
        let snapshot = catalog.pin().map_err(map_catalog)?;
        let (_, governance) = snapshot.governance_object().map_err(map_catalog)?;
        if let Some(replay) = replay_rotation(
            catalog,
            request.idempotency,
            request.actor.principal_id(),
            request.predecessor,
            request.expected,
        )? {
            return Ok(replay);
        }
        let predecessor = governance
            .credentials()
            .iter()
            .find(|credential| {
                credential.principal() == request.predecessor
                    && credential.is_active()
                    && credential.scope_code() != 4
            })
            .ok_or(ApiKeyAdministrationFailure::CredentialUnavailable)?;
        let request_digest = rotate_request_digest(
            request.idempotency,
            request.actor.principal_id(),
            predecessor.principal(),
            predecessor.scope_code(),
            predecessor.expires_at_unix_seconds(),
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
                if lifecycle.action() != ApiKeyLifecycleAction::Rotate
                    || lifecycle.actor_id() != request.actor.principal_id()
                    || lifecycle.target_principal_id() != predecessor.principal()
                    || lifecycle.scope()
                        != scope_from_code(predecessor.scope_code())
                            .ok_or(ApiKeyAdministrationFailure::PersistenceUnavailable)?
                    || lifecycle.expires_at_unix_seconds() != predecessor.expires_at_unix_seconds()
                    || lifecycle.expected_generation() != request.expected
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
                idempotency: request.idempotency,
                actor: request.actor.principal_id(),
                principal,
                target: predecessor.principal(),
                scope,
                expires_at_unix_seconds: predecessor.expires_at_unix_seconds(),
                expected: request.expected,
                generation: ResourceGeneration::new(generation)
                    .map_err(|_| ApiKeyAdministrationFailure::PersistenceUnavailable)?,
                action: ApiKeyLifecycleAction::Rotate,
            },
            Some(request_digest),
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

    /// Creates a successor in the named secondary tenant's keyring. The
    /// predecessor remains active until a separately idempotent revoke.
    pub fn rotate_for_tenant(
        catalog: &Catalog<'_>,
        key: &BootstrapKeyCustody,
        administrator: PrincipalId,
        request: ApiKeyRotationRequest,
    ) -> Result<ApiKeyCreation, ApiKeyAdministrationFailure> {
        let tenant = request
            .tenant
            .ok_or(ApiKeyAdministrationFailure::Unauthorized)?;
        if !authorizes(administrator, request.actor) {
            return Err(ApiKeyAdministrationFailure::Unauthorized);
        }
        let snapshot = catalog.pin().map_err(map_catalog)?;
        let (_, governance) = snapshot.governance_object().map_err(map_catalog)?;
        if governance.tenant() == tenant {
            return Self::rotate(catalog, key, administrator, request);
        }
        ensure_registered_tenant(&snapshot, tenant)?;
        let keyring = tenant_keyring(&snapshot, tenant)?;
        if let Some(replay) = replay_tenant_rotation(
            catalog,
            &keyring,
            request.idempotency,
            request.actor.principal_id(),
            request.predecessor,
            request.expected,
        )? {
            return Ok(replay);
        }
        let predecessor = active_tenant_credential(&keyring, request.predecessor)?;
        let request_digest = tenant_rotate_request_digest(
            request.idempotency,
            request.actor.principal_id(),
            tenant,
            predecessor.principal(),
            predecessor.scope_code(),
            predecessor.expires_at_unix_seconds(),
            request.expected,
        );
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
            PreparedTransactionResolution::Resumed(_) => {
                return tenant_key_rotation_replay(
                    catalog,
                    tenant,
                    request.idempotency,
                    request.actor.principal_id(),
                    predecessor.principal(),
                    request.expected,
                );
            },
        }
        let generation = next_generation(keyring.generation, request.expected)?;
        let CredentialMaterial {
            principal,
            salt,
            raw_secret,
            hash,
        } = credential_material(key)?;
        let mut credentials = credentials_with_capacity(&keyring.credentials)?;
        credentials.push(
            CatalogCredential::new(
                principal,
                predecessor.scope_code(),
                true,
                predecessor.expires_at_unix_seconds(),
                salt,
                hash,
            )
            .map_err(map_catalog)?,
        );
        commit_tenant_keyring(
            catalog,
            &snapshot,
            tenant,
            encode_tenant_keyring(tenant, generation, &credentials)?,
            MutationAudit {
                idempotency: request.idempotency,
                actor: request.actor.principal_id(),
                principal,
                target: predecessor.principal(),
                scope: predecessor.scope_code(),
                expires_at_unix_seconds: predecessor.expires_at_unix_seconds(),
                expected: request.expected,
                generation: ResourceGeneration::new(generation)
                    .map_err(|_| ApiKeyAdministrationFailure::PersistenceUnavailable)?,
                action: ApiKeyLifecycleAction::Rotate,
            },
            request_digest,
        )?;
        Ok(ApiKeyCreation {
            principal,
            secret: Some(Zeroizing::new(format_secret(&raw_secret))),
        })
    }

    /// Revokes one named secondary-tenant credential while retaining its
    /// redacted descriptor and replay result.
    pub fn revoke_for_tenant(
        catalog: &Catalog<'_>,
        administrator: PrincipalId,
        actor: AuthorizedContext,
        tenant: TenantId,
        principal: PrincipalId,
        expected: ResourceGeneration,
        idempotency: AdministrativeIdempotencyKey,
    ) -> Result<(), ApiKeyAdministrationFailure> {
        if !authorizes(administrator, actor) {
            return Err(ApiKeyAdministrationFailure::Unauthorized);
        }
        let snapshot = catalog.pin().map_err(map_catalog)?;
        let (_, governance) = snapshot.governance_object().map_err(map_catalog)?;
        if governance.tenant() == tenant {
            return Self::revoke(
                catalog,
                administrator,
                actor,
                principal,
                expected,
                idempotency,
            );
        }
        ensure_registered_tenant(&snapshot, tenant)?;
        let keyring = tenant_keyring(&snapshot, tenant)?;
        if replay_tenant_revocation(
            catalog,
            &keyring,
            idempotency,
            actor.principal_id(),
            principal,
            expected,
        )? {
            return Ok(());
        }
        let index = keyring
            .credentials
            .iter()
            .position(|credential| {
                credential.principal() == principal
                    && credential.is_active()
                    && credential.scope_code() != 4
            })
            .ok_or(ApiKeyAdministrationFailure::CredentialUnavailable)?;
        let scope = keyring.credentials[index].scope_code();
        let expires_at_unix_seconds = keyring.credentials[index].expires_at_unix_seconds();
        let request_digest = tenant_revoke_request_digest(
            idempotency,
            actor.principal_id(),
            tenant,
            principal,
            scope,
            expires_at_unix_seconds,
            expected,
        );
        match catalog
            .resume_prepared(
                TransactionId::new(idempotency.to_bytes()).map_err(map_catalog)?,
                request_digest,
            )
            .map_err(map_catalog)?
        {
            PreparedTransactionResolution::Absent => {},
            PreparedTransactionResolution::Unavailable => {
                return Err(ApiKeyAdministrationFailure::PersistenceUnavailable);
            },
            PreparedTransactionResolution::Resumed(_) => {
                return tenant_key_revocation_replay(
                    catalog,
                    tenant,
                    idempotency,
                    actor.principal_id(),
                    principal,
                    expected,
                );
            },
        }
        let generation = next_generation(keyring.generation, expected)?;
        let mut credentials = keyring.credentials;
        credentials[index] = credentials[index].with_active(false);
        commit_tenant_keyring(
            catalog,
            &snapshot,
            tenant,
            encode_tenant_keyring(tenant, generation, &credentials)?,
            MutationAudit {
                idempotency,
                actor: actor.principal_id(),
                principal,
                target: principal,
                scope,
                expires_at_unix_seconds,
                expected,
                generation: ResourceGeneration::new(generation)
                    .map_err(|_| ApiKeyAdministrationFailure::PersistenceUnavailable)?,
                action: ApiKeyLifecycleAction::Revoke,
            },
            request_digest,
        )
    }
}

fn authorizes(administrator: PrincipalId, actor: AuthorizedContext) -> bool {
    actor.principal_id() == administrator
        && actor.scope() == Scope::SystemAdministration
        && actor.tenant_attribution().is_none()
}

fn ensure_registered_tenant(
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

fn descriptors(
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

#[path = "api_key_administration_replay.rs"]
mod api_key_administration_replay;
use api_key_administration_replay::*;

fn active_tenant_credential(
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

#[path = "api_key_administration_keyring.rs"]
mod api_key_administration_keyring;
use api_key_administration_keyring::*;

fn tenant_create_request_digest(
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

fn tenant_rotate_request_digest(
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

fn tenant_revoke_request_digest(
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

fn tenant_key_replay(
    catalog: &Catalog<'_>,
    request: ApiKeyCreateRequest,
) -> Result<ApiKeyCreation, ApiKeyAdministrationFailure> {
    let snapshot = catalog.pin().map_err(map_catalog)?;
    replay_tenant_creation(catalog, &snapshot, request)?
        .ok_or(ApiKeyAdministrationFailure::IdempotencyConflict)
}

fn replay_tenant_creation(
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

fn rotate_request_digest(
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

struct CredentialMaterial {
    principal: PrincipalId,
    salt: [u8; 32],
    raw_secret: Zeroizing<[u8; 32]>,
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
        snapshot
            .format_epoch()
            .ok_or(ApiKeyAdministrationFailure::PersistenceUnavailable)?,
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
