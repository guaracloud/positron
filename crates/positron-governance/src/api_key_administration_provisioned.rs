//! Provisioned-tenant API-key lifecycle flow.

use super::*;

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
                tenant: Some(tenant),
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
            tenant,
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
                tenant: Some(tenant),
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
            tenant,
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
                tenant: Some(tenant),
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
