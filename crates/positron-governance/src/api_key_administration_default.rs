//! Default-tenant API-key lifecycle flow.

use super::*;

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
        let request_digest = create_request_digest(
            request.idempotency,
            request.actor.principal_id(),
            request.scope,
            request.expires_at_unix_seconds,
            request.expected,
        )?;
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
                    || lifecycle.request_digest() != Some(request_digest)
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
                tenant: None,
                principal,
                target: principal,
                scope: scope_code,
                expires_at_unix_seconds: request.expires_at_unix_seconds,
                expected: request.expected,
                generation: ResourceGeneration::new(generation)
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
                    || lifecycle.request_digest() != Some(request_digest)
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
                tenant: None,
                principal,
                target: predecessor.principal(),
                scope,
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
        let request_digest = revoke_request_digest(
            idempotency,
            actor.principal_id(),
            principal,
            scope,
            credentials[index].expires_at_unix_seconds(),
            expected,
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
                tenant: None,
                principal,
                target: principal,
                scope,
                expires_at_unix_seconds: credentials[index].expires_at_unix_seconds(),
                expected,
                generation: ResourceGeneration::new(generation)
                    .map_err(|_| ApiKeyAdministrationFailure::PersistenceUnavailable)?,
                action: ApiKeyLifecycleAction::Revoke,
            },
            request_digest,
        )
    }
}
