//! Joint Catalog proposal and governance-audit publication support.

use super::*;

pub(super) fn commit(
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

pub(super) struct MutationAudit {
    pub(super) idempotency: AdministrativeIdempotencyKey,
    pub(super) actor: PrincipalId,
    pub(super) principal: PrincipalId,
    pub(super) target: PrincipalId,
    pub(super) scope: u8,
    pub(super) expires_at_unix_seconds: Option<u64>,
    pub(super) expected: ResourceGeneration,
    pub(super) generation: ResourceGeneration,
    pub(super) action: ApiKeyLifecycleAction,
}
