//! Joint Catalog proposal and governance-audit publication support.

use super::*;

pub(super) fn commit(
    catalog: &Catalog<'_>,
    snapshot: &CatalogSnapshot,
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
        if !bytes.starts_with(b"POSGOV") {
            objects.push(CatalogObject::new(bytes.to_vec()).map_err(map_catalog)?);
        }
    }
    objects.push(CatalogObject::new(replacement).map_err(map_catalog)?);
    let audit_position = next_audit_position(snapshot)?;
    objects.push(object(ReceiptFields {
        key: audit_fields.idempotency,
        actor: audit_fields.actor,
        tenant: audit_fields.tenant,
        action: audit_fields.action,
        scope: audit_fields.scope,
        expires_at_unix_seconds: audit_fields.expires_at_unix_seconds,
        expected: audit_fields.expected,
        generation: audit_fields.generation,
        principal: audit_fields.principal,
        target: audit_fields.target,
        audit_position,
        request_digest,
    })?);
    let mut audit = Vec::with_capacity(130);
    audit.extend_from_slice(b"POSKEY02");
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
    audit.extend_from_slice(&request_digest);
    let proposal = CatalogProposal::new(
        TransactionId::new(audit_fields.idempotency.to_bytes()).map_err(map_catalog)?,
        snapshot
            .format_epoch()
            .ok_or(ApiKeyAdministrationFailure::PersistenceUnavailable)?,
        objects,
    )
    .map_err(map_catalog)?;
    let audit = AuditIntent::new(audit).map_err(map_catalog)?;
    let commit = catalog
        .commit_prepared(snapshot.identity(), proposal, audit, request_digest)
        .map_err(map_catalog)?;
    if commit
        .governance_audit_record()
        .map(|record| record.position())
        != Some(audit_position)
    {
        return Err(ApiKeyAdministrationFailure::PersistenceUnavailable);
    }
    Ok(())
}

pub(super) struct MutationAudit {
    pub(super) idempotency: AdministrativeIdempotencyKey,
    pub(super) actor: PrincipalId,
    pub(super) tenant: Option<TenantId>,
    pub(super) principal: PrincipalId,
    pub(super) target: PrincipalId,
    pub(super) scope: u8,
    pub(super) expires_at_unix_seconds: Option<u64>,
    pub(super) expected: ResourceGeneration,
    pub(super) generation: ResourceGeneration,
    pub(super) action: ApiKeyLifecycleAction,
}
