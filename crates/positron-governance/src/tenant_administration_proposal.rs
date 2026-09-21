use positron_domain::identity::PrincipalId;
use positron_kernel::{
    AuditIntent, BootstrapKeyCustody, Catalog, CatalogObject, CatalogProposal,
    PreparedTransactionResolution, TransactionId,
};
use positron_policy::IngestPolicy;

use super::tenant_administration_registry_codec::{is_registry, registry, registry_object};
use super::tenant_administration_replay::{encode_receipt, replay_snapshot, request_digest};
use super::{
    TenantAdministration, TenantAdministrationFailure, TenantCreateCandidate, TenantCreation,
    map_catalog, validate_request,
};
use crate::ResourceGeneration;
use crate::tenant_quota_record::{
    TENANT_RECORD_V3_MAGIC, is_tenant_record, tenant_record_metadata,
};

const TENANT_AUDIT_MAGIC: [u8; 8] = *b"POSTNA01";

impl TenantAdministration {
    pub fn create(
        catalog: &Catalog<'_>,
        keys: &BootstrapKeyCustody,
        instance: positron_kernel::InstanceId,
        administrator: PrincipalId,
        candidate: TenantCreateCandidate,
    ) -> Result<TenantCreation, TenantAdministrationFailure> {
        let request = &candidate.request;
        validate_request(administrator, request)?;
        let snapshot = catalog.pin().map_err(map_catalog)?;
        if let Some(replay) = replay_snapshot(&snapshot, request)? {
            return Ok(replay);
        }
        let mut registry =
            registry(&snapshot)?.ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
        let digest = request_digest(request);
        let transaction =
            TransactionId::new(request.idempotency.to_bytes()).map_err(map_catalog)?;
        let prepared = match catalog.resume_prepared(transaction, digest) {
            Ok(prepared) => prepared,
            Err(failure) => return Err(map_catalog(failure)),
        };
        match prepared {
            PreparedTransactionResolution::Absent => {},
            PreparedTransactionResolution::Unavailable => {
                return Err(TenantAdministrationFailure::PersistenceUnavailable);
            },
            PreparedTransactionResolution::Resumed(commit) => {
                let replay = replay_snapshot(&catalog.pin().map_err(map_catalog)?, request)?
                    .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
                let audit_position = commit
                    .governance_audit_record()
                    .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?
                    .position();
                return Ok(TenantCreation::new(
                    replay.tenant_id(),
                    replay.resource_generation(),
                    audit_position,
                ));
            },
        }
        let generation = ResourceGeneration::new(
            registry
                .generation
                .get()
                .checked_add(1)
                .ok_or(TenantAdministrationFailure::InvalidInput)?,
        )
        .map_err(|_| TenantAdministrationFailure::InvalidInput)?;
        let audit_position = snapshot
            .governance_audit_frontier()
            .checked_add(1)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
        let mut objects = Vec::new();
        for identity in snapshot.object_identities() {
            let bytes = snapshot
                .object(identity)
                .map_err(map_catalog)?
                .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
            if is_registry(bytes) {
                continue;
            }
            if is_tenant_record(bytes) {
                let record = tenant_record_metadata(bytes)?;
                if record.tenant == candidate.tenant || record.slug == request.slug.as_str() {
                    return Err(TenantAdministrationFailure::DuplicateTenant);
                }
            }
            objects.push(CatalogObject::new(bytes.to_vec()).map_err(map_catalog)?);
        }
        registry.tenants.push(candidate.tenant);
        objects.push(registry_object(instance, generation, &registry.tenants)?);
        let envelope = keys
            .provision_tenant_key_envelope(
                instance,
                candidate.tenant,
                keys.random_identifier()
                    .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?,
                1,
            )
            .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
        objects.push(
            CatalogObject::new(encode_record(instance, &candidate, &envelope)?)
                .map_err(map_catalog)?,
        );
        let policy = IngestPolicy::preserving(1)
            .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?
            .activated_object(candidate.tenant)
            .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
        objects.push(CatalogObject::new(policy.into_bytes()).map_err(map_catalog)?);
        objects.push(
            CatalogObject::new(encode_receipt(
                &candidate,
                registry.generation,
                generation,
                digest,
                audit_position,
            ))
            .map_err(map_catalog)?,
        );
        let commit = catalog
            .commit_prepared(
                snapshot.identity(),
                CatalogProposal::new(
                    TransactionId::new(request.idempotency.to_bytes()).map_err(map_catalog)?,
                    snapshot
                        .format_epoch()
                        .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?,
                    objects,
                )
                .map_err(map_catalog)?,
                AuditIntent::new(encode_audit(
                    &candidate,
                    registry.generation,
                    generation,
                    digest,
                ))
                .map_err(map_catalog)?,
                digest,
            )
            .map_err(map_catalog)?;
        let committed_audit_position = commit
            .governance_audit_record()
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?
            .position();
        if committed_audit_position != audit_position {
            return Err(TenantAdministrationFailure::PersistenceUnavailable);
        }
        Ok(TenantCreation::new(
            candidate.tenant,
            generation,
            audit_position,
        ))
    }
}

pub(super) fn encode_record(
    instance: positron_kernel::InstanceId,
    candidate: &TenantCreateCandidate,
    envelope: &[u8],
) -> Result<Vec<u8>, TenantAdministrationFailure> {
    let request = &candidate.request;
    let slug = request.slug.as_str().as_bytes();
    let display = request.display_name.as_bytes();
    let envelope_len =
        u16::try_from(envelope.len()).map_err(|_| TenantAdministrationFailure::InvalidInput)?;
    let mut encoded = Vec::with_capacity(
        8 + 16
            + 16
            + 1
            + slug.len()
            + 1
            + display.len()
            + 8
            + 4
            + 88
            + 1
            + 8
            + 8
            + 8
            + 2
            + envelope.len(),
    );
    encoded.extend_from_slice(&TENANT_RECORD_V3_MAGIC);
    encoded.extend_from_slice(&instance.to_bytes());
    encoded.extend_from_slice(&candidate.tenant.to_bytes());
    encoded.push(u8::try_from(slug.len()).map_err(|_| TenantAdministrationFailure::InvalidInput)?);
    encoded.extend_from_slice(slug);
    encoded
        .push(u8::try_from(display.len()).map_err(|_| TenantAdministrationFailure::InvalidInput)?);
    encoded.extend_from_slice(display);
    encoded.extend_from_slice(&request.retention_seconds.to_be_bytes());
    encoded.extend_from_slice(&1_u64.to_be_bytes());
    encoded.extend_from_slice(&request.weight.to_be_bytes());
    for value in request.resources {
        encoded.extend_from_slice(&value.to_be_bytes());
    }
    // Active lifecycle, policy generation, and independent lifecycle, display,
    // and retention generations are durable tenant state.
    encoded.push(1);
    encoded.extend_from_slice(&1_u64.to_be_bytes());
    encoded.extend_from_slice(&1_u64.to_be_bytes());
    encoded.extend_from_slice(&1_u64.to_be_bytes());
    encoded.extend_from_slice(&1_u64.to_be_bytes());
    encoded.extend_from_slice(&envelope_len.to_be_bytes());
    encoded.extend_from_slice(envelope);
    Ok(encoded)
}

fn encode_audit(
    candidate: &TenantCreateCandidate,
    prior_generation: ResourceGeneration,
    generation: ResourceGeneration,
    digest: [u8; 32],
) -> Vec<u8> {
    let mut audit = Vec::with_capacity(96);
    audit.extend_from_slice(&TENANT_AUDIT_MAGIC);
    audit.extend_from_slice(&candidate.request.idempotency.to_bytes());
    audit.extend_from_slice(&candidate.request.actor.principal_id().to_bytes());
    audit.extend_from_slice(&candidate.tenant.to_bytes());
    audit.extend_from_slice(&prior_generation.get().to_be_bytes());
    audit.extend_from_slice(&generation.get().to_be_bytes());
    audit.extend_from_slice(&digest);
    audit
}
