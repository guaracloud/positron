use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_governance::{GovernanceAuditEntry, Identity};
use positron_kernel::{
    ActiveSegmentLedger, BootstrapArtifact, BootstrapArtifactAccess, BootstrapKeyCustody,
    BootstrapObjectPurpose, Catalog, SegmentScope, StorageKernelResourceAuthority,
};
use std::sync::Arc;

use super::super::codec::{BootstrapRecord, encode_claim, encode_legacy_claim};
use super::super::storage;
use super::super::{BootstrapFailure, BootstrapFailureCode, InitializedInstance};
use super::support::{catalog_failure, key_failure};

pub(super) fn open_initial_ledgers(
    authority: &StorageKernelResourceAuthority,
    catalog: &Catalog<'_>,
    key: &BootstrapKeyCustody,
    record: &BootstrapRecord,
) -> Result<(), BootstrapFailure> {
    let shard = VirtualShardId::new(1)
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
    for signal in [SignalKind::Logs, SignalKind::Traces] {
        let scope = SegmentScope::new(record.tenant, signal, shard);
        let protection = key
            .segment_key(record.instance, scope)
            .map_err(key_failure)?;
        let ledger = ActiveSegmentLedger::open(authority, catalog, scope, protection)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::LedgerUnavailable))?;
        drop(ledger);
    }
    Ok(())
}

pub(super) fn ensure_claim(
    access: &BootstrapArtifactAccess,
    key: &BootstrapKeyCustody,
    record: &BootstrapRecord,
    secret: &[u8; 32],
) -> Result<(), BootstrapFailure> {
    let plaintext = match &record.ingest {
        Some(ingest) => encode_claim(
            record.instance,
            record.administrator,
            secret,
            ingest.principal,
            ingest
                .api_key_secret
                .as_ref()
                .ok_or_else(|| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?,
            record
                .query
                .as_ref()
                .ok_or_else(|| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?
                .principal,
            record
                .query
                .as_ref()
                .and_then(|query| query.api_key_secret.as_ref())
                .ok_or_else(|| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?,
        ),
        None => encode_legacy_claim(record.instance, record.administrator, secret),
    };
    let encrypted = key
        .protect(record.instance, BootstrapObjectPurpose::Claim, &plaintext)
        .map_err(key_failure)?;
    if storage::exists(access, BootstrapArtifact::Claim)? {
        let existing = storage::read(access, BootstrapArtifact::Claim)?;
        let opened = key
            .open_object(record.instance, BootstrapObjectPurpose::Claim, &existing)
            .map_err(key_failure)?;
        if opened != plaintext {
            return Err(BootstrapFailure::new(
                BootstrapFailureCode::IdentityMismatch,
            ));
        }
        Ok(())
    } else {
        storage::write_new(access, BootstrapArtifact::Claim, &encrypted)
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "bootstrap handoff transfers each established authority exactly once"
)]
pub(super) fn outcome(
    record: &BootstrapRecord,
    key: BootstrapKeyCustody,
    identity: Identity,
    audit: Vec<GovernanceAuditEntry>,
    authority: StorageKernelResourceAuthority,
    generation: u64,
    audit_frontier: u64,
    claim_available: bool,
) -> Result<InitializedInstance, BootstrapFailure> {
    let logs_shard = VirtualShardId::new(1)
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
    let ingest_policy = positron_ingest::IngestPolicyAuthority::new(
        positron_ingest::IngestPolicy::release_1_default()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?,
    );
    let admission_group_planner =
        Arc::new(positron_ingest::FixedAdmissionGroupPlanner::new(logs_shard));
    Ok(InitializedInstance {
        key,
        identity,
        audit,
        _authority: authority,
        instance: record.instance,
        tenant: record.tenant,
        logs_shard,
        ingest_policy,
        value_limit_profile: positron_domain::value::ValueLimitProfile::release_1_system_maximum(),
        admission_group_planner,
        tenant_slug: BootstrapRecord::tenant_slug()?,
        administrator: record.administrator,
        integrity_key_fingerprint: record.integrity_fingerprint,
        catalog_generation: generation,
        governance_audit_frontier: audit_frontier,
        claim_available,
    })
}

pub(in crate::instance_bootstrap) fn governance_audit_records(
    catalog: &Catalog<'_>,
) -> Result<Vec<GovernanceAuditEntry>, BootstrapFailure> {
    catalog
        .governance_audit_records()
        .map_err(catalog_failure)?
        .iter()
        .map(|record| {
            GovernanceAuditEntry::decode(record)
                .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))
        })
        .collect()
}
