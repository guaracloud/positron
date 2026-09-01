use std::error::Error;
use std::fs;
use std::num::NonZeroU64;
use std::path::Path;

use positron_domain::identity::TenantId;
use positron_domain::routing::{CommitPosition, SignalKind, VirtualShardId};
use positron_domain::time::UnixNanoseconds;

use super::support::{TemporaryRoot, establish_authority};
use crate::active_segment_ledger::fault::{LedgerFileEvent, with_ledger_fault};
use crate::active_segment_ledger::format::decode_header;
use crate::active_segment_ledger::object_context;
use crate::data_protection::{DataProtection, FrameLimits, FrameSequence, SegmentFramePurpose};
use crate::retention_time::RetentionTimeAuthority;
use crate::{
    ActiveSegmentLedger, Catalog, CatalogObject, CatalogProposal, CatalogSecret, FormatEpoch,
    InstanceId, LedgerCompletionState, LedgerFailureCode, MountQualification, PreparedStoreBlock,
    PrimaryDataVolume, ResourceAmounts, ResourceDimension, RetentionBucket, SegmentId,
    SegmentProtectionKey, SegmentScope, SnapshotLeaseUsage, StoreBlockIdentity, TransactionId,
    WorkClaim, WorkKind,
};
#[cfg(feature = "test-support")]
use crate::{
    CatalogPublicationFault, RecoveryWorkClaim, RecoveryWorkKind,
    with_catalog_generation_ambiguity_hook_after, with_catalog_publication_fault_after,
};

mod admission_commit;
mod format_recovery;
mod frontier_publication;
mod frontier_recovery;
mod lease_reclamation;
mod policy_authority;

fn preparation_capacity<'kernel>(
    authority: &'kernel crate::StorageKernelResourceAuthority,
    tenant: TenantId,
) -> Result<crate::ResourceReservation<'kernel>, Box<dyn Error>> {
    Ok(authority.governor().reserve(WorkClaim::tenant(
        tenant,
        WorkKind::Ingest,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1_048_576)?,
    )?)?)
}

fn copied_non_frontier_objects(
    basis: &crate::CatalogSnapshot,
) -> Result<Vec<CatalogObject>, Box<dyn Error>> {
    basis
        .plaintext_objects()
        .filter(|bytes| !bytes.starts_with(b"PRETFR01"))
        .map(|bytes| CatalogObject::new(bytes.to_vec()).map_err(Into::into))
        .collect()
}

fn governance_policy(instance: [u8; 16], tenant: TenantId, retention_seconds: u64) -> Vec<u8> {
    let slug = b"retention-test";
    let display = b"Retention test tenant";
    let mut encoded = Vec::new();
    encoded.extend_from_slice(b"POSGOV03");
    encoded.extend_from_slice(&instance);
    encoded.extend_from_slice(&tenant.to_bytes());
    encoded.push(u8::try_from(slug.len()).expect("bounded fixture slug"));
    encoded.extend_from_slice(slug);
    encoded.push(u8::try_from(display.len()).expect("bounded fixture display"));
    encoded.extend_from_slice(display);
    encoded.extend_from_slice(&[0x11; 16]);
    encoded.extend_from_slice(&[0x21; 32]);
    encoded.extend_from_slice(&[0x22; 32]);
    encoded.extend_from_slice(&[0x12; 16]);
    encoded.extend_from_slice(&[0x23; 32]);
    encoded.extend_from_slice(&[0x24; 32]);
    encoded.extend_from_slice(&[0x13; 16]);
    encoded.extend_from_slice(&[0x25; 32]);
    encoded.extend_from_slice(&[0x26; 32]);
    encoded.extend_from_slice(&[0x27; 32]);
    encoded.extend_from_slice(&[0x28; 32]);
    encoded.extend_from_slice(&1_u16.to_be_bytes());
    encoded.push(0x29);
    encoded.extend_from_slice(&1_u16.to_be_bytes());
    encoded.push(0x2a);
    encoded.extend_from_slice(&retention_seconds.to_be_bytes());
    encoded.extend_from_slice(&1_u64.to_be_bytes());
    encoded.extend_from_slice(&1_u32.to_be_bytes());
    for _ in 0..11 {
        encoded.extend_from_slice(&1_u64.to_be_bytes());
    }
    encoded.extend_from_slice(&[1, 4, 0, 1, 1]);
    encoded
}

fn install_governance_policy(
    catalog: &Catalog<'_>,
    instance: InstanceId,
    tenant: TenantId,
    retention_seconds: u64,
    transaction: u8,
) -> Result<(), Box<dyn Error>> {
    let basis = catalog.pin()?;
    let mut objects = basis
        .plaintext_objects()
        .filter(|bytes| {
            !bytes.starts_with(b"POSGOV01")
                && !bytes.starts_with(b"POSGOV02")
                && !bytes.starts_with(b"POSGOV03")
        })
        .map(|bytes| CatalogObject::new(bytes.to_vec()))
        .collect::<Result<Vec<_>, _>>()?;
    objects.push(CatalogObject::new(governance_policy(
        instance.to_bytes(),
        tenant,
        retention_seconds,
    ))?);
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([transaction; 16])?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    Ok(())
}

#[cfg(feature = "test-support")]
fn replace_retention_frontier(
    catalog: &Catalog<'_>,
    frontier: Vec<u8>,
    transaction: u8,
) -> Result<(), Box<dyn Error>> {
    let basis = catalog.pin()?;
    let mut objects = copied_non_frontier_objects(&basis)?;
    objects.push(CatalogObject::new(frontier)?);
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([transaction; 16])?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    Ok(())
}
