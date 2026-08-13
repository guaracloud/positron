use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use positron_domain::identity::TenantId;

use crate::{
    DetectedCapacity, DiskObservation, DiskPressureThresholds, GovernorPolicy,
    InventoryCardinalityLimits, MountQualification, OperatorLimits, OrdinaryPoolPolicy,
    OwnedPrimaryDataVolume, PrimaryDataVolume, RecoveryPoolCapacities, RecoveryReserve,
    ResourceAmounts, ResourceDimension, ResourceInventory, StorageKernelResourceAuthority,
    TenantQuota,
};

use super::{
    AuditIntent, Catalog, CatalogFileEvent, CatalogObject, CatalogProposal, CatalogSecret,
    FormatEpoch, InstanceId, TransactionId, with_catalog_fault,
};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

struct FuzzRoot(PathBuf);

impl FuzzRoot {
    fn new() -> Option<Self> {
        let sequence = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "positron-catalog-fuzz-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).ok()?;
        Some(Self(path))
    }
}

impl Drop for FuzzRoot {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.0) {
            eprintln!("failed to remove catalog fuzz root: {error}");
        }
    }
}

pub(super) fn fuzz_catalog_stateful(data: &[u8]) {
    if data.len() > 128 {
        return;
    }
    let Some(root) = FuzzRoot::new() else {
        return;
    };
    let Some(volume) = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost).ok()
    else {
        return;
    };
    let instance = InstanceId::new(nonzero_id(1)).expect("fixed instance identity is nonzero");
    let Some(authority) = fuzz_authority(volume) else {
        return;
    };
    let Ok(catalog) = Catalog::open(&authority, instance, secret()) else {
        return;
    };
    let operation_count = usize::from(data.first().copied().unwrap_or_default() % 3) + 1;
    let mut acknowledged = 0_u64;
    for operation in 0..operation_count {
        let selector = data.get(operation * 3 + 1).copied().unwrap_or_default();
        let transaction = data
            .get(operation * 3 + 2)
            .copied()
            .unwrap_or(operation as u8 + 2)
            .max(1);
        let payload = vec![
            data.get(operation * 3 + 3).copied().unwrap_or(transaction),
            operation as u8,
        ];
        let expected = catalog.pin().expect("catalog pins").identity();
        let result = with_catalog_fault(fault_event(selector), || {
            catalog.commit(
                expected,
                CatalogProposal::new(
                    TransactionId::new(nonzero_id(transaction))?,
                    FormatEpoch::new(1)?,
                    vec![CatalogObject::new(payload.clone())?],
                )?,
                Some(AuditIntent::new(vec![transaction])?),
            )
        });
        if result.is_ok() {
            acknowledged = acknowledged.saturating_add(1);
        }
    }
    drop(catalog);
    drop(authority);

    let corruption = (data.len() > 10).then(|| data.last().copied()).flatten();
    let corrupted_reachable_artifact = corrupt_persisted_byte(&root.0, corruption);

    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)
        .expect("fuzz catalog releases volume ownership");
    let Some(authority) = fuzz_authority(volume) else {
        return;
    };
    let recovery = Catalog::open(&authority, instance, secret());
    if corrupted_reachable_artifact {
        let failure = recovery.expect_err("reachable persisted corruption must fence recovery");
        assert!(matches!(
            failure.code(),
            super::CatalogFailureCode::IntegrityCorruption
                | super::CatalogFailureCode::AuthenticationFailed
                | super::CatalogFailureCode::UnsupportedFormat
        ));
        return;
    }
    let recovered = recovery.expect("uncorrupted persisted state must recover");
    let number = recovered.pin().expect("recovered catalog pins").number();
    assert!(number <= operation_count as u64);
    assert_eq!(
        recovered
            .governance_audit_records()
            .expect("recovered audit reads")
            .len() as u64,
        number
    );
    assert!(number >= acknowledged.saturating_sub(1));
}

fn corrupt_persisted_byte(root: &std::path::Path, selector: Option<u8>) -> bool {
    let Some(selector) = selector else {
        return false;
    };
    let directory = root.join("catalog").join("generations");
    let Ok(mut entries) = fs::read_dir(directory) else {
        return false;
    };
    while let Some(Ok(entry)) = entries.next() {
        let Ok(mut bytes) = fs::read(entry.path()) else {
            continue;
        };
        if bytes.len() != super::storage::MARKER_BYTES {
            continue;
        }
        let index = usize::from(selector) % bytes.len();
        if let Some(byte) = bytes.get_mut(index) {
            *byte ^= 0x80;
            return fs::write(entry.path(), bytes).is_ok();
        }
    }
    false
}

fn fuzz_authority(volume: OwnedPrimaryDataVolume) -> Option<StorageKernelResourceAuthority> {
    let cardinality = InventoryCardinalityLimits::new(1, 16).ok()?;
    let large = ResourceAmounts::new([
        70_000_001, 2, 2, 70_000_001, 65_541, 2, 2, 2, 2, 9, 20_000_001,
    ]);
    let small = uniform(1);
    let dual = uniform(2);
    let recovery = add(add(add(large, large)?, large)?, uniform(6))?;
    let raw = add(
        add(recovery, uniform(16))?,
        cardinality.governor_bootstrap_overhead(1).ok()?,
    )?;
    let inventory = ResourceInventory::new(
        DetectedCapacity::new(raw).ok()?,
        OperatorLimits::new(raw).ok()?,
        RecoveryReserve::new(recovery).ok()?,
        cardinality,
        DiskPressureThresholds::new(
            recovery.get(ResourceDimension::DiskHeadroomBytes),
            recovery.get(ResourceDimension::DiskHeadroomBytes) + 1,
            recovery.get(ResourceDimension::DiskHeadroomBytes) + 2,
            raw.get(ResourceDimension::DiskHeadroomBytes),
        )
        .ok()?,
        DiskObservation::new(raw.get(ResourceDimension::DiskHeadroomBytes)),
    )
    .ok()?;
    let tenant = TenantId::from_bytes([0x43; 16]).ok()?;
    let policy = GovernorPolicy::new(
        [TenantQuota::new(tenant, 1, uniform(16)).ok()?],
        OrdinaryPoolPolicy::new(uniform(4), uniform(3), uniform(2), uniform(1)).ok()?,
    )
    .ok()?;
    let pools = RecoveryPoolCapacities::new(large, small, dual, small, large, small, small).ok()?;
    StorageKernelResourceAuthority::establish_for_fuzz_with_volume(volume, inventory, policy, pools)
        .ok()
}

fn uniform(value: u64) -> ResourceAmounts {
    ResourceAmounts::new([value; 11])
}

fn add(left: ResourceAmounts, right: ResourceAmounts) -> Option<ResourceAmounts> {
    let value = |dimension| left.get(dimension).checked_add(right.get(dimension));
    Some(ResourceAmounts::new([
        value(ResourceDimension::MemoryBytes)?,
        value(ResourceDimension::QueueSlots)?,
        value(ResourceDimension::TaskSlots)?,
        value(ResourceDimension::BufferCacheBytes)?,
        value(ResourceDimension::BatchItems)?,
        value(ResourceDimension::LeaseSlots)?,
        value(ResourceDimension::RetrySlots)?,
        value(ResourceDimension::IoPermits)?,
        value(ResourceDimension::CpuWorkUnits)?,
        value(ResourceDimension::FileDescriptors)?,
        value(ResourceDimension::DiskHeadroomBytes)?,
    ]))
}

fn secret() -> CatalogSecret {
    CatalogSecret::from_owned(Box::new([0xe1; 32]), Box::new([0xf1; 32]))
}

fn nonzero_id(last: u8) -> [u8; 16] {
    let mut bytes = [0_u8; 16];
    if let Some((last_byte, _)) = bytes.split_last_mut() {
        *last_byte = last.max(1);
    }
    bytes
}

fn fault_event(selector: u8) -> CatalogFileEvent {
    let events = [
        CatalogFileEvent::WriteObject,
        CatalogFileEvent::PartialObjectWrite,
        CatalogFileEvent::SynchronizeObject,
        CatalogFileEvent::SynchronizeObjectDirectory,
        CatalogFileEvent::ReserveAudit,
        CatalogFileEvent::WriteAudit,
        CatalogFileEvent::PartialAuditWrite,
        CatalogFileEvent::SynchronizeAudit,
        CatalogFileEvent::SynchronizeAuditDirectory,
        CatalogFileEvent::WriteCommit,
        CatalogFileEvent::PartialCommitWrite,
        CatalogFileEvent::SynchronizeCommit,
        CatalogFileEvent::SynchronizeCommitDirectory,
        CatalogFileEvent::WriteMarker,
        CatalogFileEvent::PartialMarkerWrite,
        CatalogFileEvent::SynchronizeMarker,
        CatalogFileEvent::RenameMarker,
        CatalogFileEvent::SynchronizeGenerationDirectory,
    ];
    events
        .get(usize::from(selector) % events.len())
        .copied()
        .unwrap_or(CatalogFileEvent::WriteObject)
}
