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
    CatalogWrappingKey, FormatEpoch, InstanceId, TransactionId, with_catalog_fault,
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
    let operation_count = usize::from(data.first().copied().unwrap_or_default() % 4) + 1;
    let mut acknowledged = 0_u64;
    let mut latest_payload = None;
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
            latest_payload = Some(payload);
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
    if number != 0 && number == acknowledged {
        let snapshot = recovered.pin().expect("recovered catalog pins");
        let expected = latest_payload.expect("an acknowledged generation has a payload");
        let object = CatalogObject::new(expected).expect("bounded fuzz payload");
        assert_eq!(
            snapshot.object(object.identity()).expect("object lookup"),
            Some(object.plaintext.as_slice())
        );
    }

    if number != 0 && data.get(11).is_some_and(|selector| selector & 1 == 1) {
        let event = rewrap_fault_event(data.get(12).copied().unwrap_or_default());
        let rotation = with_catalog_fault(event, || {
            recovered.rewrap(
                TransactionId::new(nonzero_id(0xf0))?,
                CatalogWrappingKey::from_owned_at_epoch(Box::new([0xf2; 32]), [0xf3; 16], 2)?,
                AuditIntent::new(b"fuzz root rotation".to_vec())?,
            )
        });
        let rotation_acknowledged = rotation.is_ok();
        drop(recovered);
        drop(authority);
        let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)
            .expect("fuzz catalog releases volume after rotation");
        let Some(authority) = fuzz_authority(volume) else {
            return;
        };
        let successor = successor_secret()
            .with_predecessor(predecessor_key())
            .expect("fixed routes form a valid overlap");
        let resumed = Catalog::open(&authority, instance, successor)
            .expect("partial rewrap remains restartable with both routes");
        let completed = resumed
            .rewrap(
                TransactionId::new(nonzero_id(0xf0)).expect("fixed transaction"),
                successor_key(),
                AuditIntent::new(b"fuzz root rotation".to_vec()).expect("fixed audit"),
            )
            .expect("rotation retry completes");
        assert_eq!(completed.completed().number(), number + 3);
        assert_eq!(
            resumed
                .governance_audit_records()
                .expect("rotation audit reads")
                .len() as u64,
            number + 3
        );
        if rotation_acknowledged {
            assert_eq!(resumed.pin().expect("rotation pins").number(), number + 3);
        }
    }
}

fn corrupt_persisted_byte(root: &std::path::Path, selector: Option<u8>) -> bool {
    let Some(selector) = selector else {
        return false;
    };
    let published = fs::read_dir(root.join("catalog/generations"))
        .ok()
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .any(|entry| {
            fs::metadata(entry.path())
                .is_ok_and(|metadata| metadata.len() == super::storage::MARKER_BYTES as u64)
        });
    if !published {
        return false;
    }
    let directories = ["objects", "governance-audit", "commits", "generations"];
    let selected = directories[usize::from(selector) % directories.len()];
    let directory = root.join("catalog").join(selected);
    let Ok(mut entries) = fs::read_dir(directory) else {
        return false;
    };
    let mut corrupted = false;
    while let Some(Ok(entry)) = entries.next() {
        let Ok(mut bytes) = fs::read(entry.path()) else {
            continue;
        };
        let index = usize::from(selector).wrapping_mul(17) % bytes.len();
        if let Some(byte) = bytes.get_mut(index) {
            *byte ^= 0x80;
            corrupted |= fs::write(entry.path(), bytes).is_ok();
        }
    }
    corrupted
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

fn predecessor_key() -> CatalogWrappingKey {
    CatalogWrappingKey::from_owned_at_epoch(Box::new([0xf1; 32]), [1; 16], 1)
        .expect("fixed predecessor route")
}

fn successor_key() -> CatalogWrappingKey {
    CatalogWrappingKey::from_owned_at_epoch(Box::new([0xf2; 32]), [0xf3; 16], 2)
        .expect("fixed successor route")
}

fn successor_secret() -> CatalogSecret {
    CatalogSecret::from_owned_at_epoch(Box::new([0xe1; 32]), Box::new([0xf2; 32]), [0xf3; 16], 2)
        .expect("fixed successor secret")
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
        CatalogFileEvent::SynchronizeTransactionDigest,
        CatalogFileEvent::SynchronizeTransactionDirectory,
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

fn rewrap_fault_event(selector: u8) -> CatalogFileEvent {
    let events = [
        CatalogFileEvent::PartialRewrapWrite,
        CatalogFileEvent::SynchronizeRewrap,
        CatalogFileEvent::SynchronizeRewrapDirectory,
        CatalogFileEvent::WriteMarker,
        CatalogFileEvent::SynchronizeGenerationDirectory,
    ];
    events[usize::from(selector) % events.len()]
}
