//! External contract tests for protected durable export output.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use positron_domain::identity::TenantId;
use positron_kernel::{
    Catalog, CatalogPublicationFault, CatalogSecret, DiskPressureThresholds, ExportOutput,
    ExportOutputBinding, ExportOutputRequest, GovernorPolicy, InstanceId,
    InventoryCardinalityLimits, MountQualification, ObservedResourceEnvironment, OperatorLimits,
    OrdinaryPoolPolicy, PrimaryDataVolume, RecoveryPoolCapacities, RecoveryReserve,
    RegisteredResourceBounds, ResourceAmounts, ResourceDimension, ResourceGovernorConfiguration,
    ResourceInventory, SnapshotLeaseId, StorageKernelResourceAuthority, TenantQuota,
    with_catalog_publication_fault_after,
};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);
struct TemporaryRoot(PathBuf);
impl TemporaryRoot {
    fn new() -> Result<Self, std::io::Error> {
        let sequence = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "positron-export-output-test-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for TemporaryRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn hex(bytes: [u8; 16]) -> String {
    bytes
        .iter()
        .flat_map(|byte| [byte >> 4, byte & 0x0f])
        .map(|nibble| char::from(nibble + if nibble < 10 { b'0' } else { b'a' - 10 }))
        .collect()
}
fn payload_path(root: &TemporaryRoot, identity: [u8; 16]) -> PathBuf {
    root.path()
        .join("exports")
        .join(hex(identity))
        .join("payload")
}
fn manifest_path(root: &TemporaryRoot, identity: [u8; 16]) -> PathBuf {
    root.path()
        .join("exports")
        .join(hex(identity))
        .join("manifest")
}
fn initial_path(root: &TemporaryRoot, identity: [u8; 16]) -> PathBuf {
    root.path()
        .join("exports")
        .join(hex(identity))
        .join("initial")
}

fn amounts(value: u64) -> ResourceAmounts {
    ResourceAmounts::new([value; 11])
}
fn add(left: ResourceAmounts, right: ResourceAmounts) -> Result<ResourceAmounts, Box<dyn Error>> {
    Ok(ResourceAmounts::new([
        left.get(ResourceDimension::MemoryBytes)
            .checked_add(right.get(ResourceDimension::MemoryBytes))
            .ok_or("memory")?,
        left.get(ResourceDimension::QueueSlots)
            .checked_add(right.get(ResourceDimension::QueueSlots))
            .ok_or("queue")?,
        left.get(ResourceDimension::TaskSlots)
            .checked_add(right.get(ResourceDimension::TaskSlots))
            .ok_or("task")?,
        left.get(ResourceDimension::BufferCacheBytes)
            .checked_add(right.get(ResourceDimension::BufferCacheBytes))
            .ok_or("cache")?,
        left.get(ResourceDimension::BatchItems)
            .checked_add(right.get(ResourceDimension::BatchItems))
            .ok_or("batch")?,
        left.get(ResourceDimension::LeaseSlots)
            .checked_add(right.get(ResourceDimension::LeaseSlots))
            .ok_or("lease")?,
        left.get(ResourceDimension::RetrySlots)
            .checked_add(right.get(ResourceDimension::RetrySlots))
            .ok_or("retry")?,
        left.get(ResourceDimension::IoPermits)
            .checked_add(right.get(ResourceDimension::IoPermits))
            .ok_or("io")?,
        left.get(ResourceDimension::CpuWorkUnits)
            .checked_add(right.get(ResourceDimension::CpuWorkUnits))
            .ok_or("cpu")?,
        left.get(ResourceDimension::FileDescriptors)
            .checked_add(right.get(ResourceDimension::FileDescriptors))
            .ok_or("fd")?,
        left.get(ResourceDimension::DiskHeadroomBytes)
            .checked_add(right.get(ResourceDimension::DiskHeadroomBytes))
            .ok_or("disk")?,
    ]))
}
fn establish(
    volume: positron_kernel::OwnedPrimaryDataVolume,
) -> Result<StorageKernelResourceAuthority, Box<dyn Error>> {
    let cardinality = InventoryCardinalityLimits::new(1, 16)?;
    let large = ResourceAmounts::new([
        90_000_000, 4, 4, 90_000_000, 70_000, 4, 4, 4, 4, 16, 40_000_000,
    ]);
    let small = amounts(2);
    let durability = add(add(large, large)?, large)?;
    let recovery_capacity = add(add(add(durability, large)?, large)?, amounts(12))?;
    let ordinary = ResourceAmounts::new([
        5_000_000, 32, 32, 5_000_000, 2_048, 32, 32, 32, 32, 32, 2_000_000,
    ]);
    let governed = add(recovery_capacity, ordinary)?;
    let raw = add(governed, cardinality.governor_bootstrap_overhead(1)?)?;
    let registered = RegisteredResourceBounds::new([100, 100, 500_000_000, 500_000, 100, 100, 100])
        .map_err(|error| format!("registered: {error:?}"))?;
    let observed = ObservedResourceEnvironment::observe(&volume, registered)
        .map_err(|error| format!("observed: {error:?}"))?;
    let disk = observed.initial_disk().usable_bytes();
    let inventory = ResourceInventory::new_observed(
        observed,
        OperatorLimits::new(raw).map_err(|error| format!("limits: {error:?}"))?,
        RecoveryReserve::new(recovery_capacity).map_err(|error| format!("reserve: {error:?}"))?,
        cardinality,
        DiskPressureThresholds::new(
            recovery_capacity.get(ResourceDimension::DiskHeadroomBytes),
            recovery_capacity.get(ResourceDimension::DiskHeadroomBytes) + 1,
            recovery_capacity.get(ResourceDimension::DiskHeadroomBytes) + 2,
            disk,
        )
        .map_err(|error| format!("thresholds: {error:?}"))?,
    )
    .map_err(|error| format!("inventory: {error:?}"))?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let pool = OrdinaryPoolPolicy::new(amounts(8), amounts(6), amounts(4), amounts(2))
        .map_err(|error| format!("pool: {error:?}"))?;
    let policy = GovernorPolicy::new(
        [TenantQuota::new(tenant, 1, ordinary).map_err(|error| format!("quota: {error:?}"))?],
        pool,
    )
    .map_err(|error| format!("policy: {error:?}"))?;
    let recovery =
        RecoveryPoolCapacities::new(durability, small, small, small, large, small, small)
            .map_err(|error| format!("recovery: {error:?}"))?;
    let configuration = ResourceGovernorConfiguration::new(inventory, policy, recovery)
        .map_err(|error| format!("configuration: {error:?}"))?;
    StorageKernelResourceAuthority::establish(volume, configuration)
        .map_err(|error| format!("establish: {:?}", error.failure()).into())
}

#[test]
fn exact_retry_publishes_a_payload_synced_before_its_descriptor_and_keeps_the_committed_checkpoint()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish(volume)?;
    let instance = InstanceId::new([0x81; 16])?;
    let secret = CatalogSecret::from_owned(Box::new([0x82; 32]), Box::new([0x83; 32]));
    let catalog = Catalog::open(&authority, instance, secret)?;
    let binding = ExportOutputBinding::new(
        TenantId::from_bytes([0x41; 16])?,
        [0x84; 16],
        [0x85; 32],
        [0x86; 32],
        7,
        9,
        SnapshotLeaseId::new([0x87; 16])?,
        100,
        3_700,
    )?;
    let mut output = ExportOutput::create(&catalog, binding)?;

    let interrupted =
        with_catalog_publication_fault_after(CatalogPublicationFault::SynchronizeCommit, 0, || {
            output.append_batch(
                &catalog,
                101,
                0,
                [0x88; 32],
                b"payload-synced-before-descriptor",
                Some(b"first cursor"),
            )
        });
    assert!(matches!(
        interrupted,
        Err(error) if error.code() == positron_kernel::ExportOutputFailureCode::StorageUnavailable
    ));
    assert_eq!(output.batch_count(), 0);
    assert_eq!(output.latest_checkpoint(&catalog, 101)?, None);

    let receipt = output.append_batch(
        &catalog,
        101,
        0,
        [0x88; 32],
        b"payload-synced-before-descriptor",
        Some(b"first cursor"),
    )?;
    assert_eq!(receipt.sequence(), 0);
    assert_eq!(output.batch_count(), 1);
    assert_eq!(
        output
            .latest_checkpoint(&catalog, 101)?
            .and_then(|checkpoint| checkpoint.continuation_cursor()),
        Some(b"first cursor".to_vec())
    );
    assert!(matches!(
        output.append_batch(
            &catalog,
            101,
            0,
            [0x89; 32],
            b"substituted replay",
            Some(b"first cursor"),
        ),
        Err(error) if error.code() == positron_kernel::ExportOutputFailureCode::IdempotencyConflict
    ));

    drop(catalog);
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x82; 32]), Box::new([0x83; 32])),
    )?;
    let recovered = ExportOutput::reopen(&catalog, output.identity())?;
    assert_eq!(recovered.batch_count(), 1);
    assert_eq!(recovered.latest_receipt(), Some(receipt));
    Ok(())
}

#[test]
fn initial_cursor_is_synced_before_descriptor_publication_and_recovered_by_exact_create_retry()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish(volume)?;
    let instance = InstanceId::new([0x8a; 16])?;
    let secret = CatalogSecret::from_owned(Box::new([0x8b; 32]), Box::new([0x8c; 32]));
    let catalog = Catalog::open(&authority, instance, secret)?;
    let binding = ExportOutputBinding::new(
        TenantId::from_bytes([0x41; 16])?,
        [0x8d; 16],
        [0x8e; 32],
        [0x8f; 32],
        7,
        9,
        SnapshotLeaseId::new([0x90; 16])?,
        100,
        3_700,
    )?;
    let interrupted =
        with_catalog_publication_fault_after(CatalogPublicationFault::SynchronizeCommit, 0, || {
            ExportOutput::create_with_initial_cursor(&catalog, binding, b"original snapshot cursor")
        });
    assert!(matches!(
        interrupted,
        Err(error) if error.code() == positron_kernel::ExportOutputFailureCode::StorageUnavailable
    ));

    let output =
        ExportOutput::create_with_initial_cursor(&catalog, binding, b"original snapshot cursor")?;
    assert_eq!(
        output.initial_cursor(&catalog, 101)?.as_deref(),
        Some(b"original snapshot cursor" as &[u8])
    );
    assert!(matches!(
        ExportOutput::create_with_initial_cursor(&catalog, binding, b"substituted cursor"),
        Err(error) if error.code() == positron_kernel::ExportOutputFailureCode::IdempotencyConflict
    ));
    drop(catalog);
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x8b; 32]), Box::new([0x8c; 32])),
    )?;
    let recovered = ExportOutput::reopen(&catalog, output.identity())?;
    assert_eq!(
        recovered.initial_cursor(&catalog, 101)?.as_deref(),
        Some(b"original snapshot cursor" as &[u8])
    );
    Ok(())
}

#[test]
fn operation_addressed_initial_preparation_survives_descriptor_failure_and_catalog_advance()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish(volume)?;
    let instance = InstanceId::new([0xb1; 16])?;
    let secret = CatalogSecret::from_owned(Box::new([0xb2; 32]), Box::new([0xb3; 32]));
    let catalog = Catalog::open(&authority, instance, secret)?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let request = ExportOutputRequest::new([0xb4; 16], tenant, [0xb5; 16], [0xb6; 32])?;
    let binding = ExportOutputBinding::new_for_operation(
        request,
        [0xb7; 32],
        7,
        9,
        SnapshotLeaseId::new([0xb8; 16])?,
        100,
        3_700,
    )?;

    let interrupted =
        with_catalog_publication_fault_after(CatalogPublicationFault::SynchronizeCommit, 0, || {
            ExportOutput::create_with_initial_cursor(&catalog, binding, b"original cursor")
        });
    assert!(matches!(
        interrupted,
        Err(error) if error.code() == positron_kernel::ExportOutputFailureCode::StorageUnavailable
    ));
    assert!(
        ExportOutput::find_for_request(
            &catalog,
            tenant,
            request.destination(),
            request.request_digest(),
        )?
        .is_none()
    );

    // Publish an unrelated successor and reopen the Catalog at a later clock
    // value. Recovery must find the original operation preparation, never
    // derive a replacement snapshot binding from the advanced state.
    let unrelated = ExportOutputBinding::new(
        tenant,
        [0xb9; 16],
        [0xba; 32],
        [0xbb; 32],
        8,
        10,
        SnapshotLeaseId::new([0xbc; 16])?,
        120,
        3_720,
    )?;
    let _ = ExportOutput::create(&catalog, unrelated)?;
    drop(catalog);
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0xb2; 32]), Box::new([0xb3; 32])),
    )?;

    assert!(matches!(
        ExportOutput::recover_initial(
            &catalog,
            ExportOutputRequest::new([0xb4; 16], tenant, [0xbd; 16], [0xb6; 32])?,
            300,
        ),
        Err(error) if error.code() == positron_kernel::ExportOutputFailureCode::AuthenticationFailed
    ));
    let recovered = ExportOutput::recover_initial(&catalog, request, 300)?
        .ok_or("synced initial preparation must be discoverable by operation")?;
    assert_eq!(recovered.binding(), binding);
    assert_eq!(
        recovered.initial_cursor(&catalog, 300)?.as_deref(),
        Some(b"original cursor" as &[u8])
    );
    assert_eq!(
        recovered.identity(),
        ExportOutput::create_with_initial_cursor(&catalog, binding, b"original cursor",)?
            .identity()
    );
    assert!(matches!(
        ExportOutput::recover_initial(&catalog, request, 3_701),
        Err(error) if error.code() == positron_kernel::ExportOutputFailureCode::Expired
    ));
    Ok(())
}

#[test]
fn tampered_initial_preparation_fails_closed_without_replacement_output()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish(volume)?;
    let instance = InstanceId::new([0xbe; 16])?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0xbf; 32]), Box::new([0xc0; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let request = ExportOutputRequest::new([0xc1; 16], tenant, [0xc2; 16], [0xc3; 32])?;
    let binding = ExportOutputBinding::new_for_operation(
        request,
        [0xc4; 32],
        7,
        9,
        SnapshotLeaseId::new([0xc5; 16])?,
        100,
        3_700,
    )?;
    let output = ExportOutput::create_with_initial_cursor(&catalog, binding, b"original cursor")?;
    let path = initial_path(&root, output.identity());
    let original = fs::read(&path)?;
    let mut tampered = original.clone();
    let byte = tampered
        .last_mut()
        .ok_or("initial preparation must contain authenticated bytes")?;
    *byte ^= 0x01;
    fs::write(&path, tampered)?;

    assert!(matches!(
        ExportOutput::recover_initial(&catalog, request, 300),
        Err(error) if matches!(
            error.code(),
            positron_kernel::ExportOutputFailureCode::AuthenticationFailed
                | positron_kernel::ExportOutputFailureCode::IntegrityCorruption
                | positron_kernel::ExportOutputFailureCode::StorageUnavailable
        )
    ));
    fs::write(&path, &original[..original.len() / 2])?;
    let partial = ExportOutput::recover_initial(&catalog, request, 300)
        .expect_err("partial authenticated preparation must not recover");
    assert_ne!(
        partial.code(),
        positron_kernel::ExportOutputFailureCode::ConcurrentWriter
    );
    ExportOutput::create_with_initial_cursor(&catalog, binding, b"original cursor")
        .expect_err("partial initial preparation must not be replaced");
    assert_eq!(
        ExportOutput::find_for_request(
            &catalog,
            tenant,
            request.destination(),
            request.request_digest(),
        )?
        .map(|existing| existing.identity()),
        Some(output.identity())
    );
    Ok(())
}

#[test]
fn later_orphan_keeps_the_predecessor_checkpoint_until_its_exact_retry_publishes_it()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish(volume)?;
    let instance = InstanceId::new([0x91; 16])?;
    let secret = CatalogSecret::from_owned(Box::new([0x92; 32]), Box::new([0x93; 32]));
    let catalog = Catalog::open(&authority, instance, secret)?;
    let binding = ExportOutputBinding::new(
        TenantId::from_bytes([0x41; 16])?,
        [0x94; 16],
        [0x95; 32],
        [0x96; 32],
        7,
        9,
        SnapshotLeaseId::new([0x97; 16])?,
        100,
        3_700,
    )?;
    let mut output = ExportOutput::create(&catalog, binding)?;
    let first = output.append_batch(
        &catalog,
        101,
        0,
        [0x98; 32],
        b"committed predecessor",
        Some(b"predecessor cursor"),
    )?;

    let interrupted =
        with_catalog_publication_fault_after(CatalogPublicationFault::SynchronizeCommit, 0, || {
            output.append_batch(
                &catalog,
                102,
                1,
                [0x99; 32],
                b"final payload-synced-before-descriptor",
                Some(b"final cursor"),
            )
        });
    assert!(matches!(
        interrupted,
        Err(error) if error.code() == positron_kernel::ExportOutputFailureCode::StorageUnavailable
    ));
    let checkpoint = output
        .latest_checkpoint(&catalog, 102)?
        .ok_or("the descriptor's committed predecessor checkpoint is retained")?;
    assert_eq!(checkpoint.receipt(), first);
    assert_eq!(
        checkpoint.continuation_cursor().as_deref(),
        Some(b"predecessor cursor" as &[u8])
    );

    let final_receipt = output.append_batch(
        &catalog,
        102,
        1,
        [0x99; 32],
        b"final payload-synced-before-descriptor",
        Some(b"final cursor"),
    )?;
    assert_eq!(
        output.batch_receipts(&catalog, 102)?,
        vec![first, final_receipt]
    );
    assert_eq!(
        output
            .latest_checkpoint(&catalog, 102)?
            .ok_or("published final batch checkpoint missing")?
            .receipt(),
        final_receipt
    );
    Ok(())
}

#[test]
fn output_admission_refuses_before_decrypting_a_corrupt_prior_payload() -> Result<(), Box<dyn Error>>
{
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish(volume)?;
    let instance = InstanceId::new([0xa1; 16])?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0xa2; 32]), Box::new([0xa3; 32])),
    )?;
    let binding = ExportOutputBinding::new(
        TenantId::from_bytes([0x41; 16])?,
        [0xa4; 16],
        [0xa5; 32],
        [0xa6; 32],
        7,
        9,
        SnapshotLeaseId::new([0xa7; 16])?,
        100,
        3_700,
    )?;
    let mut output = ExportOutput::create(&catalog, binding)?;
    output.append_batch(&catalog, 101, 0, [0xa8; 32], b"committed", None)?;
    let payload = payload_path(&root, output.identity());
    let mut corrupted = fs::read(&payload)?;
    let last = corrupted
        .last_mut()
        .ok_or("protected payload must contain one encrypted record")?;
    *last ^= 0x01;
    fs::write(payload, corrupted)?;

    let reservation = output.reserve_next_batch(&catalog)?;
    let failure = output
        .append_batch(&catalog, 102, 1, [0xa9; 32], b"must-not-decrypt", None)
        .expect_err("capacity exhaustion must stop before corrupt payload decrypt");
    assert_eq!(
        failure.code(),
        positron_kernel::ExportOutputFailureCode::ResourceAdmissionRefused
    );
    drop(reservation);
    assert!(matches!(
        output.read_batch(&catalog, 102, 0),
        Err(error) if matches!(error.code(), positron_kernel::ExportOutputFailureCode::AuthenticationFailed | positron_kernel::ExportOutputFailureCode::IntegrityCorruption)
    ));
    Ok(())
}

#[test]
fn durable_output_reopens_authenticated_incremental_payload_without_rewriting_prior_batches()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish(volume)?;
    let instance = InstanceId::new([0x11; 16])?;
    let secret = CatalogSecret::from_owned(Box::new([0x12; 32]), Box::new([0x13; 32]));
    let catalog = Catalog::open(&authority, instance, secret)?;
    let binding = ExportOutputBinding::new(
        TenantId::from_bytes([0x41; 16])?,
        [0x21; 16],
        [0x22; 32],
        [0x23; 32],
        7,
        9,
        SnapshotLeaseId::new([0x24; 16])?,
        100,
        3_700,
    )?;
    let mut output = ExportOutput::create(&catalog, binding)?;
    let first = output.append_batch(&catalog, 120, 0, [0x31; 32], b"first batch", None)?;
    let second = output.append_batch(
        &catalog,
        121,
        1,
        [0x32; 32],
        b"second batch",
        Some(b"cursor"),
    )?;
    assert_eq!(first.sequence(), 0);
    assert_eq!(second.sequence(), 1);
    assert_eq!(output.read_batch(&catalog, 122, 0)?, b"first batch");
    assert_eq!(output.read_batch(&catalog, 122, 1)?, b"second batch");
    let manifest = vec![0x5a; 42_496];
    output.write_manifest(&catalog, 123, &manifest)?;
    output.write_manifest(&catalog, 124, &manifest)?;
    assert!(matches!(
        output.write_manifest(&catalog, 125, b"different manifest"),
        Err(error) if error.code() == positron_kernel::ExportOutputFailureCode::IdempotencyConflict
    ));

    let identity = output.identity();
    drop(catalog);
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x12; 32]), Box::new([0x13; 32])),
    )?;
    let recovered = ExportOutput::reopen(&catalog, identity)?;
    assert_eq!(recovered.binding(), binding);
    assert_eq!(recovered.batch_count(), 2);
    assert_eq!(recovered.latest_receipt(), Some(second));
    assert_eq!(
        recovered
            .latest_checkpoint(&catalog, 122)?
            .and_then(|checkpoint| checkpoint.continuation_cursor()),
        Some(b"cursor".to_vec())
    );
    assert_eq!(recovered.read_batch(&catalog, 122, 0)?, b"first batch");
    assert_eq!(recovered.read_manifest(&catalog, 126)?, Some(manifest));
    Ok(())
}

#[test]
fn corrupted_or_substituted_export_payload_fails_closed_after_reopen() -> Result<(), Box<dyn Error>>
{
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish(volume)?;
    let instance = InstanceId::new([0x41; 16])?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x42; 32]), Box::new([0x43; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let lease = SnapshotLeaseId::new([0x46; 16])?;
    let binding = |destination| {
        ExportOutputBinding::new(
            tenant,
            destination,
            [0x44; 32],
            [0x45; 32],
            9,
            11,
            lease,
            100,
            3_700,
        )
    };
    let mut first = ExportOutput::create(&catalog, binding([0x47; 16])?)?;
    let mut second = ExportOutput::create(&catalog, binding([0x48; 16])?)?;
    first.append_batch(
        &catalog,
        101,
        0,
        [0x49; 32],
        b"first",
        Some(b"first cursor"),
    )?;
    second.append_batch(
        &catalog,
        101,
        0,
        [0x4a; 32],
        b"second",
        Some(b"second cursor"),
    )?;
    first.write_manifest(&catalog, 102, b"terminal manifest")?;
    second.write_manifest(&catalog, 102, b"other terminal manifest")?;
    let first_path = payload_path(&root, first.identity());
    let second_path = payload_path(&root, second.identity());
    let first_manifest = manifest_path(&root, first.identity());
    let second_manifest = manifest_path(&root, second.identity());
    let first_bytes = fs::read(&first_path)?;
    fs::write(&second_path, first_bytes)?;
    fs::write(&second_manifest, fs::read(&first_manifest)?)?;
    assert!(
        matches!(second.read_batch(&catalog, 102, 0), Err(error) if matches!(error.code(), positron_kernel::ExportOutputFailureCode::AuthenticationFailed | positron_kernel::ExportOutputFailureCode::IntegrityCorruption))
    );

    let mut corrupted = fs::read(&first_path)?;
    let last = corrupted
        .len()
        .checked_sub(1)
        .ok_or("protected payload missing")?;
    let byte = corrupted
        .get_mut(last)
        .ok_or("protected payload byte missing")?;
    *byte ^= 0x01;
    fs::write(&first_path, corrupted)?;
    drop(catalog);
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x42; 32]), Box::new([0x43; 32])),
    )?;
    assert!(
        matches!(ExportOutput::reopen(&catalog, first.identity()), Err(error) if matches!(error.code(), positron_kernel::ExportOutputFailureCode::AuthenticationFailed | positron_kernel::ExportOutputFailureCode::IntegrityCorruption))
    );
    assert!(
        matches!(second.read_manifest(&catalog, 102), Err(error) if matches!(error.code(), positron_kernel::ExportOutputFailureCode::AuthenticationFailed | positron_kernel::ExportOutputFailureCode::IntegrityCorruption))
    );
    Ok(())
}
