use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest, Sha256};

use positron_kernel::{
    AuditIntent, BootstrapKeyCustody, Catalog, CatalogObject, CatalogProposal, DiskObservation,
    DiskPressureThresholds, GovernorPolicy, InventoryCardinalityLimits, MountQualification,
    ObservedResourceEnvironment, OperatorLimits, OrdinaryPoolPolicy, PrimaryDataVolume,
    RecoveryPoolCapacities, RecoveryReserve, ResourceAmounts, ResourceDimension,
    ResourceGovernorConfiguration, ResourceInventory, StorageKernelResourceAuthority, TenantQuota,
    TransactionId,
};

use super::{
    tenant_administration_proposal::encode_record,
    tenant_administration_registry_codec::{
        TENANT_REGISTRY_V2_MAGIC, decode_registry, is_registry, registry_object,
    },
    tenant_administration_replay::{TENANT_RECEIPT_MAGIC, decode_receipt, replay_receipt},
    *,
};

static NEXT_PAGED_CATALOG_ROOT: AtomicU64 = AtomicU64::new(0);

struct PagedCatalogRoot(PathBuf);

impl PagedCatalogRoot {
    fn new() -> Result<Self, std::io::Error> {
        let sequence = NEXT_PAGED_CATALOG_ROOT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "positron-tenant-list-pages-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&root)?;
        let secrets = root.join("secrets");
        fs::create_dir(&secrets)?;
        fs::set_permissions(&secrets, fs::Permissions::from_mode(0o700))?;
        Ok(Self(root))
    }

    fn secrets(&self) -> PathBuf {
        self.0.join("secrets")
    }
}

impl Drop for PagedCatalogRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn fixture_authority(
    volume: positron_kernel::OwnedPrimaryDataVolume,
    tenant: TenantId,
) -> Result<StorageKernelResourceAuthority, Box<dyn Error>> {
    let cardinality = InventoryCardinalityLimits::new(1, 16)?;
    let large = ResourceAmounts::new([
        70_000_001, 2, 2, 70_000_001, 65_541, 2, 2, 2, 2, 9, 20_000_001,
    ]);
    let small = ResourceAmounts::new([1; 11]);
    let dual = ResourceAmounts::new([2; 11]);
    let durability = add_amounts(add_amounts(large, large)?, large)?;
    let recovery_capacity = add_amounts(
        add_amounts(add_amounts(durability, large)?, large)?,
        ResourceAmounts::new([6; 11]),
    )?;
    let governed = add_amounts(recovery_capacity, ResourceAmounts::new([16; 11]))?;
    let raw = add_amounts(governed, cardinality.governor_bootstrap_overhead(1)?)?;
    let observed = ObservedResourceEnvironment::for_test(
        &volume,
        raw,
        DiskObservation::new(raw.get(ResourceDimension::DiskHeadroomBytes)),
    )?;
    let inventory = ResourceInventory::new_observed(
        observed,
        OperatorLimits::new(raw)?,
        RecoveryReserve::new(recovery_capacity)?,
        cardinality,
        DiskPressureThresholds::new(
            recovery_capacity.get(ResourceDimension::DiskHeadroomBytes),
            recovery_capacity.get(ResourceDimension::DiskHeadroomBytes) + 1,
            recovery_capacity.get(ResourceDimension::DiskHeadroomBytes) + 2,
            raw.get(ResourceDimension::DiskHeadroomBytes),
        )?,
    )?;
    let policy = GovernorPolicy::new(
        [TenantQuota::new(tenant, 1, ResourceAmounts::new([16; 11]))?],
        OrdinaryPoolPolicy::new(
            ResourceAmounts::new([4; 11]),
            ResourceAmounts::new([3; 11]),
            ResourceAmounts::new([2; 11]),
            ResourceAmounts::new([1; 11]),
        )?,
    )?;
    let recovery =
        RecoveryPoolCapacities::new(durability, small, dual, small, large, small, small)?;
    Ok(StorageKernelResourceAuthority::establish(
        volume,
        ResourceGovernorConfiguration::new(inventory, policy, recovery)?,
    )?)
}

fn add_amounts(
    left: ResourceAmounts,
    right: ResourceAmounts,
) -> Result<ResourceAmounts, Box<dyn Error>> {
    let value = |dimension| -> Result<u64, Box<dyn Error>> {
        left.get(dimension)
            .checked_add(right.get(dimension))
            .ok_or_else(|| Box::<dyn Error>::from("pagination fixture capacity overflow"))
    };
    Ok(ResourceAmounts::new([
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

fn tenant(index: u16) -> Result<TenantId, TenantAdministrationFailure> {
    let mut bytes = [0_u8; 16];
    bytes[..2].copy_from_slice(&index.to_be_bytes());
    TenantId::from_bytes(bytes).map_err(|_| TenantAdministrationFailure::InvalidInput)
}

#[test]
fn tenant_list_pages_traverse_a_large_catalog_once_and_reject_a_changed_snapshot()
-> Result<(), Box<dyn Error>> {
    const TENANT_COUNT: u16 = 130;
    const PAGE_LIMIT: usize = 64;

    let root = PagedCatalogRoot::new()?;
    let instance = positron_kernel::InstanceId::new([0x91; 16])?;
    let default_tenant = tenant(1)?;
    let authority = fixture_authority(
        PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?,
        default_tenant,
    )?;
    let keys = BootstrapKeyCustody::initialize(&root.secrets())?;
    let catalog = Catalog::open(&authority, instance, keys.catalog_secret(instance)?)?;
    let administrator = PrincipalId::from_bytes([0x92; 16])?;
    let administrator_secret = [0x93; 32];
    let administrator_salt = [0x94; 32];
    let administrator_hash = keys.salted_secret_hash(&administrator_salt, &administrator_secret)?;
    let initial = crate::InitialGovernanceIntent::create_tenant(crate::InitialTenantIntent::new(
        instance.to_bytes(),
        default_tenant,
        TenantSlug::parse_canonical("default")?,
        "Default tenant",
        administrator,
        administrator_salt,
        administrator_hash,
        PrincipalId::from_bytes([0x95; 16])?,
        [0x96; 32],
        [0x97; 32],
        PrincipalId::from_bytes([0x98; 16])?,
        [0x99; 32],
        [0x9a; 32],
        [0x9b; 32],
        [0x9c; 32],
        vec![0x9d; 48],
        keys.tenant_key_envelope(instance, default_tenant)?,
        2_592_000,
        1,
        1,
        [16; 11],
        crate::InitialAuditContext::new(1_725_000_001, [0x9e; 16], true)?,
    )?)?;
    let (governance, audit) = initial.into_parts();
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new([0x9f; 16])?,
            positron_kernel::FormatEpoch::CATALOG_V2,
            vec![
                CatalogObject::new(governance)?,
                TenantAdministration::initial_registry(instance, default_tenant)?,
            ],
        )?,
        Some(AuditIntent::new(audit)?),
    )?;
    let identity = crate::Identity::open(&catalog.pin()?)?;
    let actor = identity.attribute(
        &keys,
        crate::PresentedCredential::parse(&format!("pos_{}", "93".repeat(32)))?,
        crate::RequestedIntent::SystemAdministration,
        crate::CompatibilityHints::none(),
    )?;

    let mut expected = BTreeMap::new();
    expected.insert(
        default_tenant,
        ("default".to_owned(), "Default tenant".to_owned()),
    );
    let basis = catalog.pin()?;
    let mut objects = Vec::new();
    for object in basis.object_identities() {
        let bytes = basis.object(object)?.ok_or("catalog object")?;
        if !is_registry(bytes) {
            objects.push(CatalogObject::new(bytes.to_vec())?);
        }
    }
    let mut tenants = vec![default_tenant];
    for index in 2..=TENANT_COUNT {
        let tenant = tenant(index)?;
        let slug = format!("tenant-{index:03}");
        let display = format!("Tenant {index}");
        let mut key = [0_u8; 16];
        key[..2].copy_from_slice(&index.to_be_bytes());
        let candidate = TenantCreateRequest::new(
            actor,
            TenantCreateConfiguration::new(
                TenantSlug::parse_canonical(&slug)?,
                &display,
                2_592_000,
                1,
                [1; 11],
            ),
            AdministrativeIdempotencyKey::new(key)?,
        )
        .with_generated_tenant(tenant);
        objects.push(CatalogObject::new(encode_record(
            instance,
            &candidate,
            &[0xa1; 32],
        )?)?);
        tenants.push(tenant);
        expected.insert(tenant, (slug, display));
    }
    objects.push(registry_object(
        instance,
        ResourceGeneration::new(u64::from(TENANT_COUNT))?,
        &tenants,
    )?);
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0xa2; 16])?,
            positron_kernel::FormatEpoch::CATALOG_V2,
            objects,
        )?,
        None,
    )?;

    let snapshot = catalog.pin()?;
    let mut continuation = None;
    let mut first_continuation = None;
    let mut page_lengths = Vec::new();
    let mut seen = BTreeMap::new();
    loop {
        let page = TenantAdministration::list_page(&snapshot, continuation, PAGE_LIMIT)?;
        page_lengths.push(page.inspections().len());
        for inspection in page.inspections() {
            assert!(
                seen.insert(
                    inspection.tenant_id(),
                    (
                        inspection.slug().to_owned(),
                        inspection.display_name().to_owned()
                    ),
                )
                .is_none(),
                "a descriptor must not appear in more than one page"
            );
        }
        continuation = page.continuation();
        if first_continuation.is_none() {
            first_continuation = continuation;
        }
        if continuation.is_none() {
            break;
        }
    }
    assert_eq!(page_lengths, vec![64, 64, 2]);
    assert_eq!(
        seen, expected,
        "every durable descriptor appears exactly once"
    );

    crate::TenantProfileAdministration::update_display_name(
        &catalog,
        &identity,
        crate::TenantDisplayNameUpdateRequest::new(
            actor,
            default_tenant,
            ResourceGeneration::new(1)?,
            "Changed default tenant",
            AdministrativeIdempotencyKey::new([0xa0; 16])?,
        ),
    )?;
    let successor = catalog.pin()?;
    assert_eq!(
        TenantAdministration::list_page(
            &successor,
            Some(first_continuation.expect("the first page has a continuation")),
            PAGE_LIMIT,
        ),
        Err(TenantAdministrationFailure::StaleGeneration),
        "a display mutation changes the whole Catalog snapshot and invalidates its cursor"
    );
    Ok(())
}

#[test]
fn literal_v1_creation_receipt_replays_without_the_retired_precondition() {
    let actor = PrincipalId::from_bytes([0x41; 16]).expect("principal");
    let tenant = TenantId::from_bytes([0x42; 16]).expect("tenant");
    let key = AdministrativeIdempotencyKey::new([0x43; 16]).expect("idempotency");
    let expected = ResourceGeneration::new(7).expect("prior generation");
    let generation = ResourceGeneration::new(8).expect("successor generation");
    let legacy = digest(
        actor,
        tenant,
        "legacy",
        "Legacy tenant",
        key,
        Some(expected),
    );
    let canonical = digest(actor, tenant, "legacy", "Legacy tenant", key, None);

    let mut encoded = Vec::new();
    encoded.extend_from_slice(&TENANT_RECEIPT_MAGIC);
    encoded.extend_from_slice(&key.to_bytes());
    encoded.extend_from_slice(&actor.to_bytes());
    encoded.extend_from_slice(&tenant.to_bytes());
    encoded.extend_from_slice(&expected.get().to_be_bytes());
    encoded.extend_from_slice(&generation.get().to_be_bytes());
    encoded.extend_from_slice(&legacy);
    encoded.extend_from_slice(&17_u64.to_be_bytes());

    let receipt = decode_receipt(&encoded, key)
        .expect("historical receipt decodes")
        .expect("matching receipt");
    assert_eq!(receipt.generation, generation);
    assert_eq!(receipt.audit_position, 17);
    assert!(replay_receipt(&receipt, actor, [0; 32], canonical, legacy).is_ok());

    let changed_legacy = digest(
        actor,
        tenant,
        "legacy",
        "Changed tenant",
        key,
        Some(expected),
    );
    assert_eq!(
        replay_receipt(&receipt, actor, [0; 32], changed_legacy, [1; 32]),
        Err(TenantAdministrationFailure::IdempotencyConflict)
    );
}

#[test]
fn receipt_lookup_skips_a_well_formed_record_for_a_different_idempotency_key() {
    let recorded = AdministrativeIdempotencyKey::new([0x43; 16]).expect("recorded key");
    let sought = AdministrativeIdempotencyKey::new([0x44; 16]).expect("sought key");
    let actor = PrincipalId::from_bytes([0x41; 16]).expect("principal");
    let tenant = TenantId::from_bytes([0x42; 16]).expect("tenant");
    let expected = ResourceGeneration::new(7).expect("prior generation");
    let generation = ResourceGeneration::new(8).expect("successor generation");
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&TENANT_RECEIPT_MAGIC);
    encoded.extend_from_slice(&recorded.to_bytes());
    encoded.extend_from_slice(&actor.to_bytes());
    encoded.extend_from_slice(&tenant.to_bytes());
    encoded.extend_from_slice(&expected.get().to_be_bytes());
    encoded.extend_from_slice(&generation.get().to_be_bytes());
    encoded.extend_from_slice(&[0x45; 32]);
    encoded.extend_from_slice(&17_u64.to_be_bytes());

    assert!(
        decode_receipt(&encoded, sought)
            .expect("well-formed unrelated receipt is ignored")
            .is_none()
    );
}

#[test]
fn registry_decoder_accepts_a_high_cardinality_directory_once() {
    let count = 1_024_u16;
    let mut bytes = Vec::with_capacity(34 + usize::from(count) * 16);
    bytes.extend_from_slice(&TENANT_REGISTRY_V2_MAGIC);
    bytes.extend_from_slice(&[0x11; 16]);
    bytes.extend_from_slice(&1_u64.to_be_bytes());
    bytes.extend_from_slice(&count.to_be_bytes());
    for index in 1..=count {
        let mut tenant = [0_u8; 16];
        tenant[..2].copy_from_slice(&index.to_be_bytes());
        bytes.extend_from_slice(&tenant);
    }

    let registry = decode_registry(&bytes).expect("bounded high-cardinality registry");
    assert_eq!(registry.tenants.len(), usize::from(count));
    assert_eq!(
        registry.tenants.first().map(|tenant| tenant.to_bytes()),
        Some([0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    );
    assert_eq!(
        registry.tenants.last().map(|tenant| tenant.to_bytes()),
        Some([4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    );
}

fn digest(
    actor: PrincipalId,
    tenant: TenantId,
    slug: &str,
    display_name: &str,
    key: AdministrativeIdempotencyKey,
    expected: Option<ResourceGeneration>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(actor.to_bytes());
    hasher.update(tenant.to_bytes());
    hasher.update(slug.as_bytes());
    hasher.update(display_name.as_bytes());
    hasher.update(2_592_000_u64.to_be_bytes());
    hasher.update(1_u32.to_be_bytes());
    for resource in [1_u64; 11] {
        hasher.update(resource.to_be_bytes());
    }
    if let Some(expected) = expected {
        hasher.update(expected.get().to_be_bytes());
    }
    hasher.update(key.to_bytes());
    hasher.finalize().into()
}
