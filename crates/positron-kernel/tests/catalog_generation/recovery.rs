use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use positron_kernel::{
    AuditIntent, Catalog, CatalogFailureCode, CatalogObject, CatalogProposal, CatalogSecret,
    FormatEpoch, InstanceId, MountQualification, PrimaryDataVolume, TransactionId,
};

use super::support::establish_catalog_authority;

static NEXT_RECOVERY_ROOT: AtomicU64 = AtomicU64::new(0);

struct TemporaryRoot(PathBuf);

impl TemporaryRoot {
    fn new() -> Result<Self, std::io::Error> {
        let sequence = NEXT_RECOVERY_ROOT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "positron-catalog-recovery-test-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}

fn single_publication(root: &TemporaryRoot, instance: InstanceId) -> Result<(), Box<dyn Error>> {
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = establish_catalog_authority(volume)?;
    let catalog = Catalog::open(&authority, instance, secret())?;
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new(id(82))?,
            FormatEpoch::new(1)?,
            vec![CatalogObject::new(b"published object".to_vec())?],
        )?,
        Some(AuditIntent::new(b"action=publish".to_vec())?),
    )?;
    Ok(())
}

fn only_entry(path: PathBuf) -> Result<PathBuf, Box<dyn Error>> {
    let mut entries = fs::read_dir(path)?;
    let entry = entries.next().ok_or("expected one entry")??;
    if entries.next().is_some() {
        return Err("expected exactly one entry".into());
    }
    Ok(entry.path())
}

#[test]
fn canonical_marker_prefix_falls_back_while_arbitrary_short_bytes_fence()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let instance = InstanceId::new(id(81))?;
    single_publication(&root, instance)?;
    let marker = only_entry(root.0.join("catalog/generations"))?;
    let complete = fs::read(&marker)?;
    fs::write(
        &marker,
        complete.get(..37).ok_or("complete marker too short")?,
    )?;

    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = establish_catalog_authority(volume)?;
    let recovered = Catalog::open(&authority, instance, secret())?;

    assert_eq!(recovered.pin()?.number(), 0);
    assert!(recovered.governance_audit_records()?.is_empty());
    drop(recovered);
    drop(authority);

    fs::write(marker, b"torn")?;
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = establish_catalog_authority(volume)?;
    let failure = Catalog::open(&authority, instance, secret())
        .expect_err("arbitrary short bytes are not a torn publication");
    assert_eq!(failure.code(), CatalogFailureCode::IntegrityCorruption);
    Ok(())
}

#[test]
fn published_generation_with_corrupt_object_fails_closed() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let instance = InstanceId::new(id(81))?;
    single_publication(&root, instance)?;
    let object = only_entry(root.0.join("catalog/objects"))?;
    let mut bytes = fs::read(&object)?;
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0x80;
    fs::write(object, bytes)?;

    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = establish_catalog_authority(volume)?;
    let failure = Catalog::open(&authority, instance, secret())
        .expect_err("published generation with corrupt object must fail closed");

    assert!(matches!(
        failure.code(),
        CatalogFailureCode::IntegrityCorruption | CatalogFailureCode::AuthenticationFailed
    ));
    Ok(())
}

#[test]
fn published_generation_with_corrupt_audit_fails_closed() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let instance = InstanceId::new(id(81))?;
    single_publication(&root, instance)?;
    let audit = only_entry(root.0.join("catalog/governance-audit"))?;
    let mut bytes = fs::read(&audit)?;
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0x40;
    fs::write(audit, bytes)?;

    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = establish_catalog_authority(volume)?;
    let failure = Catalog::open(&authority, instance, secret())
        .expect_err("published generation with corrupt audit must fail closed");

    assert!(matches!(
        failure.code(),
        CatalogFailureCode::IntegrityCorruption | CatalogFailureCode::AuthenticationFailed
    ));
    Ok(())
}

#[test]
fn published_generation_with_corrupt_commit_record_fails_closed() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let instance = InstanceId::new(id(81))?;
    single_publication(&root, instance)?;
    let commit = only_entry(root.0.join("catalog/commits"))?;
    let mut bytes = fs::read(&commit)?;
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0x20;
    fs::write(commit, bytes)?;

    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = establish_catalog_authority(volume)?;
    let failure = Catalog::open(&authority, instance, secret())
        .expect_err("published generation with corrupt commit must fail closed");

    assert_eq!(failure.code(), CatalogFailureCode::IntegrityCorruption);
    Ok(())
}

#[test]
fn every_missing_or_unsafe_published_artifact_fences_as_integrity_corruption()
-> Result<(), Box<dyn Error>> {
    for relative in ["objects", "governance-audit", "commits"] {
        let root = TemporaryRoot::new()?;
        let instance = InstanceId::new(id(89))?;
        single_publication(&root, instance)?;
        let artifact = only_entry(root.0.join("catalog").join(relative))?;
        fs::remove_file(artifact)?;

        let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
        let authority = establish_catalog_authority(volume)?;
        let failure = Catalog::open(&authority, instance, secret())
            .expect_err("missing published artifact must fence recovery");
        assert_eq!(
            failure.code(),
            CatalogFailureCode::IntegrityCorruption,
            "{relative}"
        );
    }

    for shape in ["directory", "hard-link"] {
        let root = TemporaryRoot::new()?;
        let instance = InstanceId::new(id(90))?;
        single_publication(&root, instance)?;
        let object = only_entry(root.0.join("catalog/objects"))?;
        if shape == "directory" {
            fs::remove_file(&object)?;
            fs::create_dir(&object)?;
        } else {
            fs::hard_link(&object, object.with_extension("linked"))?;
        }
        let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
        let authority = establish_catalog_authority(volume)?;
        let failure = Catalog::open(&authority, instance, secret())
            .expect_err("unsafe published artifact must fence recovery");
        assert_eq!(
            failure.code(),
            CatalogFailureCode::IntegrityCorruption,
            "{shape}"
        );
    }
    Ok(())
}

#[test]
fn artifact_magic_and_kind_corruption_are_distinct_from_unknown_format_version()
-> Result<(), Box<dyn Error>> {
    for (offset, value, expected) in [
        (0_usize, b'X', CatalogFailureCode::IntegrityCorruption),
        (10, 9, CatalogFailureCode::IntegrityCorruption),
        (9, 4, CatalogFailureCode::UnsupportedFormat),
    ] {
        let root = TemporaryRoot::new()?;
        let instance = InstanceId::new(id(91))?;
        single_publication(&root, instance)?;
        let object = only_entry(root.0.join("catalog/objects"))?;
        let mut bytes = fs::read(&object)?;
        let byte = bytes
            .get_mut(offset)
            .ok_or("artifact header is unexpectedly short")?;
        *byte = value;
        fs::write(object, bytes)?;

        let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
        let authority = establish_catalog_authority(volume)?;
        let failure = Catalog::open(&authority, instance, secret())
            .expect_err("invalid artifact header must fence recovery");
        assert_eq!(failure.code(), expected, "offset {offset}");
    }
    Ok(())
}

#[test]
fn complete_marker_with_bad_magic_fences_recovery() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let instance = InstanceId::new(id(85))?;
    single_publication(&root, instance)?;
    let marker = only_entry(root.0.join("catalog/generations"))?;
    let mut bytes = fs::read(&marker)?;
    bytes[0] ^= 0x40;
    fs::write(marker, bytes)?;

    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = establish_catalog_authority(volume)?;
    let failure = Catalog::open(&authority, instance, secret())
        .expect_err("complete marker corruption must fence recovery");
    assert_eq!(failure.code(), CatalogFailureCode::IntegrityCorruption);
    Ok(())
}

#[test]
fn complete_marker_with_unknown_version_fences_recovery() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let instance = InstanceId::new(id(87))?;
    single_publication(&root, instance)?;
    let marker = only_entry(root.0.join("catalog/generations"))?;
    let mut bytes = fs::read(&marker)?;
    bytes[9] = 2;
    fs::write(marker, bytes)?;

    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = establish_catalog_authority(volume)?;
    let failure = Catalog::open(&authority, instance, secret())
        .expect_err("an unknown complete marker version must fence recovery");
    assert_eq!(failure.code(), CatalogFailureCode::UnsupportedFormat);
    Ok(())
}

#[test]
fn only_canonical_nonempty_marker_prefixes_are_unpublished_while_other_shapes_fence()
-> Result<(), Box<dyn Error>> {
    for shape in [
        "empty",
        "impossible-prefix",
        "trailing",
        "directory",
        "hard-link",
    ] {
        let root = TemporaryRoot::new()?;
        let instance = InstanceId::new(id(88))?;
        single_publication(&root, instance)?;
        let marker = only_entry(root.0.join("catalog/generations"))?;
        match shape {
            "empty" => fs::write(&marker, [])?,
            "impossible-prefix" => fs::write(&marker, b"X")?,
            "trailing" => {
                let mut bytes = fs::read(&marker)?;
                bytes.push(0);
                fs::write(&marker, bytes)?;
            },
            "directory" => {
                fs::remove_file(&marker)?;
                fs::create_dir(&marker)?;
            },
            "hard-link" => fs::hard_link(&marker, marker.with_extension("linked"))?,
            _ => return Err("unknown marker shape".into()),
        }

        let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
        let authority = establish_catalog_authority(volume)?;
        let failure = Catalog::open(&authority, instance, secret())
            .expect_err("a non-torn published-marker shape must fence recovery");
        assert_eq!(
            failure.code(),
            CatalogFailureCode::IntegrityCorruption,
            "{shape}"
        );
    }
    Ok(())
}

#[test]
fn authenticated_marker_under_a_mismatched_name_fences_recovery() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let instance = InstanceId::new(id(86))?;
    single_publication(&root, instance)?;
    let marker = only_entry(root.0.join("catalog/generations"))?;
    fs::rename(marker, root.0.join("catalog/generations/untrusted.marker"))?;

    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = establish_catalog_authority(volume)?;
    let failure = Catalog::open(&authority, instance, secret())
        .expect_err("the authenticated marker payload must authorize its exact pathname");
    assert_eq!(failure.code(), CatalogFailureCode::IntegrityCorruption);
    Ok(())
}

#[test]
fn wrong_catalog_key_cannot_open_a_published_generation() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let instance = InstanceId::new(id(81))?;
    single_publication(&root, instance)?;

    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = establish_catalog_authority(volume)?;
    let failure = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x43; 32]), Box::new([0x44; 32])),
    )
    .expect_err("wrong catalog secret must fail closed");

    assert_eq!(failure.code(), CatalogFailureCode::AuthenticationFailed);
    Ok(())
}

#[test]
fn maximum_audit_intent_remains_readable_after_restart() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let instance = InstanceId::new(id(83))?;
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = establish_catalog_authority(volume)?;
    let catalog = Catalog::open(&authority, instance, secret())?;
    let intent = vec![0x41; 65_536];
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new(id(84))?,
            FormatEpoch::new(1)?,
            vec![CatalogObject::new(b"maximum audit".to_vec())?],
        )?,
        Some(AuditIntent::new(intent.clone())?),
    )?;
    drop(catalog);
    drop(authority);

    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = establish_catalog_authority(volume)?;
    let recovered = Catalog::open(&authority, instance, secret())?;
    assert_eq!(recovered.governance_audit_records()?[0].intent(), intent);
    Ok(())
}

impl Drop for TemporaryRoot {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.0) {
            eprintln!("failed to remove recovery test root: {error}");
        }
    }
}

fn id(last: u8) -> [u8; 16] {
    let mut bytes = [0_u8; 16];
    bytes[15] = last;
    bytes
}

fn secret() -> CatalogSecret {
    CatalogSecret::from_owned(Box::new([0xc1; 32]), Box::new([0xd1; 32]))
}

#[test]
fn restart_recovers_the_complete_generation_and_audit_chain() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let instance = InstanceId::new(id(41))?;
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = establish_catalog_authority(volume)?;
    let catalog = Catalog::open(&authority, instance, secret())?;
    let first_object = CatalogObject::new(b"resource generation 1".to_vec())?;
    let first_id = first_object.identity();
    let first = catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new(id(42))?,
            FormatEpoch::new(1)?,
            vec![first_object],
        )?,
        Some(AuditIntent::new(b"action=create".to_vec())?),
    )?;
    let second_object = CatalogObject::new(b"resource generation 2".to_vec())?;
    let second_id = second_object.identity();
    let second = catalog.commit(
        first.identity(),
        CatalogProposal::new(
            TransactionId::new(id(43))?,
            FormatEpoch::new(1)?,
            vec![second_object],
        )?,
        Some(AuditIntent::new(b"action=update".to_vec())?),
    )?;
    drop(catalog);
    drop(authority);

    let reopened_volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let reopened_authority = establish_catalog_authority(reopened_volume)?;
    let recovered = Catalog::open(&reopened_authority, instance, secret())?;

    assert_eq!(recovered.pin()?.identity(), second.identity());
    assert_eq!(
        recovered.pin()?.object(second_id)?,
        Some(b"resource generation 2".as_slice())
    );
    assert_eq!(recovered.pin()?.object(first_id)?, None);
    let audit = recovered.governance_audit_records()?;
    assert_eq!(
        audit
            .iter()
            .map(|record| record.position())
            .collect::<Vec<_>>(),
        [1, 2]
    );
    assert_eq!(audit[1].predecessor_hash(), audit[0].record_hash());
    Ok(())
}
