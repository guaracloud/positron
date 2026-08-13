use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_kernel::{
    ActiveSegmentLedger, Catalog, CatalogSecret, InstanceId, LedgerFailureCode, MountQualification,
    PreparedStoreBlock, PrimaryDataVolume, SegmentId, SegmentProtectionKey, SegmentScope,
    StoreBlockIdentity,
};

use super::support::{TemporaryRoot, establish_kernel_authority};

fn prepared(
    marker: u8,
    payload: &[u8],
) -> Result<PreparedStoreBlock, positron_kernel::LedgerFailure> {
    PreparedStoreBlock::new(StoreBlockIdentity::new([marker; 16])?, payload.to_vec())
}

#[test]
fn recovery_rejects_the_wrong_segment_wrapping_key() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new(0x61)?;
    let catalog = fixture.catalog()?;
    let ledger = fixture.open(&catalog, [0x71; 32])?;
    ledger.append(prepared(1, b"protected")?)?;
    drop(ledger);

    let failure = fixture
        .open(&catalog, [0x72; 32])
        .expect_err("a different wrapping key cannot authenticate the segment DEK");
    assert_eq!(failure.code(), LedgerFailureCode::AuthenticationFailed);
    Ok(())
}

#[test]
fn physical_bootstrap_and_frontier_expose_only_opaque_key_routing_metadata()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new(0x60)?;
    let catalog = fixture.catalog()?;
    let provider_reference = [0xa1; 16];
    let ledger = ActiveSegmentLedger::open(
        &fixture.authority,
        &catalog,
        fixture.scope,
        SegmentProtectionKey::from_owned_with_route(Box::new([0x70; 32]), provider_reference, 7)?,
    )?;
    let receipt = ledger.append(prepared(1, b"opaque-bootstrap")?)?;
    drop(ledger);

    let segment = fs::read(active_segment(fixture.root.path(), receipt.segment_id()))?;
    let frontier = fs::read(active_frontier(fixture.root.path(), receipt.segment_id()))?;
    let tenant = [0x41; 16];
    let segment_identity = receipt.segment_id().to_bytes();
    for forbidden in [tenant.as_slice(), segment_identity.as_slice()] {
        assert!(
            !segment
                .windows(forbidden.len())
                .any(|window| window == forbidden)
        );
        assert!(
            !frontier
                .windows(forbidden.len())
                .any(|window| window == forbidden)
        );
    }
    assert!(
        segment
            .windows(16)
            .any(|window| window == provider_reference)
    );

    let wrong_route =
        SegmentProtectionKey::from_owned_with_route(Box::new([0x70; 32]), [0xa2; 16], 7)?;
    let failure =
        ActiveSegmentLedger::open(&fixture.authority, &catalog, fixture.scope, wrong_route)
            .expect_err("a substituted provider reference must fail closed");
    assert_eq!(failure.code(), LedgerFailureCode::AuthenticationFailed);
    Ok(())
}

#[test]
fn recovery_rejects_committed_frame_corruption_and_truncation() -> Result<(), Box<dyn Error>> {
    for truncate in [false, true] {
        let fixture = Fixture::new(if truncate { 0x62 } else { 0x63 })?;
        let catalog = fixture.catalog()?;
        let ledger = fixture.open(&catalog, [0x73; 32])?;
        let receipt = ledger.append(prepared(2, b"durable")?)?;
        drop(ledger);
        let path = active_segment(fixture.root.path(), receipt.segment_id());
        let length = fs::metadata(&path)?.len();
        if truncate {
            OpenOptions::new()
                .write(true)
                .open(&path)?
                .set_len(length - 1)?;
        } else {
            let mut file = OpenOptions::new().write(true).open(&path)?;
            file.seek(SeekFrom::End(-1))?;
            file.write_all(&[0xa5])?;
            file.sync_all()?;
        }

        let failure = fixture
            .open(&catalog, [0x73; 32])
            .expect_err("committed bytes must fail closed");
        assert!(matches!(
            failure.code(),
            LedgerFailureCode::IntegrityCorruption | LedgerFailureCode::AuthenticationFailed
        ));
    }
    Ok(())
}

#[test]
fn recovery_discards_only_bytes_after_the_authenticated_frontier() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new(0x64)?;
    let catalog = fixture.catalog()?;
    let ledger = fixture.open(&catalog, [0x74; 32])?;
    let receipt = ledger.append(prepared(3, b"frontier-bounded")?)?;
    drop(ledger);
    let path = active_segment(fixture.root.path(), receipt.segment_id());
    let durable_length = fs::metadata(&path)?.len();
    let mut file = OpenOptions::new().append(true).open(&path)?;
    file.write_all(b"unacknowledged-tail")?;
    file.sync_all()?;

    let reopened = fixture.open(&catalog, [0x74; 32])?;
    let snapshot = reopened.snapshot()?;
    assert_eq!(snapshot.frontier(), receipt.position());
    assert_eq!(snapshot.blocks().len(), 1);
    assert_eq!(
        fs::metadata(sealed_segment(fixture.root.path(), receipt.segment_id()))?.len(),
        durable_length
    );
    Ok(())
}

#[test]
fn recovery_rejects_frontier_authenticator_corruption() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new(0x65)?;
    let catalog = fixture.catalog()?;
    let ledger = fixture.open(&catalog, [0x75; 32])?;
    let receipt = ledger.append(prepared(4, b"authenticated")?)?;
    drop(ledger);
    let path = active_frontier(fixture.root.path(), receipt.segment_id());
    let mut file = OpenOptions::new().write(true).open(path)?;
    file.seek(SeekFrom::End(-1))?;
    file.write_all(&[0x5a])?;
    file.sync_all()?;

    let failure = fixture
        .open(&catalog, [0x75; 32])
        .expect_err("frontier authentication must fail closed");
    assert!(matches!(
        failure.code(),
        LedgerFailureCode::AuthenticationFailed | LedgerFailureCode::IntegrityCorruption
    ));
    Ok(())
}

#[test]
fn recovery_rejects_truncated_trailing_and_structurally_corrupt_frontiers()
-> Result<(), Box<dyn Error>> {
    for mutation in 0..5 {
        let fixture = Fixture::new(0x66 + mutation)?;
        let catalog = fixture.catalog()?;
        let ledger = fixture.open(&catalog, [0x76; 32])?;
        let receipt = ledger.append(prepared(5, b"frontier-shape")?)?;
        drop(ledger);
        let path = active_frontier(fixture.root.path(), receipt.segment_id());
        match mutation {
            0 => OpenOptions::new().write(true).open(&path)?.set_len(81)?,
            1 => {
                let mut file = OpenOptions::new().append(true).open(&path)?;
                file.write_all(&[0])?;
                file.sync_all()?;
            },
            2 => {
                let mut file = OpenOptions::new().write(true).open(&path)?;
                file.write_all(b"X")?;
                file.sync_all()?;
            },
            3 => {
                let mut file = OpenOptions::new().write(true).open(&path)?;
                file.seek(SeekFrom::Start(10))?;
                file.write_all(&2_u16.to_be_bytes())?;
                file.sync_all()?;
            },
            _ => {
                let mut file = OpenOptions::new().write(true).open(&path)?;
                file.seek(SeekFrom::Start(12))?;
                file.write_all(&0_u32.to_be_bytes())?;
                file.sync_all()?;
            },
        }
        let failure = fixture
            .open(&catalog, [0x76; 32])
            .expect_err("malformed frontiers fail closed");
        assert_eq!(
            failure.code(),
            if mutation == 3 {
                LedgerFailureCode::UnsupportedFormat
            } else {
                LedgerFailureCode::IntegrityCorruption
            }
        );
    }
    Ok(())
}

#[test]
fn recovery_rejects_an_unknown_segment_header_version() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new(0x69)?;
    let catalog = fixture.catalog()?;
    let ledger = fixture.open(&catalog, [0x79; 32])?;
    let receipt = ledger.append(prepared(6, b"versioned")?)?;
    drop(ledger);
    let path = active_segment(fixture.root.path(), receipt.segment_id());
    let mut file = OpenOptions::new().write(true).open(path)?;
    file.seek(SeekFrom::Start(9))?;
    file.write_all(&[2])?;
    file.sync_all()?;

    let failure = fixture
        .open(&catalog, [0x79; 32])
        .expect_err("unknown segment versions fail closed");
    assert_eq!(failure.code(), LedgerFailureCode::UnsupportedFormat);
    Ok(())
}

#[test]
fn sealed_segments_reject_bytes_beyond_their_frontier() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new(0x6a)?;
    let catalog = fixture.catalog()?;
    let ledger = fixture.open(&catalog, [0x7a; 32])?;
    let receipt = ledger.append(prepared(7, b"sealed-exact")?)?;
    ledger.seal()?;
    let path = sealed_segment(fixture.root.path(), receipt.segment_id());
    let mut file = OpenOptions::new().append(true).open(path)?;
    file.write_all(b"forbidden-tail")?;
    file.sync_all()?;

    let failure = fixture
        .open(&catalog, [0x7a; 32])
        .expect_err("sealed segments are immutable");
    assert_eq!(failure.code(), LedgerFailureCode::IntegrityCorruption);
    Ok(())
}

#[test]
fn recovery_rejects_missing_multiply_linked_and_duplicated_segment_artifacts()
-> Result<(), Box<dyn Error>> {
    for mutation in 0..3 {
        let fixture = Fixture::new(0x6b + mutation)?;
        let catalog = fixture.catalog()?;
        let ledger = fixture.open(&catalog, [0x7b; 32])?;
        let receipt = ledger.append(prepared(8, b"safe-path")?)?;
        drop(ledger);
        let active = active_segment(fixture.root.path(), receipt.segment_id());
        match mutation {
            0 => fs::remove_file(&active)?,
            1 => fs::hard_link(&active, fixture.root.path().join("extra-hard-link"))?,
            _ => {
                let sealed = sealed_segment(fixture.root.path(), receipt.segment_id());
                fs::copy(&active, sealed)?;
            },
        }
        let failure = fixture
            .open(&catalog, [0x7b; 32])
            .expect_err("unsafe artifact topology fails closed");
        assert_eq!(failure.code(), LedgerFailureCode::IntegrityCorruption);
    }
    Ok(())
}

#[test]
fn recovery_rejects_a_frontier_present_in_both_lifecycle_directories() -> Result<(), Box<dyn Error>>
{
    let fixture = Fixture::new(0x6e)?;
    let catalog = fixture.catalog()?;
    let ledger = fixture.open(&catalog, [0x7e; 32])?;
    let receipt = ledger.append(prepared(9, b"one-frontier")?)?;
    drop(ledger);
    let source = active_frontier(fixture.root.path(), receipt.segment_id());
    let duplicate = sealed_frontier(fixture.root.path(), receipt.segment_id());
    fs::copy(source, duplicate)?;

    let failure = fixture
        .open(&catalog, [0x7e; 32])
        .expect_err("duplicate lifecycle frontiers fail closed");
    assert_eq!(failure.code(), LedgerFailureCode::IntegrityCorruption);
    Ok(())
}

#[test]
fn an_empty_sealed_segment_rejects_unpublished_tail_bytes() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new(0x6f)?;
    let catalog = fixture.catalog()?;
    let ledger = fixture.open(&catalog, [0x7f; 32])?;
    let segment = ledger.seal()?.segment_id();
    let path = sealed_segment(fixture.root.path(), segment);
    let mut file = OpenOptions::new().append(true).open(path)?;
    file.write_all(b"no-frontier-tail")?;
    file.sync_all()?;

    let failure = fixture
        .open(&catalog, [0x7f; 32])
        .expect_err("sealed no-frontier tail fails closed");
    assert_eq!(failure.code(), LedgerFailureCode::IntegrityCorruption);
    Ok(())
}

#[test]
fn recovery_rejects_unsafe_temporary_and_unpublished_artifact_shapes() -> Result<(), Box<dyn Error>>
{
    let temporary_fixture = Fixture::new(0x70)?;
    let temporary_catalog = temporary_fixture.catalog()?;
    let temporary_ledger = temporary_fixture.open(&temporary_catalog, [0x80; 32])?;
    let segment = temporary_ledger
        .append(prepared(10, b"temporary-shape")?)?
        .segment_id();
    drop(temporary_ledger);
    fs::create_dir(
        temporary_fixture
            .root
            .path()
            .join("segments/active")
            .join(format!("{}.frontier.tmp", hex(segment.to_bytes()))),
    )?;
    let failure = temporary_fixture
        .open(&temporary_catalog, [0x80; 32])
        .expect_err("a frontier temporary directory cannot be reconciled as a file");
    assert_eq!(failure.code(), LedgerFailureCode::StorageUnavailable);

    for (seed, directory, name, expected) in [
        (
            0x71,
            "active",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.segment",
            LedgerFailureCode::StorageUnavailable,
        ),
        (
            0x72,
            "sealed",
            "unknown-artifact",
            LedgerFailureCode::IntegrityCorruption,
        ),
    ] {
        let fixture = Fixture::new(seed)?;
        let catalog = fixture.catalog()?;
        let ledger = fixture.open(&catalog, [0x81; 32])?;
        drop(ledger);
        fs::create_dir(
            fixture
                .root
                .path()
                .join("segments")
                .join(directory)
                .join(name),
        )?;
        let failure = fixture
            .open(&catalog, [0x81; 32])
            .expect_err("unsafe unpublished topology must fail closed");
        assert_eq!(failure.code(), expected);
    }
    Ok(())
}

struct Fixture {
    root: TemporaryRoot,
    authority: positron_kernel::StorageKernelResourceAuthority,
    seed: u8,
    scope: SegmentScope,
}

impl Fixture {
    fn new(seed: u8) -> Result<Self, Box<dyn Error>> {
        let root = TemporaryRoot::new()?;
        let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
        let authority = establish_kernel_authority(volume)?;
        Ok(Self {
            root,
            authority,
            seed,
            scope: SegmentScope::new(
                TenantId::from_bytes([0x41; 16])?,
                SignalKind::Logs,
                VirtualShardId::new(u32::from(seed))?,
            ),
        })
    }

    fn catalog(&self) -> Result<Catalog<'_>, Box<dyn Error>> {
        Catalog::open(
            &self.authority,
            InstanceId::new([self.seed; 16])?,
            CatalogSecret::from_owned(Box::new([self.seed + 1; 32]), Box::new([self.seed + 2; 32])),
        )
        .map_err(Into::into)
    }

    fn open<'authority, 'catalog>(
        &'authority self,
        catalog: &'catalog Catalog<'authority>,
        key: [u8; 32],
    ) -> Result<ActiveSegmentLedger<'authority, 'catalog>, positron_kernel::LedgerFailure> {
        ActiveSegmentLedger::open(
            &self.authority,
            catalog,
            self.scope,
            SegmentProtectionKey::from_owned(Box::new(key)),
        )
    }
}

fn active_segment(root: &Path, id: SegmentId) -> PathBuf {
    root.join("segments")
        .join("active")
        .join(format!("{}.segment", hex(id.to_bytes())))
}

fn active_frontier(root: &Path, id: SegmentId) -> PathBuf {
    root.join("segments")
        .join("active")
        .join(format!("{}.frontier", hex(id.to_bytes())))
}

fn sealed_segment(root: &Path, id: SegmentId) -> PathBuf {
    root.join("segments")
        .join("sealed")
        .join(format!("{}.segment", hex(id.to_bytes())))
}

fn sealed_frontier(root: &Path, id: SegmentId) -> PathBuf {
    root.join("segments")
        .join("sealed")
        .join(format!("{}.frontier", hex(id.to_bytes())))
}

fn hex(bytes: [u8; 16]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
