use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};

use positron_domain::routing::CommitPosition;

use crate::active_segment_ledger::object_context;
use crate::catalog::fuzz_authority;
use crate::data_protection::{
    DataProtection, FrameLimits, FrameSequence, SecretKeyBytes, SegmentFramePurpose,
};
use crate::{
    Catalog, CatalogFailureCode, CommittedBlock, InstanceId, LedgerFailureCode, MountQualification,
    PrimaryDataVolume, SegmentId,
};

use super::{
    FuzzRoot, block_parts, catalog_secret, install_retention_policy, open, prepared,
    prepared_retained, scope,
};
use crate::active_segment_ledger::format::{HEADER_PREFIX_BYTES, decode_header};

const AUTHENTICATION_TAG_BYTES: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PersistedArtifact {
    Bootstrap,
    Envelope,
    Frame,
    Frontier,
    Sealed,
    Catalog,
    FrontierSelectorDowngrade,
    FrontierSelectorUpgrade,
}

impl PersistedArtifact {
    pub(super) const fn from_operation(operation: u8) -> Option<Self> {
        match operation {
            7 => Some(Self::Bootstrap),
            8 => Some(Self::Envelope),
            9 => Some(Self::Frame),
            10 => Some(Self::Frontier),
            11 => Some(Self::Sealed),
            12 => Some(Self::Catalog),
            23 => Some(Self::FrontierSelectorDowngrade),
            24 => Some(Self::FrontierSelectorUpgrade),
            _ => None,
        }
    }

    const fn requires_block(self) -> bool {
        matches!(
            self,
            Self::Frame
                | Self::Frontier
                | Self::Sealed
                | Self::FrontierSelectorDowngrade
                | Self::FrontierSelectorUpgrade
        )
    }

    const fn expected_failure(self) -> PersistedFailure {
        match self {
            Self::Bootstrap => PersistedFailure::Ledger(LedgerFailureCode::UnsupportedFormat),
            Self::Envelope => PersistedFailure::Ledger(LedgerFailureCode::AuthenticationFailed),
            Self::Frame
            | Self::Frontier
            | Self::Sealed
            | Self::FrontierSelectorDowngrade
            | Self::FrontierSelectorUpgrade => {
                PersistedFailure::Ledger(LedgerFailureCode::IntegrityCorruption)
            },
            Self::Catalog => PersistedFailure::Catalog(CatalogFailureCode::IntegrityCorruption),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
struct PersistedState {
    frontier: CommitPosition,
    blocks: Vec<CommittedBlock>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PersistedFailure {
    Catalog(CatalogFailureCode),
    Ledger(LedgerFailureCode),
}

pub(super) fn run_persisted_corruption_case(
    artifact: PersistedArtifact,
    entropy: u8,
) -> PersistedArtifact {
    let pristine = FuzzRoot::new().expect("pristine persisted fuzz root is available");
    let expected = prepare_fixture(&pristine.0, artifact);
    let pristine_recovery = reopen_fixture(&pristine.0);
    if artifact == PersistedArtifact::FrontierSelectorUpgrade {
        assert!(
            pristine_recovery.is_ok(),
            "unchanged legacy selector fixture must remain readable"
        );
    } else {
        assert_eq!(
            pristine_recovery,
            Ok(expected),
            "unchanged acknowledged fixture must reopen exactly"
        );
    }

    let corrupted = FuzzRoot::new().expect("corrupted persisted fuzz root is available");
    let _ = prepare_fixture(&corrupted.0, artifact);
    corrupt_persisted_artifact(&corrupted.0, artifact, entropy)
        .expect("selected persisted artifact is mutable");
    assert_eq!(
        reopen_fixture(&corrupted.0),
        Err(artifact.expected_failure()),
        "persisted corruption must produce its documented typed outcome"
    );
    artifact
}

fn prepare_fixture(root: &Path, artifact: PersistedArtifact) -> PersistedState {
    let volume = PrimaryDataVolume::acquire(root, MountQualification::LocalHost)
        .expect("persisted fixture volume opens");
    let authority = fuzz_authority(volume).expect("persisted fixture authority opens");
    let instance = InstanceId::new([0x81; 16]).expect("fixed instance identity");
    let catalog = Catalog::open(&authority, instance, catalog_secret())
        .expect("persisted fixture catalog opens");
    let retention = if matches!(
        artifact,
        PersistedArtifact::Frontier | PersistedArtifact::FrontierSelectorDowngrade
    ) {
        install_retention_policy(&catalog, instance, scope().tenant_id());
        Some(
            crate::RetentionTimeAuthority::establish_with_manual_elapsed(
                positron_domain::time::UnixNanoseconds::new(1_000_000_000),
            ),
        )
    } else {
        None
    };
    let ledger = if let Some((retention_time, _)) = &retention {
        open(&authority, retention_time, &catalog, scope())
            .expect("retained persisted fixture ledger opens")
    } else {
        crate::ActiveSegmentLedger::open(
            &authority,
            &catalog,
            scope(),
            crate::SegmentProtectionKey::from_owned(Box::new([0x91; 32])),
        )
        .expect("persisted fixture ledger opens")
    };
    if artifact.requires_block() {
        let (identity, payload) = block_parts(0, 0xa5);
        let prepared = if retention.is_some() {
            prepared_retained(&ledger, &authority, identity, payload)
        } else {
            prepared(identity, payload)
        };
        ledger
            .append(prepared)
            .expect("persisted fixture block commits");
    }
    let segment = ledger
        .active_segment_id()
        .expect("persisted fixture active segment identity");
    let snapshot = ledger.snapshot().expect("persisted fixture snapshots");
    let expected = PersistedState {
        frontier: snapshot.frontier(),
        blocks: snapshot.blocks().to_vec(),
    };
    drop(snapshot);
    if artifact == PersistedArtifact::Sealed {
        ledger.seal().expect("persisted fixture segment seals");
    } else {
        drop(ledger);
    }
    if artifact == PersistedArtifact::FrontierSelectorUpgrade {
        rewrite_as_legacy_v2(root, segment).expect("legacy selector fixture rewrites");
    }
    drop(catalog);
    drop(authority);
    expected
}

fn reopen_fixture(root: &Path) -> Result<PersistedState, PersistedFailure> {
    let volume = PrimaryDataVolume::acquire(root, MountQualification::LocalHost)
        .expect("persisted fixture releases volume ownership");
    let authority = fuzz_authority(volume).expect("persisted recovery authority opens");
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x81; 16]).expect("fixed instance identity"),
        catalog_secret(),
    )
    .map_err(|failure| PersistedFailure::Catalog(failure.code()))?;
    let ledger = crate::ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope(),
        crate::SegmentProtectionKey::from_owned(Box::new([0x91; 32])),
    )
    .map_err(|failure| PersistedFailure::Ledger(failure.code()))?;
    let snapshot = ledger
        .snapshot()
        .map_err(|failure| PersistedFailure::Ledger(failure.code()))?;
    Ok(PersistedState {
        frontier: snapshot.frontier(),
        blocks: snapshot.blocks().to_vec(),
    })
}

fn corrupt_persisted_artifact(
    root: &Path,
    artifact: PersistedArtifact,
    entropy: u8,
) -> io::Result<()> {
    let path = match artifact {
        PersistedArtifact::Bootstrap | PersistedArtifact::Envelope | PersistedArtifact::Frame => {
            first_file(root.join("segments/active"), "segment")?
        },
        PersistedArtifact::Frontier
        | PersistedArtifact::FrontierSelectorDowngrade
        | PersistedArtifact::FrontierSelectorUpgrade => {
            first_file(root.join("segments/active"), "frontier")?
        },
        PersistedArtifact::Sealed => first_file(root.join("segments/sealed"), "segment")?,
        PersistedArtifact::Catalog => first_file(root.join("catalog/objects"), "frame")?,
    };
    if matches!(
        artifact,
        PersistedArtifact::FrontierSelectorDowngrade | PersistedArtifact::FrontierSelectorUpgrade
    ) {
        let selected = match artifact {
            PersistedArtifact::FrontierSelectorDowngrade => 2_u16,
            PersistedArtifact::FrontierSelectorUpgrade => 3_u16,
            _ => {
                return Err(io::Error::other(
                    "selector artifact changed during mutation",
                ));
            },
        };
        let mut bytes = fs::read(&path)?;
        let selector = bytes.get_mut(10..12).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "frontier selector absent")
        })?;
        selector.copy_from_slice(&selected.to_be_bytes());
        fs::write(path, bytes)?;
        return Ok(());
    }
    let bytes = fs::read(&path)?;
    let range = corruption_range(&bytes, artifact)?;
    let width = range
        .end
        .checked_sub(range.start)
        .filter(|width| *width != 0)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty corruption range"))?;
    let offset = range.start + usize::from(entropy) % width;
    let mut file = fs::OpenOptions::new().read(true).write(true).open(path)?;
    file.seek(SeekFrom::Start(offset as u64))?;
    let mut byte = [0_u8; 1];
    file.read_exact(&mut byte)?;
    byte[0] ^= 1_u8 << (entropy % 8);
    file.seek(SeekFrom::Start(offset as u64))?;
    file.write_all(&byte)?;
    file.sync_all()
}

fn corruption_range(bytes: &[u8], artifact: PersistedArtifact) -> io::Result<Range<usize>> {
    match artifact {
        PersistedArtifact::Bootstrap => Ok(8..10),
        PersistedArtifact::Envelope => {
            let header = decode_header(bytes).map_err(invalid_fixture)?;
            Ok(HEADER_PREFIX_BYTES..HEADER_PREFIX_BYTES + header.wrapped_key.len())
        },
        PersistedArtifact::Frame
        | PersistedArtifact::Frontier
        | PersistedArtifact::Sealed
        | PersistedArtifact::Catalog
        | PersistedArtifact::FrontierSelectorDowngrade
        | PersistedArtifact::FrontierSelectorUpgrade => {
            let start = bytes
                .len()
                .checked_sub(AUTHENTICATION_TAG_BYTES)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "persisted artifact has no tag")
                })?;
            Ok(start..bytes.len())
        },
    }
}

fn rewrite_as_legacy_v2(root: &Path, segment: SegmentId) -> Result<(), Box<dyn std::error::Error>> {
    let active = root.join("segments/active");
    let segment_path = first_file(active.clone(), "segment")?;
    let frontier_path = first_file(active, "frontier")?;
    let original_segment = fs::read(&segment_path)?;
    let header = decode_header(&original_segment)?;
    let object = object_context(scope(), segment)?;
    let wrapping_key = SecretKeyBytes::from_owned(Box::new([0x91; 32]));
    let key = DataProtection::unwrap_segment_key_with_route(
        &wrapping_key,
        header.wrapped_key,
        [0x81; 16],
        object,
        header.route,
    )?;
    let (identity, _) = block_parts(0, 0xa5);
    let exact_time = 4_000_000_000_i64;
    let mut block_plaintext = Vec::from(identity.to_bytes());
    block_plaintext.push(2);
    block_plaintext.extend_from_slice(&exact_time.to_be_bytes());
    block_plaintext.extend_from_slice(b"legacy-v2-selector-upgrade");
    let block_frame = DataProtection::protect_frame(
        &key,
        object.frame(SegmentFramePurpose::StoreBlock, FrameSequence::new(1))?,
        &block_plaintext,
        FrameLimits::new(1_048_576)?,
    )?;
    let mut encoded_segment = original_segment
        .get(..header.encoded_bytes)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "segment header truncated"))?
        .to_vec();
    encoded_segment.extend_from_slice(&u32::try_from(block_frame.as_bytes().len())?.to_be_bytes());
    encoded_segment.extend_from_slice(block_frame.as_bytes());
    fs::write(segment_path, &encoded_segment)?;

    let mut frontier_plaintext = Vec::with_capacity(33);
    frontier_plaintext.extend_from_slice(&u64::try_from(encoded_segment.len())?.to_be_bytes());
    frontier_plaintext.extend_from_slice(&1_u64.to_be_bytes());
    frontier_plaintext.extend_from_slice(&CommitPosition::origin().next()?.value().to_be_bytes());
    frontier_plaintext.push(2);
    frontier_plaintext.extend_from_slice(&exact_time.to_be_bytes());
    let frontier_frame = DataProtection::protect_frame(
        &key,
        object.frame(
            SegmentFramePurpose::DurabilityFrontier,
            FrameSequence::new(u64::MAX - 1),
        )?,
        &frontier_plaintext,
        FrameLimits::new(512)?,
    )?;
    let mut encoded_frontier = Vec::with_capacity(16 + frontier_frame.as_bytes().len());
    encoded_frontier.extend_from_slice(b"PFRONT02");
    encoded_frontier.extend_from_slice(&1_u16.to_be_bytes());
    encoded_frontier.extend_from_slice(&2_u16.to_be_bytes());
    encoded_frontier
        .extend_from_slice(&u32::try_from(frontier_frame.as_bytes().len())?.to_be_bytes());
    encoded_frontier.extend_from_slice(frontier_frame.as_bytes());
    fs::write(frontier_path, encoded_frontier)?;
    Ok(())
}

fn first_file(directory: PathBuf, extension: &str) -> io::Result<PathBuf> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.extension().and_then(|value| value.to_str()) == Some(extension) {
            paths.push(path);
        }
    }
    paths.sort();
    paths
        .into_iter()
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "persisted fuzz artifact is absent"))
}

fn invalid_fixture(_: crate::LedgerFailure) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid persisted fuzz fixture")
}
