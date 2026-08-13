use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};

use positron_domain::routing::CommitPosition;

use crate::catalog::fuzz_authority;
use crate::{
    Catalog, CatalogFailureCode, CommittedBlock, InstanceId, LedgerFailureCode, MountQualification,
    PrimaryDataVolume,
};

use super::{FuzzRoot, block_parts, catalog_secret, open, prepared, scope};
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
            _ => None,
        }
    }

    const fn requires_block(self) -> bool {
        matches!(self, Self::Frame | Self::Frontier | Self::Sealed)
    }

    const fn expected_failure(self) -> PersistedFailure {
        match self {
            Self::Bootstrap => PersistedFailure::Ledger(LedgerFailureCode::UnsupportedFormat),
            Self::Envelope => PersistedFailure::Ledger(LedgerFailureCode::AuthenticationFailed),
            Self::Frame | Self::Frontier | Self::Sealed => {
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
    assert_eq!(
        reopen_fixture(&pristine.0),
        Ok(expected),
        "unchanged acknowledged fixture must reopen exactly"
    );

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
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x81; 16]).expect("fixed instance identity"),
        catalog_secret(),
    )
    .expect("persisted fixture catalog opens");
    let ledger = open(&authority, &catalog, scope()).expect("persisted fixture ledger opens");
    if artifact.requires_block() {
        let (identity, payload) = block_parts(0, 0xa5);
        ledger
            .append(prepared(identity, payload))
            .expect("persisted fixture block commits");
    }
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
    let ledger = open(&authority, &catalog, scope())
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
        PersistedArtifact::Frontier => first_file(root.join("segments/active"), "frontier")?,
        PersistedArtifact::Sealed => first_file(root.join("segments/sealed"), "segment")?,
        PersistedArtifact::Catalog => first_file(root.join("catalog/objects"), "frame")?,
    };
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
        | PersistedArtifact::Catalog => {
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
