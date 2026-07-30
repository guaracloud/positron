use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::Shutdown;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt as _;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags};
use sha2::{Digest, Sha256};

use crate::bounded_runners::FrozenBoundedRunnerRegistry;
use crate::error::XtaskError;

const REGISTRY_PATH: &str = "qualification/engineering/quality-fixtures.tsv";
const INTEGRITY_REGISTRY_PATH: &str = "qualification/engineering/integrity-fixtures.tsv";
const ADVERSARIAL_MANIFEST_PATH: &str = "qualification/fixtures/adversarial/manifest.json";
const HARNESS_REGISTRY_PATH: &str = "qualification/engineering/fixture-harness.tsv";
const REGISTRY_HEADER: &str = "fixture_id\tgate_id\tpublication_point\tfault_schedule\tseed\tpredecessor\tsuccessor\texpected_reopen";
const INTEGRITY_REGISTRY_HEADER: &str = "fixture_id\tmutation\tseed\texpected_reopen";
const HARNESS_REGISTRY_HEADER: &str = "interface_id\texecutable\twriter_operation\trecovery_operation\tready_protocol\tmaximum_wait_ms\ttermination\trecovery_protocol\twriter_arguments\trecovery_arguments";
const MAXIMUM_REGISTRY_BYTES: usize = 16_384;
const MAXIMUM_IDENTITY_REGISTRY_BYTES: usize = 65_536;
const MAXIMUM_FIXTURES: usize = 32;
const MAXIMUM_OWNED_DIRECTORY_ENTRIES: usize = 64;
const MAXIMUM_FIELD_BYTES: usize = 96;
const MAXIMUM_STATE_BYTES: usize = 1_024;
const MAXIMUM_INTEGRITY_OBJECT_BYTES: usize = 8_192;
const MAXIMUM_PROCESS_RECORD_BYTES: usize = 1_024;
const MAXIMUM_PROCESS_ARGUMENTS: usize = 9;
const CORRECTNESS_GATE: &str = "EG-CORRECT";
const FAULT_GATE: &str = "EG-FAULT";

#[cfg(not(any(
    all(
        target_os = "macos",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
)))]
compile_error!(
    "the fixture directory-capability boundary supports only registered macOS and Linux x86_64/aarch64 hosts"
);

const CORRECTNESS_PUBLICATION_POINTS: [PublicationPoint; 2] = [
    PublicationPoint::BeforePublication,
    PublicationPoint::AfterPublication,
];
const FAULT_PUBLICATION_POINTS: [PublicationPoint; 9] = [
    PublicationPoint::PartialWriteBoundary,
    PublicationPoint::CrashBoundary,
    PublicationPoint::RestartBoundary,
    PublicationPoint::CorruptionBoundary,
    PublicationPoint::FullDiskBoundary,
    PublicationPoint::ClockBoundary,
    PublicationPoint::CancellationBoundary,
    PublicationPoint::NetworkBoundary,
    PublicationPoint::ProviderBoundary,
];

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum PublicationPoint {
    BeforePublication,
    AfterPublication,
    PartialWriteBoundary,
    CrashBoundary,
    RestartBoundary,
    CorruptionBoundary,
    FullDiskBoundary,
    ClockBoundary,
    CancellationBoundary,
    NetworkBoundary,
    ProviderBoundary,
}

impl PublicationPoint {
    fn parse(value: &str) -> Result<Self, XtaskError> {
        match value {
            "before-publication" => Ok(Self::BeforePublication),
            "after-publication" => Ok(Self::AfterPublication),
            "partial-write-boundary" => Ok(Self::PartialWriteBoundary),
            "crash-boundary" => Ok(Self::CrashBoundary),
            "restart-boundary" => Ok(Self::RestartBoundary),
            "corruption-boundary" => Ok(Self::CorruptionBoundary),
            "full-disk-boundary" => Ok(Self::FullDiskBoundary),
            "clock-boundary" => Ok(Self::ClockBoundary),
            "cancellation-boundary" => Ok(Self::CancellationBoundary),
            "network-boundary" => Ok(Self::NetworkBoundary),
            "provider-boundary" => Ok(Self::ProviderBoundary),
            _ => Err(XtaskError::invalid(
                "quality fixture registry",
                format!("unknown publication point `{value}`"),
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::BeforePublication => "before-publication",
            Self::AfterPublication => "after-publication",
            Self::PartialWriteBoundary => "partial-write-boundary",
            Self::CrashBoundary => "crash-boundary",
            Self::RestartBoundary => "restart-boundary",
            Self::CorruptionBoundary => "corruption-boundary",
            Self::FullDiskBoundary => "full-disk-boundary",
            Self::ClockBoundary => "clock-boundary",
            Self::CancellationBoundary => "cancellation-boundary",
            Self::NetworkBoundary => "network-boundary",
            Self::ProviderBoundary => "provider-boundary",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CrashSchedule {
    AfterCandidateSync,
    AfterPublicationSync,
    PartialWrite,
    Crash,
    Restart,
    Corruption,
    FullDisk,
    Clock,
    Cancellation,
    Network,
    Provider,
}

impl CrashSchedule {
    fn parse(value: &str) -> Result<Self, XtaskError> {
        match value {
            "crash-after-candidate-sync" => Ok(Self::AfterCandidateSync),
            "crash-after-publication-sync" => Ok(Self::AfterPublicationSync),
            "inject-partial-write" => Ok(Self::PartialWrite),
            "inject-crash" => Ok(Self::Crash),
            "inject-restart" => Ok(Self::Restart),
            "inject-corruption" => Ok(Self::Corruption),
            "inject-full-disk" => Ok(Self::FullDisk),
            "inject-clock" => Ok(Self::Clock),
            "inject-cancellation" => Ok(Self::Cancellation),
            "inject-network" => Ok(Self::Network),
            "inject-provider" => Ok(Self::Provider),
            _ => Err(XtaskError::invalid(
                "quality fixture registry",
                format!("unknown crash schedule `{value}`"),
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::AfterCandidateSync => "crash-after-candidate-sync",
            Self::AfterPublicationSync => "crash-after-publication-sync",
            Self::PartialWrite => "inject-partial-write",
            Self::Crash => "inject-crash",
            Self::Restart => "inject-restart",
            Self::Corruption => "inject-corruption",
            Self::FullDisk => "inject-full-disk",
            Self::Clock => "inject-clock",
            Self::Cancellation => "inject-cancellation",
            Self::Network => "inject-network",
            Self::Provider => "inject-provider",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QualityFixtureAdapter {
    CandidatePersistence,
    PublicationPersistence,
    PartialWrite,
    ProcessCrash,
    Restart,
    Corruption,
    BoundedStorage,
    ControlledClock,
    Cancellation,
    NetworkPublication,
    ProviderPublication,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AdapterObservation {
    adapter: &'static str,
    injection: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FaultOperationReceipt {
    observation: AdapterObservation,
    error_identity: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FixtureFault {
    CapacityExhausted,
    ClockRegressed,
    Cancelled,
    NetworkUnavailable,
    ProviderUnavailable,
}

impl FixtureFault {
    fn observation(self) -> AdapterObservation {
        match self {
            Self::CapacityExhausted => AdapterObservation {
                adapter: "bounded-storage-adapter",
                injection: "capacity-exhausted",
            },
            Self::ClockRegressed => AdapterObservation {
                adapter: "controlled-clock-adapter",
                injection: "clock-regressed",
            },
            Self::Cancelled => AdapterObservation {
                adapter: "cancellation-adapter",
                injection: "cancelled-before-publication",
            },
            Self::NetworkUnavailable => AdapterObservation {
                adapter: "network-publication-adapter",
                injection: "network-unavailable",
            },
            Self::ProviderUnavailable => AdapterObservation {
                adapter: "provider-publication-adapter",
                injection: "provider-unavailable",
            },
        }
    }
}

#[derive(Debug)]
struct BoundedCandidateWriter {
    remaining_bytes: usize,
}

#[derive(Debug)]
enum BoundedCandidateWriteError {
    CapacityExhausted {
        attempted_bytes: usize,
        remaining_bytes: usize,
    },
    Persistence(XtaskError),
}

impl BoundedCandidateWriter {
    fn persist(
        &mut self,
        case_root: &DirectoryCapability,
        candidate: &str,
        bytes: &[u8],
    ) -> Result<(), BoundedCandidateWriteError> {
        if bytes.len() > self.remaining_bytes {
            return Err(BoundedCandidateWriteError::CapacityExhausted {
                attempted_bytes: bytes.len(),
                remaining_bytes: self.remaining_bytes,
            });
        }
        write_fault_bytes(case_root, candidate, bytes)
            .map_err(BoundedCandidateWriteError::Persistence)?;
        self.remaining_bytes -= bytes.len();
        Ok(())
    }
}

#[derive(Debug)]
struct ControlledPublicationClock {
    ticks: [u64; 2],
    next: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RegressedClockError {
    fault: FixtureFault,
    last_observed: u64,
    publication: u64,
}

impl ControlledPublicationClock {
    fn regressed() -> Self {
        Self {
            ticks: [2, 1],
            next: 0,
        }
    }

    fn tick(&mut self) -> Result<u64, XtaskError> {
        let tick = self.ticks.get(self.next).copied().ok_or_else(|| {
            XtaskError::invalid(
                "controlled clock fixture",
                "publication consumed more than two registered ticks",
            )
        })?;
        self.next += 1;
        Ok(tick)
    }
}

#[derive(Debug)]
struct FixtureCancellationToken {
    requested: bool,
}

enum CandidateStateOutcome {
    Absent,
    ValidState(String),
    IntentionallyMalformedState,
    ReadIoSecurityError(XtaskError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CandidateStateParseError {
    NotUtf8,
    WrongFieldCount,
    RegisteredCorruption,
    IntegrityMismatch,
}

impl FixtureCancellationToken {
    fn requested() -> Self {
        Self { requested: true }
    }

    fn consume(&mut self) -> bool {
        let requested = self.requested;
        self.requested = false;
        requested
    }
}

impl QualityFixtureAdapter {
    fn for_schedule(schedule: CrashSchedule) -> Self {
        match schedule {
            CrashSchedule::AfterCandidateSync => Self::CandidatePersistence,
            CrashSchedule::AfterPublicationSync => Self::PublicationPersistence,
            CrashSchedule::PartialWrite => Self::PartialWrite,
            CrashSchedule::Crash => Self::ProcessCrash,
            CrashSchedule::Restart => Self::Restart,
            CrashSchedule::Corruption => Self::Corruption,
            CrashSchedule::FullDisk => Self::BoundedStorage,
            CrashSchedule::Clock => Self::ControlledClock,
            CrashSchedule::Cancellation => Self::Cancellation,
            CrashSchedule::Network => Self::NetworkPublication,
            CrashSchedule::Provider => Self::ProviderPublication,
        }
    }

    fn expected_observation(self) -> AdapterObservation {
        match self {
            Self::CandidatePersistence => AdapterObservation {
                adapter: "candidate-persistence-adapter",
                injection: "candidate-synced",
            },
            Self::PublicationPersistence => AdapterObservation {
                adapter: "publication-persistence-adapter",
                injection: "successor-published",
            },
            Self::PartialWrite => AdapterObservation {
                adapter: "partial-write-adapter",
                injection: "partial-write-injected",
            },
            Self::ProcessCrash => AdapterObservation {
                adapter: "process-crash-adapter",
                injection: "crash-window-open",
            },
            Self::Restart => AdapterObservation {
                adapter: "restart-adapter",
                injection: "successor-published",
            },
            Self::Corruption => AdapterObservation {
                adapter: "corruption-adapter",
                injection: "candidate-corrupted",
            },
            Self::BoundedStorage => AdapterObservation {
                adapter: "bounded-storage-adapter",
                injection: "capacity-exhausted",
            },
            Self::ControlledClock => AdapterObservation {
                adapter: "controlled-clock-adapter",
                injection: "clock-regressed",
            },
            Self::Cancellation => AdapterObservation {
                adapter: "cancellation-adapter",
                injection: "cancelled-before-publication",
            },
            Self::NetworkPublication => AdapterObservation {
                adapter: "network-publication-adapter",
                injection: "network-unavailable",
            },
            Self::ProviderPublication => AdapterObservation {
                adapter: "provider-publication-adapter",
                injection: "provider-unavailable",
            },
        }
    }
}

#[derive(Debug)]
struct FixtureCase {
    fixture_id: String,
    gate_id: String,
    publication_point: PublicationPoint,
    fault_schedule: CrashSchedule,
    seed: String,
    predecessor: String,
    successor: String,
    expected_reopen: String,
}

#[derive(Debug)]
struct FixtureRegistry {
    cases: Vec<FixtureCase>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IntegrityMutation {
    None,
    CorruptPayload,
    DeleteObject,
}

impl IntegrityMutation {
    fn parse(value: &str) -> Result<Self, XtaskError> {
        match value {
            "none" => Ok(Self::None),
            "corrupt-payload" => Ok(Self::CorruptPayload),
            "delete-object" => Ok(Self::DeleteObject),
            _ => Err(XtaskError::invalid(
                "integrity fixture registry",
                format!("unknown integrity mutation `{value}`"),
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::CorruptPayload => "corrupt-payload",
            Self::DeleteObject => "delete-object",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IntegrityExpectedReopen {
    Verified,
    DigestMismatch,
    MissingObject,
}

impl IntegrityExpectedReopen {
    fn parse(value: &str) -> Result<Self, XtaskError> {
        match value {
            "verified" => Ok(Self::Verified),
            "digest-mismatch" => Ok(Self::DigestMismatch),
            "missing-object" => Ok(Self::MissingObject),
            _ => Err(XtaskError::invalid(
                "integrity fixture registry",
                format!("unknown expected reopen outcome `{value}`"),
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::DigestMismatch => "digest-mismatch",
            Self::MissingObject => "missing-object",
        }
    }
}

#[derive(Debug)]
struct IntegrityCase {
    fixture_id: String,
    mutation: IntegrityMutation,
    seed: String,
    expected_reopen: IntegrityExpectedReopen,
}

#[derive(Debug)]
struct IntegrityRegistry {
    cases: Vec<IntegrityCase>,
}

#[derive(Debug)]
struct HarnessInterface {
    interface_id: String,
    writer_operation: String,
    recovery_operation: String,
    ready_protocol: String,
    maximum_wait: Duration,
    recovery_protocol: String,
}

#[derive(Debug)]
struct OwnedFixtureRoot {
    parent: DirectoryCapability,
    directory: DirectoryCapability,
    name: String,
    path: PathBuf,
    active: bool,
}

#[derive(Debug)]
pub(crate) struct DirectoryCapability {
    file: fs::File,
    diagnostic_path: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DirectoryIdentity {
    device: u64,
    inode: u64,
}

#[derive(Debug)]
pub(crate) struct FileCapability {
    file: fs::File,
    parent: fs::File,
    name: String,
    diagnostic_path: PathBuf,
    identity: FileIdentity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FileIdentity {
    device: u64,
    inode: u64,
}

#[derive(Debug)]
struct ChildReconciliation {
    status: std::process::ExitStatus,
    kill_sent: bool,
}

struct ProcessRootClaim<'a> {
    owned_root: &'a Path,
    case_root: &'a Path,
    owned_identity: &'a str,
    case_identity: &'a str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OpenedFileIdentity {
    device: u64,
    inode: u64,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl OpenedFileIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.size(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }
}

impl DirectoryIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }

    pub(crate) fn token(self) -> String {
        format!("{}-{}", self.device, self.inode)
    }

    fn parse(path: &Path, value: &str) -> Result<Self, XtaskError> {
        let Some((device, inode)) = value.split_once('-') else {
            return Err(XtaskError::invalid_path(
                path,
                "fixture directory identity token is malformed",
            ));
        };
        let device = device.parse::<u64>().map_err(|_| {
            XtaskError::invalid_path(path, "fixture directory device identity is invalid")
        })?;
        let inode = inode.parse::<u64>().map_err(|_| {
            XtaskError::invalid_path(path, "fixture directory inode identity is invalid")
        })?;
        Ok(Self { device, inode })
    }
}

impl DirectoryCapability {
    pub(crate) fn open(path: &Path, label: &str) -> Result<Self, XtaskError> {
        let file = rustix::fs::openat(
            rustix::fs::CWD,
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(fs::File::from)
        .map_err(|source| {
            XtaskError::io(
                format!("open {label} {}", path.display()),
                rustix_io(source),
            )
        })?;
        let metadata = file.metadata().map_err(|source| {
            XtaskError::io(format!("inspect opened {label} {}", path.display()), source)
        })?;
        if !metadata.file_type().is_dir() {
            return Err(XtaskError::invalid_path(
                path,
                format!("{label} is not a directory"),
            ));
        }
        let capability = Self {
            file,
            diagnostic_path: path.to_path_buf(),
        };
        capability.entry_names(label)?;
        Ok(capability)
    }

    pub(crate) fn open_child_directory(&self, name: &str, label: &str) -> Result<Self, XtaskError> {
        validate_leaf_name(&self.diagnostic_path, name)?;
        let diagnostic_path = self.diagnostic_path.join(name);
        let file = rustix::fs::openat(
            &self.file,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(fs::File::from)
        .map_err(|source| {
            XtaskError::io(
                format!("open {label} {}", diagnostic_path.display()),
                rustix_io(source),
            )
        })?;
        Ok(Self {
            file,
            diagnostic_path,
        })
    }

    pub(crate) fn create_child_directory(
        &self,
        name: &str,
        label: &str,
    ) -> Result<Self, XtaskError> {
        validate_leaf_name(&self.diagnostic_path, name)?;
        let path = self.diagnostic_path.join(name);
        rustix::fs::mkdirat(&self.file, name, Mode::RWXU).map_err(|source| {
            XtaskError::io(
                format!("create {label} {}", path.display()),
                rustix_io(source),
            )
        })?;
        self.sync()?;
        self.open_child_directory(name, label)
    }

    pub(crate) fn open_or_create_child_directory(
        &self,
        name: &str,
        label: &str,
    ) -> Result<Self, XtaskError> {
        validate_leaf_name(&self.diagnostic_path, name)?;
        let path = self.diagnostic_path.join(name);
        match rustix::fs::mkdirat(&self.file, name, Mode::RWXU) {
            Ok(()) => {
                self.sync()?;
                self.open_child_directory(name, label)
            },
            Err(rustix::io::Errno::EXIST) => self.open_child_directory(name, label),
            Err(source) => Err(XtaskError::io(
                format!("create {label} {}", path.display()),
                rustix_io(source),
            )),
        }
    }

    fn entry_names(&self, label: &str) -> Result<Vec<String>, XtaskError> {
        let directory = Dir::read_from(&self.file).map_err(|source| {
            XtaskError::io(
                format!("enumerate {label} {}", self.diagnostic_path.display()),
                rustix_io(source),
            )
        })?;
        let mut names = Vec::new();
        for entry in directory {
            let entry = entry.map_err(|source| {
                XtaskError::io(format!("read {label} directory entry"), rustix_io(source))
            })?;
            let name = entry.file_name().to_str().map_err(|_| {
                XtaskError::invalid_path(
                    &self.diagnostic_path,
                    format!("{label} entry name is not UTF-8"),
                )
            })?;
            if !matches!(name, "." | "..") {
                if names.len() >= MAXIMUM_OWNED_DIRECTORY_ENTRIES {
                    return Err(XtaskError::invalid_path(
                        &self.diagnostic_path,
                        format!("{label} exceeds {MAXIMUM_OWNED_DIRECTORY_ENTRIES} entries"),
                    ));
                }
                names.push(name.to_owned());
            }
        }
        Ok(names)
    }

    pub(crate) fn identity(&self) -> Result<DirectoryIdentity, XtaskError> {
        self.file
            .metadata()
            .map(|metadata| DirectoryIdentity::from_metadata(&metadata))
            .map_err(|source| {
                XtaskError::io(
                    format!(
                        "inspect fixture directory capability {}",
                        self.diagnostic_path.display()
                    ),
                    source,
                )
            })
    }

    fn require_identity(&self, expected: DirectoryIdentity) -> Result<(), XtaskError> {
        if self.identity()? != expected {
            return Err(XtaskError::invalid_path(
                &self.diagnostic_path,
                "fixture directory identity does not match the parent claim",
            ));
        }
        Ok(())
    }

    pub(crate) fn sync(&self) -> Result<(), XtaskError> {
        self.file.sync_all().map_err(|source| {
            XtaskError::io(
                format!(
                    "synchronize fixture directory {}",
                    self.diagnostic_path.display()
                ),
                source,
            )
        })
    }

    fn read_bounded(
        &self,
        name: &str,
        maximum_bytes: usize,
        limit_label: &str,
    ) -> Result<Vec<u8>, XtaskError> {
        validate_leaf_name(&self.diagnostic_path, name)?;
        let path = self.diagnostic_path.join(name);
        let file = rustix::fs::openat(
            &self.file,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(fs::File::from)
        .map_err(|source| {
            if source == rustix::io::Errno::LOOP {
                XtaskError::invalid_path(&path, format!("{limit_label} is a symbolic link"))
            } else {
                XtaskError::io(
                    format!("open {limit_label} {}", path.display()),
                    rustix_io(source),
                )
            }
        })?;
        read_bounded_opened_file(file, &path, maximum_bytes, limit_label)
    }

    fn read_bounded_optional(
        &self,
        name: &str,
        maximum_bytes: usize,
        limit_label: &str,
    ) -> Result<Option<Vec<u8>>, XtaskError> {
        validate_leaf_name(&self.diagnostic_path, name)?;
        let path = self.diagnostic_path.join(name);
        match rustix::fs::openat(
            &self.file,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(file) => {
                read_bounded_opened_file(fs::File::from(file), &path, maximum_bytes, limit_label)
                    .map(Some)
            },
            Err(rustix::io::Errno::NOENT) => Ok(None),
            Err(rustix::io::Errno::LOOP) => Err(XtaskError::invalid_path(
                &path,
                format!("{limit_label} is a symbolic link"),
            )),
            Err(source) => Err(XtaskError::io(
                format!("open {limit_label} {}", path.display()),
                rustix_io(source),
            )),
        }
    }

    fn create_file(
        &self,
        name: &str,
        bytes: &[u8],
        maximum_bytes: usize,
    ) -> Result<(), XtaskError> {
        validate_leaf_name(&self.diagnostic_path, name)?;
        let path = self.diagnostic_path.join(name);
        if bytes.len() > maximum_bytes {
            return Err(XtaskError::invalid_path(
                &path,
                format!("fixture object exceeds {maximum_bytes} bytes"),
            ));
        }
        let mut file = rustix::fs::openat(
            &self.file,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map(fs::File::from)
        .map_err(|source| {
            XtaskError::io(format!("create {}", path.display()), rustix_io(source))
        })?;
        file.write_all(bytes)
            .and_then(|()| file.flush())
            .and_then(|()| file.sync_all())
            .map_err(|source| XtaskError::io(format!("persist {}", path.display()), source))
    }

    pub(crate) fn create_file_capability(
        &self,
        name: &str,
        label: &str,
    ) -> Result<FileCapability, XtaskError> {
        validate_leaf_name(&self.diagnostic_path, name)?;
        let diagnostic_path = self.diagnostic_path.join(name);
        let file = rustix::fs::openat(
            &self.file,
            name,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map(fs::File::from)
        .map_err(|source| {
            XtaskError::io(
                format!("create {label} {}", diagnostic_path.display()),
                rustix_io(source),
            )
        })?;
        let metadata = file.metadata().map_err(|source| {
            XtaskError::io(
                format!("inspect created {label} {}", diagnostic_path.display()),
                source,
            )
        })?;
        if !metadata.file_type().is_file() {
            return Err(XtaskError::invalid_path(
                &diagnostic_path,
                format!("{label} is not a regular file"),
            ));
        }
        Ok(FileCapability {
            file,
            parent: self.file.try_clone().map_err(|source| {
                XtaskError::io(
                    format!(
                        "duplicate parent capability for {label} {}",
                        diagnostic_path.display()
                    ),
                    source,
                )
            })?,
            name: name.to_owned(),
            diagnostic_path,
            identity: FileIdentity::from_metadata(&metadata),
        })
    }

    fn open_file_capability_optional(
        &self,
        name: &str,
        label: &str,
    ) -> Result<Option<FileCapability>, XtaskError> {
        validate_leaf_name(&self.diagnostic_path, name)?;
        let diagnostic_path = self.diagnostic_path.join(name);
        let file = match rustix::fs::openat(
            &self.file,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(file) => fs::File::from(file),
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(rustix::io::Errno::LOOP) => {
                return Err(XtaskError::invalid_path(
                    &diagnostic_path,
                    format!("{label} canonical name is a symbolic link"),
                ));
            },
            Err(source) => {
                return Err(XtaskError::io(
                    format!("open {label} {}", diagnostic_path.display()),
                    rustix_io(source),
                ));
            },
        };
        let metadata = file.metadata().map_err(|source| {
            XtaskError::io(
                format!("inspect opened {label} {}", diagnostic_path.display()),
                source,
            )
        })?;
        if !metadata.file_type().is_file() {
            return Err(XtaskError::invalid_path(
                &diagnostic_path,
                format!("{label} is not a regular file"),
            ));
        }
        Ok(Some(FileCapability {
            file,
            parent: self.file.try_clone().map_err(|source| {
                XtaskError::io(
                    format!(
                        "duplicate parent capability for {label} {}",
                        diagnostic_path.display()
                    ),
                    source,
                )
            })?,
            name: name.to_owned(),
            diagnostic_path,
            identity: FileIdentity::from_metadata(&metadata),
        }))
    }

    pub(crate) fn require_child_directory_identity(
        &self,
        name: &str,
        expected: DirectoryIdentity,
        label: &str,
    ) -> Result<(), XtaskError> {
        let child = self.open_child_directory(name, label).map_err(|_| {
            XtaskError::invalid_path(
                &self.diagnostic_path.join(name),
                format!("{label} canonical name was replaced"),
            )
        })?;
        if child.identity()? != expected {
            return Err(XtaskError::invalid_path(
                &self.diagnostic_path.join(name),
                format!("{label} canonical name was replaced"),
            ));
        }
        Ok(())
    }

    pub(crate) fn require_child_file_identity(
        &self,
        name: &str,
        expected: FileIdentity,
        label: &str,
    ) -> Result<(), XtaskError> {
        validate_leaf_name(&self.diagnostic_path, name)?;
        let path = self.diagnostic_path.join(name);
        let file = rustix::fs::openat(
            &self.file,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(fs::File::from)
        .map_err(|_| {
            XtaskError::invalid_path(&path, format!("{label} canonical name was replaced"))
        })?;
        let metadata = file.metadata().map_err(|source| {
            XtaskError::io(
                format!("inspect canonical {label} {}", path.display()),
                source,
            )
        })?;
        if FileIdentity::from_metadata(&metadata) != expected {
            return Err(XtaskError::invalid_path(
                &path,
                format!("{label} canonical name was replaced"),
            ));
        }
        Ok(())
    }

    fn replace_file(
        &self,
        name: &str,
        bytes: &[u8],
        maximum_bytes: usize,
    ) -> Result<(), XtaskError> {
        validate_leaf_name(&self.diagnostic_path, name)?;
        let path = self.diagnostic_path.join(name);
        if bytes.len() > maximum_bytes {
            return Err(XtaskError::invalid_path(
                &path,
                format!("fixture object exceeds {maximum_bytes} bytes"),
            ));
        }
        let mut file = rustix::fs::openat(
            &self.file,
            name,
            OFlags::WRONLY | OFlags::TRUNC | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(fs::File::from)
        .map_err(|source| XtaskError::io(format!("open {}", path.display()), rustix_io(source)))?;
        file.write_all(bytes)
            .and_then(|()| file.flush())
            .and_then(|()| file.sync_all())
            .map_err(|source| XtaskError::io(format!("persist {}", path.display()), source))
    }

    fn remove_file(&self, name: &str) -> Result<(), XtaskError> {
        validate_leaf_name(&self.diagnostic_path, name)?;
        let path = self.diagnostic_path.join(name);
        rustix::fs::unlinkat(&self.file, name, AtFlags::empty()).map_err(|source| {
            XtaskError::io(format!("remove {}", path.display()), rustix_io(source))
        })
    }

    fn rename(&self, from: &str, to: &str) -> Result<(), XtaskError> {
        validate_leaf_name(&self.diagnostic_path, from)?;
        validate_leaf_name(&self.diagnostic_path, to)?;
        rustix::fs::renameat(&self.file, from, &self.file, to).map_err(|source| {
            XtaskError::io(
                format!(
                    "rename fixture object {} as {}",
                    self.diagnostic_path.join(from).display(),
                    self.diagnostic_path.join(to).display()
                ),
                rustix_io(source),
            )
        })
    }

    fn hard_link(&self, from: &str, to: &str) -> Result<(), XtaskError> {
        validate_leaf_name(&self.diagnostic_path, from)?;
        validate_leaf_name(&self.diagnostic_path, to)?;
        rustix::fs::linkat(&self.file, from, &self.file, to, AtFlags::empty()).map_err(|source| {
            XtaskError::io(
                format!(
                    "link fixture object {} as {}",
                    self.diagnostic_path.join(from).display(),
                    self.diagnostic_path.join(to).display()
                ),
                rustix_io(source),
            )
        })
    }
}

impl FileIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }

    pub(crate) fn token(self) -> String {
        format!("{}-{}", self.device, self.inode)
    }
}

impl FileCapability {
    pub(crate) fn artifact_output(
        &self,
    ) -> Result<crate::controlled_execution::ArtifactOutput, XtaskError> {
        let file = self.file.try_clone().map_err(|source| {
            XtaskError::io(
                format!(
                    "duplicate artifact capability {}",
                    self.diagnostic_path.display()
                ),
                source,
            )
        })?;
        let parent = self.parent.try_clone().map_err(|source| {
            XtaskError::io(
                format!(
                    "duplicate artifact parent capability {}",
                    self.diagnostic_path.display()
                ),
                source,
            )
        })?;
        Ok(crate::controlled_execution::ArtifactOutput::new(
            file,
            parent,
            self.name.clone(),
            self.diagnostic_path.clone(),
            self.identity.device,
            self.identity.inode,
        ))
    }

    pub(crate) fn identity(&self) -> FileIdentity {
        self.identity
    }

    pub(crate) fn diagnostic_path(&self) -> &Path {
        &self.diagnostic_path
    }

    pub(crate) fn read_bounded(
        &self,
        maximum_bytes: usize,
        label: &str,
    ) -> Result<Vec<u8>, XtaskError> {
        let mut file = self.file.try_clone().map_err(|source| {
            XtaskError::io(
                format!(
                    "duplicate artifact capability {}",
                    self.diagnostic_path.display()
                ),
                source,
            )
        })?;
        file.seek(SeekFrom::Start(0)).map_err(|source| {
            XtaskError::io(
                format!("seek {label} {}", self.diagnostic_path.display()),
                source,
            )
        })?;
        read_bounded_opened_file(file, &self.diagnostic_path, maximum_bytes, label)
    }
}

fn rustix_io(source: rustix::io::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(source.raw_os_error())
}

fn validate_leaf_name(path: &Path, name: &str) -> Result<(), XtaskError> {
    let mut components = Path::new(name).components();
    if matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none() {
        return Ok(());
    }
    Err(XtaskError::invalid_path(
        path,
        "fixture capability leaf name is not one normal path component",
    ))
}

#[derive(Debug)]
enum FrozenRegistry<Registry> {
    Valid(Registry),
    Invalid(String),
}

impl<Registry> FrozenRegistry<Registry> {
    fn get(&self, label: &str) -> Result<&Registry, XtaskError> {
        match self {
            Self::Valid(registry) => Ok(registry),
            Self::Invalid(error) => Err(XtaskError::invalid(label, error)),
        }
    }
}

#[derive(Debug)]
pub(crate) struct FrozenQualificationFixtures {
    adversarial_manifest: Box<[u8]>,
    quality_registry_bytes: Box<[u8]>,
    integrity_registry_bytes: Box<[u8]>,
    harness_registry_bytes: Box<[u8]>,
    bounded_runners: FrozenBoundedRunnerRegistry,
    quality_registry: FrozenRegistry<FixtureRegistry>,
    integrity_registry: FrozenRegistry<IntegrityRegistry>,
    harness: HarnessInterface,
    seed_digest: String,
    fault_schedule_digest: String,
}

#[derive(Debug)]
pub(crate) struct IntegrityIdentity {
    pub(crate) revision: String,
    pub(crate) artifact: String,
    pub(crate) target: String,
    pub(crate) environment: String,
    pub(crate) command: String,
    pub(crate) fixtures: String,
    pub(crate) result: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IntegrityReadFailure {
    MissingObject,
    DigestMismatch,
    InvalidObject,
    IdentityMismatch,
    Io,
}

impl FixtureRegistry {
    fn parse(path: &Path, bytes: &[u8]) -> Result<Self, XtaskError> {
        if bytes.len() > MAXIMUM_REGISTRY_BYTES {
            return Err(XtaskError::invalid_path(
                path,
                format!("fixture registry exceeds {MAXIMUM_REGISTRY_BYTES} bytes"),
            ));
        }
        let content = std::str::from_utf8(bytes)
            .map_err(|_| XtaskError::invalid_path(path, "fixture registry is not UTF-8"))?;
        let mut lines = content.lines();
        if lines.next() != Some(REGISTRY_HEADER) {
            return Err(XtaskError::invalid_path(
                path,
                "fixture registry header is not exact",
            ));
        }
        let mut cases = Vec::new();
        let mut fixture_ids = BTreeSet::new();
        for (offset, line) in lines.enumerate() {
            if cases.len() >= MAXIMUM_FIXTURES {
                return Err(XtaskError::invalid_path(
                    path,
                    format!("fixture registry exceeds {MAXIMUM_FIXTURES} rows"),
                ));
            }
            let fields = line.split('\t').collect::<Vec<_>>();
            let [
                fixture_id,
                gate_id,
                publication_point,
                fault_schedule,
                seed,
                predecessor,
                successor,
                expected_reopen,
            ] = fields.as_slice()
            else {
                return Err(XtaskError::invalid_path(
                    path,
                    format!(
                        "fixture row {} does not contain exactly 8 fields",
                        offset + 2
                    ),
                ));
            };
            for (field_name, value) in [
                ("fixture_id", *fixture_id),
                ("gate_id", *gate_id),
                ("publication_point", *publication_point),
                ("fault_schedule", *fault_schedule),
                ("seed", *seed),
                ("predecessor", *predecessor),
                ("successor", *successor),
                ("expected_reopen", *expected_reopen),
            ] {
                validate_field(path, offset + 2, field_name, value)?;
            }
            if !matches!(*gate_id, CORRECTNESS_GATE | FAULT_GATE) {
                return Err(XtaskError::invalid_path(
                    path,
                    format!("fixture gate `{gate_id}` is not an exact consumed gate"),
                ));
            }
            if !fixture_ids.insert((*fixture_id).to_owned()) {
                return Err(XtaskError::invalid_path(
                    path,
                    format!("fixture id `{fixture_id}` is duplicated"),
                ));
            }
            cases.push(FixtureCase {
                fixture_id: (*fixture_id).to_owned(),
                gate_id: (*gate_id).to_owned(),
                publication_point: PublicationPoint::parse(publication_point)?,
                fault_schedule: CrashSchedule::parse(fault_schedule)?,
                seed: (*seed).to_owned(),
                predecessor: (*predecessor).to_owned(),
                successor: (*successor).to_owned(),
                expected_reopen: (*expected_reopen).to_owned(),
            });
        }
        if cases.is_empty() {
            return Err(XtaskError::invalid_path(
                path,
                "fixture registry contains no cases",
            ));
        }
        let registry = Self { cases };
        registry.validate_complete_consumption(path)?;
        Ok(registry)
    }

    fn cases_for(&self, gate_id: &str) -> Vec<&FixtureCase> {
        self.cases
            .iter()
            .filter(|case| case.gate_id == gate_id)
            .collect()
    }

    fn validate_complete_consumption(&self, path: &Path) -> Result<(), XtaskError> {
        let correctness = self.cases_for(CORRECTNESS_GATE);
        let fault = self.cases_for(FAULT_GATE);
        let consumed = correctness.len().checked_add(fault.len()).ok_or_else(|| {
            XtaskError::invalid_path(path, "fixture gate consumption count overflowed")
        })?;
        if consumed != self.cases.len() {
            return Err(XtaskError::invalid_path(
                path,
                format!(
                    "fixture registry contains {} rows but exactly {consumed} rows are consumed",
                    self.cases.len()
                ),
            ));
        }
        Ok(())
    }
}

impl IntegrityRegistry {
    fn parse(path: &Path, bytes: &[u8]) -> Result<Self, XtaskError> {
        if bytes.len() > MAXIMUM_REGISTRY_BYTES {
            return Err(XtaskError::invalid_path(
                path,
                format!("integrity fixture registry exceeds {MAXIMUM_REGISTRY_BYTES} bytes"),
            ));
        }
        let content = std::str::from_utf8(bytes).map_err(|_| {
            XtaskError::invalid_path(path, "integrity fixture registry is not UTF-8")
        })?;
        let mut lines = content.lines();
        if lines.next() != Some(INTEGRITY_REGISTRY_HEADER) {
            return Err(XtaskError::invalid_path(
                path,
                "integrity fixture registry header is not exact",
            ));
        }
        let mut cases = Vec::new();
        let mut fixture_ids = BTreeSet::new();
        let mut mutations = BTreeSet::new();
        for (offset, line) in lines.enumerate() {
            if cases.len() >= MAXIMUM_FIXTURES {
                return Err(XtaskError::invalid_path(
                    path,
                    format!("integrity fixture registry exceeds {MAXIMUM_FIXTURES} rows"),
                ));
            }
            let fields = line.split('\t').collect::<Vec<_>>();
            let [fixture_id, mutation, seed, expected_reopen] = fields.as_slice() else {
                return Err(XtaskError::invalid_path(
                    path,
                    format!(
                        "integrity fixture row {} does not contain exactly 4 fields",
                        offset + 2
                    ),
                ));
            };
            for (field_name, value) in [
                ("fixture_id", *fixture_id),
                ("mutation", *mutation),
                ("seed", *seed),
                ("expected_reopen", *expected_reopen),
            ] {
                validate_field(path, offset + 2, field_name, value)?;
            }
            let mutation = IntegrityMutation::parse(mutation)?;
            if !fixture_ids.insert((*fixture_id).to_owned()) {
                return Err(XtaskError::invalid_path(
                    path,
                    format!("integrity fixture id `{fixture_id}` is duplicated"),
                ));
            }
            if !mutations.insert(mutation.as_str()) {
                return Err(XtaskError::invalid_path(
                    path,
                    format!(
                        "integrity mutation `{}` must have exactly one fixture",
                        mutation.as_str()
                    ),
                ));
            }
            cases.push(IntegrityCase {
                fixture_id: (*fixture_id).to_owned(),
                mutation,
                seed: (*seed).to_owned(),
                expected_reopen: IntegrityExpectedReopen::parse(expected_reopen)?,
            });
        }
        let expected = ["none", "corrupt-payload", "delete-object"];
        if cases.len() != expected.len()
            || expected
                .iter()
                .any(|mutation| !mutations.contains(mutation))
        {
            return Err(XtaskError::invalid(
                "EG-INTEGRITY fixture registry",
                "expected exactly one none, corrupt-payload, and delete-object fixture",
            ));
        }
        for case in &cases {
            let expected = match case.mutation {
                IntegrityMutation::None => IntegrityExpectedReopen::Verified,
                IntegrityMutation::CorruptPayload => IntegrityExpectedReopen::DigestMismatch,
                IntegrityMutation::DeleteObject => IntegrityExpectedReopen::MissingObject,
            };
            if case.expected_reopen != expected {
                return Err(XtaskError::invalid(
                    format!("integrity fixture `{}`", case.fixture_id),
                    "registered expected outcome does not match its mutation",
                ));
            }
        }
        Ok(Self { cases })
    }
}

impl HarnessInterface {
    fn parse(path: &Path, bytes: &[u8]) -> Result<Self, XtaskError> {
        if bytes.len() > MAXIMUM_REGISTRY_BYTES {
            return Err(XtaskError::invalid_path(
                path,
                format!("fixture harness registry exceeds {MAXIMUM_REGISTRY_BYTES} bytes"),
            ));
        }
        let content = std::str::from_utf8(bytes)
            .map_err(|_| XtaskError::invalid_path(path, "fixture harness registry is not UTF-8"))?;
        let mut lines = content.lines();
        if lines.next() != Some(HARNESS_REGISTRY_HEADER) {
            return Err(XtaskError::invalid_path(
                path,
                "fixture harness registry header is not exact",
            ));
        }
        let row = lines.next().ok_or_else(|| {
            XtaskError::invalid_path(path, "fixture harness registry contains no interface")
        })?;
        if lines.next().is_some() {
            return Err(XtaskError::invalid_path(
                path,
                "fixture harness registry must contain exactly one interface",
            ));
        }
        let fields = row.split('\t').collect::<Vec<_>>();
        let [
            interface_id,
            executable,
            writer_operation,
            recovery_operation,
            ready_protocol,
            maximum_wait_ms,
            termination,
            recovery_protocol,
            writer_arguments,
            recovery_arguments,
        ] = fields.as_slice()
        else {
            return Err(XtaskError::invalid_path(
                path,
                "fixture harness registry row does not contain exactly 10 fields",
            ));
        };
        for (field_name, value) in [
            ("interface_id", *interface_id),
            ("executable", *executable),
            ("writer_operation", *writer_operation),
            ("recovery_operation", *recovery_operation),
            ("ready_protocol", *ready_protocol),
            ("termination", *termination),
            ("recovery_protocol", *recovery_protocol),
            ("writer_arguments", *writer_arguments),
            ("recovery_arguments", *recovery_arguments),
        ] {
            validate_field(path, 2, field_name, value)?;
        }
        if (
            *interface_id,
            *executable,
            *writer_operation,
            *recovery_operation,
            *ready_protocol,
            *termination,
            *recovery_protocol,
            *writer_arguments,
            *recovery_arguments,
        ) != (
            "quality-engineering-state-v1",
            "current-xtask",
            "writer",
            "recover",
            "publication-point-ready-v1",
            "force-kill-and-reap",
            "recovery-v1",
            "owned-root-case-root-owned-id-case-id-publication-point-fault-schedule-predecessor-successor",
            "owned-root-case-root-directory-ids-result-name-recovery-protocol-schedule-oracle",
        ) {
            return Err(XtaskError::invalid_path(
                path,
                "fixture harness process interface does not match its registered contract",
            ));
        }
        let maximum_wait_ms = maximum_wait_ms.parse::<u64>().map_err(|_| {
            XtaskError::invalid_path(path, "fixture harness maximum_wait_ms is not an integer")
        })?;
        if !(1..=30_000).contains(&maximum_wait_ms) {
            return Err(XtaskError::invalid_path(
                path,
                "fixture harness maximum_wait_ms must be in 1..=30000",
            ));
        }
        Ok(Self {
            interface_id: (*interface_id).to_owned(),
            writer_operation: (*writer_operation).to_owned(),
            recovery_operation: (*recovery_operation).to_owned(),
            ready_protocol: (*ready_protocol).to_owned(),
            maximum_wait: Duration::from_millis(maximum_wait_ms),
            recovery_protocol: (*recovery_protocol).to_owned(),
        })
    }
}

impl FrozenQualificationFixtures {
    pub(crate) fn capture(root: &Path) -> Result<Self, XtaskError> {
        let adversarial_manifest = read_frozen_input(
            root,
            ADVERSARIAL_MANIFEST_PATH,
            MAXIMUM_IDENTITY_REGISTRY_BYTES,
        )?;
        let quality_registry_bytes =
            read_frozen_input(root, REGISTRY_PATH, MAXIMUM_IDENTITY_REGISTRY_BYTES)?;
        let integrity_registry_bytes = read_frozen_input(
            root,
            INTEGRITY_REGISTRY_PATH,
            MAXIMUM_IDENTITY_REGISTRY_BYTES,
        )?;
        let harness_registry_bytes =
            read_frozen_input(root, HARNESS_REGISTRY_PATH, MAXIMUM_IDENTITY_REGISTRY_BYTES)?;
        let bounded_runner_bytes = read_frozen_input(
            root,
            "qualification/engineering/concurrency-fixtures.tsv",
            16_384,
        )?;
        let bounded_spawn_site_bytes = read_frozen_input(
            root,
            "qualification/engineering/concurrency-spawn-sites.tsv",
            16_384,
        )?;
        let bounded_runners =
            FrozenBoundedRunnerRegistry::capture(bounded_runner_bytes, bounded_spawn_site_bytes)?;
        let quality_registry =
            match FixtureRegistry::parse(&root.join(REGISTRY_PATH), &quality_registry_bytes) {
                Ok(registry) => FrozenRegistry::Valid(registry),
                Err(error) => FrozenRegistry::Invalid(error.to_string()),
            };
        let integrity_registry = match IntegrityRegistry::parse(
            &root.join(INTEGRITY_REGISTRY_PATH),
            &integrity_registry_bytes,
        ) {
            Ok(registry) => FrozenRegistry::Valid(registry),
            Err(error) => FrozenRegistry::Invalid(error.to_string()),
        };
        let harness =
            HarnessInterface::parse(&root.join(HARNESS_REGISTRY_PATH), &harness_registry_bytes)?;
        let (seed_digest, fault_schedule_digest) = seed_and_schedule_digests(
            &quality_registry_bytes,
            &integrity_registry_bytes,
            bounded_runners.bytes(),
        );
        Ok(Self {
            adversarial_manifest: adversarial_manifest.into_boxed_slice(),
            quality_registry_bytes: quality_registry_bytes.into_boxed_slice(),
            integrity_registry_bytes: integrity_registry_bytes.into_boxed_slice(),
            harness_registry_bytes: harness_registry_bytes.into_boxed_slice(),
            bounded_runners,
            quality_registry,
            integrity_registry,
            harness,
            seed_digest,
            fault_schedule_digest,
        })
    }

    pub(crate) fn identity_payload(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        for (relative, bytes) in [
            (
                ADVERSARIAL_MANIFEST_PATH,
                self.adversarial_manifest.as_ref(),
            ),
            (REGISTRY_PATH, self.quality_registry_bytes.as_ref()),
            (
                INTEGRITY_REGISTRY_PATH,
                self.integrity_registry_bytes.as_ref(),
            ),
            (HARNESS_REGISTRY_PATH, self.harness_registry_bytes.as_ref()),
            (
                "qualification/engineering/concurrency-fixtures.tsv",
                self.bounded_runners.bytes(),
            ),
            (
                "qualification/engineering/concurrency-spawn-sites.tsv",
                self.bounded_runners.spawn_site_bytes(),
            ),
        ] {
            payload.extend_from_slice(relative.as_bytes());
            payload.push(0);
            payload.extend_from_slice(bytes);
            payload.push(0);
        }
        payload
    }

    pub(crate) fn seed_digest(&self) -> &str {
        &self.seed_digest
    }

    pub(crate) fn fault_schedule_digest(&self) -> &str {
        &self.fault_schedule_digest
    }

    pub(crate) fn bounded_runners(&self) -> &FrozenBoundedRunnerRegistry {
        &self.bounded_runners
    }
}

pub(crate) fn run_correctness(
    fixtures: &FrozenQualificationFixtures,
    temporary_root: &Path,
) -> Result<String, XtaskError> {
    let cases = fixtures
        .quality_registry
        .get("frozen quality fixture registry")?
        .cases_for(CORRECTNESS_GATE);
    validate_exact_publication_points(CORRECTNESS_GATE, &cases, &CORRECTNESS_PUBLICATION_POINTS)?;
    let fixture_root = OwnedFixtureRoot::create(temporary_root, "correctness")?;
    let outcome = (|| {
        let mut outcomes = Vec::with_capacity(cases.len());
        for case in cases {
            outcomes.push(execute_state_transition(
                &fixture_root,
                case,
                &fixtures.harness,
            )?);
        }
        Ok(format!(
            "quality-engineering-fixtures={}; process-interface={}; interface-id={}; {}",
            REGISTRY_PATH,
            HARNESS_REGISTRY_PATH,
            fixtures.harness.interface_id,
            outcomes.join(",")
        ))
    })();
    fixture_root.finish(outcome)
}

pub(crate) fn run_fault(
    fixtures: &FrozenQualificationFixtures,
    temporary_root: &Path,
) -> Result<String, XtaskError> {
    let cases = fixtures
        .quality_registry
        .get("frozen quality fixture registry")?
        .cases_for(FAULT_GATE);
    validate_exact_publication_points(FAULT_GATE, &cases, &FAULT_PUBLICATION_POINTS)?;
    let fixture_root = OwnedFixtureRoot::create(temporary_root, "fault")?;
    let outcome = (|| {
        let publication_point_count = cases.len();
        let mut outcomes = Vec::with_capacity(cases.len());
        for case in cases {
            outcomes.push(execute_state_transition(
                &fixture_root,
                case,
                &fixtures.harness,
            )?);
        }
        Ok(format!(
            "quality-engineering-fixtures={}; process-interface={}; interface-id={}; one-to-one-publication-points={}; exact-fault-classes=partial-write+crash+restart+corruption+full-disk+clock+cancellation+network+provider; {}",
            REGISTRY_PATH,
            HARNESS_REGISTRY_PATH,
            fixtures.harness.interface_id,
            publication_point_count,
            outcomes.join(",")
        ))
    })();
    fixture_root.finish(outcome)
}

pub(crate) fn run_integrity(
    fixtures: &FrozenQualificationFixtures,
    temporary_root: &Path,
    identity: &IntegrityIdentity,
) -> Result<String, XtaskError> {
    let integrity_registry = fixtures
        .integrity_registry
        .get("frozen integrity fixture registry")?;
    let fixture_root = OwnedFixtureRoot::create(temporary_root, "integrity")?;
    let outcome = (|| {
        let mut outcomes = Vec::with_capacity(integrity_registry.cases.len());
        for case in &integrity_registry.cases {
            outcomes.push(execute_integrity_case(&fixture_root, case, identity)?);
        }
        Ok(format!(
            "quality-engineering-fixtures={}; identity=revision+artifact+target+environment+command+fixtures+seed+schedule+result; {}",
            INTEGRITY_REGISTRY_PATH,
            outcomes.join(",")
        ))
    })();
    fixture_root.finish(outcome)
}

fn seed_and_schedule_digests(quality: &[u8], integrity: &[u8], bounded: &[u8]) -> (String, String) {
    let mut seed_hasher = Sha256::new();
    seed_hasher.update(b"positron-quality-fixture-seeds-v1\0");
    seed_hasher.update(quality);
    seed_hasher.update(b"\0");
    seed_hasher.update(integrity);
    seed_hasher.update(b"\0");
    seed_hasher.update(bounded);
    let mut schedule_hasher = Sha256::new();
    schedule_hasher.update(b"positron-quality-fault-schedules-v1\0");
    schedule_hasher.update(quality);
    schedule_hasher.update(b"\0");
    schedule_hasher.update(integrity);
    schedule_hasher.update(b"\0");
    schedule_hasher.update(bounded);
    (
        format!("sha256:{:x}", seed_hasher.finalize()),
        format!("sha256:{:x}", schedule_hasher.finalize()),
    )
}

fn read_frozen_input(
    root: &Path,
    relative: &str,
    maximum_bytes: usize,
) -> Result<Vec<u8>, XtaskError> {
    let mut directory = DirectoryCapability::open(root, "frozen fixture root")?;
    let mut components = Path::new(relative).components().peekable();
    while let Some(component) = components.next() {
        let Component::Normal(component) = component else {
            return Err(XtaskError::invalid_path(
                &root.join(relative),
                "frozen fixture path is not strictly relative",
            ));
        };
        let component = component.to_str().ok_or_else(|| {
            XtaskError::invalid_path(&root.join(relative), "frozen fixture path is not UTF-8")
        })?;
        if components.peek().is_some() {
            directory =
                directory.open_child_directory(component, "frozen fixture directory component")?;
        } else {
            return directory.read_bounded(component, maximum_bytes, "fixture identity input");
        }
    }
    Err(XtaskError::invalid_path(
        &root.join(relative),
        "frozen fixture path is empty",
    ))
}

fn read_bounded_opened_file(
    mut file: fs::File,
    diagnostic_path: &Path,
    maximum_bytes: usize,
    limit_label: &str,
) -> Result<Vec<u8>, XtaskError> {
    let before = file.metadata().map_err(|source| {
        XtaskError::io(format!("inspect {}", diagnostic_path.display()), source)
    })?;
    if !before.file_type().is_file() {
        return Err(XtaskError::invalid_path(
            diagnostic_path,
            format!("{limit_label} is not a regular file"),
        ));
    }
    if before.len() > maximum_bytes as u64 {
        return Err(XtaskError::invalid_path(
            diagnostic_path,
            format!("{limit_label} exceeds {maximum_bytes} bytes"),
        ));
    }
    let bounded_capacity = maximum_bytes.checked_add(1).ok_or_else(|| {
        XtaskError::invalid_path(diagnostic_path, format!("{limit_label} bound overflowed"))
    })?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(bounded_capacity).map_err(|error| {
        XtaskError::invalid_path(
            diagnostic_path,
            format!("reserve bounded {limit_label} buffer failed: {error}"),
        )
    })?;
    let read_limit = u64::try_from(bounded_capacity).map_err(|_| {
        XtaskError::invalid_path(
            diagnostic_path,
            format!("{limit_label} bound does not fit u64"),
        )
    })?;
    Read::by_ref(&mut file)
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|source| XtaskError::io(format!("read {}", diagnostic_path.display()), source))?;
    if bytes.len() > maximum_bytes {
        return Err(XtaskError::invalid_path(
            diagnostic_path,
            format!("{limit_label} exceeds {maximum_bytes} bytes"),
        ));
    }
    let after = file.metadata().map_err(|source| {
        XtaskError::io(format!("reinspect {}", diagnostic_path.display()), source)
    })?;
    if OpenedFileIdentity::from_metadata(&before) != OpenedFileIdentity::from_metadata(&after)
        || after.len() != bytes.len() as u64
    {
        return Err(XtaskError::invalid_path(
            diagnostic_path,
            format!("{limit_label} changed while it was read"),
        ));
    }
    Ok(bytes)
}

fn execute_integrity_case(
    fixture_root: &OwnedFixtureRoot,
    case: &IntegrityCase,
    identity: &IntegrityIdentity,
) -> Result<String, XtaskError> {
    let case_root = fixture_root.create_case(&case.fixture_id)?;
    let original = "prior-attempt.evidence";
    write_integrity_object(&case_root, original, identity, case)?;
    case_root.sync()?;
    let reopened = "reopen.evidence";
    let original_bytes =
        case_root.read_bounded(original, MAXIMUM_INTEGRITY_OBJECT_BYTES, "integrity object")?;
    case_root.create_file(reopened, &original_bytes, MAXIMUM_INTEGRITY_OBJECT_BYTES)?;
    case_root.sync()?;

    match case.mutation {
        IntegrityMutation::None => {},
        IntegrityMutation::CorruptPayload => corrupt_integrity_payload(&case_root, reopened)?,
        IntegrityMutation::DeleteObject => {
            case_root.remove_file(reopened)?;
            case_root.sync()?;
        },
    }

    let outcome = match read_integrity_object(&case_root, reopened, identity, case) {
        Ok(()) => IntegrityExpectedReopen::Verified,
        Err(IntegrityReadFailure::DigestMismatch) => IntegrityExpectedReopen::DigestMismatch,
        Err(IntegrityReadFailure::MissingObject) => IntegrityExpectedReopen::MissingObject,
        Err(
            IntegrityReadFailure::InvalidObject
            | IntegrityReadFailure::IdentityMismatch
            | IntegrityReadFailure::Io,
        ) => {
            return Err(XtaskError::invalid(
                format!("integrity fixture `{}`", case.fixture_id),
                "reopen returned a non-canonical failure classification",
            ));
        },
    };
    if outcome != case.expected_reopen {
        return Err(XtaskError::invalid(
            format!("integrity fixture `{}`", case.fixture_id),
            format!(
                "reopen returned `{}`, expected `{}`",
                outcome.as_str(),
                case.expected_reopen.as_str()
            ),
        ));
    }
    read_integrity_object(&case_root, original, identity, case).map_err(|failure| {
        XtaskError::invalid(
            format!("integrity fixture `{}`", case.fixture_id),
            format!("prior attempt was not preserved: {failure:?}"),
        )
    })?;
    Ok(format!(
        "{}:{}:original-preserved:seed={}:schedule={}",
        case.fixture_id,
        outcome.as_str(),
        case.seed,
        case.mutation.as_str()
    ))
}

fn write_integrity_object(
    directory: &DirectoryCapability,
    name: &str,
    identity: &IntegrityIdentity,
    case: &IntegrityCase,
) -> Result<(), XtaskError> {
    let payload = format!("fixture-payload-{}", case.fixture_id);
    let payload_digest = integrity_payload_digest(payload.as_bytes());
    let content = format!(
        "schema=1\nrevision={}\nartifact={}\ntarget={}\nenvironment={}\ncommand={}\nfixtures={}\nseed={}\nschedule={}\nresult={}\npayload={payload}\npayload_digest={payload_digest}\n",
        identity.revision,
        identity.artifact,
        identity.target,
        identity.environment,
        identity.command,
        identity.fixtures,
        case.seed,
        case.mutation.as_str(),
        identity.result,
    );
    if content.len() > MAXIMUM_INTEGRITY_OBJECT_BYTES {
        return Err(XtaskError::invalid_path(
            &directory.diagnostic_path.join(name),
            format!("integrity object exceeds {MAXIMUM_INTEGRITY_OBJECT_BYTES} bytes"),
        ));
    }
    directory.create_file(name, content.as_bytes(), MAXIMUM_INTEGRITY_OBJECT_BYTES)
}

fn read_integrity_object(
    directory: &DirectoryCapability,
    name: &str,
    identity: &IntegrityIdentity,
    case: &IntegrityCase,
) -> Result<(), IntegrityReadFailure> {
    let bytes = match directory.read_bounded_optional(
        name,
        MAXIMUM_INTEGRITY_OBJECT_BYTES,
        "integrity object",
    ) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return Err(IntegrityReadFailure::MissingObject),
        Err(_) => return Err(IntegrityReadFailure::Io),
    };
    if bytes.len() > MAXIMUM_INTEGRITY_OBJECT_BYTES {
        return Err(IntegrityReadFailure::InvalidObject);
    }
    let content = std::str::from_utf8(&bytes).map_err(|_| IntegrityReadFailure::InvalidObject)?;
    let lines = content.lines().collect::<Vec<_>>();
    let [
        schema,
        revision,
        artifact,
        target,
        environment,
        command,
        fixtures,
        seed,
        schedule,
        result,
        payload,
        payload_digest,
    ] = lines.as_slice()
    else {
        return Err(IntegrityReadFailure::InvalidObject);
    };
    let expected = [
        ("schema", "1"),
        ("revision", identity.revision.as_str()),
        ("artifact", identity.artifact.as_str()),
        ("target", identity.target.as_str()),
        ("environment", identity.environment.as_str()),
        ("command", identity.command.as_str()),
        ("fixtures", identity.fixtures.as_str()),
        ("seed", case.seed.as_str()),
        ("schedule", case.mutation.as_str()),
        ("result", identity.result.as_str()),
    ];
    for (line, (expected_key, expected_value)) in [
        *schema,
        *revision,
        *artifact,
        *target,
        *environment,
        *command,
        *fixtures,
        *seed,
        *schedule,
        *result,
    ]
    .into_iter()
    .zip(expected)
    {
        let Some((key, value)) = line.split_once('=') else {
            return Err(IntegrityReadFailure::InvalidObject);
        };
        if key != expected_key || value != expected_value {
            return Err(IntegrityReadFailure::IdentityMismatch);
        }
    }
    let Some(payload) = payload.strip_prefix("payload=") else {
        return Err(IntegrityReadFailure::InvalidObject);
    };
    let Some(payload_digest) = payload_digest.strip_prefix("payload_digest=") else {
        return Err(IntegrityReadFailure::InvalidObject);
    };
    if integrity_payload_digest(payload.as_bytes()) != payload_digest {
        return Err(IntegrityReadFailure::DigestMismatch);
    }
    Ok(())
}

fn corrupt_integrity_payload(
    directory: &DirectoryCapability,
    name: &str,
) -> Result<(), XtaskError> {
    let path = directory.diagnostic_path.join(name);
    let mut bytes =
        directory.read_bounded(name, MAXIMUM_INTEGRITY_OBJECT_BYTES, "integrity object")?;
    let marker = b"payload=fixture-payload-";
    let start = bytes
        .windows(marker.len())
        .position(|window| window == marker)
        .and_then(|offset| offset.checked_add(marker.len()))
        .ok_or_else(|| {
            XtaskError::invalid_path(&path, "integrity fixture payload marker is missing")
        })?;
    let byte = bytes.get_mut(start).ok_or_else(|| {
        XtaskError::invalid_path(&path, "integrity fixture payload is unexpectedly empty")
    })?;
    *byte = if *byte == b'x' { b'y' } else { b'x' };
    directory.replace_file(name, &bytes, MAXIMUM_INTEGRITY_OBJECT_BYTES)
}

fn integrity_payload_digest(payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"positron-quality-integrity-object-v1\0");
    hasher.update(payload);
    format!("sha256:{:x}", hasher.finalize())
}

fn validate_exact_publication_points(
    gate_id: &str,
    cases: &[&FixtureCase],
    expected_points: &[PublicationPoint],
) -> Result<(), XtaskError> {
    if cases.len() != expected_points.len() {
        return Err(XtaskError::invalid(
            format!("{gate_id} fixture registry"),
            format!(
                "expected exactly {} publication-point fixtures, found {}",
                expected_points.len(),
                cases.len()
            ),
        ));
    }
    for expected in expected_points {
        let matching = cases
            .iter()
            .filter(|case| case.publication_point == *expected)
            .count();
        if matching != 1 {
            return Err(XtaskError::invalid(
                format!("{gate_id} fixture registry"),
                format!(
                    "publication point `{}` must have exactly one fixture, found {matching}",
                    expected.as_str()
                ),
            ));
        }
    }
    Ok(())
}

fn execute_state_transition(
    fixture_root: &OwnedFixtureRoot,
    case: &FixtureCase,
    harness: &HarnessInterface,
) -> Result<String, XtaskError> {
    validate_schedule_mapping(case)?;
    let case_root = fixture_root.create_case(&case.fixture_id)?;
    let owned_identity = fixture_root.directory.identity()?.token();
    let case_identity = case_root.identity()?.token();
    let executable = std::env::current_exe()
        .map_err(|source| XtaskError::io("resolve current xtask executable", source))?;
    let mut writer = Command::new(&executable)
        .env_clear()
        .args([
            "quality-fixture",
            harness.writer_operation.as_str(),
            fixture_root.path.to_str().ok_or_else(|| {
                XtaskError::invalid_path(&fixture_root.path, "fixture root is not valid UTF-8")
            })?,
            case_root.diagnostic_path.to_str().ok_or_else(|| {
                XtaskError::invalid_path(
                    &case_root.diagnostic_path,
                    "fixture path is not valid UTF-8",
                )
            })?,
            owned_identity.as_str(),
            case_identity.as_str(),
            case.publication_point.as_str(),
            case.fault_schedule.as_str(),
            case.predecessor.as_str(),
            case.successor.as_str(),
        ])
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        // positron-concurrency-spawn: execute_state_transition\tfixture-writer-v1
        .spawn()
        .map_err(|source| XtaskError::io("launch fixture writer process", source))?;
    let writer_pid = writer.id();
    if let Err(error) = wait_for_ready_acknowledgement(
        &mut writer,
        &case_root,
        harness,
        case.publication_point,
        writer_pid,
    ) {
        return match force_terminate_and_reap(
            &mut writer,
            "fixture writer process",
            harness.maximum_wait,
        ) {
            Ok(_) => Err(error),
            Err(reconciliation) => Err(XtaskError::invalid(
                "fixture writer process",
                format!("{error}; process reconciliation also failed: {reconciliation}"),
            )),
        };
    }
    let writer_reconciliation =
        force_terminate_and_reap(&mut writer, "fixture writer process", harness.maximum_wait)?;
    if !writer_reconciliation.kill_sent || writer_reconciliation.status.success() {
        return Err(XtaskError::invalid(
            format!("fixture writer `{}`", case.fixture_id),
            format!(
                "writer was not forcibly terminated and reaped as registered: status={}, kill-sent={}",
                writer_reconciliation.status, writer_reconciliation.kill_sent
            ),
        ));
    }

    let mut recovery = Command::new(&executable)
        .env_clear()
        .args([
            "quality-fixture",
            harness.recovery_operation.as_str(),
            fixture_root.path.to_str().ok_or_else(|| {
                XtaskError::invalid_path(&fixture_root.path, "fixture root is not valid UTF-8")
            })?,
            case_root.diagnostic_path.to_str().ok_or_else(|| {
                XtaskError::invalid_path(
                    &case_root.diagnostic_path,
                    "fixture path is not valid UTF-8",
                )
            })?,
            owned_identity.as_str(),
            case_identity.as_str(),
            "recovery.result",
            harness.recovery_protocol.as_str(),
            case.fault_schedule.as_str(),
            case.expected_reopen.as_str(),
        ])
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        // positron-concurrency-spawn: execute_state_transition\tfixture-recovery-v1
        .spawn()
        .map_err(|source| XtaskError::io("launch fresh fixture recovery process", source))?;
    let recovery_pid = recovery.id();
    if let Err(error) = wait_for_successful_child(
        &mut recovery,
        harness.maximum_wait,
        "fixture recovery process",
    ) {
        return match force_terminate_and_reap(
            &mut recovery,
            "fixture recovery process",
            harness.maximum_wait,
        ) {
            Ok(_) => Err(error),
            Err(reconciliation) => Err(XtaskError::invalid(
                "fixture recovery process",
                format!("{error}; process reconciliation also failed: {reconciliation}"),
            )),
        };
    }
    if recovery_pid == writer_pid {
        return Err(XtaskError::invalid(
            format!("fixture recovery `{}`", case.fixture_id),
            "fresh recovery process reused the writer process identity",
        ));
    }
    let (reopened, recovery_digest, observation) =
        read_recovery_result(&case_root, "recovery.result", harness, recovery_pid)?;
    let predecessor_or_successor = reopened == case.predecessor || reopened == case.successor;
    if !predecessor_or_successor || reopened != case.expected_reopen {
        return Err(XtaskError::invalid(
            format!("state-transition fixture `{}`", case.fixture_id),
            format!(
                "restart observed `{reopened}`; expected exact predecessor-or-successor `{}`",
                case.expected_reopen
            ),
        ));
    }
    Ok(format!(
        "{}:{}:{}:adapter={}:injection={}:seed={}:ack={}:writer=forcibly-terminated-and-reaped:writer-pid={writer_pid}:recovery-pid={recovery_pid}:recovery=fresh-process:recovery-digest={recovery_digest}",
        case.fixture_id,
        case.fault_schedule.as_str(),
        reopened,
        observation.adapter,
        observation.injection,
        case.seed,
        harness.ready_protocol,
    ))
}

fn validate_schedule_mapping(case: &FixtureCase) -> Result<(), XtaskError> {
    let exact = matches!(
        (case.publication_point, case.fault_schedule),
        (
            PublicationPoint::BeforePublication,
            CrashSchedule::AfterCandidateSync
        ) | (
            PublicationPoint::AfterPublication,
            CrashSchedule::AfterPublicationSync
        ) | (
            PublicationPoint::PartialWriteBoundary,
            CrashSchedule::PartialWrite
        ) | (PublicationPoint::CrashBoundary, CrashSchedule::Crash)
            | (PublicationPoint::RestartBoundary, CrashSchedule::Restart)
            | (
                PublicationPoint::CorruptionBoundary,
                CrashSchedule::Corruption
            )
            | (PublicationPoint::FullDiskBoundary, CrashSchedule::FullDisk)
            | (PublicationPoint::ClockBoundary, CrashSchedule::Clock)
            | (
                PublicationPoint::CancellationBoundary,
                CrashSchedule::Cancellation
            )
            | (PublicationPoint::NetworkBoundary, CrashSchedule::Network)
            | (PublicationPoint::ProviderBoundary, CrashSchedule::Provider)
    );
    if !exact {
        return Err(XtaskError::invalid(
            format!("fixture `{}`", case.fixture_id),
            format!(
                "publication point `{}` does not own schedule `{}`",
                case.publication_point.as_str(),
                case.fault_schedule.as_str()
            ),
        ));
    }
    let expected = match case.publication_point {
        PublicationPoint::AfterPublication | PublicationPoint::RestartBoundary => &case.successor,
        PublicationPoint::BeforePublication
        | PublicationPoint::PartialWriteBoundary
        | PublicationPoint::CrashBoundary
        | PublicationPoint::CorruptionBoundary
        | PublicationPoint::FullDiskBoundary
        | PublicationPoint::ClockBoundary
        | PublicationPoint::CancellationBoundary
        | PublicationPoint::NetworkBoundary
        | PublicationPoint::ProviderBoundary => &case.predecessor,
    };
    if &case.expected_reopen != expected {
        return Err(XtaskError::invalid(
            format!("fixture `{}`", case.fixture_id),
            "expected reopen state does not match the registered publication-point oracle",
        ));
    }
    Ok(())
}

fn wait_for_ready_acknowledgement(
    writer: &mut std::process::Child,
    case_root: &DirectoryCapability,
    harness: &HarnessInterface,
    publication_point: PublicationPoint,
    expected_pid: u32,
) -> Result<(), XtaskError> {
    let deadline = Instant::now() + harness.maximum_wait;
    loop {
        if let Some(bytes) = case_root.read_bounded_optional(
            "writer.ready",
            MAXIMUM_PROCESS_RECORD_BYTES,
            "fixture acknowledgement",
        )? {
            let ready = case_root.diagnostic_path.join("writer.ready");
            let content = std::str::from_utf8(&bytes).map_err(|_| {
                XtaskError::invalid_path(&ready, "fixture acknowledgement is not UTF-8")
            })?;
            let fields = content.trim_end().split('\t').collect::<Vec<_>>();
            let [protocol, pid, point] = fields.as_slice() else {
                return Err(XtaskError::invalid_path(
                    &ready,
                    "fixture acknowledgement does not contain exactly three fields",
                ));
            };
            if *protocol != harness.ready_protocol || *point != publication_point.as_str() {
                return Err(XtaskError::invalid_path(
                    &ready,
                    "fixture acknowledgement does not match the registered interface",
                ));
            }
            let pid = pid.parse::<u32>().map_err(|_| {
                XtaskError::invalid_path(&ready, "fixture acknowledgement PID is invalid")
            })?;
            if pid != expected_pid {
                return Err(XtaskError::invalid_path(
                    &ready,
                    "fixture acknowledgement PID does not match the owned writer",
                ));
            }
            return Ok(());
        }
        if let Some(status) = writer
            .try_wait()
            .map_err(|source| XtaskError::io("observe fixture writer process", source))?
        {
            return Err(XtaskError::invalid(
                "fixture writer process",
                format!(
                    "writer exited with {status} before the registered publication-point acknowledgement"
                ),
            ));
        }
        if Instant::now() >= deadline {
            return Err(XtaskError::invalid(
                "fixture writer process",
                "writer did not acknowledge its publication point before the registered deadline",
            ));
        }
        thread::sleep(Duration::from_millis(1));
    }
}

fn wait_for_successful_child(
    child: &mut std::process::Child,
    maximum_wait: Duration,
    label: &str,
) -> Result<(), XtaskError> {
    let deadline = Instant::now() + maximum_wait;
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|source| XtaskError::io(format!("observe {label}"), source))?
        {
            if status.success() {
                return Ok(());
            }
            return Err(XtaskError::invalid(
                label,
                format!("child returned abnormal status {status}"),
            ));
        }
        if Instant::now() >= deadline {
            return Err(XtaskError::invalid(
                label,
                "child did not complete before the registered deadline",
            ));
        }
        thread::sleep(Duration::from_millis(1));
    }
}

fn force_terminate_and_reap(
    child: &mut std::process::Child,
    label: &str,
    maximum_wait: Duration,
) -> Result<ChildReconciliation, XtaskError> {
    let raw_pid = i32::try_from(child.id()).map_err(|_| {
        XtaskError::invalid(
            format!("{label} termination"),
            "child PID does not fit the registered process-group identity",
        )
    })?;
    let process_group = rustix::process::Pid::from_raw(raw_pid).ok_or_else(|| {
        XtaskError::invalid(
            format!("{label} termination"),
            "child PID is not a nonzero process-group identity",
        )
    })?;
    if let Some(status) = child
        .try_wait()
        .map_err(|source| XtaskError::io(format!("observe {label} before termination"), source))?
    {
        return Ok(ChildReconciliation {
            status,
            kill_sent: false,
        });
    }
    let kill = rustix::process::kill_process_group(process_group, rustix::process::Signal::KILL);
    if let Err(source) = kill {
        return Err(XtaskError::invalid(
            format!("{label} termination"),
            format!(
                "process-group kill failed with `{source}`; pid={}; kill-sent=false",
                child.id()
            ),
        ));
    }
    let deadline = Instant::now().checked_add(maximum_wait).ok_or_else(|| {
        XtaskError::invalid(
            format!("{label} reap"),
            "registered reap deadline cannot be represented",
        )
    })?;
    let mut terminal_status = None;
    loop {
        if terminal_status.is_none() {
            terminal_status = observe_child_reap(child, label)?;
        }
        if let Some(status) = terminal_status {
            return Ok(ChildReconciliation {
                status,
                kill_sent: true,
            });
        }
        if Instant::now() >= deadline {
            let status = terminal_status
                .map(|status| status.to_string())
                .unwrap_or_else(|| "not-reaped".to_owned());
            return Err(XtaskError::invalid(
                format!("{label} reap"),
                format!(
                    "{label} reap deadline elapsed; pid={}; kill-sent=true; process-group-kill-sent=true; direct-status={status}",
                    child.id()
                ),
            ));
        }
        thread::sleep(Duration::from_millis(1));
    }
}

fn observe_child_reap(
    child: &mut std::process::Child,
    label: &str,
) -> Result<Option<std::process::ExitStatus>, XtaskError> {
    child
        .try_wait()
        .map_err(|source| XtaskError::io(format!("observe {label} reap"), source))
}

fn read_recovery_result(
    case_root: &DirectoryCapability,
    name: &str,
    harness: &HarnessInterface,
    expected_pid: u32,
) -> Result<(String, String, AdapterObservation), XtaskError> {
    let path = case_root.diagnostic_path.join(name);
    let bytes = case_root.read_bounded(name, MAXIMUM_PROCESS_RECORD_BYTES, "recovery result")?;
    let content = std::str::from_utf8(&bytes)
        .map_err(|_| XtaskError::invalid_path(&path, "recovery result is not UTF-8"))?;
    let fields = content.trim_end().split('\t').collect::<Vec<_>>();
    let [protocol, pid, state, digest, adapter, injection] = fields.as_slice() else {
        return Err(XtaskError::invalid_path(
            &path,
            "recovery result does not contain exactly six fields",
        ));
    };
    if *protocol != harness.recovery_protocol {
        return Err(XtaskError::invalid_path(
            &path,
            "recovery result protocol is not registered",
        ));
    }
    let pid = pid
        .parse::<u32>()
        .map_err(|_| XtaskError::invalid_path(&path, "recovery result PID is invalid"))?;
    if pid != expected_pid {
        return Err(XtaskError::invalid_path(
            &path,
            "recovery result PID does not match the fresh child",
        ));
    }
    let expected_digest = recovered_state_digest(state);
    if *digest != expected_digest {
        return Err(XtaskError::invalid_path(
            &path,
            "recovery result digest does not bind the observed durable state",
        ));
    }
    let observation = [
        CrashSchedule::AfterCandidateSync,
        CrashSchedule::AfterPublicationSync,
        CrashSchedule::PartialWrite,
        CrashSchedule::Crash,
        CrashSchedule::Restart,
        CrashSchedule::Corruption,
        CrashSchedule::FullDisk,
        CrashSchedule::Clock,
        CrashSchedule::Cancellation,
        CrashSchedule::Network,
        CrashSchedule::Provider,
    ]
    .into_iter()
    .map(QualityFixtureAdapter::for_schedule)
    .map(QualityFixtureAdapter::expected_observation)
    .find(|observation| observation.adapter == *adapter && observation.injection == *injection)
    .ok_or_else(|| {
        XtaskError::invalid_path(
            &path,
            "recovery result does not name a registered adapter observation",
        )
    })?;
    Ok(((*state).to_owned(), (*digest).to_owned(), observation))
}

pub(crate) fn run_process(arguments: impl Iterator<Item = String>) -> Result<(), XtaskError> {
    let arguments = arguments
        .take(MAXIMUM_PROCESS_ARGUMENTS + 1)
        .collect::<Vec<_>>();
    if arguments.len() > MAXIMUM_PROCESS_ARGUMENTS {
        return Err(XtaskError::usage(format!(
            "quality-fixture argument count exceeds the exact maximum of {MAXIMUM_PROCESS_ARGUMENTS}"
        )));
    }
    match arguments.as_slice() {
        [
            operation,
            owned_root,
            case_root,
            owned_identity,
            case_identity,
            publication_point,
            fault_schedule,
            predecessor,
            successor,
        ] if operation == "writer" => run_writer_process(
            &ProcessRootClaim {
                owned_root: Path::new(owned_root),
                case_root: Path::new(case_root),
                owned_identity,
                case_identity,
            },
            PublicationPoint::parse(publication_point)?,
            CrashSchedule::parse(fault_schedule)?,
            predecessor,
            successor,
        ),
        [
            operation,
            owned_root,
            case_root,
            owned_identity,
            case_identity,
            result_name,
            recovery_protocol,
            fault_schedule,
            expected_reopen,
        ] if operation == "recover" => run_recovery_process(
            &ProcessRootClaim {
                owned_root: Path::new(owned_root),
                case_root: Path::new(case_root),
                owned_identity,
                case_identity,
            },
            result_name,
            recovery_protocol,
            CrashSchedule::parse(fault_schedule)?,
            expected_reopen,
        ),
        _ => Err(XtaskError::usage(
            "quality-fixture requires an exact registered writer or recover invocation",
        )),
    }
}

fn run_writer_process(
    claim: &ProcessRootClaim<'_>,
    publication_point: PublicationPoint,
    fault_schedule: CrashSchedule,
    predecessor: &str,
    successor: &str,
) -> Result<(), XtaskError> {
    let case_root = claim_process_root(claim)?;
    validate_field(&case_root.diagnostic_path, 0, "predecessor", predecessor)?;
    validate_field(&case_root.diagnostic_path, 0, "successor", successor)?;
    let published = "published.state";
    let candidate = "candidate.state";
    write_state(&case_root, published, predecessor)?;
    case_root.sync()?;
    let adapter = QualityFixtureAdapter::for_schedule(fault_schedule);
    execute_fixture_adapter(&case_root, adapter, candidate, published, successor)?;
    let content = format!(
        "publication-point-ready-v1\t{}\t{}\n",
        std::process::id(),
        publication_point.as_str()
    );
    write_atomic_process_record(&case_root, "writer.ready", content.as_bytes())?;
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    Err(XtaskError::invalid(
        "fixture writer process",
        "parent did not forcibly terminate the acknowledged writer before its safety deadline",
    ))
}

fn execute_fixture_adapter(
    case_root: &DirectoryCapability,
    adapter: QualityFixtureAdapter,
    candidate: &str,
    published: &str,
    successor: &str,
) -> Result<AdapterObservation, XtaskError> {
    let observation = match adapter {
        QualityFixtureAdapter::CandidatePersistence => {
            write_state(case_root, candidate, successor)?;
            adapter.expected_observation()
        },
        QualityFixtureAdapter::PublicationPersistence | QualityFixtureAdapter::Restart => {
            write_state(case_root, candidate, successor)?;
            case_root.rename(candidate, published)?;
            case_root.sync()?;
            adapter.expected_observation()
        },
        QualityFixtureAdapter::PartialWrite => {
            write_fault_bytes(case_root, candidate, b"partial-state")?;
            adapter.expected_observation()
        },
        QualityFixtureAdapter::ProcessCrash => {
            write_state(case_root, candidate, successor)?;
            adapter.expected_observation()
        },
        QualityFixtureAdapter::Corruption => {
            write_state(case_root, candidate, successor)?;
            corrupt_state_file(case_root, candidate)?;
            adapter.expected_observation()
        },
        QualityFixtureAdapter::BoundedStorage
        | QualityFixtureAdapter::ControlledClock
        | QualityFixtureAdapter::Cancellation
        | QualityFixtureAdapter::NetworkPublication
        | QualityFixtureAdapter::ProviderPublication => {
            let receipt = exercise_deterministic_fault(case_root, adapter, candidate, successor)?;
            write_fault_operation_receipt(case_root, &receipt)?;
            receipt.observation
        },
    };
    write_adapter_observation(case_root, observation)?;
    Ok(observation)
}

fn exercise_deterministic_fault(
    case_root: &DirectoryCapability,
    adapter: QualityFixtureAdapter,
    candidate: &str,
    successor: &str,
) -> Result<FaultOperationReceipt, XtaskError> {
    let (fault, error_identity) = match adapter {
        QualityFixtureAdapter::BoundedStorage => {
            let attempted = encoded_state(successor)?;
            let mut writer = BoundedCandidateWriter { remaining_bytes: 0 };
            match writer.persist(case_root, candidate, &attempted) {
                Err(BoundedCandidateWriteError::CapacityExhausted {
                    attempted_bytes,
                    remaining_bytes,
                }) => (
                    FixtureFault::CapacityExhausted,
                    format!(
                        "capacity-exhausted-attempted-positive-{}-remaining-{remaining_bytes}",
                        attempted_bytes > 0
                    ),
                ),
                Err(BoundedCandidateWriteError::Persistence(error)) => {
                    return Err(error);
                },
                Ok(()) => {
                    return Err(XtaskError::invalid(
                        "bounded storage fixture adapter",
                        "zero-capacity candidate writer accepted persisted bytes",
                    ));
                },
            }
        },
        QualityFixtureAdapter::ControlledClock => {
            let mut clock = ControlledPublicationClock::regressed();
            match validate_monotonic_publication(&mut clock)? {
                Err(RegressedClockError {
                    fault: fault @ FixtureFault::ClockRegressed,
                    last_observed,
                    publication,
                }) => (
                    fault,
                    format!("clock-regressed-last-{last_observed}-publication-{publication}"),
                ),
                Err(error) => {
                    return Err(unexpected_fixture_fault(adapter, error.fault));
                },
                Ok(()) => {
                    return Err(XtaskError::invalid(
                        "controlled clock fixture adapter",
                        "regressed publication timestamp passed monotonic validation",
                    ));
                },
            }
        },
        QualityFixtureAdapter::Cancellation => {
            let mut cancellation = FixtureCancellationToken::requested();
            match validate_publication_cancellation(&mut cancellation) {
                Err(fault @ FixtureFault::Cancelled) => {
                    (fault, "cancellation-consumed-requested-true".to_owned())
                },
                Err(fault) => {
                    return Err(unexpected_fixture_fault(adapter, fault));
                },
                Ok(()) => {
                    return Err(XtaskError::invalid(
                        "cancellation fixture adapter",
                        "requested cancellation did not abort publication",
                    ));
                },
            }
        },
        QualityFixtureAdapter::NetworkPublication => {
            match send_over_closed_network(successor.as_bytes())? {
                Err((fault @ FixtureFault::NetworkUnavailable, identity)) => (fault, identity),
                Err(fault) => {
                    return Err(unexpected_fixture_fault(adapter, fault.0));
                },
                Ok(()) => {
                    return Err(XtaskError::invalid(
                        "network publication fixture adapter",
                        "closed network endpoint accepted publication bytes",
                    ));
                },
            }
        },
        QualityFixtureAdapter::ProviderPublication => {
            match send_to_closed_provider(successor.as_bytes())? {
                Err((fault @ FixtureFault::ProviderUnavailable, identity)) => (fault, identity),
                Err(fault) => {
                    return Err(unexpected_fixture_fault(adapter, fault.0));
                },
                Ok(()) => {
                    return Err(XtaskError::invalid(
                        "provider publication fixture adapter",
                        "closed provider process accepted publication bytes",
                    ));
                },
            }
        },
        _ => {
            return Err(XtaskError::invalid(
                "deterministic fixture fault",
                "adapter does not own a deterministic fault operation",
            ));
        },
    };
    Ok(FaultOperationReceipt {
        observation: fault.observation(),
        error_identity,
    })
}

fn unexpected_fixture_fault(adapter: QualityFixtureAdapter, fault: FixtureFault) -> XtaskError {
    XtaskError::invalid(
        "deterministic fixture fault",
        format!("adapter `{adapter:?}` produced unexpected fault `{fault:?}`"),
    )
}

fn validate_monotonic_publication(
    clock: &mut ControlledPublicationClock,
) -> Result<Result<(), RegressedClockError>, XtaskError> {
    let last_observed = clock.tick()?;
    let publication = clock.tick()?;
    if publication < last_observed {
        return Ok(Err(RegressedClockError {
            fault: FixtureFault::ClockRegressed,
            last_observed,
            publication,
        }));
    }
    Ok(Ok(()))
}

fn validate_publication_cancellation(
    cancellation: &mut FixtureCancellationToken,
) -> Result<(), FixtureFault> {
    if cancellation.consume() {
        return Err(FixtureFault::Cancelled);
    }
    Ok(())
}

fn send_over_closed_network(
    bytes: &[u8],
) -> Result<Result<(), (FixtureFault, String)>, XtaskError> {
    let (mut publisher, receiver) = UnixStream::pair()
        .map_err(|source| XtaskError::io("create hermetic network socket pair", source))?;
    receiver
        .shutdown(Shutdown::Both)
        .map_err(|source| XtaskError::io("close hermetic network receiver", source))?;
    drop(receiver);
    match publisher.write_all(bytes) {
        Ok(()) => Ok(Ok(())),
        Err(source)
            if matches!(
                source.kind(),
                std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::NotConnected
            ) =>
        {
            Ok(Err((
                FixtureFault::NetworkUnavailable,
                format!(
                    "closed-unix-stream-send-os-{}",
                    source.raw_os_error().unwrap_or_default()
                ),
            )))
        },
        Err(source) => Err(XtaskError::io(
            "send through hermetic network boundary",
            source,
        )),
    }
}

fn send_to_closed_provider(bytes: &[u8]) -> Result<Result<(), (FixtureFault, String)>, XtaskError> {
    let executable = std::env::current_exe()
        .map_err(|source| XtaskError::io("resolve provider fixture executable", source))?;
    let mut provider = Command::new(executable)
        .arg("quality-fixture")
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        // positron-concurrency-spawn: send_to_closed_provider\tfixture-provider-v1
        .spawn()
        .map_err(|source| XtaskError::io("launch hermetic provider process", source))?;
    let mut input = provider.stdin.take().ok_or_else(|| {
        XtaskError::invalid(
            "hermetic provider process",
            "provider IPC input descriptor was unavailable",
        )
    })?;
    let status = observe_provider_exit(&mut provider)?;
    match input.write_all(bytes) {
        Ok(()) => Ok(Ok(())),
        Err(source) if source.kind() == std::io::ErrorKind::BrokenPipe => Ok(Err((
            FixtureFault::ProviderUnavailable,
            format!(
                "closed-provider-ipc-status-{}-os-{}",
                status.code().unwrap_or_default(),
                source.raw_os_error().unwrap_or_default()
            ),
        ))),
        Err(source) => Err(XtaskError::io(
            "send through hermetic provider IPC boundary",
            source,
        )),
    }
}

fn observe_provider_exit(
    provider: &mut std::process::Child,
) -> Result<std::process::ExitStatus, XtaskError> {
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        match provider.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(1)),
            Ok(None) => {
                provider.kill().map_err(|source| {
                    XtaskError::io("terminate stalled hermetic provider process", source)
                })?;
                let reap_deadline = Instant::now() + Duration::from_secs(1);
                loop {
                    match provider.try_wait() {
                        Ok(Some(_)) => {
                            return Err(XtaskError::invalid(
                                "hermetic provider process",
                                "provider did not close its IPC endpoint before the bounded deadline",
                            ));
                        },
                        Ok(None) if Instant::now() < reap_deadline => {
                            thread::sleep(Duration::from_millis(1));
                        },
                        Ok(None) => {
                            return Err(XtaskError::invalid(
                                "hermetic provider process",
                                "terminated provider could not be reaped before the bounded deadline",
                            ));
                        },
                        Err(source) => {
                            return Err(XtaskError::io(
                                "reap terminated hermetic provider process",
                                source,
                            ));
                        },
                    }
                }
            },
            Err(source) => {
                return Err(XtaskError::io("observe hermetic provider process", source));
            },
        }
    }
}

fn write_fault_operation_receipt(
    case_root: &DirectoryCapability,
    receipt: &FaultOperationReceipt,
) -> Result<(), XtaskError> {
    let content = format!(
        "fixture-fault-operation-v1\t{}\t{}\t{}\n",
        receipt.observation.adapter, receipt.observation.injection, receipt.error_identity
    );
    write_process_record(case_root, "fault.operation", content.as_bytes())?;
    case_root.sync()
}

fn write_adapter_observation(
    case_root: &DirectoryCapability,
    observation: AdapterObservation,
) -> Result<(), XtaskError> {
    let content = format!(
        "fixture-adapter-v1\t{}\t{}\n",
        observation.adapter, observation.injection
    );
    write_process_record(case_root, "adapter.observation", content.as_bytes())?;
    case_root.sync()
}

fn run_recovery_process(
    claim: &ProcessRootClaim<'_>,
    result_name: &str,
    recovery_protocol: &str,
    fault_schedule: CrashSchedule,
    expected_reopen: &str,
) -> Result<(), XtaskError> {
    let case_root = claim_process_root(claim)?;
    if recovery_protocol != "recovery-v1" {
        return Err(XtaskError::invalid(
            "fixture recovery process",
            "recovery protocol is not registered",
        ));
    }
    validate_leaf_name(&case_root.diagnostic_path, result_name)?;
    let state = read_state(&case_root, "published.state")?;
    let observation =
        validate_recovered_adapter_effect(&case_root, fault_schedule, expected_reopen, &state)?;
    let digest = recovered_state_digest(&state);
    let content = format!(
        "{recovery_protocol}\t{}\t{state}\t{digest}\t{}\t{}\n",
        std::process::id(),
        observation.adapter,
        observation.injection,
    );
    write_process_record(&case_root, result_name, content.as_bytes())?;
    case_root.sync()
}

fn validate_recovered_adapter_effect(
    case_root: &DirectoryCapability,
    fault_schedule: CrashSchedule,
    expected_reopen: &str,
    reopened: &str,
) -> Result<AdapterObservation, XtaskError> {
    validate_field(
        &case_root.diagnostic_path,
        0,
        "expected_reopen",
        expected_reopen,
    )?;
    if reopened != expected_reopen {
        return Err(XtaskError::invalid(
            "fixture recovery adapter oracle",
            format!(
                "reopened durable state `{reopened}` does not match registered oracle `{expected_reopen}`"
            ),
        ));
    }
    let adapter = QualityFixtureAdapter::for_schedule(fault_schedule);
    let expected = adapter.expected_observation();
    let observed = read_adapter_observation(case_root)?;
    if observed != expected {
        return Err(XtaskError::invalid(
            "fixture recovery adapter oracle",
            format!(
                "adapter observation `{}/{}` does not match registered `{}/{}`",
                observed.adapter, observed.injection, expected.adapter, expected.injection
            ),
        ));
    }
    if matches!(
        adapter,
        QualityFixtureAdapter::BoundedStorage
            | QualityFixtureAdapter::ControlledClock
            | QualityFixtureAdapter::Cancellation
            | QualityFixtureAdapter::NetworkPublication
            | QualityFixtureAdapter::ProviderPublication
    ) {
        let durable_receipt = read_fault_operation_receipt(case_root)?;
        if durable_receipt.observation != expected {
            return Err(XtaskError::invalid(
                "fixture recovery fault operation",
                format!(
                    "durable operation `{}/{}` does not match registered `{}/{}`",
                    durable_receipt.observation.adapter,
                    durable_receipt.observation.injection,
                    expected.adapter,
                    expected.injection
                ),
            ));
        }
        let independent_receipt = exercise_deterministic_fault(
            case_root,
            adapter,
            "recovery-probe.state",
            expected_reopen,
        )?;
        if independent_receipt != durable_receipt {
            return Err(XtaskError::invalid(
                "fixture recovery fault operation",
                format!(
                    "independent operation result `{}` does not match durable `{}`",
                    independent_receipt.error_identity, durable_receipt.error_identity
                ),
            ));
        }
    }

    let candidate_state = match read_candidate_state_once(case_root, adapter) {
        CandidateStateOutcome::ReadIoSecurityError(error) => return Err(error),
        outcome => outcome,
    };
    let actual_effect_matches = match adapter {
        QualityFixtureAdapter::CandidatePersistence | QualityFixtureAdapter::ProcessCrash => {
            matches!(
                &candidate_state,
                CandidateStateOutcome::ValidState(candidate) if candidate != reopened
            )
        },
        QualityFixtureAdapter::PublicationPersistence | QualityFixtureAdapter::Restart => {
            matches!(candidate_state, CandidateStateOutcome::Absent)
        },
        QualityFixtureAdapter::PartialWrite | QualityFixtureAdapter::Corruption => {
            matches!(
                candidate_state,
                CandidateStateOutcome::IntentionallyMalformedState
            )
        },
        QualityFixtureAdapter::BoundedStorage
        | QualityFixtureAdapter::ControlledClock
        | QualityFixtureAdapter::Cancellation
        | QualityFixtureAdapter::NetworkPublication
        | QualityFixtureAdapter::ProviderPublication => {
            matches!(candidate_state, CandidateStateOutcome::Absent)
        },
    };
    if !actual_effect_matches {
        return Err(XtaskError::invalid(
            "fixture recovery adapter oracle",
            format!(
                "actual durable candidate state does not match adapter `{}`",
                expected.adapter
            ),
        ));
    }
    Ok(expected)
}

fn read_candidate_state_once(
    case_root: &DirectoryCapability,
    adapter: QualityFixtureAdapter,
) -> CandidateStateOutcome {
    let candidate = match case_root
        .open_file_capability_optional("candidate.state", "fixture candidate state")
    {
        Ok(Some(candidate)) => candidate,
        Ok(None) => return CandidateStateOutcome::Absent,
        Err(error) => return CandidateStateOutcome::ReadIoSecurityError(error),
    };
    let bytes = match candidate.read_bounded(MAXIMUM_STATE_BYTES, "fixture candidate state") {
        Ok(bytes) => bytes,
        Err(error) => return CandidateStateOutcome::ReadIoSecurityError(error),
    };
    if let Err(error) = case_root.require_child_file_identity(
        "candidate.state",
        candidate.identity(),
        "fixture candidate state",
    ) {
        return CandidateStateOutcome::ReadIoSecurityError(error);
    }
    match parse_candidate_state_bytes(&bytes) {
        Ok(state) => CandidateStateOutcome::ValidState(state),
        Err(CandidateStateParseError::WrongFieldCount)
            if adapter == QualityFixtureAdapter::PartialWrite
                && bytes.as_slice() == b"partial-state" =>
        {
            CandidateStateOutcome::IntentionallyMalformedState
        },
        Err(CandidateStateParseError::RegisteredCorruption)
            if adapter == QualityFixtureAdapter::Corruption =>
        {
            CandidateStateOutcome::IntentionallyMalformedState
        },
        Err(error) => CandidateStateOutcome::ReadIoSecurityError(XtaskError::invalid_path(
            candidate.diagnostic_path(),
            format!("fixture candidate state is unexpectedly malformed: {error:?}"),
        )),
    }
}

fn parse_candidate_state_bytes(bytes: &[u8]) -> Result<String, CandidateStateParseError> {
    let content = std::str::from_utf8(bytes).map_err(|_| CandidateStateParseError::NotUtf8)?;
    let fields = content.lines().collect::<Vec<_>>();
    let [state, catalog, audit, digest] = fields.as_slice() else {
        return Err(CandidateStateParseError::WrongFieldCount);
    };
    if *catalog != format!("catalog-{state}")
        || *audit != format!("audit-{state}")
        || *digest != state_digest(state, catalog, audit)
    {
        if is_registered_corruption(bytes, catalog, audit, digest) {
            return Err(CandidateStateParseError::RegisteredCorruption);
        }
        return Err(CandidateStateParseError::IntegrityMismatch);
    }
    Ok((*state).to_owned())
}

fn is_registered_corruption(bytes: &[u8], catalog: &str, audit: &str, digest: &str) -> bool {
    let Some(original_state) = catalog.strip_prefix("catalog-") else {
        return false;
    };
    if audit != format!("audit-{original_state}")
        || digest != state_digest(original_state, catalog, audit)
    {
        return false;
    }
    let mut expected = format!("{original_state}\n{catalog}\n{audit}\n{digest}\n").into_bytes();
    let Some(first_byte) = expected.first_mut() else {
        return false;
    };
    *first_byte = if *first_byte == b'x' { b'y' } else { b'x' };
    expected == bytes
}

fn read_adapter_observation(
    case_root: &DirectoryCapability,
) -> Result<AdapterObservation, XtaskError> {
    let path = case_root.diagnostic_path.join("adapter.observation");
    let bytes = case_root.read_bounded(
        "adapter.observation",
        MAXIMUM_PROCESS_RECORD_BYTES,
        "fixture adapter observation",
    )?;
    let content = std::str::from_utf8(&bytes)
        .map_err(|_| XtaskError::invalid_path(&path, "fixture adapter observation is not UTF-8"))?;
    let fields = content.trim_end().split('\t').collect::<Vec<_>>();
    let [protocol, adapter, injection] = fields.as_slice() else {
        return Err(XtaskError::invalid_path(
            &path,
            "fixture adapter observation does not contain exactly three fields",
        ));
    };
    if *protocol != "fixture-adapter-v1" {
        return Err(XtaskError::invalid_path(
            &path,
            "fixture adapter observation protocol is not registered",
        ));
    }
    let schedule_adapter = [
        CrashSchedule::AfterCandidateSync,
        CrashSchedule::AfterPublicationSync,
        CrashSchedule::PartialWrite,
        CrashSchedule::Crash,
        CrashSchedule::Restart,
        CrashSchedule::Corruption,
        CrashSchedule::FullDisk,
        CrashSchedule::Clock,
        CrashSchedule::Cancellation,
        CrashSchedule::Network,
        CrashSchedule::Provider,
    ]
    .into_iter()
    .map(QualityFixtureAdapter::for_schedule)
    .find(|candidate| candidate.expected_observation().adapter == *adapter)
    .ok_or_else(|| {
        XtaskError::invalid_path(
            &path,
            "fixture adapter observation names an unknown adapter",
        )
    })?;
    let observation = schedule_adapter.expected_observation();
    if observation.injection != *injection {
        return Err(XtaskError::invalid_path(
            &path,
            "fixture adapter observation names an unknown injection",
        ));
    }
    Ok(observation)
}

fn read_fault_operation_receipt(
    case_root: &DirectoryCapability,
) -> Result<FaultOperationReceipt, XtaskError> {
    let path = case_root.diagnostic_path.join("fault.operation");
    let bytes = case_root.read_bounded(
        "fault.operation",
        MAXIMUM_PROCESS_RECORD_BYTES,
        "fixture fault operation receipt",
    )?;
    let content = std::str::from_utf8(&bytes).map_err(|_| {
        XtaskError::invalid_path(&path, "fixture fault operation receipt is not UTF-8")
    })?;
    let fields = content.trim_end().split('\t').collect::<Vec<_>>();
    let [protocol, adapter, injection, error_identity] = fields.as_slice() else {
        return Err(XtaskError::invalid_path(
            &path,
            "fixture fault operation receipt does not contain exactly four fields",
        ));
    };
    if *protocol != "fixture-fault-operation-v1" {
        return Err(XtaskError::invalid_path(
            &path,
            "fixture fault operation receipt protocol is not registered",
        ));
    }
    validate_field(&path, 0, "fault error identity", error_identity)?;
    let observation = [
        CrashSchedule::FullDisk,
        CrashSchedule::Clock,
        CrashSchedule::Cancellation,
        CrashSchedule::Network,
        CrashSchedule::Provider,
    ]
    .into_iter()
    .map(QualityFixtureAdapter::for_schedule)
    .map(QualityFixtureAdapter::expected_observation)
    .find(|candidate| candidate.adapter == *adapter && candidate.injection == *injection)
    .ok_or_else(|| {
        XtaskError::invalid_path(
            &path,
            "fixture fault operation receipt names an unknown result",
        )
    })?;
    Ok(FaultOperationReceipt {
        observation,
        error_identity: (*error_identity).to_owned(),
    })
}

fn claim_process_root(claim: &ProcessRootClaim<'_>) -> Result<DirectoryCapability, XtaskError> {
    let ProcessRootClaim {
        owned_root,
        case_root,
        owned_identity,
        case_identity,
    } = claim;
    if !owned_root.is_absolute() || !case_root.is_absolute() {
        return Err(XtaskError::invalid_path(
            case_root,
            "fixture process owned root and case root must be absolute",
        ));
    }
    if case_root.parent() != Some(owned_root) {
        return Err(XtaskError::invalid_path(
            case_root,
            "fixture process case root is not a direct child of the exact owned root",
        ));
    }
    let expected_owned = DirectoryIdentity::parse(owned_root, owned_identity)?;
    let expected_case = DirectoryIdentity::parse(case_root, case_identity)?;
    let owned = DirectoryCapability::open(owned_root, "fixture process owned root")?;
    owned.require_identity(expected_owned)?;
    let case_name = case_root
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| XtaskError::invalid_path(case_root, "fixture case name is not UTF-8"))?;
    if let Ok(case) = owned.open_child_directory(case_name, "fixture process case root")
        && case.identity()? == expected_case
    {
        return Ok(case);
    }
    for name in owned.entry_names("fixture process owned root")? {
        let Ok(case) = owned.open_child_directory(&name, "fixture process case candidate") else {
            continue;
        };
        if case.identity()? == expected_case {
            return Ok(case);
        }
    }
    Err(XtaskError::invalid_path(
        case_root,
        "fixture process case identity is no longer present beneath the owned root",
    ))
}

fn write_process_record(
    directory: &DirectoryCapability,
    name: &str,
    bytes: &[u8],
) -> Result<(), XtaskError> {
    let path = directory.diagnostic_path.join(name);
    if bytes.len() > MAXIMUM_PROCESS_RECORD_BYTES {
        return Err(XtaskError::invalid_path(
            &path,
            format!("process record exceeds {MAXIMUM_PROCESS_RECORD_BYTES} bytes"),
        ));
    }
    directory.create_file(name, bytes, MAXIMUM_PROCESS_RECORD_BYTES)
}

fn write_atomic_process_record(
    directory: &DirectoryCapability,
    name: &str,
    bytes: &[u8],
) -> Result<(), XtaskError> {
    validate_leaf_name(&directory.diagnostic_path, name)?;
    let staged = format!("{name}.staged");
    write_process_record(directory, &staged, bytes)?;
    directory.hard_link(&staged, name)?;
    directory.sync()
}

fn write_fault_bytes(
    directory: &DirectoryCapability,
    name: &str,
    bytes: &[u8],
) -> Result<(), XtaskError> {
    write_process_record(directory, name, bytes)?;
    directory.sync()
}

fn corrupt_state_file(directory: &DirectoryCapability, name: &str) -> Result<(), XtaskError> {
    let path = directory.diagnostic_path.join(name);
    let mut bytes = directory.read_bounded(name, MAXIMUM_STATE_BYTES, "fixture state")?;
    let byte = bytes
        .first_mut()
        .ok_or_else(|| XtaskError::invalid_path(&path, "state candidate is unexpectedly empty"))?;
    *byte = if *byte == b'x' { b'y' } else { b'x' };
    directory.replace_file(name, &bytes, MAXIMUM_STATE_BYTES)
}

fn write_state(directory: &DirectoryCapability, name: &str, state: &str) -> Result<(), XtaskError> {
    let path = directory.diagnostic_path.join(name);
    let content = encoded_state(state)?;
    if content.len() > MAXIMUM_STATE_BYTES {
        return Err(XtaskError::invalid_path(
            &path,
            format!("fixture state exceeds {MAXIMUM_STATE_BYTES} bytes"),
        ));
    }
    directory.create_file(name, &content, MAXIMUM_STATE_BYTES)
}

fn encoded_state(state: &str) -> Result<Vec<u8>, XtaskError> {
    let catalog = format!("catalog-{state}");
    let audit = format!("audit-{state}");
    let digest = state_digest(state, &catalog, &audit);
    let content = format!("{state}\n{catalog}\n{audit}\n{digest}\n").into_bytes();
    if content.len() > MAXIMUM_STATE_BYTES {
        return Err(XtaskError::invalid(
            "fixture state",
            format!("fixture state exceeds {MAXIMUM_STATE_BYTES} bytes"),
        ));
    }
    Ok(content)
}

fn read_state(directory: &DirectoryCapability, name: &str) -> Result<String, XtaskError> {
    let path = directory.diagnostic_path.join(name);
    let bytes = directory.read_bounded(name, MAXIMUM_STATE_BYTES, "reopened fixture state")?;
    let content = std::str::from_utf8(&bytes)
        .map_err(|_| XtaskError::invalid_path(&path, "reopened fixture state is not UTF-8"))?;
    let fields = content.lines().collect::<Vec<_>>();
    let [state, catalog, audit, digest] = fields.as_slice() else {
        return Err(XtaskError::invalid_path(
            &path,
            "reopened fixture state does not contain exactly four fields",
        ));
    };
    if *catalog != format!("catalog-{state}")
        || *audit != format!("audit-{state}")
        || *digest != state_digest(state, catalog, audit)
    {
        return Err(XtaskError::invalid_path(
            &path,
            "reopened fixture state is mixed or corrupted",
        ));
    }
    Ok((*state).to_owned())
}

fn state_digest(state: &str, catalog: &str, audit: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"positron-quality-state-fixture-v1\0");
    hasher.update(state.as_bytes());
    hasher.update(b"\0");
    hasher.update(catalog.as_bytes());
    hasher.update(b"\0");
    hasher.update(audit.as_bytes());
    format!("sha256:{:x}", hasher.finalize())
}

fn recovered_state_digest(state: &str) -> String {
    let catalog = format!("catalog-{state}");
    let audit = format!("audit-{state}");
    let state_digest = state_digest(state, &catalog, &audit);
    let bytes = format!("{state}\n{catalog}\n{audit}\n{state_digest}\n");
    let mut hasher = Sha256::new();
    hasher.update(b"positron-quality-recovered-state-v1\0");
    hasher.update(bytes.as_bytes());
    format!("sha256:{:x}", hasher.finalize())
}

impl OwnedFixtureRoot {
    fn create(temporary_root: &Path, name: &str) -> Result<Self, XtaskError> {
        validate_field(temporary_root, 0, "fixture_root_name", name)?;
        let parent = DirectoryCapability::open(temporary_root, "attempt temporary root")?;
        let name = format!("qualification-fixtures-{name}");
        let path = temporary_root.join(&name);
        let directory = match rustix::fs::mkdirat(&parent.file, name.as_str(), Mode::RWXU) {
            Ok(()) => {
                parent.sync()?;
                parent.open_child_directory(&name, "owned fixture root")?
            },
            Err(rustix::io::Errno::EXIST) => {
                let stat =
                    rustix::fs::statat(&parent.file, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
                        .map_err(|source| {
                            XtaskError::io(
                                format!("inspect occupied fixture root {}", path.display()),
                                rustix_io(source),
                            )
                        })?;
                if !FileType::from_raw_mode(stat.st_mode).is_dir() {
                    return Err(XtaskError::invalid_path(
                        &path,
                        "owned fixture directory component is not a directory",
                    ));
                }
                return Err(XtaskError::invalid_path(
                    &path,
                    "owned fixture directory is already occupied",
                ));
            },
            Err(source) => {
                return Err(XtaskError::io(
                    format!("create owned fixture root {}", path.display()),
                    rustix_io(source),
                ));
            },
        };
        Ok(Self {
            parent,
            directory,
            name,
            path,
            active: true,
        })
    }

    fn create_case(&self, fixture_id: &str) -> Result<DirectoryCapability, XtaskError> {
        validate_field(&self.path, 0, "fixture_id", fixture_id)?;
        self.directory
            .create_child_directory(fixture_id, "owned fixture case")
    }

    fn finish<T>(mut self, outcome: Result<T, XtaskError>) -> Result<T, XtaskError> {
        let cleanup = self.cleanup();
        match (outcome, cleanup) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(cleanup_error)) => Err(cleanup_error),
            (Err(error), Err(cleanup_error)) => Err(XtaskError::invalid(
                "qualification fixture cleanup",
                format!("{error}; cleanup also failed: {cleanup_error}"),
            )),
        }
    }

    fn cleanup(&mut self) -> Result<(), XtaskError> {
        if !self.active {
            return Ok(());
        }
        remove_directory_contents(&self.directory)?;
        let identity = self.directory.identity()?;
        remove_child_directory_by_identity(&self.parent, identity)?;
        self.active = false;
        self.parent.sync().map_err(|error| {
            XtaskError::invalid(
                "qualification fixture cleanup",
                format!(
                    "removed {} but could not synchronize its parent: {error}",
                    self.path.display()
                ),
            )
        })?;
        match rustix::fs::statat(
            &self.parent.file,
            self.name.as_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Err(rustix::io::Errno::NOENT) => Ok(()),
            Ok(_) => Err(XtaskError::invalid_path(
                &self.path,
                "canonical fixture root name was replaced during cleanup",
            )),
            Err(source) => Err(XtaskError::io(
                format!(
                    "inspect canonical fixture root after cleanup {}",
                    self.path.display()
                ),
                rustix_io(source),
            )),
        }
    }
}

impl Drop for OwnedFixtureRoot {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            eprintln!("qualification fixture RAII cleanup failed: {error}");
        }
    }
}

fn remove_directory_contents(directory: &DirectoryCapability) -> Result<(), XtaskError> {
    for name in directory.entry_names("owned fixture directory")? {
        let stat = rustix::fs::statat(&directory.file, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|source| XtaskError::io("inspect owned fixture entry", rustix_io(source)))?;
        if FileType::from_raw_mode(stat.st_mode).is_dir() {
            let child = directory.open_child_directory(&name, "owned fixture cleanup directory")?;
            remove_directory_contents(&child)?;
            rustix::fs::unlinkat(&directory.file, name.as_str(), AtFlags::REMOVEDIR).map_err(
                |source| {
                    XtaskError::io(
                        format!(
                            "remove owned fixture directory {}",
                            directory.diagnostic_path.join(&name).display()
                        ),
                        rustix_io(source),
                    )
                },
            )?;
        } else {
            directory.remove_file(&name)?;
        }
    }
    directory.sync()
}

fn remove_child_directory_by_identity(
    parent: &DirectoryCapability,
    expected: DirectoryIdentity,
) -> Result<(), XtaskError> {
    for name in parent.entry_names("fixture parent during cleanup")? {
        let Ok(child) = parent.open_child_directory(&name, "fixture cleanup candidate") else {
            continue;
        };
        if child.identity()? == expected {
            return rustix::fs::unlinkat(&parent.file, name.as_str(), AtFlags::REMOVEDIR).map_err(
                |source| {
                    XtaskError::io(
                        format!(
                            "remove owned fixture root {}",
                            parent.diagnostic_path.join(&name).display()
                        ),
                        rustix_io(source),
                    )
                },
            );
        }
    }
    Err(XtaskError::invalid_path(
        &parent.diagnostic_path,
        "owned fixture root identity disappeared before cleanup",
    ))
}

fn validate_field(path: &Path, line: usize, field: &str, value: &str) -> Result<(), XtaskError> {
    let valid = !value.is_empty()
        && value.len() <= MAXIMUM_FIELD_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-'));
    if valid {
        return Ok(());
    }
    Err(XtaskError::invalid_path(
        path,
        format!(
            "fixture row {line} field `{field}` must be 1..={MAXIMUM_FIELD_BYTES} ASCII alphanumeric or hyphen bytes"
        ),
    ))
}
