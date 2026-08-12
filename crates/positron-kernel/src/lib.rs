//! Positron's shared Storage Kernel boundary.
//!
//! This slice owns the concrete Release 1 Primary Data Volume. Catalog,
//! encryption, active-segment, durability-frontier, and bootstrap behavior are
//! intentionally outside this crate's current implemented surface.

#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Read, Write};
use std::path::Path;

#[cfg(test)]
use std::path::PathBuf;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

/// The concrete Release 1 Primary Data Volume entry point.
///
/// Construction is intentionally unavailable: callers receive ownership only
/// through [`PrimaryDataVolume::acquire`].
pub enum PrimaryDataVolume {}

/// A process-lifetime ownership claim over one Primary Data Volume.
pub struct OwnedPrimaryDataVolume {
    _root: File,
    _ownership_lock: File,
    _root_identity: VolumeRootIdentity,
}

impl std::fmt::Debug for OwnedPrimaryDataVolume {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("OwnedPrimaryDataVolume { <redacted> }")
    }
}

impl OwnedPrimaryDataVolume {
    /// Returns the stable opaque filesystem identity captured at acquisition.
    #[must_use]
    pub const fn root_identity(&self) -> VolumeRootIdentity {
        self._root_identity
    }
}

/// The opaque filesystem identity of one Primary Data Volume root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VolumeRootIdentity {
    device: u64,
    inode: u64,
}

/// A typed failure returned while acquiring a Primary Data Volume.
#[derive(Debug)]
pub struct VolumeFailure {
    code: VolumeFailureCode,
    retry_class: VolumeRetryClass,
    completion_state: VolumeCompletionState,
    operation: VolumeOperation,
    source: io::Error,
}

/// The stable class of a Primary Data Volume acquisition failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VolumeFailureCode {
    /// The configured root does not exist.
    Missing,
    /// Another writer currently owns the configured volume.
    Busy,
    /// The operating system denied the required volume access.
    PermissionDenied,
    /// The filesystem cannot provide the required storage capacity.
    Exhausted,
    /// The filesystem is mounted or exposed read-only.
    ReadOnly,
    /// The filesystem does not provide a required database-safe capability.
    Unsupported,
    /// A bounded operating-system fault may clear on retry.
    Transient,
    /// Existing volume state cannot be safely interpreted or cleaned.
    Inconsistent,
    /// The configured root is not safe to use as a database volume.
    Unsafe,
}

/// Whether and how a failed acquisition may be retried.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VolumeRetryClass {
    /// Retrying requires an operator or environment correction.
    AfterExternalCorrection,
    /// A bounded retry may succeed after the current owner or transient fault clears.
    AfterBackoff,
    /// Retrying the same root cannot make the rejected configuration safe.
    Never,
}

/// The durable completion truth of a failed acquisition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VolumeCompletionState {
    /// Acquisition stopped before the owned probe began.
    Rejected,
    /// The failed probe left no dedicated probe artifacts behind.
    ProbeCleaned,
    /// Probe residue remains because bounded cleanup could not prove it safe.
    ProbeCleanupIncomplete,
}

/// The bounded operation that produced a Primary Data Volume failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VolumeOperation {
    /// Classifying the configured root before acquisition.
    ClassifyRoot,
    /// Confirming that the opened directory is the classified filesystem root.
    VerifyRootIdentity,
    /// Opening the fixed process-lifetime ownership-lock file.
    OpenOwnershipLock,
    /// Acquiring exclusive operating-system ownership.
    AcquireOwnershipLock,
    /// Preparing the dedicated bounded capability-probe area.
    PrepareProbe,
    /// Opening the probe file with exclusive creation.
    OpenProbeFile,
    /// Writing the probe payload.
    WriteProbeFile,
    /// Durably synchronizing the probe file contents.
    SynchronizeProbeFile,
    /// Reopening synchronized probe contents through a new file handle.
    ReopenProbeFile,
    /// Reading and verifying synchronized probe contents.
    ReadProbeFile,
    /// Comparing reopened contents with the synchronized probe payload.
    VerifyProbeContents,
    /// Truncating synchronized probe contents to a shorter valid prefix.
    TruncateProbeFile,
    /// Confirming that synchronized truncation retained exactly the prefix.
    VerifyProbeTruncation,
    /// Atomically renaming probe output within the same directory.
    RenameProbeFile,
    /// Durably synchronizing the probe directory after publication.
    SynchronizeProbeDirectory,
    /// Removing the bounded set of dedicated probe artifacts.
    CleanupProbe,
}

impl VolumeFailure {
    fn from_io(operation: VolumeOperation, source: io::Error) -> Self {
        let code = match source.kind() {
            io::ErrorKind::NotFound => VolumeFailureCode::Missing,
            io::ErrorKind::PermissionDenied => VolumeFailureCode::PermissionDenied,
            io::ErrorKind::StorageFull => VolumeFailureCode::Exhausted,
            io::ErrorKind::ReadOnlyFilesystem => VolumeFailureCode::ReadOnly,
            io::ErrorKind::Unsupported => VolumeFailureCode::Unsupported,
            io::ErrorKind::AlreadyExists
            | io::ErrorKind::InvalidData
            | io::ErrorKind::UnexpectedEof => VolumeFailureCode::Inconsistent,
            io::ErrorKind::WouldBlock if operation == VolumeOperation::AcquireOwnershipLock => {
                VolumeFailureCode::Busy
            },
            io::ErrorKind::Interrupted | io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => {
                VolumeFailureCode::Transient
            },
            _ => VolumeFailureCode::Unsafe,
        };
        let retry_class = match code {
            VolumeFailureCode::Exhausted
            | VolumeFailureCode::Missing
            | VolumeFailureCode::PermissionDenied
            | VolumeFailureCode::ReadOnly => VolumeRetryClass::AfterExternalCorrection,
            VolumeFailureCode::Busy | VolumeFailureCode::Transient => {
                VolumeRetryClass::AfterBackoff
            },
            VolumeFailureCode::Inconsistent
            | VolumeFailureCode::Unsafe
            | VolumeFailureCode::Unsupported => VolumeRetryClass::Never,
        };
        Self {
            code,
            retry_class,
            completion_state: VolumeCompletionState::Rejected,
            operation,
            source,
        }
    }

    fn inconsistent_probe(source: io::Error) -> Self {
        Self {
            code: VolumeFailureCode::Inconsistent,
            retry_class: VolumeRetryClass::Never,
            completion_state: VolumeCompletionState::ProbeCleanupIncomplete,
            operation: VolumeOperation::PrepareProbe,
            source,
        }
    }

    fn probe_failure(operation: VolumeOperation, source: io::Error) -> Self {
        let mut failure = Self::from_io(operation, source);
        failure.completion_state = VolumeCompletionState::ProbeCleaned;
        failure
    }

    fn inconsistent_cleanup(source: io::Error) -> Self {
        Self {
            code: VolumeFailureCode::Inconsistent,
            retry_class: VolumeRetryClass::Never,
            completion_state: VolumeCompletionState::ProbeCleanupIncomplete,
            operation: VolumeOperation::CleanupProbe,
            source,
        }
    }

    /// Returns the stable code intended for caller control flow.
    #[must_use]
    pub const fn code(&self) -> VolumeFailureCode {
        self.code
    }

    /// Returns the retry classification for this failure.
    #[must_use]
    pub const fn retry_class(&self) -> VolumeRetryClass {
        self.retry_class
    }

    /// Returns the truthful durable completion state.
    #[must_use]
    pub const fn completion_state(&self) -> VolumeCompletionState {
        self.completion_state
    }

    /// Returns the bounded operation that failed.
    #[must_use]
    pub const fn operation(&self) -> VolumeOperation {
        self.operation
    }
}

impl Display for VolumeFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("primary data volume acquisition failed")
    }
}

impl Error for VolumeFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

impl PrimaryDataVolume {
    /// Acquires an existing filesystem directory as the Primary Data Volume.
    ///
    /// This operation never creates a missing root and refuses a root reached
    /// through a symbolic link.
    pub fn acquire(root: &Path) -> Result<OwnedPrimaryDataVolume, VolumeFailure> {
        let path_metadata =
            perform_io(VolumeOperation::ClassifyRoot, || fs::symlink_metadata(root))
                .map_err(|source| VolumeFailure::from_io(VolumeOperation::ClassifyRoot, source))?;
        if !path_metadata.file_type().is_dir() {
            return Err(VolumeFailure::from_io(
                VolumeOperation::ClassifyRoot,
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "primary data volume root is not a directory",
                ),
            ));
        }

        let root_file = perform_io(VolumeOperation::ClassifyRoot, || File::open(root))
            .map_err(|source| VolumeFailure::from_io(VolumeOperation::ClassifyRoot, source))?;
        let handle_metadata = perform_io(VolumeOperation::ClassifyRoot, || root_file.metadata())
            .map_err(|source| VolumeFailure::from_io(VolumeOperation::ClassifyRoot, source))?;
        let path_identity = root_identity(&path_metadata)?;
        let handle_identity = root_identity(&handle_metadata)?;
        if !values_match(
            VolumeOperation::VerifyRootIdentity,
            &path_identity,
            &handle_identity,
        ) {
            return Err(VolumeFailure::from_io(
                VolumeOperation::VerifyRootIdentity,
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "primary data volume root changed while being acquired",
                ),
            ));
        }

        let ownership_lock_path = root.join(".positron-volume.lock");
        let ownership_lock = open_ownership_artifact(&ownership_lock_path)?;
        verify_ownership_artifact(&ownership_lock_path, &ownership_lock, handle_identity)?;
        try_lock_ownership(&ownership_lock).map_err(|source| {
            VolumeFailure::from_io(VolumeOperation::AcquireOwnershipLock, source)
        })?;
        run_capability_probe(root, &root_file)?;

        Ok(OwnedPrimaryDataVolume {
            _root: root_file,
            _ownership_lock: ownership_lock,
            _root_identity: handle_identity,
        })
    }
}

fn open_ownership_artifact(path: &Path) -> Result<File, VolumeFailure> {
    let existing = perform_io(VolumeOperation::OpenOwnershipLock, || {
        fs::symlink_metadata(path)
    });
    let create_new = match existing {
        Ok(metadata) if metadata.file_type().is_file() => false,
        Ok(_) => {
            return Err(VolumeFailure::from_io(
                VolumeOperation::OpenOwnershipLock,
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "ownership artifact is not a regular volume file",
                ),
            ));
        },
        Err(source) if source.kind() == io::ErrorKind::NotFound => true,
        Err(source) => {
            return Err(VolumeFailure::from_io(
                VolumeOperation::OpenOwnershipLock,
                source,
            ));
        },
    };
    perform_io(VolumeOperation::OpenOwnershipLock, || {
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        if create_new {
            options.create_new(true);
        }
        options.open(path)
    })
    .map_err(|source| VolumeFailure::from_io(VolumeOperation::OpenOwnershipLock, source))
}

fn try_lock_ownership(ownership_lock: &File) -> Result<(), io::Error> {
    perform_io(VolumeOperation::AcquireOwnershipLock, || {
        ownership_lock.try_lock().map_err(|failure| match failure {
            TryLockError::WouldBlock => io::Error::from(io::ErrorKind::WouldBlock),
            TryLockError::Error(source) => source,
        })
    })
}

fn reject_existing_probe_residue(root: &Path) -> Result<(), VolumeFailure> {
    let probe_path = root.join(".positron-volume-probe");
    match perform_io(VolumeOperation::PrepareProbe, || {
        fs::symlink_metadata(&probe_path)
    }) {
        Ok(_) => Err(VolumeFailure::inconsistent_probe(io::Error::new(
            io::ErrorKind::InvalidData,
            "dedicated capability-probe area contains residual state",
        ))),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(VolumeFailure::from_io(
            VolumeOperation::PrepareProbe,
            source,
        )),
    }
}

fn run_capability_probe(root: &Path, root_file: &File) -> Result<(), VolumeFailure> {
    const PROBE_PAYLOAD: &[u8] = b"positron-volume-probe";

    reject_existing_probe_residue(root)?;
    let probe_path = root.join(".positron-volume-probe");
    perform_io(VolumeOperation::PrepareProbe, || {
        fs::create_dir(&probe_path)
    })
    .map_err(|source| VolumeFailure::from_io(VolumeOperation::PrepareProbe, source))?;

    let probe_result = (|| {
        let candidate_path = probe_path.join("candidate");
        let mut candidate = perform_io(VolumeOperation::OpenProbeFile, || {
            OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&candidate_path)
        })
        .map_err(|source| VolumeFailure::probe_failure(VolumeOperation::OpenProbeFile, source))?;
        write_probe_payload(&mut candidate, PROBE_PAYLOAD).map_err(|source| {
            VolumeFailure::probe_failure(VolumeOperation::WriteProbeFile, source)
        })?;
        perform_io(VolumeOperation::SynchronizeProbeFile, || {
            candidate.sync_all()
        })
        .map_err(|source| {
            VolumeFailure::probe_failure(VolumeOperation::SynchronizeProbeFile, source)
        })?;
        drop(candidate);

        let mut reopened = perform_io(VolumeOperation::ReopenProbeFile, || {
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(&candidate_path)
        })
        .map_err(|source| VolumeFailure::probe_failure(VolumeOperation::ReopenProbeFile, source))?;
        let mut observed = [0_u8; PROBE_PAYLOAD.len()];
        perform_io(VolumeOperation::ReadProbeFile, || {
            reopened.read_exact(&mut observed)
        })
        .map_err(|source| VolumeFailure::probe_failure(VolumeOperation::ReadProbeFile, source))?;
        if !values_match(
            VolumeOperation::VerifyProbeContents,
            observed.as_slice(),
            PROBE_PAYLOAD,
        ) {
            return Err(VolumeFailure::probe_failure(
                VolumeOperation::VerifyProbeContents,
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "synchronized probe contents changed after reopen",
                ),
            ));
        }
        perform_io(VolumeOperation::TruncateProbeFile, || reopened.set_len(8)).map_err(
            |source| VolumeFailure::probe_failure(VolumeOperation::TruncateProbeFile, source),
        )?;
        perform_io(VolumeOperation::SynchronizeProbeFile, || {
            reopened.sync_all()
        })
        .map_err(|source| {
            VolumeFailure::probe_failure(VolumeOperation::SynchronizeProbeFile, source)
        })?;
        drop(reopened);

        let mut truncated = perform_io(VolumeOperation::ReopenProbeFile, || {
            File::open(&candidate_path)
        })
        .map_err(|source| VolumeFailure::probe_failure(VolumeOperation::ReopenProbeFile, source))?;
        let expected_prefix = b"positron";
        let mut observed_prefix = [0_u8; 8];
        perform_io(VolumeOperation::ReadProbeFile, || {
            truncated.read_exact(&mut observed_prefix)
        })
        .map_err(|source| VolumeFailure::probe_failure(VolumeOperation::ReadProbeFile, source))?;
        let mut trailing = [0_u8; 1];
        let trailing_count = perform_io(VolumeOperation::ReadProbeFile, || {
            truncated.read(&mut trailing)
        })
        .map_err(|source| VolumeFailure::probe_failure(VolumeOperation::ReadProbeFile, source))?;
        if !values_match(
            VolumeOperation::VerifyProbeTruncation,
            observed_prefix.as_slice(),
            expected_prefix,
        ) || trailing_count != 0
        {
            return Err(VolumeFailure::probe_failure(
                VolumeOperation::VerifyProbeTruncation,
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "probe truncation was not stable after synchronization",
                ),
            ));
        }
        drop(truncated);

        let published_path = probe_path.join("published");
        perform_io(VolumeOperation::RenameProbeFile, || {
            fs::rename(&candidate_path, &published_path)
        })
        .map_err(|source| VolumeFailure::probe_failure(VolumeOperation::RenameProbeFile, source))?;
        let probe_directory = perform_io(VolumeOperation::SynchronizeProbeDirectory, || {
            File::open(&probe_path)
        })
        .map_err(|source| {
            VolumeFailure::probe_failure(VolumeOperation::SynchronizeProbeDirectory, source)
        })?;
        perform_io(VolumeOperation::SynchronizeProbeDirectory, || {
            probe_directory.sync_all()
        })
        .map_err(|source| {
            VolumeFailure::probe_failure(VolumeOperation::SynchronizeProbeDirectory, source)
        })?;
        Ok(())
    })();

    let cleanup_result = cleanup_probe(root, root_file);
    match (probe_result, cleanup_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(failure), Ok(())) => Err(failure),
        (_, Err(source)) => Err(VolumeFailure::inconsistent_cleanup(source)),
    }
}

fn write_probe_payload(file: &mut File, payload: &[u8]) -> Result<(), io::Error> {
    #[cfg(test)]
    if let Some((byte_count, kind)) = take_partial_write_fault() {
        let prefix_length = byte_count.min(payload.len());
        let prefix = payload.get(..prefix_length).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid partial-write prefix")
        })?;
        file.write_all(prefix)?;
        return Err(io::Error::from(kind));
    }
    perform_io(VolumeOperation::WriteProbeFile, || file.write_all(payload))
}

fn cleanup_probe(root: &Path, root_file: &File) -> Result<(), io::Error> {
    let probe_path = root.join(".positron-volume-probe");
    for name in ["candidate", "published"] {
        let artifact_path = probe_path.join(name);
        match perform_io(VolumeOperation::CleanupProbe, || {
            fs::remove_file(&artifact_path)
        }) {
            Ok(()) => {},
            Err(source) if source.kind() == io::ErrorKind::NotFound => {},
            Err(source) => return Err(source),
        }
    }
    perform_io(VolumeOperation::CleanupProbe, || {
        fs::remove_dir(&probe_path)
    })?;
    perform_io(VolumeOperation::CleanupProbe, || root_file.sync_all())
}

#[cfg(test)]
#[derive(Clone, Copy)]
struct OperationFault {
    operation: VolumeOperation,
    remaining_matches: usize,
    effect: OperationFaultEffect,
}

#[cfg(test)]
#[derive(Clone, Copy)]
enum OperationFaultEffect {
    Before(io::ErrorKind),
    PartialWrite {
        byte_count: usize,
        kind: io::ErrorKind,
    },
}

#[cfg(test)]
thread_local! {
    static OPERATION_FAULT: std::cell::Cell<Option<OperationFault>> = const { std::cell::Cell::new(None) };
    static FORCED_MISMATCH: std::cell::Cell<Option<VolumeOperation>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn with_operation_fault<T>(
    operation: VolumeOperation,
    kind: io::ErrorKind,
    action: impl FnOnce() -> T,
) -> T {
    with_operation_fault_at(operation, 1, kind, action)
}

#[cfg(test)]
fn with_operation_fault_at<T>(
    operation: VolumeOperation,
    occurrence: usize,
    kind: io::ErrorKind,
    action: impl FnOnce() -> T,
) -> T {
    OPERATION_FAULT.with(|fault| {
        let previous = fault.replace(Some(OperationFault {
            operation,
            remaining_matches: occurrence.max(1),
            effect: OperationFaultEffect::Before(kind),
        }));
        let result = action();
        fault.set(previous);
        result
    })
}

#[cfg(test)]
fn with_partial_write_fault<T>(
    byte_count: usize,
    kind: io::ErrorKind,
    action: impl FnOnce() -> T,
) -> T {
    OPERATION_FAULT.with(|fault| {
        let previous = fault.replace(Some(OperationFault {
            operation: VolumeOperation::WriteProbeFile,
            remaining_matches: 1,
            effect: OperationFaultEffect::PartialWrite { byte_count, kind },
        }));
        let result = action();
        fault.set(previous);
        result
    })
}

#[cfg(test)]
fn with_forced_mismatch<T>(operation: VolumeOperation, action: impl FnOnce() -> T) -> T {
    FORCED_MISMATCH.with(|fault| {
        let previous = fault.replace(Some(operation));
        let result = action();
        fault.set(previous);
        result
    })
}

fn values_match<T: PartialEq + ?Sized>(_operation: VolumeOperation, left: &T, right: &T) -> bool {
    #[cfg(test)]
    if FORCED_MISMATCH.with(|fault| fault.get() == Some(_operation)) {
        return false;
    }
    left == right
}

#[cfg(test)]
fn take_partial_write_fault() -> Option<(usize, io::ErrorKind)> {
    OPERATION_FAULT.with(|fault| {
        let scheduled = fault.get()?;
        match scheduled {
            OperationFault {
                operation: VolumeOperation::WriteProbeFile,
                remaining_matches: 1,
                effect: OperationFaultEffect::PartialWrite { byte_count, kind },
            } => {
                fault.set(None);
                Some((byte_count, kind))
            },
            _ => None,
        }
    })
}

fn perform_io<T>(
    _operation: VolumeOperation,
    action: impl FnOnce() -> Result<T, io::Error>,
) -> Result<T, io::Error> {
    #[cfg(test)]
    if let Some(kind) = take_operation_fault(_operation) {
        return Err(io::Error::from(kind));
    }
    action()
}

#[cfg(test)]
fn take_operation_fault(operation: VolumeOperation) -> Option<io::ErrorKind> {
    OPERATION_FAULT.with(|fault| {
        let mut scheduled = fault.get()?;
        if scheduled.operation != operation {
            return None;
        }
        if scheduled.remaining_matches > 1 {
            scheduled.remaining_matches -= 1;
            fault.set(Some(scheduled));
            return None;
        }
        match scheduled.effect {
            OperationFaultEffect::Before(kind) => {
                fault.set(None);
                Some(kind)
            },
            OperationFaultEffect::PartialWrite { .. } => None,
        }
    })
}

#[cfg(unix)]
fn verify_ownership_artifact(
    path: &Path,
    file: &File,
    root_id: VolumeRootIdentity,
) -> Result<(), VolumeFailure> {
    let path_metadata = perform_io(VolumeOperation::OpenOwnershipLock, || {
        fs::symlink_metadata(path)
    })
    .map_err(|source| VolumeFailure::from_io(VolumeOperation::OpenOwnershipLock, source))?;
    let handle_metadata = perform_io(VolumeOperation::OpenOwnershipLock, || file.metadata())
        .map_err(|source| VolumeFailure::from_io(VolumeOperation::OpenOwnershipLock, source))?;
    let path_identity = root_identity(&path_metadata)?;
    let handle_identity = root_identity(&handle_metadata)?;
    let safe = path_metadata.file_type().is_file()
        && handle_metadata.file_type().is_file()
        && path_metadata.nlink() == 1
        && handle_metadata.nlink() == 1
        && path_identity == handle_identity
        && handle_identity.device == root_id.device;
    if safe {
        Ok(())
    } else {
        Err(VolumeFailure::from_io(
            VolumeOperation::OpenOwnershipLock,
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "ownership artifact is not a safe single-link volume file",
            ),
        ))
    }
}

#[cfg(not(unix))]
fn verify_ownership_artifact(
    _path: &Path,
    _file: &File,
    _root_identity: VolumeRootIdentity,
) -> Result<(), VolumeFailure> {
    Err(VolumeFailure::from_io(
        VolumeOperation::OpenOwnershipLock,
        io::Error::new(
            io::ErrorKind::Unsupported,
            "ownership artifacts require a supported Unix filesystem",
        ),
    ))
}

#[cfg(unix)]
fn root_identity(metadata: &fs::Metadata) -> Result<VolumeRootIdentity, VolumeFailure> {
    Ok(VolumeRootIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(not(unix))]
fn root_identity(_metadata: &fs::Metadata) -> Result<VolumeRootIdentity, VolumeFailure> {
    Err(VolumeFailure::from_io(
        VolumeOperation::ClassifyRoot,
        io::Error::new(
            io::ErrorKind::Unsupported,
            "primary data volumes require a supported Unix filesystem",
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Result<Self, io::Error> {
            let sequence = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "positron-primary-volume-unit-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path)?;
            Ok(Self(path))
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            if let Err(error) = fs::remove_dir_all(&self.0) {
                eprintln!("failed to remove unit-test root: {error}");
            }
        }
    }

    #[test]
    fn probe_write_permission_failure_is_typed_and_cleaned() -> Result<(), Box<dyn Error>> {
        let root = TestRoot::new()?;

        let failure = with_operation_fault(
            VolumeOperation::WriteProbeFile,
            io::ErrorKind::PermissionDenied,
            || PrimaryDataVolume::acquire(&root.0),
        )
        .expect_err("injected probe write must fail");

        assert_eq!(failure.code(), VolumeFailureCode::PermissionDenied);
        assert_eq!(failure.operation(), VolumeOperation::WriteProbeFile);
        assert_eq!(
            failure.completion_state(),
            VolumeCompletionState::ProbeCleaned
        );
        assert!(!root.0.join(".positron-volume-probe").exists());
        Ok(())
    }

    #[test]
    fn probe_file_sync_exhaustion_is_typed_and_cleaned() -> Result<(), Box<dyn Error>> {
        let root = TestRoot::new()?;

        let failure = with_operation_fault(
            VolumeOperation::SynchronizeProbeFile,
            io::ErrorKind::StorageFull,
            || PrimaryDataVolume::acquire(&root.0),
        )
        .expect_err("injected probe sync must fail");

        assert_eq!(failure.code(), VolumeFailureCode::Exhausted);
        assert_eq!(failure.operation(), VolumeOperation::SynchronizeProbeFile);
        assert_eq!(
            failure.completion_state(),
            VolumeCompletionState::ProbeCleaned
        );
        assert!(!root.0.join(".positron-volume-probe").exists());
        Ok(())
    }

    #[test]
    fn probe_reopen_short_read_is_inconsistent_and_cleaned() -> Result<(), Box<dyn Error>> {
        let root = TestRoot::new()?;

        let failure = with_operation_fault(
            VolumeOperation::ReadProbeFile,
            io::ErrorKind::UnexpectedEof,
            || PrimaryDataVolume::acquire(&root.0),
        )
        .expect_err("injected short read must fail");

        assert_eq!(failure.code(), VolumeFailureCode::Inconsistent);
        assert_eq!(failure.operation(), VolumeOperation::ReadProbeFile);
        assert_eq!(
            failure.completion_state(),
            VolumeCompletionState::ProbeCleaned
        );
        assert!(!root.0.join(".positron-volume-probe").exists());
        Ok(())
    }

    #[test]
    fn probe_truncation_read_only_failure_is_typed_and_cleaned() -> Result<(), Box<dyn Error>> {
        let root = TestRoot::new()?;

        let failure = with_operation_fault(
            VolumeOperation::TruncateProbeFile,
            io::ErrorKind::ReadOnlyFilesystem,
            || PrimaryDataVolume::acquire(&root.0),
        )
        .expect_err("injected read-only truncation must fail");

        assert_eq!(failure.code(), VolumeFailureCode::ReadOnly);
        assert_eq!(failure.operation(), VolumeOperation::TruncateProbeFile);
        assert_eq!(
            failure.completion_state(),
            VolumeCompletionState::ProbeCleaned
        );
        assert!(!root.0.join(".positron-volume-probe").exists());
        Ok(())
    }

    #[test]
    fn probe_rename_unsupported_failure_is_typed_and_cleaned() -> Result<(), Box<dyn Error>> {
        let root = TestRoot::new()?;

        let failure = with_operation_fault(
            VolumeOperation::RenameProbeFile,
            io::ErrorKind::Unsupported,
            || PrimaryDataVolume::acquire(&root.0),
        )
        .expect_err("injected unsupported rename must fail");

        assert_eq!(failure.code(), VolumeFailureCode::Unsupported);
        assert_eq!(failure.operation(), VolumeOperation::RenameProbeFile);
        assert_eq!(
            failure.completion_state(),
            VolumeCompletionState::ProbeCleaned
        );
        assert!(!root.0.join(".positron-volume-probe").exists());
        Ok(())
    }

    #[test]
    fn probe_directory_sync_interruption_is_transient_and_cleaned() -> Result<(), Box<dyn Error>> {
        let root = TestRoot::new()?;

        let failure = with_operation_fault(
            VolumeOperation::SynchronizeProbeDirectory,
            io::ErrorKind::Interrupted,
            || PrimaryDataVolume::acquire(&root.0),
        )
        .expect_err("injected directory sync interruption must fail");

        assert_eq!(failure.code(), VolumeFailureCode::Transient);
        assert_eq!(failure.retry_class(), VolumeRetryClass::AfterBackoff);
        assert_eq!(
            failure.operation(),
            VolumeOperation::SynchronizeProbeDirectory
        );
        assert_eq!(
            failure.completion_state(),
            VolumeCompletionState::ProbeCleaned
        );
        assert!(!root.0.join(".positron-volume-probe").exists());
        Ok(())
    }

    #[test]
    fn partial_probe_write_is_reported_and_cleaned() -> Result<(), Box<dyn Error>> {
        let root = TestRoot::new()?;

        let failure = with_partial_write_fault(5, io::ErrorKind::StorageFull, || {
            PrimaryDataVolume::acquire(&root.0)
        })
        .expect_err("partial probe write must fail");

        assert_eq!(failure.code(), VolumeFailureCode::Exhausted);
        assert_eq!(failure.operation(), VolumeOperation::WriteProbeFile);
        assert_eq!(
            failure.completion_state(),
            VolumeCompletionState::ProbeCleaned
        );
        assert!(!root.0.join(".positron-volume-probe").exists());
        Ok(())
    }

    #[test]
    fn post_truncation_reopen_failure_is_typed_and_cleaned() -> Result<(), Box<dyn Error>> {
        let root = TestRoot::new()?;

        let failure = with_operation_fault_at(
            VolumeOperation::ReopenProbeFile,
            2,
            io::ErrorKind::Interrupted,
            || PrimaryDataVolume::acquire(&root.0),
        )
        .expect_err("second probe reopen must be faultable");

        assert_eq!(failure.code(), VolumeFailureCode::Transient);
        assert_eq!(failure.operation(), VolumeOperation::ReopenProbeFile);
        assert_eq!(
            failure.completion_state(),
            VolumeCompletionState::ProbeCleaned
        );
        assert!(!root.0.join(".positron-volume-probe").exists());
        Ok(())
    }

    #[test]
    fn ambiguous_probe_cleanup_is_preserved_and_fails_closed() -> Result<(), Box<dyn Error>> {
        let root = TestRoot::new()?;

        let failure = with_operation_fault_at(
            VolumeOperation::CleanupProbe,
            2,
            io::ErrorKind::PermissionDenied,
            || PrimaryDataVolume::acquire(&root.0),
        )
        .expect_err("injected cleanup failure must fail closed");

        assert_eq!(failure.code(), VolumeFailureCode::Inconsistent);
        assert_eq!(failure.retry_class(), VolumeRetryClass::Never);
        assert_eq!(failure.operation(), VolumeOperation::CleanupProbe);
        assert_eq!(
            failure.completion_state(),
            VolumeCompletionState::ProbeCleanupIncomplete
        );
        assert!(root.0.join(".positron-volume-probe/published").exists());
        Ok(())
    }

    #[test]
    fn root_acquisition_faults_remain_typed_and_precede_the_probe() -> Result<(), Box<dyn Error>> {
        let cases = [
            (
                VolumeOperation::ClassifyRoot,
                1,
                io::ErrorKind::PermissionDenied,
                VolumeFailureCode::PermissionDenied,
            ),
            (
                VolumeOperation::ClassifyRoot,
                2,
                io::ErrorKind::TimedOut,
                VolumeFailureCode::Transient,
            ),
            (
                VolumeOperation::ClassifyRoot,
                3,
                io::ErrorKind::InvalidData,
                VolumeFailureCode::Inconsistent,
            ),
            (
                VolumeOperation::OpenOwnershipLock,
                1,
                io::ErrorKind::ReadOnlyFilesystem,
                VolumeFailureCode::ReadOnly,
            ),
            (
                VolumeOperation::OpenOwnershipLock,
                2,
                io::ErrorKind::PermissionDenied,
                VolumeFailureCode::PermissionDenied,
            ),
            (
                VolumeOperation::OpenOwnershipLock,
                3,
                io::ErrorKind::InvalidData,
                VolumeFailureCode::Inconsistent,
            ),
            (
                VolumeOperation::AcquireOwnershipLock,
                1,
                io::ErrorKind::Unsupported,
                VolumeFailureCode::Unsupported,
            ),
        ];

        for (operation, occurrence, kind, expected_code) in cases {
            let root = TestRoot::new()?;
            let failure = with_operation_fault_at(operation, occurrence, kind, || {
                PrimaryDataVolume::acquire(&root.0)
            })
            .expect_err("scheduled root acquisition fault must fail");

            assert_eq!(failure.code(), expected_code);
            assert_eq!(failure.operation(), operation);
            assert_eq!(failure.completion_state(), VolumeCompletionState::Rejected);
            assert!(!root.0.join(".positron-volume-probe").exists());
        }
        Ok(())
    }

    #[test]
    fn root_identity_change_fails_before_volume_mutation() -> Result<(), Box<dyn Error>> {
        let root = TestRoot::new()?;

        let failure = with_forced_mismatch(VolumeOperation::VerifyRootIdentity, || {
            PrimaryDataVolume::acquire(&root.0)
        })
        .expect_err("changed root identity must fail");

        assert_eq!(failure.code(), VolumeFailureCode::Inconsistent);
        assert_eq!(failure.operation(), VolumeOperation::VerifyRootIdentity);
        assert_eq!(failure.completion_state(), VolumeCompletionState::Rejected);
        assert!(fs::read_dir(&root.0)?.next().is_none());
        Ok(())
    }

    #[test]
    fn probe_content_mismatch_is_inconsistent_and_cleaned() -> Result<(), Box<dyn Error>> {
        let root = TestRoot::new()?;

        let failure = with_forced_mismatch(VolumeOperation::VerifyProbeContents, || {
            PrimaryDataVolume::acquire(&root.0)
        })
        .expect_err("changed reopened contents must fail");

        assert_eq!(failure.code(), VolumeFailureCode::Inconsistent);
        assert_eq!(failure.operation(), VolumeOperation::VerifyProbeContents);
        assert_eq!(
            failure.completion_state(),
            VolumeCompletionState::ProbeCleaned
        );
        assert!(!root.0.join(".positron-volume-probe").exists());
        Ok(())
    }

    #[test]
    fn unstable_probe_truncation_is_inconsistent_and_cleaned() -> Result<(), Box<dyn Error>> {
        let root = TestRoot::new()?;

        let failure = with_forced_mismatch(VolumeOperation::VerifyProbeTruncation, || {
            PrimaryDataVolume::acquire(&root.0)
        })
        .expect_err("unstable truncation must fail");

        assert_eq!(failure.code(), VolumeFailureCode::Inconsistent);
        assert_eq!(failure.operation(), VolumeOperation::VerifyProbeTruncation);
        assert_eq!(
            failure.completion_state(),
            VolumeCompletionState::ProbeCleaned
        );
        assert!(!root.0.join(".positron-volume-probe").exists());
        Ok(())
    }

    #[test]
    fn remaining_probe_boundaries_are_faultable_through_acquisition() -> Result<(), Box<dyn Error>>
    {
        let cases = [
            (VolumeOperation::PrepareProbe, 1),
            (VolumeOperation::PrepareProbe, 2),
            (VolumeOperation::OpenProbeFile, 1),
            (VolumeOperation::SynchronizeProbeFile, 2),
            (VolumeOperation::ReadProbeFile, 2),
            (VolumeOperation::ReadProbeFile, 3),
            (VolumeOperation::SynchronizeProbeDirectory, 2),
        ];

        for (operation, occurrence) in cases {
            let root = TestRoot::new()?;
            let failure = with_operation_fault_at(
                operation,
                occurrence,
                io::ErrorKind::PermissionDenied,
                || PrimaryDataVolume::acquire(&root.0),
            )
            .expect_err("scheduled probe fault must fail");

            assert_eq!(failure.code(), VolumeFailureCode::PermissionDenied);
            assert_eq!(failure.operation(), operation);
            assert!(!root.0.join(".positron-volume-probe").exists());
        }
        Ok(())
    }

    #[test]
    fn every_cleanup_boundary_fails_closed_with_residue_truth() -> Result<(), Box<dyn Error>> {
        for occurrence in [1, 3, 4] {
            let root = TestRoot::new()?;
            let failure = with_operation_fault_at(
                VolumeOperation::CleanupProbe,
                occurrence,
                io::ErrorKind::PermissionDenied,
                || PrimaryDataVolume::acquire(&root.0),
            )
            .expect_err("scheduled cleanup fault must fail closed");

            assert_eq!(failure.code(), VolumeFailureCode::Inconsistent);
            assert_eq!(failure.operation(), VolumeOperation::CleanupProbe);
            assert_eq!(
                failure.completion_state(),
                VolumeCompletionState::ProbeCleanupIncomplete
            );
            assert_eq!(
                root.0.join(".positron-volume-probe").exists(),
                occurrence != 4
            );
        }
        Ok(())
    }

    #[test]
    fn typed_failure_retains_its_operating_system_source() -> Result<(), Box<dyn Error>> {
        let root = TestRoot::new()?;
        let missing = root.0.join("missing");
        let failure = PrimaryDataVolume::acquire(&missing).expect_err("missing root must fail");

        let source = Error::source(&failure).ok_or("volume failure must retain a source")?;

        assert!(!source.to_string().is_empty());
        Ok(())
    }
}
