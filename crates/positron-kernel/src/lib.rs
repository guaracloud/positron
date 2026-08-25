//! Positron's shared Storage Kernel boundary.
//!
//! This slice owns the concrete Release 1 Primary Data Volume and authenticated
//! encrypted-frame protection. Authoritative frame context, object keys, and
//! frame protection remain private to the Storage Kernel. The Active Segment
//! Ledger owns durable frame-sequence allocation and exposes only opaque block,
//! receipt, and snapshot capabilities.
//!
//! Provider bootstrap and broader key lifecycle remain outside this crate's
//! implemented surface.
//!
//! Frame authority is deliberately unavailable to dependent crates. Each
//! promised private name is checked independently so one inaccessible import
//! cannot hide an accidentally exported sibling:
//!
//! ```compile_fail
//! use positron_kernel::DataProtection;
//! ```
//! ```compile_fail
//! use positron_kernel::ObjectDataKey;
//! ```
//! ```compile_fail
//! use positron_kernel::SecretKeyInput;
//! ```
//! ```compile_fail
//! use positron_kernel::FrameObjectContext;
//! ```
//! ```compile_fail
//! use positron_kernel::FrameContext;
//! ```
//! ```compile_fail
//! use positron_kernel::FrameSequence;
//! ```
//! ```compile_fail
//! use positron_kernel::FrameLimits;
//! ```
//! ```compile_fail
//! use positron_kernel::EncryptedFrame;
//! ```
//! ```compile_fail
//! use positron_kernel::CryptoBackend;
//! ```
//! ```compile_fail
//! use positron_kernel::VerifiedFrame;
//! ```
//! ```compile_fail
//! use positron_kernel::FrameObjectId;
//! ```
//! ```compile_fail
//! use positron_kernel::KeyEpoch;
//! ```
//! ```compile_fail
//! use positron_kernel::SegmentFramePurpose;
//! ```
//! ```compile_fail
//! use positron_kernel::SystemObjectKind;
//! ```
//! ```compile_fail
//! use positron_kernel::FrameFailure;
//! ```
//! ```compile_fail
//! use positron_kernel::FrameFailureCode;
//! ```

#![forbid(unsafe_code)]

#[cfg(test)]
extern crate self as positron_kernel;

mod active_segment_ledger;
mod catalog;
#[allow(dead_code)]
mod data_protection;
mod instance_bootstrap_storage;
mod lifecycle_clock;
mod resource_governor;

pub use catalog::{
    AuditIntent, Catalog, CatalogCommit, CatalogFailure, CatalogFailureCode, CatalogGenerationId,
    CatalogObject, CatalogObjectId, CatalogProposal, CatalogRotation, CatalogSecret,
    CatalogSnapshot, CatalogWrappingKey, FormatEpoch, GovernanceAuditRecord, InstanceId,
    TransactionId,
};
#[cfg(feature = "test-support")]
pub use catalog::{
    CatalogPublicationFault, with_catalog_publication_fault_after,
    with_catalog_publication_hook_after,
};
#[cfg(feature = "test-support")]
pub use catalog::{GovernanceFixtureObject, GovernanceFixtureTarget};

#[cfg(feature = "test-support")]
pub use active_segment_ledger::publish_snapshot_lease_marker_for_test;
pub use active_segment_ledger::{
    ActiveSegmentLedger, AppendCancellation, CommitReceipt, CommittedBlock, LedgerCompletionState,
    LedgerFailure, LedgerFailureCode, LedgerSnapshot, MAX_SNAPSHOT_LEASE_TTL_SECONDS,
    PreparedStoreBlock, SealedSegment, SegmentId, SegmentProtectionKey, SegmentScope,
    SnapshotLeaseAttempt, SnapshotLeaseGrant, SnapshotLeaseId, SnapshotLeaseUsage,
    StoreBlockIdentity,
};

pub use data_protection::{
    BootstrapIntegrityIdentity, BootstrapKeyCustody, BootstrapKeyFailure, BootstrapKeyIdentity,
    BootstrapObjectPurpose, ControlTokenAuthentication, ControlTokenFailure, ControlTokenProtector,
    QueryResultDigest,
};

pub use instance_bootstrap_storage::{
    BootstrapArtifact, BootstrapArtifactAccess, BootstrapEntry, BootstrapLayout,
    BootstrapStorageFailure, InstanceBootstrapStorage,
};

pub use lifecycle_clock::{
    FixedLifecycleClockSource, IngestTime, LifecycleClock, LifecycleClockFailure,
    LifecycleClockSource, SystemLifecycleClockSource,
};

pub use resource_governor::{
    AdmissionCompletionState, AdmissionFailure, AdmissionFailureCode, AdmissionRetry,
    CAPACITY_OBSERVATION_TRANSIENT_MEMORY_BYTES, CPU_WORK_UNITS_PER_LOGICAL_CPU,
    CapacityObservationFailure, CapacityObservationSource, DetectedCapacity, DiskObservation,
    DiskPressureState, DiskPressureThresholds, EstablishmentFailure, ExistingCapacityDisposition,
    GovernorFailure, GovernorLifecycle, GovernorPolicy, InventoryCardinalityLimits, LimitingScope,
    MAX_OUTSTANDING_RESERVATIONS, MAX_TENANT_QUOTAS, ObservedResourceEnvironment, OperatorLimits,
    OrdinaryPool, OrdinaryPoolPolicy, RESOURCE_DIMENSION_COUNT, RecoveryAuthority,
    RecoveryInterruption, RecoveryPoolCapacities, RecoveryReserve, RecoveryScope,
    RecoveryWorkClaim, RecoveryWorkKind, RegisteredResourceBounds, ReleaseOutcome, ResizeFailure,
    ResizeFailureCode, ResizeOutcome, ResourceAmounts, ResourceDimension, ResourceGovernor,
    ResourceGovernorConfiguration, ResourceInventory, ResourceReservation, ResourceSnapshot,
    ShutdownReconciliation, StorageKernelResourceAuthority, TenantQuota,
    TransferredResourceReservation, WorkClaim, WorkClass, WorkKind,
};

#[cfg(fuzzing)]
#[doc(hidden)]
pub use resource_governor::fuzz_linux_capacity_parsers;

#[cfg(fuzzing)]
#[doc(hidden)]
pub use data_protection::fuzz_authenticated_frame;

#[cfg(fuzzing)]
#[doc(hidden)]
pub use data_protection::fuzz_local_root_key_file;

#[cfg(fuzzing)]
#[doc(hidden)]
pub use data_protection::fuzz_control_token_protector;

#[cfg(fuzzing)]
#[doc(hidden)]
pub use catalog::fuzz_catalog_stateful;

#[cfg(fuzzing)]
#[doc(hidden)]
pub use active_segment_ledger::fuzz_active_segment_stateful;

#[cfg(fuzzing)]
#[doc(hidden)]
pub use active_segment_ledger::fuzz_snapshot_lease_record;

use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::{self, File, TryLockError};
use std::io::{self, Read, Write};
use std::path::Path;

use rustix::fs::{self as unix_fs, AtFlags, Mode, OFlags};

#[cfg(test)]
use std::path::PathBuf;

#[cfg(test)]
use std::cell::RefCell;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

/// The concrete Release 1 Primary Data Volume entry point.
///
/// Construction is intentionally unavailable: callers receive ownership only
/// through [`PrimaryDataVolume::acquire`].
pub enum PrimaryDataVolume {}

const PRIMARY_DATA_VOLUME_PROBE_PAYLOAD_BYTES: usize = 21;
const PRIMARY_DATA_VOLUME_PROBE_PAYLOAD: &[u8; PRIMARY_DATA_VOLUME_PROBE_PAYLOAD_BYTES] =
    b"positron-volume-probe";

/// Fixed resource bound of the synchronous pre-governor volume bootstrap.
///
/// Primary Data Volume qualification precedes Resource Governor establishment,
/// so it cannot consume a governor reservation. The acquisition algorithm is
/// instead structurally bounded: it retains the root and ownership handles,
/// opens at most one probe directory and one probe file at a time, performs no
/// concurrent I/O, and writes only the fixed probe payload reported here. This
/// value describes that bootstrap algorithm; it is not an admission authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrimaryDataVolumeBootstrapBounds {
    maximum_open_file_descriptors: u8,
    maximum_concurrent_io_operations: u8,
    maximum_probe_payload_bytes: usize,
}

impl PrimaryDataVolumeBootstrapBounds {
    /// Maximum volume-owned file descriptors open at the same time.
    #[must_use]
    pub const fn maximum_open_file_descriptors(self) -> u8 {
        self.maximum_open_file_descriptors
    }

    /// Maximum bootstrap I/O operations executing at the same time.
    #[must_use]
    pub const fn maximum_concurrent_io_operations(self) -> u8 {
        self.maximum_concurrent_io_operations
    }

    /// Exact byte length of the only payload written by the capability probe.
    #[must_use]
    pub const fn maximum_probe_payload_bytes(self) -> usize {
        self.maximum_probe_payload_bytes
    }
}

const PRIMARY_DATA_VOLUME_BOOTSTRAP_BOUNDS: PrimaryDataVolumeBootstrapBounds =
    PrimaryDataVolumeBootstrapBounds {
        maximum_open_file_descriptors: 4,
        maximum_concurrent_io_operations: 1,
        maximum_probe_payload_bytes: PRIMARY_DATA_VOLUME_PROBE_PAYLOAD_BYTES,
    };

/// A process-lifetime ownership claim over one Primary Data Volume.
pub struct OwnedPrimaryDataVolume {
    _root: File,
    _ownership_lock: File,
    _root_identity: VolumeRootIdentity,
    qualification: MountQualification,
    filesystem: VolumeFileSystem,
    mount_identity: VolumeMountIdentity,
}

impl std::fmt::Debug for OwnedPrimaryDataVolume {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("OwnedPrimaryDataVolume { <redacted> }")
    }
}

impl OwnedPrimaryDataVolume {
    /// Returns the trusted deployment provenance accepted at acquisition.
    #[must_use]
    pub const fn qualification(&self) -> MountQualification {
        self.qualification
    }

    /// Returns the stable opaque filesystem identity captured at acquisition.
    #[must_use]
    pub const fn root_identity(&self) -> VolumeRootIdentity {
        self._root_identity
    }

    /// Returns the closed local filesystem qualification used at acquisition.
    #[must_use]
    pub const fn filesystem(&self) -> VolumeFileSystem {
        self.filesystem
    }

    /// Returns the opaque qualified mount identity bound at acquisition.
    #[must_use]
    pub const fn mount_identity(&self) -> VolumeMountIdentity {
        self.mount_identity
    }
}

/// Trusted deployment provenance for a Primary Data Volume mount.
///
/// This value must be supplied by trusted application composition. `LocalHost`
/// is valid only for a native local-host mount and must never be used to
/// relabel PVC, network, or other externally provided storage. Release 1 has
/// no accepted external or PVC qualification-matrix entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MountQualification {
    /// A native local-host mount selected by trusted composition.
    LocalHost,
    /// External or PVC storage without an accepted Release 1 matrix entry.
    UnverifiedExternalOrPvc,
}

/// A kernel-identified local filesystem qualified for the Release 1 contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VolumeFileSystem {
    /// Apple File System.
    Apfs,
    /// Linux ext2, ext3, or ext4.
    Ext,
    /// XFS.
    Xfs,
    /// Btrfs.
    Btrfs,
    /// ZFS.
    Zfs,
}

/// The opaque identity of a qualified local filesystem mount.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VolumeMountIdentity {
    device: u64,
    filesystem: VolumeFileSystem,
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
    /// Acquisition stopped before creating the dedicated probe directory.
    RejectedBeforeProbeMutation,
    /// Probe artifacts are absent and their removal was synchronized to the root.
    ProbeCleanupSynchronized,
    /// Probe artifacts are physically absent, but the final root synchronization failed.
    ProbeCleanupDurabilityUncertain,
    /// Probe residue is present or cannot be safely distinguished from unknown state.
    ProbeResiduePresent,
}

/// The bounded operation that produced a Primary Data Volume failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VolumeOperation {
    /// Classifying the configured root before acquisition.
    ClassifyRoot,
    /// Binding the root handle to a qualified local filesystem mount.
    ClassifyMount,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VolumeEvent {
    ClassifyRootPath,
    OpenRootDirectory,
    ReadRootHandleIdentity,
    ClassifyMount,
    InspectProbeResidue,
    BeforeOwnershipArtifact,
    CreateOwnershipArtifact,
    OpenOwnershipArtifact,
    AcquireOwnership,
    VerifyOwnershipAfterLock,
    CreateProbeDirectory,
    OpenProbeDirectory,
    CreateProbeCandidate,
    WriteProbePayload,
    SynchronizeProbePayload,
    ReopenProbePayload,
    ReadProbePayload,
    TruncateProbePayload,
    SynchronizeProbeTruncation,
    ReopenTruncatedProbe,
    ReadTruncatedProbe,
    RenameProbeCandidate,
    SynchronizeProbeDirectory,
    CleanupProbeCandidate,
    CleanupProbePublished,
    CleanupProbeDirectory,
    SynchronizeRootAfterCleanup,
}

#[cfg(test)]
thread_local! {
    static EVENT_ACTION: RefCell<Option<ScheduledEventAction>> = RefCell::new(None);
    static EVENT_FAULT: std::cell::Cell<Option<(VolumeEvent, io::ErrorKind)>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
type ScheduledEventAction = (VolumeEvent, Box<dyn FnOnce()>);

#[cfg(test)]
fn with_event_action<T>(
    event: VolumeEvent,
    event_action: impl FnOnce() + 'static,
    action: impl FnOnce() -> T,
) -> T {
    EVENT_ACTION.with(|scheduled| {
        let previous = scheduled.replace(Some((event, Box::new(event_action))));
        let result = action();
        scheduled.replace(previous);
        result
    })
}

#[cfg(test)]
fn with_event_fault<T>(event: VolumeEvent, kind: io::ErrorKind, action: impl FnOnce() -> T) -> T {
    EVENT_FAULT.with(|scheduled| {
        let previous = scheduled.replace(Some((event, kind)));
        let result = action();
        scheduled.set(previous);
        result
    })
}

fn emit_event(_event: VolumeEvent) -> Result<(), io::Error> {
    #[cfg(test)]
    EVENT_ACTION.with(|scheduled| {
        let should_run = scheduled
            .borrow()
            .as_ref()
            .is_some_and(|(event, _)| *event == _event);
        if should_run && let Some((_, action)) = scheduled.borrow_mut().take() {
            action();
        }
    });
    #[cfg(test)]
    if let Some((event, kind)) = EVENT_FAULT.with(|scheduled| scheduled.get())
        && event == _event
    {
        EVENT_FAULT.with(|scheduled| scheduled.set(None));
        return Err(io::Error::from(kind));
    }
    Ok(())
}

fn acquisition_event(event: VolumeEvent, operation: VolumeOperation) -> Result<(), VolumeFailure> {
    emit_event(event).map_err(|source| VolumeFailure::from_io(operation, source))
}

fn probe_event(event: VolumeEvent, operation: VolumeOperation) -> Result<(), VolumeFailure> {
    emit_event(event).map_err(|source| VolumeFailure::probe_failure(operation, source))
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
            completion_state: VolumeCompletionState::RejectedBeforeProbeMutation,
            operation,
            source,
        }
    }

    fn inconsistent_probe(source: io::Error) -> Self {
        Self {
            code: VolumeFailureCode::Inconsistent,
            retry_class: VolumeRetryClass::Never,
            completion_state: VolumeCompletionState::ProbeResiduePresent,
            operation: VolumeOperation::PrepareProbe,
            source,
        }
    }

    fn probe_failure(operation: VolumeOperation, source: io::Error) -> Self {
        let mut failure = Self::from_io(operation, source);
        failure.completion_state = VolumeCompletionState::ProbeCleanupSynchronized;
        failure
    }

    fn inconsistent_cleanup(source: io::Error, artifacts_absent: bool) -> Self {
        Self {
            code: VolumeFailureCode::Inconsistent,
            retry_class: VolumeRetryClass::Never,
            completion_state: if artifacts_absent {
                VolumeCompletionState::ProbeCleanupDurabilityUncertain
            } else {
                VolumeCompletionState::ProbeResiduePresent
            },
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
    /// Returns the immutable resource bound for pre-governor acquisition.
    #[must_use]
    pub const fn bootstrap_resource_bounds() -> PrimaryDataVolumeBootstrapBounds {
        PRIMARY_DATA_VOLUME_BOOTSTRAP_BOUNDS
    }

    /// Acquires an existing filesystem directory as the Primary Data Volume.
    ///
    /// `qualification` is trusted deployment provenance, not a filesystem
    /// inference. After accepting that provenance, the kernel performs its
    /// filesystem consistency check before creating ownership or probe
    /// artifacts.
    ///
    /// This operation never creates a missing root and refuses a root reached
    /// through a symbolic link.
    pub fn acquire(
        root: &Path,
        qualification: MountQualification,
    ) -> Result<OwnedPrimaryDataVolume, VolumeFailure> {
        Self::acquire_with_identity(root, qualification, None)
    }

    pub(crate) fn acquire_bound(
        root: &Path,
        qualification: MountQualification,
        expected: VolumeRootIdentity,
    ) -> Result<OwnedPrimaryDataVolume, VolumeFailure> {
        Self::acquire_with_identity(root, qualification, Some(expected))
    }

    fn acquire_with_identity(
        root: &Path,
        qualification: MountQualification,
        expected: Option<VolumeRootIdentity>,
    ) -> Result<OwnedPrimaryDataVolume, VolumeFailure> {
        if qualification == MountQualification::UnverifiedExternalOrPvc {
            return Err(VolumeFailure::from_io(
                VolumeOperation::ClassifyMount,
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "external or PVC mount has no Release 1 qualification-matrix entry",
                ),
            ));
        }
        acquisition_event(VolumeEvent::ClassifyRootPath, VolumeOperation::ClassifyRoot)?;
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

        acquisition_event(
            VolumeEvent::OpenRootDirectory,
            VolumeOperation::ClassifyRoot,
        )?;
        let root_file = perform_io(VolumeOperation::ClassifyRoot, || File::open(root))
            .map_err(|source| VolumeFailure::from_io(VolumeOperation::ClassifyRoot, source))?;
        acquisition_event(
            VolumeEvent::ReadRootHandleIdentity,
            VolumeOperation::ClassifyRoot,
        )?;
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
        if expected.is_some_and(|expected| expected != handle_identity) {
            return Err(VolumeFailure::from_io(
                VolumeOperation::VerifyRootIdentity,
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "primary data volume root differs from its bound identity",
                ),
            ));
        }

        let filesystem = qualify_local_mount(&root_file)?;
        let mount_identity = VolumeMountIdentity {
            device: handle_identity.device,
            filesystem,
        };

        acquisition_event(
            VolumeEvent::BeforeOwnershipArtifact,
            VolumeOperation::VerifyRootIdentity,
        )?;
        let current_metadata = fs::symlink_metadata(root).map_err(|source| {
            VolumeFailure::from_io(VolumeOperation::VerifyRootIdentity, source)
        })?;
        if root_identity(&current_metadata)? != handle_identity {
            return Err(VolumeFailure::from_io(
                VolumeOperation::VerifyRootIdentity,
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "primary data volume root changed before ownership acquisition",
                ),
            ));
        }
        reject_existing_probe_residue(&root_file)?;
        let ownership_lock = open_ownership_artifact(&root_file)?;
        verify_ownership_artifact(&root_file, &ownership_lock, handle_identity)?;
        try_lock_ownership(&ownership_lock).map_err(|source| {
            VolumeFailure::from_io(VolumeOperation::AcquireOwnershipLock, source)
        })?;
        acquisition_event(
            VolumeEvent::VerifyOwnershipAfterLock,
            VolumeOperation::OpenOwnershipLock,
        )?;
        verify_ownership_artifact(&root_file, &ownership_lock, handle_identity)?;
        run_capability_probe(&root_file)?;
        verify_ownership_artifact(&root_file, &ownership_lock, handle_identity)?;
        let final_metadata = fs::symlink_metadata(root).map_err(|source| {
            let mut failure = VolumeFailure::from_io(VolumeOperation::VerifyRootIdentity, source);
            failure.completion_state = VolumeCompletionState::ProbeCleanupSynchronized;
            failure
        })?;
        if root_identity(&final_metadata)? != handle_identity {
            let mut failure = VolumeFailure::from_io(
                VolumeOperation::VerifyRootIdentity,
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "primary data volume root changed during capability verification",
                ),
            );
            failure.completion_state = VolumeCompletionState::ProbeCleanupSynchronized;
            return Err(failure);
        }

        Ok(OwnedPrimaryDataVolume {
            _root: root_file,
            _ownership_lock: ownership_lock,
            _root_identity: handle_identity,
            qualification,
            filesystem,
            mount_identity,
        })
    }
}

fn open_ownership_artifact(root: &File) -> Result<File, VolumeFailure> {
    const NAME: &str = ".positron-volume.lock";
    let existing_flags = OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    acquisition_event(
        VolumeEvent::OpenOwnershipArtifact,
        VolumeOperation::OpenOwnershipLock,
    )?;
    match unix_fs::openat(root, NAME, existing_flags, Mode::empty()) {
        Ok(fd) => Ok(File::from(fd)),
        Err(rustix::io::Errno::NOENT) => {
            acquisition_event(
                VolumeEvent::CreateOwnershipArtifact,
                VolumeOperation::OpenOwnershipLock,
            )?;
            match unix_fs::openat(
                root,
                NAME,
                existing_flags | OFlags::CREATE | OFlags::EXCL,
                Mode::RUSR | Mode::WUSR,
            ) {
                Ok(fd) => Ok(File::from(fd)),
                Err(rustix::io::Errno::EXIST) => {
                    unix_fs::openat(root, NAME, existing_flags, Mode::empty())
                        .map(File::from)
                        .map_err(io::Error::from)
                        .map_err(|source| {
                            VolumeFailure::from_io(VolumeOperation::OpenOwnershipLock, source)
                        })
                },
                Err(source) => Err(VolumeFailure::from_io(
                    VolumeOperation::OpenOwnershipLock,
                    io::Error::from(source),
                )),
            }
        },
        Err(source) => Err(VolumeFailure::from_io(
            VolumeOperation::OpenOwnershipLock,
            io::Error::from(source),
        )),
    }
}

#[cfg(target_os = "macos")]
fn qualify_local_mount(root: &File) -> Result<VolumeFileSystem, VolumeFailure> {
    acquisition_event(VolumeEvent::ClassifyMount, VolumeOperation::ClassifyMount)?;
    let statistics = unix_fs::fstatfs(root)
        .map_err(io::Error::from)
        .map_err(|source| VolumeFailure::from_io(VolumeOperation::ClassifyMount, source))?;
    let end = statistics
        .f_fstypename
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(statistics.f_fstypename.len());
    let name = statistics.f_fstypename.get(..end).unwrap_or_default();
    if name
        .iter()
        .copied()
        .eq(b"apfs".iter().map(|byte| *byte as i8))
    {
        Ok(VolumeFileSystem::Apfs)
    } else {
        Err(VolumeFailure::from_io(
            VolumeOperation::ClassifyMount,
            io::Error::new(
                io::ErrorKind::Unsupported,
                "filesystem mount is not in the Release 1 local qualification set",
            ),
        ))
    }
}

#[cfg(target_os = "linux")]
fn qualify_local_mount(root: &File) -> Result<VolumeFileSystem, VolumeFailure> {
    acquisition_event(VolumeEvent::ClassifyMount, VolumeOperation::ClassifyMount)?;
    let statistics = unix_fs::fstatfs(root)
        .map_err(io::Error::from)
        .map_err(|source| VolumeFailure::from_io(VolumeOperation::ClassifyMount, source))?;
    match statistics.f_type as u64 {
        0xEF53 => Ok(VolumeFileSystem::Ext),
        0x5846_5342 => Ok(VolumeFileSystem::Xfs),
        0x9123_683E => Ok(VolumeFileSystem::Btrfs),
        0x2FC1_2FC1 => Ok(VolumeFileSystem::Zfs),
        _ => Err(VolumeFailure::from_io(
            VolumeOperation::ClassifyMount,
            io::Error::new(
                io::ErrorKind::Unsupported,
                "filesystem mount is not in the Release 1 local qualification set",
            ),
        )),
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn qualify_local_mount(_root: &File) -> Result<VolumeFileSystem, VolumeFailure> {
    Err(VolumeFailure::from_io(
        VolumeOperation::ClassifyMount,
        io::Error::new(
            io::ErrorKind::Unsupported,
            "filesystem mount qualification is unavailable on this platform",
        ),
    ))
}

fn try_lock_ownership(ownership_lock: &File) -> Result<(), io::Error> {
    emit_event(VolumeEvent::AcquireOwnership)?;
    perform_io(VolumeOperation::AcquireOwnershipLock, || {
        ownership_lock.try_lock().map_err(|failure| match failure {
            TryLockError::WouldBlock => io::Error::from(io::ErrorKind::WouldBlock),
            TryLockError::Error(source) => source,
        })
    })
}

fn reject_existing_probe_residue(root: &File) -> Result<(), VolumeFailure> {
    acquisition_event(
        VolumeEvent::InspectProbeResidue,
        VolumeOperation::PrepareProbe,
    )?;
    match unix_fs::statat(root, ".positron-volume-probe", AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => Err(VolumeFailure::inconsistent_probe(io::Error::new(
            io::ErrorKind::InvalidData,
            "dedicated capability-probe area contains residual state",
        ))),
        Err(rustix::io::Errno::NOENT) => Ok(()),
        Err(source) => Err(VolumeFailure::from_io(
            VolumeOperation::PrepareProbe,
            io::Error::from(source),
        )),
    }
}

fn run_capability_probe(root: &File) -> Result<(), VolumeFailure> {
    acquisition_event(
        VolumeEvent::CreateProbeDirectory,
        VolumeOperation::PrepareProbe,
    )?;
    unix_fs::mkdirat(
        root,
        ".positron-volume-probe",
        Mode::RUSR | Mode::WUSR | Mode::XUSR,
    )
    .map_err(io::Error::from)
    .map_err(|source| VolumeFailure::from_io(VolumeOperation::PrepareProbe, source))?;
    let created_probe_identity = entry_identity(root, ".positron-volume-probe")
        .map_err(|source| VolumeFailure::probe_failure(VolumeOperation::PrepareProbe, source))?;
    if let Err(failure) = probe_event(
        VolumeEvent::OpenProbeDirectory,
        VolumeOperation::PrepareProbe,
    ) {
        return finish_unopened_probe_failure(root, created_probe_identity, failure);
    }
    let probe_directory = match unix_fs::openat(
        root,
        ".positron-volume-probe",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    {
        Ok(directory) => directory,
        Err(source) => {
            let failure = VolumeFailure::probe_failure(
                VolumeOperation::PrepareProbe,
                io::Error::from(source),
            );
            return finish_unopened_probe_failure(root, created_probe_identity, failure);
        },
    };
    let probe_identity = file_identity(&probe_directory)?;
    if probe_identity != created_probe_identity {
        return Err(VolumeFailure::inconsistent_cleanup(
            io::Error::new(
                io::ErrorKind::InvalidData,
                "probe directory identity changed while opening",
            ),
            false,
        ));
    }

    let mut owned_artifact_identity = None;
    let probe_result = (|| {
        probe_event(
            VolumeEvent::CreateProbeCandidate,
            VolumeOperation::OpenProbeFile,
        )?;
        let mut candidate = unix_fs::openat(
            &probe_directory,
            "candidate",
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map(File::from)
        .map_err(io::Error::from)
        .map_err(|source| VolumeFailure::probe_failure(VolumeOperation::OpenProbeFile, source))?;
        let candidate_identity = file_identity(&candidate)?;
        owned_artifact_identity = Some(candidate_identity);
        probe_event(
            VolumeEvent::WriteProbePayload,
            VolumeOperation::WriteProbeFile,
        )?;
        write_probe_payload(&mut candidate, PRIMARY_DATA_VOLUME_PROBE_PAYLOAD).map_err(
            |source| VolumeFailure::probe_failure(VolumeOperation::WriteProbeFile, source),
        )?;
        probe_event(
            VolumeEvent::SynchronizeProbePayload,
            VolumeOperation::SynchronizeProbeFile,
        )?;
        perform_io(VolumeOperation::SynchronizeProbeFile, || {
            candidate.sync_all()
        })
        .map_err(|source| {
            VolumeFailure::probe_failure(VolumeOperation::SynchronizeProbeFile, source)
        })?;
        drop(candidate);

        probe_event(
            VolumeEvent::ReopenProbePayload,
            VolumeOperation::ReopenProbeFile,
        )?;
        let mut reopened =
            open_probe_file(&probe_directory, "candidate", true).map_err(|source| {
                VolumeFailure::probe_failure(VolumeOperation::ReopenProbeFile, source)
            })?;
        verify_file_identity(
            &reopened,
            candidate_identity,
            VolumeOperation::ReopenProbeFile,
        )?;
        let mut observed = [0_u8; PRIMARY_DATA_VOLUME_PROBE_PAYLOAD_BYTES];
        probe_event(
            VolumeEvent::ReadProbePayload,
            VolumeOperation::ReadProbeFile,
        )?;
        perform_io(VolumeOperation::ReadProbeFile, || {
            reopened.read_exact(&mut observed)
        })
        .map_err(|source| VolumeFailure::probe_failure(VolumeOperation::ReadProbeFile, source))?;
        if !values_match(
            VolumeOperation::VerifyProbeContents,
            observed.as_slice(),
            PRIMARY_DATA_VOLUME_PROBE_PAYLOAD,
        ) {
            return Err(VolumeFailure::probe_failure(
                VolumeOperation::VerifyProbeContents,
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "synchronized probe contents changed after reopen",
                ),
            ));
        }
        probe_event(
            VolumeEvent::TruncateProbePayload,
            VolumeOperation::TruncateProbeFile,
        )?;
        perform_io(VolumeOperation::TruncateProbeFile, || reopened.set_len(8)).map_err(
            |source| VolumeFailure::probe_failure(VolumeOperation::TruncateProbeFile, source),
        )?;
        probe_event(
            VolumeEvent::SynchronizeProbeTruncation,
            VolumeOperation::SynchronizeProbeFile,
        )?;
        perform_io(VolumeOperation::SynchronizeProbeFile, || {
            reopened.sync_all()
        })
        .map_err(|source| {
            VolumeFailure::probe_failure(VolumeOperation::SynchronizeProbeFile, source)
        })?;
        drop(reopened);

        probe_event(
            VolumeEvent::ReopenTruncatedProbe,
            VolumeOperation::ReopenProbeFile,
        )?;
        let mut truncated =
            open_probe_file(&probe_directory, "candidate", false).map_err(|source| {
                VolumeFailure::probe_failure(VolumeOperation::ReopenProbeFile, source)
            })?;
        verify_file_identity(
            &truncated,
            candidate_identity,
            VolumeOperation::ReopenProbeFile,
        )?;
        let expected_prefix = b"positron";
        let mut observed_prefix = [0_u8; 8];
        probe_event(
            VolumeEvent::ReadTruncatedProbe,
            VolumeOperation::ReadProbeFile,
        )?;
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

        probe_event(
            VolumeEvent::RenameProbeCandidate,
            VolumeOperation::RenameProbeFile,
        )?;
        verify_entry_identity(&probe_directory, "candidate", candidate_identity)?;
        unix_fs::renameat(&probe_directory, "candidate", &probe_directory, "published")
            .map_err(io::Error::from)
            .map_err(|source| {
                VolumeFailure::probe_failure(VolumeOperation::RenameProbeFile, source)
            })?;
        verify_entry_identity(&probe_directory, "published", candidate_identity)?;
        probe_event(
            VolumeEvent::SynchronizeProbeDirectory,
            VolumeOperation::SynchronizeProbeDirectory,
        )?;
        perform_io(VolumeOperation::SynchronizeProbeDirectory, || {
            probe_directory.sync_all()
        })
        .map_err(|source| {
            VolumeFailure::probe_failure(VolumeOperation::SynchronizeProbeDirectory, source)
        })?;
        Ok(candidate_identity)
    })();

    let cleanup_result = cleanup_probe(
        root,
        &probe_directory,
        probe_identity,
        owned_artifact_identity,
    );
    match (probe_result, cleanup_result) {
        (Ok(_), Ok(())) => Ok(()),
        (Err(failure), Ok(())) => Err(failure),
        (_, Err((source, artifacts_absent))) => Err(VolumeFailure::inconsistent_cleanup(
            source,
            artifacts_absent,
        )),
    }
}

fn finish_unopened_probe_failure(
    root: &File,
    probe_identity: VolumeRootIdentity,
    failure: VolumeFailure,
) -> Result<(), VolumeFailure> {
    let cleanup = verify_entry_identity(root, ".positron-volume-probe", probe_identity)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))
        .and_then(|()| {
            unix_fs::unlinkat(root, ".positron-volume-probe", AtFlags::REMOVEDIR)
                .map_err(io::Error::from)
        });
    match cleanup {
        Ok(()) => match root.sync_all() {
            Ok(()) => Err(failure),
            Err(source) => Err(VolumeFailure::inconsistent_cleanup(source, true)),
        },
        Err(source) => Err(VolumeFailure::inconsistent_cleanup(source, false)),
    }
}

fn file_identity(file: &File) -> Result<VolumeRootIdentity, VolumeFailure> {
    file.metadata()
        .map_err(|source| VolumeFailure::from_io(VolumeOperation::VerifyRootIdentity, source))
        .and_then(|metadata| root_identity(&metadata))
}

fn verify_file_identity(
    file: &File,
    expected: VolumeRootIdentity,
    operation: VolumeOperation,
) -> Result<(), VolumeFailure> {
    let metadata = file
        .metadata()
        .map_err(|source| VolumeFailure::probe_failure(operation, source))?;
    let observed = root_identity(&metadata)?;
    if observed == expected && metadata.file_type().is_file() && metadata.nlink() == 1 {
        Ok(())
    } else {
        Err(VolumeFailure::probe_failure(
            operation,
            io::Error::new(io::ErrorKind::InvalidData, "probe file identity changed"),
        ))
    }
}

fn entry_identity(directory: &File, name: &str) -> Result<VolumeRootIdentity, io::Error> {
    let metadata =
        unix_fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW).map_err(io::Error::from)?;
    Ok(VolumeRootIdentity {
        device: metadata.st_dev as u64,
        inode: metadata.st_ino,
    })
}

fn verify_entry_identity(
    directory: &File,
    name: &str,
    expected: VolumeRootIdentity,
) -> Result<(), VolumeFailure> {
    let observed = entry_identity(directory, name).map_err(|source| {
        VolumeFailure::probe_failure(VolumeOperation::VerifyRootIdentity, source)
    })?;
    if observed == expected {
        Ok(())
    } else {
        Err(VolumeFailure::probe_failure(
            VolumeOperation::VerifyRootIdentity,
            io::Error::new(
                io::ErrorKind::InvalidData,
                "volume artifact identity changed",
            ),
        ))
    }
}

fn open_probe_file(directory: &File, name: &str, writable: bool) -> Result<File, io::Error> {
    let access = if writable {
        OFlags::RDWR
    } else {
        OFlags::RDONLY
    };
    unix_fs::openat(
        directory,
        name,
        access | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(io::Error::from)
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

fn cleanup_probe(
    root: &File,
    probe: &File,
    probe_identity: VolumeRootIdentity,
    expected_artifact: Option<VolumeRootIdentity>,
) -> Result<(), (io::Error, bool)> {
    for (name, event) in [
        ("candidate", VolumeEvent::CleanupProbeCandidate),
        ("published", VolumeEvent::CleanupProbePublished),
    ] {
        emit_event(event).map_err(|source| (source, false))?;
        match entry_identity(probe, name) {
            Ok(identity) if Some(identity) == expected_artifact => {
                unix_fs::unlinkat(probe, name, AtFlags::empty())
                    .map_err(io::Error::from)
                    .map_err(|source| (source, false))?;
            },
            Ok(_) => {
                return Err((
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "probe cleanup encountered an unowned artifact",
                    ),
                    false,
                ));
            },
            Err(source) if source.kind() == io::ErrorKind::NotFound => {},
            Err(source) => return Err((source, false)),
        }
    }
    verify_entry_identity(root, ".positron-volume-probe", probe_identity).map_err(|failure| {
        (
            io::Error::new(io::ErrorKind::InvalidData, failure.to_string()),
            false,
        )
    })?;
    emit_event(VolumeEvent::CleanupProbeDirectory).map_err(|source| (source, false))?;
    unix_fs::unlinkat(root, ".positron-volume-probe", AtFlags::REMOVEDIR)
        .map_err(io::Error::from)
        .map_err(|source| (source, false))?;
    emit_event(VolumeEvent::SynchronizeRootAfterCleanup).map_err(|source| (source, true))?;
    root.sync_all().map_err(|source| (source, true))
}

#[cfg(test)]
thread_local! {
    static PARTIAL_WRITE_FAULT: std::cell::Cell<Option<(usize, io::ErrorKind)>> = const { std::cell::Cell::new(None) };
    static FORCED_MISMATCH: std::cell::Cell<Option<VolumeOperation>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn with_partial_write_fault<T>(
    byte_count: usize,
    kind: io::ErrorKind,
    action: impl FnOnce() -> T,
) -> T {
    PARTIAL_WRITE_FAULT.with(|fault| {
        let previous = fault.replace(Some((byte_count, kind)));
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
    PARTIAL_WRITE_FAULT.with(|fault| {
        let scheduled = fault.get();
        fault.set(None);
        scheduled
    })
}

fn perform_io<T>(
    _operation: VolumeOperation,
    action: impl FnOnce() -> Result<T, io::Error>,
) -> Result<T, io::Error> {
    action()
}

#[cfg(unix)]
fn verify_ownership_artifact(
    root: &File,
    file: &File,
    root_id: VolumeRootIdentity,
) -> Result<(), VolumeFailure> {
    let handle_metadata = perform_io(VolumeOperation::OpenOwnershipLock, || file.metadata())
        .map_err(|source| VolumeFailure::from_io(VolumeOperation::OpenOwnershipLock, source))?;
    let path_identity = entry_identity(root, ".positron-volume.lock")
        .map_err(|source| VolumeFailure::from_io(VolumeOperation::OpenOwnershipLock, source))?;
    let handle_identity = root_identity(&handle_metadata)?;
    let safe = handle_metadata.file_type().is_file()
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
    _root: &File,
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
    fn root_swap_before_ownership_mutation_fails_without_touching_either_directory()
    -> Result<(), Box<dyn Error>> {
        let parent = TestRoot::new()?;
        let configured = parent.0.join("configured");
        let original = parent.0.join("original");
        fs::create_dir(&configured)?;
        let configured_for_swap = configured.clone();
        let original_for_swap = original.clone();

        let failure = with_event_action(
            VolumeEvent::BeforeOwnershipArtifact,
            move || {
                fs::rename(&configured_for_swap, &original_for_swap)
                    .expect("test root move must succeed");
                fs::create_dir(&configured_for_swap).expect("test replacement must succeed");
            },
            || PrimaryDataVolume::acquire(&configured, MountQualification::LocalHost),
        )
        .expect_err("replaced root must fail closed");

        assert_eq!(failure.code(), VolumeFailureCode::Inconsistent);
        assert_eq!(failure.operation(), VolumeOperation::VerifyRootIdentity);
        assert!(fs::read_dir(&configured)?.next().is_none());
        assert!(fs::read_dir(&original)?.next().is_none());
        Ok(())
    }

    #[test]
    fn detached_root_before_ownership_fails_without_creating_volume_artifacts()
    -> Result<(), Box<dyn Error>> {
        let parent = TestRoot::new()?;
        let configured = parent.0.join("configured");
        let detached = parent.0.join("detached");
        fs::create_dir(&configured)?;
        let configured_for_detach = configured.clone();
        let detached_for_detach = detached.clone();

        let failure = with_event_action(
            VolumeEvent::BeforeOwnershipArtifact,
            move || {
                fs::rename(&configured_for_detach, &detached_for_detach)
                    .expect("test root detach must succeed");
            },
            || PrimaryDataVolume::acquire(&configured, MountQualification::LocalHost),
        )
        .expect_err("detached root must fail closed");

        assert_eq!(failure.code(), VolumeFailureCode::Missing);
        assert_eq!(failure.operation(), VolumeOperation::VerifyRootIdentity);
        assert_eq!(
            failure.completion_state(),
            VolumeCompletionState::RejectedBeforeProbeMutation
        );
        assert!(fs::read_dir(&detached)?.next().is_none());
        Ok(())
    }

    #[test]
    fn bootstrap_resource_bounds_are_exact_and_immutable() {
        let bounds = PrimaryDataVolume::bootstrap_resource_bounds();

        assert_eq!(bounds.maximum_open_file_descriptors(), 4);
        assert_eq!(bounds.maximum_concurrent_io_operations(), 1);
        assert_eq!(bounds.maximum_probe_payload_bytes(), 21);
    }

    #[cfg(unix)]
    fn open_volume_descriptor_count(root: &Path) -> Result<usize, io::Error> {
        use std::collections::HashSet;

        fn insert_identity(
            identities: &mut HashSet<(u64, u64)>,
            path: &Path,
        ) -> Result<(), io::Error> {
            match fs::metadata(path) {
                Ok(metadata) => {
                    identities.insert((metadata.dev(), metadata.ino()));
                    Ok(())
                },
                Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(source) => Err(source),
            }
        }

        let probe = root.join(".positron-volume-probe");
        let mut identities = HashSet::new();
        insert_identity(&mut identities, root)?;
        insert_identity(&mut identities, &root.join(".positron-volume.lock"))?;
        insert_identity(&mut identities, &probe)?;
        insert_identity(&mut identities, &probe.join("candidate"))?;
        insert_identity(&mut identities, &probe.join("published"))?;

        #[cfg(target_os = "linux")]
        let descriptor_directory = Path::new("/proc/self/fd");
        #[cfg(not(target_os = "linux"))]
        let descriptor_directory = Path::new("/dev/fd");

        let mut count = 0_usize;
        for entry in fs::read_dir(descriptor_directory)? {
            let entry = entry?;
            if let Ok(metadata) = fs::metadata(entry.path())
                && identities.contains(&(metadata.dev(), metadata.ino()))
            {
                count = count
                    .checked_add(1)
                    .ok_or_else(|| io::Error::other("descriptor count overflow"))?;
            }
        }
        Ok(count)
    }

    #[cfg(unix)]
    #[test]
    fn bootstrap_never_exceeds_descriptor_bound_and_failures_leak_none()
    -> Result<(), Box<dyn Error>> {
        use std::cell::Cell;
        use std::rc::Rc;

        let events = [
            VolumeEvent::ClassifyRootPath,
            VolumeEvent::OpenRootDirectory,
            VolumeEvent::ReadRootHandleIdentity,
            VolumeEvent::ClassifyMount,
            VolumeEvent::InspectProbeResidue,
            VolumeEvent::BeforeOwnershipArtifact,
            VolumeEvent::CreateOwnershipArtifact,
            VolumeEvent::OpenOwnershipArtifact,
            VolumeEvent::AcquireOwnership,
            VolumeEvent::VerifyOwnershipAfterLock,
            VolumeEvent::CreateProbeDirectory,
            VolumeEvent::OpenProbeDirectory,
            VolumeEvent::CreateProbeCandidate,
            VolumeEvent::WriteProbePayload,
            VolumeEvent::SynchronizeProbePayload,
            VolumeEvent::ReopenProbePayload,
            VolumeEvent::ReadProbePayload,
            VolumeEvent::TruncateProbePayload,
            VolumeEvent::SynchronizeProbeTruncation,
            VolumeEvent::ReopenTruncatedProbe,
            VolumeEvent::ReadTruncatedProbe,
            VolumeEvent::RenameProbeCandidate,
            VolumeEvent::SynchronizeProbeDirectory,
            VolumeEvent::CleanupProbeCandidate,
            VolumeEvent::CleanupProbePublished,
            VolumeEvent::CleanupProbeDirectory,
            VolumeEvent::SynchronizeRootAfterCleanup,
        ];
        let maximum = usize::from(
            PrimaryDataVolume::bootstrap_resource_bounds().maximum_open_file_descriptors(),
        );

        for event in events {
            let root = TestRoot::new()?;
            let observed = Rc::new(Cell::new(None));
            let observed_at_event = Rc::clone(&observed);
            let inspected_root = root.0.clone();
            let acquired = with_event_action(
                event,
                move || {
                    observed_at_event.set(Some(
                        open_volume_descriptor_count(&inspected_root)
                            .expect("descriptor observation must succeed"),
                    ));
                },
                || PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost),
            )?;
            assert!(
                observed.get().is_some_and(|count| count <= maximum),
                "descriptor bound exceeded at {event:?}: {:?}",
                observed.get()
            );
            drop(acquired);
            assert_eq!(open_volume_descriptor_count(&root.0)?, 0);

            let failed_root = TestRoot::new()?;
            let failure = with_event_fault(event, io::ErrorKind::Interrupted, || {
                PrimaryDataVolume::acquire(&failed_root.0, MountQualification::LocalHost)
            });
            assert!(failure.is_err(), "fault must be observed at {event:?}");
            assert_eq!(open_volume_descriptor_count(&failed_root.0)?, 0);
        }
        Ok(())
    }

    #[test]
    fn detached_root_after_probe_fails_with_synchronized_cleanup_truth()
    -> Result<(), Box<dyn Error>> {
        let parent = TestRoot::new()?;
        let configured = parent.0.join("configured");
        let detached = parent.0.join("detached");
        fs::create_dir(&configured)?;
        let configured_for_detach = configured.clone();
        let detached_for_detach = detached.clone();

        let failure = with_event_action(
            VolumeEvent::SynchronizeRootAfterCleanup,
            move || {
                fs::rename(&configured_for_detach, &detached_for_detach)
                    .expect("test root detach must succeed");
            },
            || PrimaryDataVolume::acquire(&configured, MountQualification::LocalHost),
        )
        .expect_err("detached root must fail closed");

        assert_eq!(failure.code(), VolumeFailureCode::Missing);
        assert_eq!(failure.operation(), VolumeOperation::VerifyRootIdentity);
        assert_eq!(
            failure.completion_state(),
            VolumeCompletionState::ProbeCleanupSynchronized
        );
        let names = fs::read_dir(&detached)?
            .map(|entry| entry.map(|value| value.file_name()))
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(names, [".positron-volume.lock"]);
        Ok(())
    }

    #[test]
    fn root_swaps_at_semantic_boundaries_never_redirect_volume_mutation()
    -> Result<(), Box<dyn Error>> {
        let events = [
            VolumeEvent::ClassifyMount,
            VolumeEvent::InspectProbeResidue,
            VolumeEvent::OpenOwnershipArtifact,
            VolumeEvent::CreateOwnershipArtifact,
            VolumeEvent::AcquireOwnership,
            VolumeEvent::CreateProbeDirectory,
            VolumeEvent::OpenProbeDirectory,
            VolumeEvent::CreateProbeCandidate,
            VolumeEvent::WriteProbePayload,
            VolumeEvent::SynchronizeProbePayload,
            VolumeEvent::ReopenProbePayload,
            VolumeEvent::ReadProbePayload,
            VolumeEvent::TruncateProbePayload,
            VolumeEvent::SynchronizeProbeTruncation,
            VolumeEvent::ReopenTruncatedProbe,
            VolumeEvent::ReadTruncatedProbe,
            VolumeEvent::RenameProbeCandidate,
            VolumeEvent::SynchronizeProbeDirectory,
            VolumeEvent::CleanupProbeCandidate,
            VolumeEvent::CleanupProbePublished,
            VolumeEvent::CleanupProbeDirectory,
            VolumeEvent::SynchronizeRootAfterCleanup,
        ];

        for event in events {
            let parent = TestRoot::new()?;
            let configured = parent.0.join("configured");
            let original = parent.0.join("original");
            fs::create_dir(&configured)?;
            let configured_for_swap = configured.clone();
            let original_for_swap = original.clone();

            let failure = with_event_action(
                event,
                move || {
                    fs::rename(&configured_for_swap, &original_for_swap)
                        .expect("test root move must succeed");
                    fs::create_dir(&configured_for_swap).expect("test replacement must succeed");
                },
                || PrimaryDataVolume::acquire(&configured, MountQualification::LocalHost),
            )
            .expect_err("replaced configured root must fail closed");

            assert!(fs::read_dir(&configured)?.next().is_none(), "{event:?}");
            assert_eq!(failure.operation(), VolumeOperation::VerifyRootIdentity);
            if matches!(
                event,
                VolumeEvent::ClassifyMount | VolumeEvent::BeforeOwnershipArtifact
            ) {
                assert!(fs::read_dir(&original)?.next().is_none(), "{event:?}");
            } else {
                let names = fs::read_dir(&original)?
                    .map(|entry| entry.map(|value| value.file_name()))
                    .collect::<Result<Vec<_>, _>>()?;
                assert_eq!(names, [".positron-volume.lock"], "{event:?}");
            }
        }
        Ok(())
    }

    #[test]
    fn unknown_mount_qualification_fails_before_any_volume_artifact() -> Result<(), Box<dyn Error>>
    {
        let root = TestRoot::new()?;

        let failure = with_event_fault(
            VolumeEvent::ClassifyMount,
            io::ErrorKind::Unsupported,
            || PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost),
        )
        .expect_err("unknown mount must fail closed");

        assert_eq!(failure.code(), VolumeFailureCode::Unsupported);
        assert_eq!(failure.operation(), VolumeOperation::ClassifyMount);
        assert_eq!(
            failure.completion_state(),
            VolumeCompletionState::RejectedBeforeProbeMutation
        );
        assert!(fs::read_dir(&root.0)?.next().is_none());
        Ok(())
    }

    #[test]
    fn competing_first_lock_creator_is_reported_busy() -> Result<(), Box<dyn Error>> {
        use std::sync::{Arc, Mutex};

        let root = TestRoot::new()?;
        let held = Arc::new(Mutex::new(None));
        let held_for_race = Arc::clone(&held);
        let lock_path = root.0.join(".positron-volume.lock");

        let failure = with_event_action(
            VolumeEvent::CreateOwnershipArtifact,
            move || {
                let competitor =
                    File::create(&lock_path).expect("competitor lock create must work");
                competitor
                    .try_lock()
                    .expect("competitor lock acquisition must work");
                *held_for_race.lock().expect("test mutex must be healthy") = Some(competitor);
            },
            || PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost),
        )
        .expect_err("contended first creation must fail");

        assert_eq!(failure.code(), VolumeFailureCode::Busy);
        assert_eq!(failure.retry_class(), VolumeRetryClass::AfterBackoff);
        assert_eq!(failure.operation(), VolumeOperation::AcquireOwnershipLock);
        assert!(!root.0.join(".positron-volume-probe").exists());
        Ok(())
    }

    #[test]
    fn final_cleanup_sync_failure_reports_absent_but_durability_uncertain()
    -> Result<(), Box<dyn Error>> {
        let root = TestRoot::new()?;

        let failure = with_event_fault(
            VolumeEvent::SynchronizeRootAfterCleanup,
            io::ErrorKind::Interrupted,
            || PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost),
        )
        .expect_err("final cleanup sync must remain truthful");

        assert_eq!(failure.code(), VolumeFailureCode::Inconsistent);
        assert_eq!(failure.operation(), VolumeOperation::CleanupProbe);
        assert_eq!(
            failure.completion_state(),
            VolumeCompletionState::ProbeCleanupDurabilityUncertain
        );
        assert!(!root.0.join(".positron-volume-probe").exists());
        Ok(())
    }

    #[test]
    fn ownership_artifact_swap_before_locking_fails_closed() -> Result<(), Box<dyn Error>> {
        let root = TestRoot::new()?;
        let lock = root.0.join(".positron-volume.lock");
        let displaced = root.0.join("displaced-lock");
        let lock_for_swap = lock.clone();
        let displaced_for_swap = displaced.clone();

        let failure = with_event_action(
            VolumeEvent::AcquireOwnership,
            move || {
                fs::rename(&lock_for_swap, &displaced_for_swap)
                    .expect("test lock move must succeed");
                fs::write(&lock_for_swap, b"unknown-owner").expect("replacement must succeed");
            },
            || PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost),
        )
        .expect_err("swapped ownership artifact must fail closed");

        assert_eq!(failure.operation(), VolumeOperation::OpenOwnershipLock);
        assert_eq!(fs::read(lock)?, b"unknown-owner");
        assert!(displaced.exists());
        assert!(!root.0.join(".positron-volume-probe").exists());
        Ok(())
    }

    #[test]
    fn probe_directory_swap_before_opening_never_mutates_the_replacement()
    -> Result<(), Box<dyn Error>> {
        let root = TestRoot::new()?;
        let probe = root.0.join(".positron-volume-probe");
        let displaced = root.0.join("displaced-probe");
        let probe_for_swap = probe.clone();
        let displaced_for_swap = displaced.clone();

        let failure = with_event_action(
            VolumeEvent::OpenProbeDirectory,
            move || {
                fs::rename(&probe_for_swap, &displaced_for_swap)
                    .expect("test probe move must succeed");
                fs::create_dir(&probe_for_swap).expect("probe replacement must succeed");
            },
            || PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost),
        )
        .expect_err("swapped probe directory must fail closed");

        assert_eq!(failure.code(), VolumeFailureCode::Inconsistent);
        assert_eq!(
            failure.completion_state(),
            VolumeCompletionState::ProbeResiduePresent
        );
        assert!(fs::read_dir(&probe)?.next().is_none());
        assert!(fs::read_dir(&displaced)?.next().is_none());
        Ok(())
    }

    #[test]
    fn probe_directory_swap_after_opening_preserves_the_replacement() -> Result<(), Box<dyn Error>>
    {
        let root = TestRoot::new()?;
        let probe = root.0.join(".positron-volume-probe");
        let displaced = root.0.join("displaced-probe");
        let probe_for_swap = probe.clone();
        let displaced_for_swap = displaced.clone();

        let failure = with_event_action(
            VolumeEvent::WriteProbePayload,
            move || {
                fs::rename(&probe_for_swap, &displaced_for_swap)
                    .expect("test probe move must succeed");
                fs::create_dir(&probe_for_swap).expect("probe replacement must succeed");
                fs::write(probe_for_swap.join("unknown"), b"preserve")
                    .expect("unknown replacement entry must succeed");
            },
            || PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost),
        )
        .expect_err("swapped probe directory must fail closed");

        assert_eq!(failure.code(), VolumeFailureCode::Inconsistent);
        assert_eq!(
            failure.completion_state(),
            VolumeCompletionState::ProbeResiduePresent
        );
        assert_eq!(fs::read(probe.join("unknown"))?, b"preserve");
        assert!(fs::read_dir(displaced)?.next().is_none());
        Ok(())
    }

    #[test]
    fn candidate_swap_before_truncation_never_truncates_the_replacement()
    -> Result<(), Box<dyn Error>> {
        let root = TestRoot::new()?;
        let foreign = root.0.join("foreign");
        fs::write(&foreign, b"foreign-content-must-survive")?;
        let root_for_swap = root.0.clone();
        let foreign_for_swap = foreign.clone();

        let failure = with_event_action(
            VolumeEvent::TruncateProbePayload,
            move || {
                let probe = root_for_swap.join(".positron-volume-probe");
                fs::rename(probe.join("candidate"), probe.join("displaced-candidate"))
                    .expect("candidate move must succeed");
                fs::hard_link(&foreign_for_swap, probe.join("candidate"))
                    .expect("replacement hard link must succeed");
            },
            || PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost),
        )
        .expect_err("swapped candidate must fail closed");

        assert_eq!(failure.code(), VolumeFailureCode::Inconsistent);
        assert_eq!(fs::read(foreign)?, b"foreign-content-must-survive");
        assert_eq!(
            failure.completion_state(),
            VolumeCompletionState::ProbeResiduePresent
        );
        Ok(())
    }

    #[test]
    fn probe_write_permission_failure_is_typed_and_cleaned() -> Result<(), Box<dyn Error>> {
        let root = TestRoot::new()?;

        let failure = with_event_fault(
            VolumeEvent::WriteProbePayload,
            io::ErrorKind::PermissionDenied,
            || PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost),
        )
        .expect_err("injected probe write must fail");

        assert_eq!(failure.code(), VolumeFailureCode::PermissionDenied);
        assert_eq!(failure.operation(), VolumeOperation::WriteProbeFile);
        assert_eq!(
            failure.completion_state(),
            VolumeCompletionState::ProbeCleanupSynchronized
        );
        assert!(!root.0.join(".positron-volume-probe").exists());
        Ok(())
    }

    #[test]
    fn probe_file_sync_exhaustion_is_typed_and_cleaned() -> Result<(), Box<dyn Error>> {
        let root = TestRoot::new()?;

        let failure = with_event_fault(
            VolumeEvent::SynchronizeProbePayload,
            io::ErrorKind::StorageFull,
            || PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost),
        )
        .expect_err("injected probe sync must fail");

        assert_eq!(failure.code(), VolumeFailureCode::Exhausted);
        assert_eq!(failure.operation(), VolumeOperation::SynchronizeProbeFile);
        assert_eq!(
            failure.completion_state(),
            VolumeCompletionState::ProbeCleanupSynchronized
        );
        assert!(!root.0.join(".positron-volume-probe").exists());
        Ok(())
    }

    #[test]
    fn probe_reopen_short_read_is_inconsistent_and_cleaned() -> Result<(), Box<dyn Error>> {
        let root = TestRoot::new()?;

        let failure = with_event_fault(
            VolumeEvent::ReadProbePayload,
            io::ErrorKind::UnexpectedEof,
            || PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost),
        )
        .expect_err("injected short read must fail");

        assert_eq!(failure.code(), VolumeFailureCode::Inconsistent);
        assert_eq!(failure.operation(), VolumeOperation::ReadProbeFile);
        assert_eq!(
            failure.completion_state(),
            VolumeCompletionState::ProbeCleanupSynchronized
        );
        assert!(!root.0.join(".positron-volume-probe").exists());
        Ok(())
    }

    #[test]
    fn probe_truncation_read_only_failure_is_typed_and_cleaned() -> Result<(), Box<dyn Error>> {
        let root = TestRoot::new()?;

        let failure = with_event_fault(
            VolumeEvent::TruncateProbePayload,
            io::ErrorKind::ReadOnlyFilesystem,
            || PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost),
        )
        .expect_err("injected read-only truncation must fail");

        assert_eq!(failure.code(), VolumeFailureCode::ReadOnly);
        assert_eq!(failure.operation(), VolumeOperation::TruncateProbeFile);
        assert_eq!(
            failure.completion_state(),
            VolumeCompletionState::ProbeCleanupSynchronized
        );
        assert!(!root.0.join(".positron-volume-probe").exists());
        Ok(())
    }

    #[test]
    fn probe_rename_unsupported_failure_is_typed_and_cleaned() -> Result<(), Box<dyn Error>> {
        let root = TestRoot::new()?;

        let failure = with_event_fault(
            VolumeEvent::RenameProbeCandidate,
            io::ErrorKind::Unsupported,
            || PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost),
        )
        .expect_err("injected unsupported rename must fail");

        assert_eq!(failure.code(), VolumeFailureCode::Unsupported);
        assert_eq!(failure.operation(), VolumeOperation::RenameProbeFile);
        assert_eq!(
            failure.completion_state(),
            VolumeCompletionState::ProbeCleanupSynchronized
        );
        assert!(!root.0.join(".positron-volume-probe").exists());
        Ok(())
    }

    #[test]
    fn probe_directory_sync_interruption_is_transient_and_cleaned() -> Result<(), Box<dyn Error>> {
        let root = TestRoot::new()?;

        let failure = with_event_fault(
            VolumeEvent::SynchronizeProbeDirectory,
            io::ErrorKind::Interrupted,
            || PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost),
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
            VolumeCompletionState::ProbeCleanupSynchronized
        );
        assert!(!root.0.join(".positron-volume-probe").exists());
        Ok(())
    }

    #[test]
    fn partial_probe_write_is_reported_and_cleaned() -> Result<(), Box<dyn Error>> {
        let root = TestRoot::new()?;

        let failure = with_partial_write_fault(5, io::ErrorKind::StorageFull, || {
            PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)
        })
        .expect_err("partial probe write must fail");

        assert_eq!(failure.code(), VolumeFailureCode::Exhausted);
        assert_eq!(failure.operation(), VolumeOperation::WriteProbeFile);
        assert_eq!(
            failure.completion_state(),
            VolumeCompletionState::ProbeCleanupSynchronized
        );
        assert!(!root.0.join(".positron-volume-probe").exists());
        Ok(())
    }

    #[test]
    fn post_truncation_reopen_failure_is_typed_and_cleaned() -> Result<(), Box<dyn Error>> {
        let root = TestRoot::new()?;

        let failure = with_event_fault(
            VolumeEvent::ReopenTruncatedProbe,
            io::ErrorKind::Interrupted,
            || PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost),
        )
        .expect_err("second probe reopen must be faultable");

        assert_eq!(failure.code(), VolumeFailureCode::Transient);
        assert_eq!(failure.operation(), VolumeOperation::ReopenProbeFile);
        assert_eq!(
            failure.completion_state(),
            VolumeCompletionState::ProbeCleanupSynchronized
        );
        assert!(!root.0.join(".positron-volume-probe").exists());
        Ok(())
    }

    #[test]
    fn ambiguous_probe_cleanup_is_preserved_and_fails_closed() -> Result<(), Box<dyn Error>> {
        let root = TestRoot::new()?;

        let failure = with_event_fault(
            VolumeEvent::CleanupProbePublished,
            io::ErrorKind::PermissionDenied,
            || PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost),
        )
        .expect_err("injected cleanup failure must fail closed");

        assert_eq!(failure.code(), VolumeFailureCode::Inconsistent);
        assert_eq!(failure.retry_class(), VolumeRetryClass::Never);
        assert_eq!(failure.operation(), VolumeOperation::CleanupProbe);
        assert_eq!(
            failure.completion_state(),
            VolumeCompletionState::ProbeResiduePresent
        );
        assert!(root.0.join(".positron-volume-probe/published").exists());
        Ok(())
    }

    #[test]
    fn root_acquisition_faults_remain_typed_and_precede_the_probe() -> Result<(), Box<dyn Error>> {
        let cases = [
            (
                VolumeEvent::ClassifyRootPath,
                VolumeOperation::ClassifyRoot,
                io::ErrorKind::PermissionDenied,
                VolumeFailureCode::PermissionDenied,
            ),
            (
                VolumeEvent::OpenRootDirectory,
                VolumeOperation::ClassifyRoot,
                io::ErrorKind::TimedOut,
                VolumeFailureCode::Transient,
            ),
            (
                VolumeEvent::ReadRootHandleIdentity,
                VolumeOperation::ClassifyRoot,
                io::ErrorKind::InvalidData,
                VolumeFailureCode::Inconsistent,
            ),
            (
                VolumeEvent::OpenOwnershipArtifact,
                VolumeOperation::OpenOwnershipLock,
                io::ErrorKind::ReadOnlyFilesystem,
                VolumeFailureCode::ReadOnly,
            ),
            (
                VolumeEvent::CreateOwnershipArtifact,
                VolumeOperation::OpenOwnershipLock,
                io::ErrorKind::PermissionDenied,
                VolumeFailureCode::PermissionDenied,
            ),
            (
                VolumeEvent::VerifyOwnershipAfterLock,
                VolumeOperation::OpenOwnershipLock,
                io::ErrorKind::InvalidData,
                VolumeFailureCode::Inconsistent,
            ),
            (
                VolumeEvent::AcquireOwnership,
                VolumeOperation::AcquireOwnershipLock,
                io::ErrorKind::Unsupported,
                VolumeFailureCode::Unsupported,
            ),
        ];

        for (event, operation, kind, expected_code) in cases {
            let root = TestRoot::new()?;
            let failure = with_event_fault(event, kind, || {
                PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)
            })
            .expect_err("scheduled root acquisition fault must fail");

            assert_eq!(failure.code(), expected_code);
            assert_eq!(failure.operation(), operation);
            assert_eq!(
                failure.completion_state(),
                VolumeCompletionState::RejectedBeforeProbeMutation
            );
            assert!(!root.0.join(".positron-volume-probe").exists(), "{event:?}");
        }
        Ok(())
    }

    #[test]
    fn root_identity_change_fails_before_volume_mutation() -> Result<(), Box<dyn Error>> {
        let root = TestRoot::new()?;

        let failure = with_forced_mismatch(VolumeOperation::VerifyRootIdentity, || {
            PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)
        })
        .expect_err("changed root identity must fail");

        assert_eq!(failure.code(), VolumeFailureCode::Inconsistent);
        assert_eq!(failure.operation(), VolumeOperation::VerifyRootIdentity);
        assert_eq!(
            failure.completion_state(),
            VolumeCompletionState::RejectedBeforeProbeMutation
        );
        assert!(fs::read_dir(&root.0)?.next().is_none());
        Ok(())
    }

    #[test]
    fn probe_content_mismatch_is_inconsistent_and_cleaned() -> Result<(), Box<dyn Error>> {
        let root = TestRoot::new()?;

        let failure = with_forced_mismatch(VolumeOperation::VerifyProbeContents, || {
            PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)
        })
        .expect_err("changed reopened contents must fail");

        assert_eq!(failure.code(), VolumeFailureCode::Inconsistent);
        assert_eq!(failure.operation(), VolumeOperation::VerifyProbeContents);
        assert_eq!(
            failure.completion_state(),
            VolumeCompletionState::ProbeCleanupSynchronized
        );
        assert!(!root.0.join(".positron-volume-probe").exists());
        Ok(())
    }

    #[test]
    fn unstable_probe_truncation_is_inconsistent_and_cleaned() -> Result<(), Box<dyn Error>> {
        let root = TestRoot::new()?;

        let failure = with_forced_mismatch(VolumeOperation::VerifyProbeTruncation, || {
            PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)
        })
        .expect_err("unstable truncation must fail");

        assert_eq!(failure.code(), VolumeFailureCode::Inconsistent);
        assert_eq!(failure.operation(), VolumeOperation::VerifyProbeTruncation);
        assert_eq!(
            failure.completion_state(),
            VolumeCompletionState::ProbeCleanupSynchronized
        );
        assert!(!root.0.join(".positron-volume-probe").exists());
        Ok(())
    }

    #[test]
    fn remaining_probe_boundaries_are_faultable_through_acquisition() -> Result<(), Box<dyn Error>>
    {
        let cases = [
            (
                VolumeEvent::InspectProbeResidue,
                VolumeOperation::PrepareProbe,
            ),
            (
                VolumeEvent::CreateProbeDirectory,
                VolumeOperation::PrepareProbe,
            ),
            (
                VolumeEvent::OpenProbeDirectory,
                VolumeOperation::PrepareProbe,
            ),
            (
                VolumeEvent::CreateProbeCandidate,
                VolumeOperation::OpenProbeFile,
            ),
            (
                VolumeEvent::SynchronizeProbeTruncation,
                VolumeOperation::SynchronizeProbeFile,
            ),
            (
                VolumeEvent::ReadTruncatedProbe,
                VolumeOperation::ReadProbeFile,
            ),
        ];

        for (event, operation) in cases {
            let root = TestRoot::new()?;
            let failure = with_event_fault(event, io::ErrorKind::PermissionDenied, || {
                PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)
            })
            .expect_err("scheduled probe fault must fail");

            assert_eq!(failure.code(), VolumeFailureCode::PermissionDenied);
            assert_eq!(failure.operation(), operation);
            assert!(!root.0.join(".positron-volume-probe").exists(), "{event:?}");
        }
        Ok(())
    }

    #[test]
    fn every_cleanup_boundary_fails_closed_with_residue_truth() -> Result<(), Box<dyn Error>> {
        let cases = [
            (
                VolumeEvent::CleanupProbeCandidate,
                VolumeCompletionState::ProbeResiduePresent,
                true,
            ),
            (
                VolumeEvent::CleanupProbeDirectory,
                VolumeCompletionState::ProbeResiduePresent,
                true,
            ),
            (
                VolumeEvent::SynchronizeRootAfterCleanup,
                VolumeCompletionState::ProbeCleanupDurabilityUncertain,
                false,
            ),
        ];
        for (event, completion_state, residue_exists) in cases {
            let root = TestRoot::new()?;
            let failure = with_event_fault(event, io::ErrorKind::PermissionDenied, || {
                PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)
            })
            .expect_err("scheduled cleanup fault must fail closed");

            assert_eq!(failure.code(), VolumeFailureCode::Inconsistent);
            assert_eq!(failure.operation(), VolumeOperation::CleanupProbe);
            assert_eq!(failure.completion_state(), completion_state);
            assert_eq!(
                root.0.join(".positron-volume-probe").exists(),
                residue_exists
            );
        }
        Ok(())
    }

    #[test]
    fn typed_failure_retains_its_operating_system_source() -> Result<(), Box<dyn Error>> {
        let root = TestRoot::new()?;
        let missing = root.0.join("missing");
        let failure = PrimaryDataVolume::acquire(&missing, MountQualification::LocalHost)
            .expect_err("missing root must fail");

        let source = Error::source(&failure).ok_or("volume failure must retain a source")?;

        assert!(!source.to_string().is_empty());
        Ok(())
    }
}
