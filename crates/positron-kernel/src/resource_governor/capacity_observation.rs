//! Host- and volume-authoritative initial resource observation.

use std::error::Error;
use std::fmt::{Display, Formatter};

use rustix::fs::fstatvfs;
use rustix::process::{Resource, getrlimit};

use super::inventory::{DetectedCapacity, DiskObservation};
use super::model::{ResourceAmounts, ResourceDimension};

#[cfg(any(target_os = "linux", test, fuzzing))]
mod linux;

#[cfg(fuzzing)]
#[doc(hidden)]
pub fn fuzz_linux_capacity_parsers(data: &[u8]) {
    linux::fuzz_parsers(data);
}

pub const CPU_WORK_UNITS_PER_LOGICAL_CPU: u64 = 1_000;
/// Maximum simultaneous heap payload used by Linux capacity observation.
///
/// Membership and mountinfo must coexist because parsed components borrow
/// them. One resolved path and one limit-file buffer may coexist with those
/// two buffers. Scratch reads use a fixed stack array and are excluded.
pub const CAPACITY_OBSERVATION_TRANSIENT_MEMORY_BYTES: u64 = 64 * 1_024 // retained membership buffer
    + 1_024 * 1_024 // retained mountinfo buffer
    + 4_096 // one resolved path buffer
    + 128 // one limit-file buffer
    + 4_096 // fixed bounded-read scratch
    + 64 * 1_024; // conservative fixed stack state and container headers
const RETAINED_PRIMARY_VOLUME_DESCRIPTORS: u64 = 2;
const REGISTERED_DIMENSIONS: [ResourceDimension; 7] = [
    ResourceDimension::QueueSlots,
    ResourceDimension::TaskSlots,
    ResourceDimension::BufferCacheBytes,
    ResourceDimension::BatchItems,
    ResourceDimension::LeaseSlots,
    ResourceDimension::RetrySlots,
    ResourceDimension::IoPermits,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapacityObservationSource {
    RegisteredBounds,
    HostCpu,
    HostMemory,
    CgroupMembership,
    CgroupMounts,
    CgroupCpu,
    CgroupMemory,
    ProcessFileDescriptors,
    PrimaryVolumeFilesystem,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapacityObservationFailure {
    UnsupportedPlatform,
    ObservationUnavailable { source: CapacityObservationSource },
    MalformedLimit { source: CapacityObservationSource },
    AmbiguousHierarchy,
    Arithmetic { source: CapacityObservationSource },
    AllocationUnavailable { source: CapacityObservationSource },
    ZeroCapacity { dimension: ResourceDimension },
}

impl Display for CapacityObservationFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("resource capacity observation failed")
    }
}

impl Error for CapacityObservationFailure {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegisteredResourceBounds([u64; 7]);

impl RegisteredResourceBounds {
    pub fn new(values: [u64; 7]) -> Result<Self, CapacityObservationFailure> {
        if let Some(dimension) = REGISTERED_DIMENSIONS
            .into_iter()
            .zip(values)
            .find_map(|(dimension, value)| (value == 0).then_some(dimension))
        {
            return Err(CapacityObservationFailure::ZeroCapacity { dimension });
        }
        Ok(Self(values))
    }

    const fn amounts(self) -> [u64; 7] {
        self.0
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct ObservedResourceEnvironment {
    detected_capacity: DetectedCapacity,
    initial_disk: DiskObservation,
    volume_binding: ObservedVolumeBinding,
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct ObservedVolumeBinding {
    root_identity: crate::VolumeRootIdentity,
    mount_identity: crate::VolumeMountIdentity,
    filesystem: crate::VolumeFileSystem,
    qualification: crate::MountQualification,
}

impl ObservedVolumeBinding {
    fn capture(volume: &crate::OwnedPrimaryDataVolume) -> Self {
        Self {
            root_identity: volume.root_identity(),
            mount_identity: volume.mount_identity(),
            filesystem: volume.filesystem(),
            qualification: volume.qualification(),
        }
    }

    pub(super) fn matches(&self, volume: &crate::OwnedPrimaryDataVolume) -> bool {
        self.root_identity == volume.root_identity()
            && self.mount_identity == volume.mount_identity()
            && self.filesystem == volume.filesystem()
            && self.qualification == volume.qualification()
    }
}

impl ObservedResourceEnvironment {
    #[cfg(test)]
    pub(crate) fn for_test(
        volume: &crate::OwnedPrimaryDataVolume,
        detected: ResourceAmounts,
        initial_disk: DiskObservation,
    ) -> Result<Self, super::GovernorFailure> {
        Ok(Self {
            detected_capacity: DetectedCapacity::new(detected)?,
            initial_disk,
            volume_binding: ObservedVolumeBinding::capture(volume),
        })
    }

    pub fn observe(
        volume: &crate::OwnedPrimaryDataVolume,
        registered: RegisteredResourceBounds,
    ) -> Result<Self, CapacityObservationFailure> {
        let memory = observe_memory()?;
        if memory <= CAPACITY_OBSERVATION_TRANSIENT_MEMORY_BYTES {
            return Err(CapacityObservationFailure::ZeroCapacity {
                dimension: ResourceDimension::MemoryBytes,
            });
        }
        let cpu = observe_cpu()?;
        let descriptors = observe_file_descriptors()?;
        let disk = observe_disk_bytes(volume)?;
        let [queue, task, buffer, batch, lease, retry, io] = registered.amounts();
        let amounts = ResourceAmounts::new([
            memory,
            queue,
            task,
            buffer,
            batch,
            lease,
            retry,
            io,
            cpu,
            descriptors,
            disk,
        ]);
        Ok(Self {
            detected_capacity: DetectedCapacity::from_observed(amounts),
            initial_disk: DiskObservation::from_observed(disk),
            volume_binding: ObservedVolumeBinding::capture(volume),
        })
    }

    #[must_use]
    pub const fn detected_capacity(&self) -> DetectedCapacity {
        self.detected_capacity
    }

    #[must_use]
    pub const fn initial_disk(&self) -> DiskObservation {
        self.initial_disk
    }

    pub(super) fn into_parts(self) -> (DetectedCapacity, DiskObservation, ObservedVolumeBinding) {
        (
            self.detected_capacity,
            self.initial_disk,
            self.volume_binding,
        )
    }
}

fn observe_cpu() -> Result<u64, CapacityObservationFailure> {
    let parallelism = std::thread::available_parallelism().map_err(|_| {
        CapacityObservationFailure::ObservationUnavailable {
            source: CapacityObservationSource::HostCpu,
        }
    })?;
    let host = u64::try_from(parallelism.get())
        .ok()
        .and_then(|value| value.checked_mul(CPU_WORK_UNITS_PER_LOGICAL_CPU))
        .ok_or(CapacityObservationFailure::Arithmetic {
            source: CapacityObservationSource::HostCpu,
        })?;
    #[cfg(target_os = "linux")]
    {
        linux::observe_cpu_work_units(host)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(host)
    }
}

#[cfg(target_os = "macos")]
fn observe_memory() -> Result<u64, CapacityObservationFailure> {
    let physical = positron_darwin_system::physical_memory_bytes().map_err(|_| {
        CapacityObservationFailure::ObservationUnavailable {
            source: CapacityObservationSource::HostMemory,
        }
    })?;
    let process_limit = positron_darwin_system::process_available_memory_bytes().map_err(|_| {
        CapacityObservationFailure::ObservationUnavailable {
            source: CapacityObservationSource::HostMemory,
        }
    })?;
    let host_available = positron_darwin_system::host_available_memory_bytes().map_err(|_| {
        CapacityObservationFailure::ObservationUnavailable {
            source: CapacityObservationSource::HostMemory,
        }
    })?;
    nonzero(
        ResourceDimension::MemoryBytes,
        process_limit.map_or(physical.min(host_available), |limit| {
            physical.min(host_available).min(limit)
        }),
    )
}

#[cfg(target_os = "linux")]
fn observe_memory() -> Result<u64, CapacityObservationFailure> {
    linux::observe_memory_bytes()
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn observe_memory() -> Result<u64, CapacityObservationFailure> {
    Err(CapacityObservationFailure::UnsupportedPlatform)
}

fn observe_file_descriptors() -> Result<u64, CapacityObservationFailure> {
    let limit = getrlimit(Resource::Nofile);
    let finite_limit = match limit.current.or(limit.maximum) {
        Some(limit) => limit,
        None => infinite_descriptor_ceiling()?,
    };
    let open = open_file_descriptor_count()?;
    detected_descriptor_capacity(finite_limit, open)
}

fn detected_descriptor_capacity(
    finite_limit: u64,
    open: u64,
) -> Result<u64, CapacityObservationFailure> {
    finite_limit
        .checked_sub(open)
        .and_then(|remaining| remaining.checked_add(RETAINED_PRIMARY_VOLUME_DESCRIPTORS))
        .ok_or(CapacityObservationFailure::Arithmetic {
            source: CapacityObservationSource::ProcessFileDescriptors,
        })
}

#[cfg(target_os = "macos")]
fn infinite_descriptor_ceiling() -> Result<u64, CapacityObservationFailure> {
    positron_darwin_system::maximum_file_descriptor_count().map_err(|_| {
        CapacityObservationFailure::ObservationUnavailable {
            source: CapacityObservationSource::ProcessFileDescriptors,
        }
    })
}

#[cfg(target_os = "linux")]
fn infinite_descriptor_ceiling() -> Result<u64, CapacityObservationFailure> {
    use std::io::Read as _;

    const MAX_LIMIT_BYTES: usize = 64;
    let mut file = std::fs::File::open("/proc/sys/fs/nr_open").map_err(|_| {
        CapacityObservationFailure::ObservationUnavailable {
            source: CapacityObservationSource::ProcessFileDescriptors,
        }
    })?;
    let mut bytes = [0_u8; MAX_LIMIT_BYTES];
    let mut length = 0_usize;
    while length < bytes.len() {
        let count = file.read(&mut bytes[length..]).map_err(|_| {
            CapacityObservationFailure::ObservationUnavailable {
                source: CapacityObservationSource::ProcessFileDescriptors,
            }
        })?;
        if count == 0 {
            break;
        }
        length = length
            .checked_add(count)
            .ok_or(CapacityObservationFailure::Arithmetic {
                source: CapacityObservationSource::ProcessFileDescriptors,
            })?;
    }
    let mut overflow = [0_u8; 1];
    if file
        .read(&mut overflow)
        .map_err(|_| CapacityObservationFailure::ObservationUnavailable {
            source: CapacityObservationSource::ProcessFileDescriptors,
        })?
        != 0
    {
        return Err(CapacityObservationFailure::ObservationUnavailable {
            source: CapacityObservationSource::ProcessFileDescriptors,
        });
    }
    let text = std::str::from_utf8(&bytes[..length]).map_err(|_| {
        CapacityObservationFailure::MalformedLimit {
            source: CapacityObservationSource::ProcessFileDescriptors,
        }
    })?;
    let ceiling =
        text.trim()
            .parse::<u64>()
            .map_err(|_| CapacityObservationFailure::MalformedLimit {
                source: CapacityObservationSource::ProcessFileDescriptors,
            })?;
    nonzero(ResourceDimension::FileDescriptors, ceiling)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn infinite_descriptor_ceiling() -> Result<u64, CapacityObservationFailure> {
    Err(CapacityObservationFailure::UnsupportedPlatform)
}

#[cfg(target_os = "macos")]
fn open_file_descriptor_count() -> Result<u64, CapacityObservationFailure> {
    positron_darwin_system::open_file_descriptor_count().map_err(|_| {
        CapacityObservationFailure::ObservationUnavailable {
            source: CapacityObservationSource::ProcessFileDescriptors,
        }
    })
}

#[cfg(target_os = "linux")]
fn open_file_descriptor_count() -> Result<u64, CapacityObservationFailure> {
    const MAX_OPEN_DESCRIPTORS: u64 = 65_536;
    let entries = std::fs::read_dir("/proc/self/fd").map_err(|_| {
        CapacityObservationFailure::ObservationUnavailable {
            source: CapacityObservationSource::ProcessFileDescriptors,
        }
    })?;
    let mut count = 0_u64;
    for entry in entries {
        entry.map_err(|_| CapacityObservationFailure::ObservationUnavailable {
            source: CapacityObservationSource::ProcessFileDescriptors,
        })?;
        count = count
            .checked_add(1)
            .ok_or(CapacityObservationFailure::Arithmetic {
                source: CapacityObservationSource::ProcessFileDescriptors,
            })?;
        if count > MAX_OPEN_DESCRIPTORS {
            return Err(CapacityObservationFailure::ObservationUnavailable {
                source: CapacityObservationSource::ProcessFileDescriptors,
            });
        }
    }
    // `read_dir` retains one observer descriptor while enumerating; keeping it
    // in the count is a conservative transient baseline.
    Ok(count)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn open_file_descriptor_count() -> Result<u64, CapacityObservationFailure> {
    Err(CapacityObservationFailure::UnsupportedPlatform)
}

pub(super) fn observe_disk_bytes(
    volume: &crate::OwnedPrimaryDataVolume,
) -> Result<u64, CapacityObservationFailure> {
    let statistics = fstatvfs(&volume._root).map_err(|_| {
        CapacityObservationFailure::ObservationUnavailable {
            source: CapacityObservationSource::PrimaryVolumeFilesystem,
        }
    })?;
    let bytes = statistics.f_bavail.checked_mul(statistics.f_frsize).ok_or(
        CapacityObservationFailure::Arithmetic {
            source: CapacityObservationSource::PrimaryVolumeFilesystem,
        },
    )?;
    nonzero(ResourceDimension::DiskHeadroomBytes, bytes)
}

fn nonzero(dimension: ResourceDimension, value: u64) -> Result<u64, CapacityObservationFailure> {
    if value == 0 {
        Err(CapacityObservationFailure::ZeroCapacity { dimension })
    } else {
        Ok(value)
    }
}

#[cfg(test)]
#[path = "capacity_observation/tests/general.rs"]
mod tests;
