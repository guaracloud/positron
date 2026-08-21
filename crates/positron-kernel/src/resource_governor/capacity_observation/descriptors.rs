//! Process file-descriptor capacity observation.

use rustix::process::{Resource, getrlimit};

use super::{CapacityObservationFailure, CapacityObservationSource};
#[cfg(target_os = "linux")]
use super::{ResourceDimension, nonzero};

const RETAINED_PRIMARY_VOLUME_DESCRIPTORS: u64 = 2;

pub(super) fn observe_file_descriptors() -> Result<u64, CapacityObservationFailure> {
    let limit = getrlimit(Resource::Nofile);
    let finite_limit = match limit.current.or(limit.maximum) {
        Some(limit) => limit,
        None => infinite_descriptor_ceiling()?,
    };
    let open = open_file_descriptor_count()?;
    detected_descriptor_capacity(finite_limit, open)
}

pub(super) fn detected_descriptor_capacity(
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
pub(super) fn open_file_descriptor_count() -> Result<u64, CapacityObservationFailure> {
    positron_darwin_system::open_file_descriptor_count().map_err(|_| {
        CapacityObservationFailure::ObservationUnavailable {
            source: CapacityObservationSource::ProcessFileDescriptors,
        }
    })
}

#[cfg(target_os = "linux")]
pub(super) fn open_file_descriptor_count() -> Result<u64, CapacityObservationFailure> {
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
pub(super) fn open_file_descriptor_count() -> Result<u64, CapacityObservationFailure> {
    Err(CapacityObservationFailure::UnsupportedPlatform)
}
