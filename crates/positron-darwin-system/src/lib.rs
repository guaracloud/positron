//! Narrow safe macOS host-resource observations.

use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DarwinSystemObservationError {
    PhysicalMemoryUnavailable,
    HostAvailableMemoryUnavailable,
    HostAvailableMemoryZero,
    HostAvailableMemoryArithmetic,
    HostPortDeallocationUnavailable,
    FileDescriptorCountUnavailable,
    FileDescriptorCountExceedsBound,
    FileDescriptorCeilingUnavailable,
}

impl Display for DarwinSystemObservationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("macOS system resource observation failed")
    }
}

impl Error for DarwinSystemObservationError {}

#[cfg(target_os = "macos")]
mod native;

#[cfg(target_os = "macos")]
pub fn physical_memory_bytes() -> Result<u64, DarwinSystemObservationError> {
    native::physical_memory_bytes()
}

#[cfg(target_os = "macos")]
pub fn process_available_memory_bytes() -> Result<Option<u64>, DarwinSystemObservationError> {
    native::process_available_memory_bytes()
}

#[cfg(target_os = "macos")]
pub fn host_available_memory_bytes() -> Result<u64, DarwinSystemObservationError> {
    native::host_available_memory_bytes()
}

#[cfg(target_os = "macos")]
pub fn open_file_descriptor_count() -> Result<u64, DarwinSystemObservationError> {
    native::open_file_descriptor_count()
}

#[cfg(target_os = "macos")]
pub fn maximum_file_descriptor_count() -> Result<u64, DarwinSystemObservationError> {
    native::maximum_file_descriptor_count()
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::{
        DarwinSystemObservationError, checked_host_available_memory_bytes,
        host_available_memory_bytes, maximum_file_descriptor_count, open_file_descriptor_count,
        physical_memory_bytes, process_available_memory_bytes,
    };

    #[test]
    fn live_memory_observations_are_positive() {
        let physical = physical_memory_bytes();
        assert!(
            physical.is_ok(),
            "physical observation failed: {physical:?}"
        );
        let available = process_available_memory_bytes();
        assert!(
            available.is_ok(),
            "process limit probe failed: {available:?}"
        );
        let host_available = host_available_memory_bytes();
        assert!(
            host_available.is_ok(),
            "host-available observation failed: {host_available:?}"
        );
        assert!(physical.unwrap_or_default() > 0);
        assert!(host_available.unwrap_or_default() > 0);
        assert!(open_file_descriptor_count().is_ok());
        assert!(maximum_file_descriptor_count().unwrap_or_default() > 0);
    }

    #[test]
    fn host_available_memory_arithmetic_is_checked() {
        assert_eq!(checked_host_available_memory_bytes(2, 3, 4), Ok(20));
        assert_eq!(
            checked_host_available_memory_bytes(0, 0, 4),
            Err(DarwinSystemObservationError::HostAvailableMemoryZero)
        );
        assert_eq!(
            checked_host_available_memory_bytes(u64::MAX, 1, 1),
            Err(DarwinSystemObservationError::HostAvailableMemoryArithmetic)
        );
        assert_eq!(
            checked_host_available_memory_bytes(1, 1, u64::MAX),
            Err(DarwinSystemObservationError::HostAvailableMemoryArithmetic)
        );
    }
}

#[cfg(target_os = "macos")]
fn checked_host_available_memory_bytes(
    free_pages: u64,
    inactive_pages: u64,
    page_size: u64,
) -> Result<u64, DarwinSystemObservationError> {
    let available_pages = free_pages
        .checked_add(inactive_pages)
        .ok_or(DarwinSystemObservationError::HostAvailableMemoryArithmetic)?;
    let available_bytes = available_pages
        .checked_mul(page_size)
        .ok_or(DarwinSystemObservationError::HostAvailableMemoryArithmetic)?;
    if available_bytes == 0 {
        Err(DarwinSystemObservationError::HostAvailableMemoryZero)
    } else {
        Ok(available_bytes)
    }
}
