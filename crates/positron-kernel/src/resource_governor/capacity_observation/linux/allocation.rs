//! Explicitly fallible bounded storage used before governor establishment.

use std::ffi::OsString;
use std::io::Read;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

use crate::resource_governor::{CapacityObservationFailure, CapacityObservationSource};

const READ_SCRATCH_BYTES: usize = 4_096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AllocationStage {
    FileBuffer,
    ResolvedPath,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct AllocationControl {
    fail_at: Option<AllocationStage>,
}

impl AllocationControl {
    pub(super) const NONE: Self = Self { fail_at: None };

    #[cfg(test)]
    pub(super) const fn failing(stage: AllocationStage) -> Self {
        Self {
            fail_at: Some(stage),
        }
    }

    fn reserve(
        self,
        bytes: &mut Vec<u8>,
        capacity: usize,
        stage: AllocationStage,
        source: CapacityObservationSource,
    ) -> Result<(), CapacityObservationFailure> {
        if self.fail_at == Some(stage) {
            return Err(CapacityObservationFailure::AllocationUnavailable { source });
        }
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| CapacityObservationFailure::AllocationUnavailable { source })
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct BoundedBytes {
    bytes: Vec<u8>,
}

impl BoundedBytes {
    pub(super) fn read(
        mut reader: impl Read,
        maximum: u64,
        source: CapacityObservationSource,
        control: AllocationControl,
    ) -> Result<Self, CapacityObservationFailure> {
        let maximum = usize::try_from(maximum)
            .map_err(|_| CapacityObservationFailure::Arithmetic { source })?;
        let mut bytes = Vec::new();
        control.reserve(&mut bytes, maximum, AllocationStage::FileBuffer, source)?;
        let mut scratch = [0_u8; READ_SCRATCH_BYTES];
        while bytes.len() < maximum {
            let remaining = maximum.saturating_sub(bytes.len());
            let requested = remaining.min(scratch.len());
            let count = reader
                .read(&mut scratch[..requested])
                .map_err(|_| CapacityObservationFailure::ObservationUnavailable { source })?;
            if count == 0 {
                return Ok(Self { bytes });
            }
            bytes.extend_from_slice(&scratch[..count]);
        }
        let mut overflow = [0_u8; 1];
        let count = reader
            .read(&mut overflow)
            .map_err(|_| CapacityObservationFailure::ObservationUnavailable { source })?;
        if count != 0 {
            Err(CapacityObservationFailure::ObservationUnavailable { source })
        } else {
            Ok(Self { bytes })
        }
    }

    #[cfg(test)]
    pub(super) fn from_slice(
        contents: &[u8],
        maximum: u64,
        source: CapacityObservationSource,
    ) -> Result<Self, CapacityObservationFailure> {
        Self::read(contents, maximum, source, AllocationControl::NONE)
    }

    pub(super) fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

pub(super) struct BoundedPathBytes {
    bytes: Vec<u8>,
    maximum: usize,
}

impl BoundedPathBytes {
    pub(super) fn new(
        required_capacity: usize,
        maximum: usize,
        source: CapacityObservationSource,
        control: AllocationControl,
    ) -> Result<Self, CapacityObservationFailure> {
        if required_capacity == 0 || required_capacity > maximum {
            return Err(CapacityObservationFailure::MalformedLimit { source });
        }
        let mut bytes = Vec::new();
        control.reserve(
            &mut bytes,
            required_capacity,
            AllocationStage::ResolvedPath,
            source,
        )?;
        Ok(Self { bytes, maximum })
    }

    pub(super) fn push(
        &mut self,
        byte: u8,
        source: CapacityObservationSource,
    ) -> Result<(), CapacityObservationFailure> {
        if self.bytes.len() >= self.maximum || self.bytes.len() >= self.bytes.capacity() {
            return Err(CapacityObservationFailure::MalformedLimit { source });
        }
        self.bytes.push(byte);
        Ok(())
    }

    pub(super) fn extend(
        &mut self,
        value: &[u8],
        source: CapacityObservationSource,
    ) -> Result<(), CapacityObservationFailure> {
        let next = self
            .bytes
            .len()
            .checked_add(value.len())
            .ok_or(CapacityObservationFailure::Arithmetic { source })?;
        if next > self.maximum || next > self.bytes.capacity() {
            return Err(CapacityObservationFailure::MalformedLimit { source });
        }
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    pub(super) fn into_path(self) -> PathBuf {
        PathBuf::from(OsString::from_vec(self.bytes))
    }
}

#[cfg(test)]
#[path = "../tests/allocation.rs"]
mod tests;
