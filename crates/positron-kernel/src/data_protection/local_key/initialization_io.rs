//! Durable initialization I/O and deterministic failure injection.

use std::fs::File;
use std::io::{self, Write};
use std::time::{SystemTime, SystemTimeError, UNIX_EPOCH};

use crate::data_protection::{CryptoBackend, CryptoBackendFailure, RustCryptoBackend};

pub(super) fn fill_random(destination: &mut [u8]) -> Result<(), CryptoBackendFailure> {
    #[cfg(test)]
    if take_matching_fault(|fault| {
        fault == InitializationFault::Entropy
            || (fault == InitializationFault::RootKeyEntropy && destination.len() == 32)
    })
    .is_some()
    {
        return Err(CryptoBackendFailure::EntropyUnavailable);
    }
    RustCryptoBackend.fill_random(destination)
}

pub(super) fn unix_creation_seconds() -> Result<u64, SystemTimeError> {
    #[cfg(test)]
    if take_matching_fault(|fault| fault == InitializationFault::Clock).is_some() {
        return UNIX_EPOCH
            .duration_since(SystemTime::now())
            .map(|duration| duration.as_secs());
    }
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
}

pub(super) fn write_new_key(file: &mut File, payload: &[u8]) -> Result<(), io::Error> {
    #[cfg(test)]
    if let Some(InitializationFault::PartialWrite(length)) =
        take_matching_fault(|fault| matches!(fault, InitializationFault::PartialWrite(_)))
    {
        let prefix = payload
            .get(..length.min(payload.len()))
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        file.write_all(prefix)?;
        return Err(io::Error::from(io::ErrorKind::Other));
    }
    file.write_all(payload)
}

pub(super) fn synchronize_key_file(file: &File) -> Result<(), io::Error> {
    #[cfg(test)]
    if take_matching_fault(|fault| fault == InitializationFault::SynchronizeKeyFile).is_some() {
        return Err(io::Error::from(io::ErrorKind::Other));
    }
    file.sync_all()
}

pub(super) fn synchronize_security_directory(directory: &File) -> Result<(), io::Error> {
    #[cfg(test)]
    if take_matching_fault(|fault| fault == InitializationFault::SynchronizeSecurityDirectory)
        .is_some()
    {
        return Err(io::Error::from(io::ErrorKind::Other));
    }
    directory.sync_all()
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InitializationFault {
    PartialWrite(usize),
    SynchronizeKeyFile,
    SynchronizeSecurityDirectory,
    Entropy,
    RootKeyEntropy,
    Clock,
}

#[cfg(test)]
pub(super) fn with_initialization_fault<T>(
    fault: InitializationFault,
    operation: impl FnOnce() -> T,
) -> T {
    INITIALIZATION_FAULT.with(|injected| {
        let previous = injected.replace(Some(fault));
        let result = operation();
        injected.set(previous);
        result
    })
}

#[cfg(test)]
thread_local! {
    static INITIALIZATION_FAULT: std::cell::Cell<Option<InitializationFault>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn take_matching_fault(
    matches: impl FnOnce(InitializationFault) -> bool,
) -> Option<InitializationFault> {
    INITIALIZATION_FAULT.with(|injected| {
        let fault = injected.get();
        if fault.is_some_and(matches) {
            injected.take()
        } else {
            None
        }
    })
}
