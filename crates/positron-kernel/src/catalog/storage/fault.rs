use super::super::types::CatalogFailure;

#[cfg(any(test, fuzzing, feature = "test-support"))]
use super::super::types::CatalogFailureCode;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CatalogFileEvent {
    SynchronizeTransactionDigest,
    SynchronizeTransactionDirectory,
    WriteObject,
    PartialObjectWrite,
    SynchronizeObject,
    SynchronizeObjectDirectory,
    ReserveAudit,
    WriteAudit,
    PartialAuditWrite,
    SynchronizeAudit,
    SynchronizeAuditDirectory,
    WriteCommit,
    PartialCommitWrite,
    SynchronizeCommit,
    SynchronizeCommitDirectory,
    WriteMarker,
    PartialMarkerWrite,
    SynchronizeMarker,
    RenameMarker,
    SynchronizeGenerationDirectory,
    PartialRewrapWrite,
    SynchronizeRewrap,
    SynchronizeRewrapDirectory,
}

pub(super) fn injected_partial_write_length(
    _event: CatalogFileEvent,
    _payload_length: usize,
) -> Option<usize> {
    #[cfg(any(test, fuzzing, feature = "test-support"))]
    if should_inject(_event) {
        return Some(_payload_length / 2);
    }
    None
}

pub(super) fn emit_event(_event: CatalogFileEvent) -> Result<(), CatalogFailure> {
    #[cfg(any(test, fuzzing, feature = "test-support"))]
    if should_inject(_event) {
        return Err(CatalogFailure::new(CatalogFailureCode::StorageUnavailable));
    }
    Ok(())
}

#[cfg(any(test, fuzzing, feature = "test-support"))]
thread_local! {
    static CATALOG_FAULT: std::cell::Cell<Option<(CatalogFileEvent, usize)>> = const { std::cell::Cell::new(None) };
}

#[cfg(any(test, fuzzing, feature = "test-support"))]
fn should_inject(event: CatalogFileEvent) -> bool {
    CATALOG_FAULT.with(|fault| match fault.get() {
        Some((selected, 0)) if selected == event => {
            fault.set(None);
            true
        },
        Some((selected, remaining)) if selected == event => {
            fault.set(Some((selected, remaining - 1)));
            false
        },
        _ => false,
    })
}

#[cfg(any(test, fuzzing))]
pub(crate) fn with_catalog_fault<T>(event: CatalogFileEvent, action: impl FnOnce() -> T) -> T {
    with_catalog_fault_after(event, 0, action)
}

#[cfg(any(test, fuzzing, feature = "test-support"))]
pub(crate) fn with_catalog_fault_after<T>(
    event: CatalogFileEvent,
    preceding_occurrences: usize,
    action: impl FnOnce() -> T,
) -> T {
    CATALOG_FAULT.with(|fault| {
        let previous = fault.replace(Some((event, preceding_occurrences)));
        let result = action();
        fault.set(previous);
        result
    })
}

/// Narrow catalog-publication fault controls for cross-crate integration tests.
///
/// This is available only through the non-default `test-support` feature and
/// delegates to the same one-shot catalog storage fault authority used by the
/// kernel's own crash tests.
#[cfg(feature = "test-support")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatalogPublicationFault {
    SynchronizeCommit,
}

#[cfg(feature = "test-support")]
impl CatalogPublicationFault {
    const fn storage_event(self) -> CatalogFileEvent {
        match self {
            Self::SynchronizeCommit => CatalogFileEvent::SynchronizeCommit,
        }
    }
}

/// Injects one typed catalog publication failure after the requested number of
/// matching events. This never exists in a default product build.
#[cfg(feature = "test-support")]
pub fn with_catalog_publication_fault_after<T>(
    fault: CatalogPublicationFault,
    preceding_occurrences: usize,
    action: impl FnOnce() -> T,
) -> T {
    with_catalog_fault_after(fault.storage_event(), preceding_occurrences, action)
}
