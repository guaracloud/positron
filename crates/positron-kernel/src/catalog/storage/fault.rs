use super::super::types::CatalogFailure;

#[cfg(any(test, fuzzing, feature = "test-support"))]
use super::super::types::CatalogFailureCode;
#[cfg(any(test, fuzzing, feature = "test-support"))]
use std::boxed::Box;
#[cfg(any(test, fuzzing, feature = "test-support"))]
use std::cell::RefCell;

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
    BeforeLeaseMarkerBasis,
}

pub(super) fn injected_partial_write_length(
    _event: CatalogFileEvent,
    _payload_length: usize,
) -> Option<usize> {
    #[cfg(any(test, fuzzing, feature = "test-support"))]
    if should_inject(_event, None) {
        return Some(_payload_length / 2);
    }
    None
}

pub(super) fn emit_event(_event: CatalogFileEvent) -> Result<(), CatalogFailure> {
    #[cfg(any(test, fuzzing, feature = "test-support"))]
    if should_inject(_event, None) {
        return Err(CatalogFailure::new(CatalogFailureCode::StorageUnavailable));
    }
    Ok(())
}

#[cfg(any(test, fuzzing, feature = "test-support"))]
thread_local! {
    static CATALOG_FAULT: RefCell<Option<CatalogFault>> = const { RefCell::new(None) };
}

#[cfg(any(test, fuzzing, feature = "test-support"))]
type CatalogFaultHook = dyn for<'a> Fn(&'a crate::catalog::Catalog<'a>);

#[cfg(any(test, fuzzing, feature = "test-support"))]
struct CatalogFault {
    event: CatalogFileEvent,
    remaining: usize,
    fail: bool,
    hook: Option<Box<CatalogFaultHook>>,
}

#[cfg(any(test, fuzzing, feature = "test-support"))]
fn should_inject(event: CatalogFileEvent, catalog: Option<&crate::catalog::Catalog<'_>>) -> bool {
    let (fail, hook) = CATALOG_FAULT.with(|fault| {
        let mut fault = fault.borrow_mut();
        let Some(selected) = fault.as_mut() else {
            return (false, None);
        };
        if selected.event != event {
            return (false, None);
        }
        if selected.remaining > 0 {
            selected.remaining -= 1;
            return (false, None);
        }
        let Some(selected) = fault.take() else {
            return (false, None);
        };
        (selected.fail, selected.hook)
    });
    if let Some(hook) = hook
        && let Some(catalog) = catalog
    {
        hook(catalog);
    }
    fail
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
        let previous = fault.replace(Some(CatalogFault {
            event,
            remaining: preceding_occurrences,
            fail: true,
            hook: None,
        }));
        let result = action();
        fault.replace(previous);
        result
    })
}

#[cfg(any(test, fuzzing, feature = "test-support"))]
pub(crate) fn with_catalog_fault_hook_after<T>(
    event: CatalogFileEvent,
    preceding_occurrences: usize,
    hook: impl for<'a> Fn(&'a crate::catalog::Catalog<'a>) + 'static,
    action: impl FnOnce() -> T,
) -> T {
    CATALOG_FAULT.with(|fault| {
        let previous = fault.replace(Some(CatalogFault {
            event,
            remaining: preceding_occurrences,
            fail: false,
            hook: Some(Box::new(hook)),
        }));
        let result = action();
        fault.replace(previous);
        result
    })
}

#[cfg(any(test, fuzzing, feature = "test-support"))]
pub(crate) fn before_lease_marker_basis(
    catalog: &crate::catalog::Catalog<'_>,
) -> Result<(), CatalogFailure> {
    if should_inject(CatalogFileEvent::BeforeLeaseMarkerBasis, Some(catalog)) {
        Err(CatalogFailure::new(CatalogFailureCode::StorageUnavailable))
    } else {
        Ok(())
    }
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

/// Runs one action after the marker-resume publication seam has been reached.
/// The hook uses the same one-shot Catalog storage fault authority as crash
/// injection, but does not fail the operation itself.
#[cfg(feature = "test-support")]
pub fn with_catalog_publication_hook_after<T>(
    preceding_occurrences: usize,
    hook: impl for<'a> Fn(&'a crate::catalog::Catalog<'a>) + 'static,
    action: impl FnOnce() -> T,
) -> T {
    with_catalog_fault_hook_after(
        CatalogFileEvent::BeforeLeaseMarkerBasis,
        preceding_occurrences,
        hook,
        action,
    )
}
