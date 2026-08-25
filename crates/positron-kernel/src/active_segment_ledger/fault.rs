use super::LedgerFailure;
#[cfg(any(test, fuzzing, feature = "test-support"))]
use super::io::map_errno;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LedgerFileEvent {
    WriteFrame,
    PartialFrameWrite,
    SynchronizeFrame,
    InspectSegmentMetadata,
    RemoveFrontierTemporary,
    CreateFrontierTemporary,
    WriteFrontier,
    PartialFrontierWrite,
    SynchronizeFrontier,
    RenameFrontier,
    SynchronizeFrontierDirectory,
    TruncatePostFrontier,
    RenameSealSegment,
    RenameSealFrontier,
    SynchronizeSealedDirectory,
    SynchronizeActiveDirectory,
    CreateSegment,
    WriteSegmentHeader,
    PartialSegmentHeaderWrite,
    SynchronizeSegmentHeader,
    SynchronizeSegmentDirectory,
    #[cfg(any(test, fuzzing, feature = "test-support"))]
    BeforeLeaseUsagePublication,
    #[cfg(any(test, fuzzing, feature = "test-support"))]
    AfterLeaseUsagePublication,
}

pub(super) fn emit_event(_event: LedgerFileEvent) -> Result<(), LedgerFailure> {
    #[cfg(any(test, fuzzing, feature = "test-support"))]
    if matches!(
        _event,
        LedgerFileEvent::BeforeLeaseUsagePublication | LedgerFileEvent::AfterLeaseUsagePublication
    ) && injected_errno(_event).is_some()
    {
        return Err(LedgerFailure::ambiguous(
            super::LedgerFailureCode::StorageUnavailable,
        ));
    }
    #[cfg(any(test, fuzzing, feature = "test-support"))]
    if let Some(error) = injected_errno(_event) {
        return Err(map_errno(error));
    }
    Ok(())
}

#[cfg(any(test, fuzzing, feature = "test-support"))]
thread_local! {
    static LEDGER_FAULT: std::cell::Cell<Option<(LedgerFileEvent, rustix::io::Errno)>> = const { std::cell::Cell::new(None) };
}

#[cfg(any(test, fuzzing, feature = "test-support"))]
fn injected_errno(event: LedgerFileEvent) -> Option<rustix::io::Errno> {
    LEDGER_FAULT.with(|fault| {
        if fault.get().is_some_and(|(candidate, _)| candidate == event) {
            let error = fault.get().map(|(_, error)| error);
            fault.set(None);
            error
        } else {
            None
        }
    })
}

#[cfg(any(test, fuzzing, feature = "test-support"))]
pub(super) fn injected_partial_write_length(
    event: LedgerFileEvent,
    length: usize,
) -> Option<usize> {
    injected_errno(event).map(|_| length.saturating_sub(1).max(1))
}

#[cfg(not(any(test, fuzzing, feature = "test-support")))]
pub(super) const fn injected_partial_write_length(
    _event: LedgerFileEvent,
    _length: usize,
) -> Option<usize> {
    None
}

#[cfg(any(test, fuzzing))]
pub(crate) fn with_ledger_fault<T>(event: LedgerFileEvent, action: impl FnOnce() -> T) -> T {
    with_ledger_errno(event, rustix::io::Errno::IO, action)
}

#[cfg(any(test, fuzzing))]
pub(crate) fn with_ledger_errno<T>(
    event: LedgerFileEvent,
    error: rustix::io::Errno,
    action: impl FnOnce() -> T,
) -> T {
    LEDGER_FAULT.with(|fault| {
        let previous = fault.replace(Some((event, error)));
        let result = action();
        fault.set(previous);
        result
    })
}
