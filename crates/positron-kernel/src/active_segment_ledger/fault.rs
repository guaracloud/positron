use super::LedgerFailure;
#[cfg(any(test, fuzzing))]
use super::LedgerFailureCode;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LedgerFileEvent {
    WriteFrame,
    PartialFrameWrite,
    SynchronizeFrame,
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
}

pub(super) fn emit_event(_event: LedgerFileEvent) -> Result<(), LedgerFailure> {
    #[cfg(any(test, fuzzing))]
    if let Some(code) = injected_code(_event) {
        return Err(LedgerFailure::new(code));
    }
    Ok(())
}

#[cfg(any(test, fuzzing))]
thread_local! {
    static LEDGER_FAULT: std::cell::Cell<Option<(LedgerFileEvent, LedgerFailureCode)>> = const { std::cell::Cell::new(None) };
}

#[cfg(any(test, fuzzing))]
fn injected_code(event: LedgerFileEvent) -> Option<LedgerFailureCode> {
    LEDGER_FAULT.with(|fault| {
        if fault.get().is_some_and(|(candidate, _)| candidate == event) {
            let code = fault.get().map(|(_, code)| code);
            fault.set(None);
            code
        } else {
            None
        }
    })
}

#[cfg(any(test, fuzzing))]
pub(super) fn injected_partial_write_length(
    event: LedgerFileEvent,
    length: usize,
) -> Option<usize> {
    injected_code(event).map(|_| length.saturating_sub(1).max(1))
}

#[cfg(not(any(test, fuzzing)))]
pub(super) const fn injected_partial_write_length(
    _event: LedgerFileEvent,
    _length: usize,
) -> Option<usize> {
    None
}

#[cfg(any(test, fuzzing))]
pub(crate) fn with_ledger_fault<T>(event: LedgerFileEvent, action: impl FnOnce() -> T) -> T {
    with_ledger_fault_code(event, LedgerFailureCode::StorageUnavailable, action)
}

#[cfg(any(test, fuzzing))]
pub(crate) fn with_ledger_fault_code<T>(
    event: LedgerFileEvent,
    code: LedgerFailureCode,
    action: impl FnOnce() -> T,
) -> T {
    LEDGER_FAULT.with(|fault| {
        let previous = fault.replace(Some((event, code)));
        let result = action();
        fault.set(previous);
        result
    })
}
