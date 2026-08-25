use super::LedgerFailure;
#[cfg(any(test, fuzzing, feature = "test-support"))]
use super::io::map_errno;
#[cfg(any(test, fuzzing, feature = "test-support"))]
use std::cell::RefCell;

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
    #[cfg(any(test, fuzzing, feature = "test-support"))]
    BeforeLeaseUsageReconciliation,
    #[cfg(any(test, fuzzing, feature = "test-support"))]
    BeforeLeaseMarkerPublication,
    #[cfg(any(test, fuzzing, feature = "test-support"))]
    BeforeLeaseCreationReconciliation,
}

pub(super) fn emit_event(_event: LedgerFileEvent) -> Result<(), LedgerFailure> {
    #[cfg(any(test, fuzzing, feature = "test-support"))]
    if matches!(
        _event,
        LedgerFileEvent::BeforeLeaseUsagePublication
            | LedgerFileEvent::AfterLeaseUsagePublication
            | LedgerFileEvent::BeforeLeaseUsageReconciliation
            | LedgerFileEvent::BeforeLeaseMarkerPublication
            | LedgerFileEvent::BeforeLeaseCreationReconciliation
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
    static LEDGER_FAULT: RefCell<Option<Vec<(LedgerFileEvent, rustix::io::Errno)>>> = const { RefCell::new(None) };
}

#[cfg(any(test, fuzzing, feature = "test-support"))]
fn injected_errno(event: LedgerFileEvent) -> Option<rustix::io::Errno> {
    LEDGER_FAULT.with(|fault| {
        let mut fault = fault.borrow_mut();
        let sequence = fault.as_mut()?;
        if sequence
            .first()
            .is_some_and(|(candidate, _)| *candidate == event)
        {
            let (_, error) = sequence.remove(0);
            if sequence.is_empty() {
                *fault = None;
            }
            Some(error)
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
        let previous = fault.replace(Some(vec![(event, error)]));
        let result = action();
        fault.replace(previous);
        result
    })
}

#[cfg(any(test, fuzzing))]
pub(crate) fn with_ledger_fault_sequence<T>(
    events: &[LedgerFileEvent],
    action: impl FnOnce() -> T,
) -> T {
    LEDGER_FAULT.with(|fault| {
        let previous = fault.replace(Some(
            events
                .iter()
                .copied()
                .map(|event| (event, rustix::io::Errno::IO))
                .collect(),
        ));
        let result = action();
        fault.replace(previous);
        result
    })
}
