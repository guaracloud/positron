use super::*;
use crate::active_segment_ledger::SegmentRetention;

pub(in crate::active_segment_ledger) fn publish_frontier(
    directory: &File,
    id: SegmentId,
    key: &ObjectDataKey,
    durable_bytes: u64,
    next_sequence: u64,
    position: CommitPosition,
    segment_retention: SegmentRetention,
) -> Result<[u8; 32], LedgerFailure> {
    let mut plaintext = Vec::with_capacity(FRONTIER_V2_PLAINTEXT_BYTES);
    plaintext.extend_from_slice(&durable_bytes.to_be_bytes());
    plaintext.extend_from_slice(&next_sequence.to_be_bytes());
    plaintext.extend_from_slice(&position.value().to_be_bytes());
    let (retention_tag, retention_instant) = match segment_retention {
        SegmentRetention::Empty => (0_u8, 0_i64),
        SegmentRetention::Unavailable => (1_u8, 0_i64),
        SegmentRetention::Complete(instant) => (2_u8, instant.instant().value()),
    };
    plaintext.push(retention_tag);
    plaintext.extend_from_slice(&retention_instant.to_be_bytes());
    let context = key
        .object
        .frame(
            SegmentFramePurpose::DurabilityFrontier,
            FrameSequence::new(
                u64::MAX
                    .checked_sub(next_sequence)
                    .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?,
            ),
        )
        .map_err(map_frame_failure)?;
    let frame = DataProtection::protect_frame(
        key,
        context,
        &plaintext,
        FrameLimits::new(MAX_FRONTIER_FRAME_BYTES).map_err(map_frame_failure)?,
    )
    .map_err(map_frame_failure)?;
    let frame_length = u32::try_from(frame.as_bytes().len())
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let mut encoded = Vec::with_capacity(FRONTIER_PREFIX_BYTES + frame.as_bytes().len());
    encoded.extend_from_slice(FRONTIER_MAGIC);
    encoded.extend_from_slice(&1_u16.to_be_bytes());
    encoded.extend_from_slice(&3_u16.to_be_bytes());
    encoded.extend_from_slice(&frame_length.to_be_bytes());
    encoded.extend_from_slice(frame.as_bytes());
    let authenticator = receipt_authenticator(key, durable_bytes, next_sequence, position)?;
    let temporary = frontier_temporary_name(id);
    emit_event(LedgerFileEvent::RemoveFrontierTemporary)?;
    match unix_fs::unlinkat(directory, &temporary, rustix::fs::AtFlags::empty()) {
        Ok(()) | Err(rustix::io::Errno::NOENT) => {},
        Err(error) => return Err(map_errno(error)),
    }
    emit_event(LedgerFileEvent::WriteFrontier)
        .map_err(|failure| LedgerFailure::post_mutation(failure.code()))?;
    emit_event(LedgerFileEvent::CreateFrontierTemporary)?;
    let mut file = unix_fs::openat(
        directory,
        &temporary,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map(File::from)
    .map_err(map_errno)?;
    use std::io::Write;
    if let Some(partial) =
        injected_partial_write_length(LedgerFileEvent::PartialFrontierWrite, encoded.len())
    {
        let partial_bytes = encoded
            .get(..partial)
            .ok_or_else(|| LedgerFailure::post_mutation(LedgerFailureCode::IntegrityCorruption))?;
        file.write_all(partial_bytes)
            .map_err(|error| LedgerFailure::post_mutation(map_io_error(error).code()))?;
        return Err(LedgerFailure::post_mutation(
            LedgerFailureCode::StorageUnavailable,
        ));
    }
    file.write_all(&encoded)
        .map_err(|error| LedgerFailure::post_mutation(map_io_error(error).code()))?;
    emit_event(LedgerFileEvent::SynchronizeFrontier)
        .map_err(|failure| LedgerFailure::post_mutation(failure.code()))?;
    synchronize(&file).map_err(|failure| LedgerFailure::post_mutation(failure.code()))?;
    emit_event(LedgerFileEvent::RenameFrontier)
        .map_err(|failure| LedgerFailure::post_mutation(failure.code()))?;
    unix_fs::renameat(directory, &temporary, directory, frontier_name(id))
        .map_err(|error| LedgerFailure::post_mutation(map_errno(error).code()))?;
    emit_event(LedgerFileEvent::SynchronizeFrontierDirectory)
        .map_err(|failure| LedgerFailure::ambiguous(failure.code()))?;
    synchronize(directory).map_err(|failure| LedgerFailure::ambiguous(failure.code()))?;
    Ok(authenticator)
}
