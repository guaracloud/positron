use std::io::{Seek, SeekFrom, Write};

use crate::data_protection::{EncryptedFrame, ObjectDataKey};

use super::*;

impl LedgerStorage {
    pub(in crate::active_segment_ledger) fn append_and_commit<R>(
        &self,
        key: &ObjectDataKey,
        sequence: u64,
        position: positron_domain::routing::CommitPosition,
        frame_bytes: u32,
        protect_frame: impl FnOnce() -> Result<EncryptedFrame, LedgerFailure>,
        admit_durability: impl FnOnce() -> Result<R, LedgerFailure>,
    ) -> Result<[u8; 32], AppendFailure> {
        let unchanged = SegmentMutation::NotStarted;
        let metadata = self
            .current
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))
            .map_err(|failure| unchanged.failure(failure))?;
        let mut file = open_regular(&self.active, &segment_name(metadata.id), true)
            .map_err(|failure| unchanged.failure(failure))?;
        file.seek(SeekFrom::End(0))
            .map_err(map_io_error)
            .map_err(|failure| unchanged.failure(failure))?;
        emit_event(LedgerFileEvent::WriteFrame).map_err(|failure| unchanged.failure(failure))?;
        let prefix = frame_bytes.to_be_bytes();
        let partial = injected_partial_write_length(LedgerFileEvent::PartialFrameWrite, 4);
        let prefix_bytes = partial.map_or(prefix.as_slice(), |length| &prefix[..length]);
        let mutation = write_segment_bytes(&mut file, prefix_bytes, SegmentMutation::NotStarted)?;
        if partial.is_some() {
            return Err(mutation.failure(LedgerFailure::new(LedgerFailureCode::StorageUnavailable)));
        }
        let encrypted = protect_frame().map_err(|failure| mutation.failure(failure))?;
        write_segment_bytes(&mut file, encrypted.as_bytes(), mutation)?;
        let _durability = admit_durability().map_err(|failure| mutation.failure(failure))?;
        emit_event(LedgerFileEvent::SynchronizeFrame)
            .map_err(|failure| mutation.failure(failure))?;
        synchronize(&file).map_err(|failure| mutation.failure(failure))?;
        emit_event(LedgerFileEvent::InspectSegmentMetadata)
            .map_err(|failure| mutation.failure(failure))?;
        let durable_bytes = file
            .metadata()
            .map_err(map_io_error)
            .map_err(|failure| mutation.failure(failure))?
            .len();
        publish_frontier(
            &self.active,
            metadata.id,
            key,
            durable_bytes,
            sequence
                .checked_add(1)
                .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))
                .map_err(|failure| mutation.failure(failure))?,
            position,
        )
        .map_err(|failure| mutation.failure(failure))
    }
}

pub(in crate::active_segment_ledger) fn write_segment_bytes(
    file: &mut impl Write,
    bytes: &[u8],
    mut mutation: SegmentMutation,
) -> Result<SegmentMutation, AppendFailure> {
    let mut written = 0_usize;
    while written < bytes.len() {
        match file.write(&bytes[written..]) {
            Ok(0) => {
                return Err(mutation.failure(map_io_error(std::io::Error::from(
                    std::io::ErrorKind::WriteZero,
                ))));
            },
            Ok(count) => {
                written = written.checked_add(count).ok_or_else(|| {
                    mutation.failure(LedgerFailure::new(LedgerFailureCode::LimitExceeded))
                })?;
                mutation = SegmentMutation::BytesWritten;
            },
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {},
            Err(error) => return Err(mutation.failure(map_io_error(error))),
        }
    }
    Ok(mutation)
}
