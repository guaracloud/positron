use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::num::NonZeroU64;

use positron_domain::routing::CommitPosition;
use rustix::fs::{self as unix_fs, Mode, OFlags};

use crate::data_protection::{
    DataProtection, FrameFailureCode, FrameLimits, FrameSequence, ObjectDataKey,
    SegmentFramePurpose,
};

use super::fault::{LedgerFileEvent, emit_event, injected_partial_write_length};
use super::format::{SegmentMetadata, position_from_value};
use super::io::{map_errno, map_io_error, open_regular, synchronize};
use super::{
    CommittedBlock, LedgerFailure, LedgerFailureCode, MAX_ENCODED_FRAME_BYTES,
    MAX_RETAINED_BLOCK_BYTES, SegmentId, StoreBlockIdentity, map_frame_failure,
};
const FRONTIER_MAGIC: &[u8; 8] = b"PFRONT02";
const FRONTIER_PREFIX_BYTES: usize = 8 + 2 + 2 + 4;
const FRONTIER_PLAINTEXT_BYTES: usize = 8 + 8 + 8;
const MAX_FRONTIER_FRAME_BYTES: u32 = 512;
const MAX_RECOVERED_BLOCKS: usize = 1_024;

pub(super) struct RecoveryState {
    pub(super) frontier: CommitPosition,
    pub(super) blocks: Vec<CommittedBlock>,
}
struct PublishedFrontier {
    durable_bytes: u64,
    next_sequence: u64,
    position: CommitPosition,
    authenticator: [u8; 32],
}

pub(super) fn recover(
    segment_directory: &File,
    frontier_directory: &File,
    metadata: SegmentMetadata,
    key: &ObjectDataKey,
    header_bytes: usize,
    allow_post_frontier_truncation: bool,
) -> Result<RecoveryState, LedgerFailure> {
    let mut file = open_regular(
        segment_directory,
        &segment_name(metadata.id),
        allow_post_frontier_truncation,
    )?;
    let frontier = read_frontier(frontier_directory, metadata.id, key)?;
    let file_length = file.metadata().map_err(map_io_error)?.len();
    let header_length = u64::try_from(header_bytes)
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let Some(PublishedFrontier {
        durable_bytes,
        next_sequence,
        position,
        authenticator,
    }) = frontier
    else {
        if file_length < header_length {
            return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
        }
        if file_length > header_length {
            if !allow_post_frontier_truncation {
                return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
            }
            emit_event(LedgerFileEvent::TruncatePostFrontier)?;
            file.set_len(header_length).map_err(map_io_error)?;
            synchronize(&file)?;
        }
        return Ok(RecoveryState {
            frontier: metadata.base_position,
            blocks: Vec::new(),
        });
    };
    if durable_bytes < header_length || file_length < durable_bytes {
        return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
    }
    if file_length > durable_bytes {
        if !allow_post_frontier_truncation {
            return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
        }
        emit_event(LedgerFileEvent::TruncatePostFrontier)?;
        file.set_len(durable_bytes).map_err(map_io_error)?;
        synchronize(&file)?;
    }
    file.seek(SeekFrom::Start(header_length))
        .map_err(map_io_error)?;
    let blocks = read_blocks(
        &mut file,
        durable_bytes - header_length,
        metadata.base_position,
        metadata.id,
        authenticator,
        key,
    )?;
    let expected_blocks = usize::try_from(next_sequence)
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?;
    if blocks.len() != expected_blocks
        || position.value()
            != metadata
                .base_position
                .value()
                .checked_add(next_sequence)
                .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?
    {
        return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
    }
    Ok(RecoveryState {
        frontier: position,
        blocks,
    })
}

pub(super) fn read_blocks(
    file: &mut File,
    encoded_bytes: u64,
    base: CommitPosition,
    segment: SegmentId,
    frontier_authenticator: [u8; 32],
    key: &ObjectDataKey,
) -> Result<Vec<CommittedBlock>, LedgerFailure> {
    let mut blocks = Vec::new();
    let mut consumed = 0_u64;
    let mut plaintext_bytes = 0_usize;
    while consumed < encoded_bytes {
        if blocks.len() >= MAX_RECOVERED_BLOCKS {
            return Err(LedgerFailure::new(LedgerFailureCode::LimitExceeded));
        }
        let mut length = [0_u8; 4];
        file.read_exact(&mut length).map_err(map_integrity_read)?;
        let frame_bytes = usize::try_from(u32::from_be_bytes(length))
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        if frame_bytes > MAX_ENCODED_FRAME_BYTES as usize {
            return Err(LedgerFailure::new(LedgerFailureCode::LimitExceeded));
        }
        let mut frame = vec![0_u8; frame_bytes];
        file.read_exact(&mut frame).map_err(map_integrity_read)?;
        let sequence = u64::try_from(blocks.len())
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        let context = key
            .object
            .frame(
                SegmentFramePurpose::StoreBlock,
                FrameSequence::new(
                    sequence
                        .checked_add(1)
                        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?,
                ),
            )
            .map_err(map_frame_failure)?;
        let verified = DataProtection::open_frame(
            key,
            context,
            &frame,
            FrameLimits::new(MAX_ENCODED_FRAME_BYTES).map_err(map_frame_failure)?,
        )
        .map_err(map_frame_failure)?;
        let plaintext = verified.as_plaintext();
        let identity = StoreBlockIdentity::new(
            plaintext
                .get(..16)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?,
        )
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?;
        let payload = plaintext
            .get(16..)
            .filter(|bytes| !bytes.is_empty())
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?;
        plaintext_bytes = plaintext_bytes
            .checked_add(payload.len())
            .filter(|bytes| *bytes <= MAX_RETAINED_BLOCK_BYTES)
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        let increment = sequence
            .checked_add(1)
            .and_then(NonZeroU64::new)
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        let position = base
            .advance_by(increment)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        blocks.push(CommittedBlock {
            identity,
            position,
            payload: payload.to_vec(),
            segment,
            frontier_authenticator,
        });
        consumed = consumed
            .checked_add(4)
            .and_then(|value| value.checked_add(frame_bytes as u64))
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        if consumed > encoded_bytes {
            return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
        }
    }
    Ok(blocks)
}

pub(super) fn publish_frontier(
    directory: &File,
    id: SegmentId,
    key: &ObjectDataKey,
    durable_bytes: u64,
    next_sequence: u64,
    position: CommitPosition,
) -> Result<[u8; 32], LedgerFailure> {
    let mut plaintext = Vec::with_capacity(FRONTIER_PLAINTEXT_BYTES);
    plaintext.extend_from_slice(&durable_bytes.to_be_bytes());
    plaintext.extend_from_slice(&next_sequence.to_be_bytes());
    plaintext.extend_from_slice(&position.value().to_be_bytes());
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
    encoded.extend_from_slice(&1_u16.to_be_bytes());
    encoded.extend_from_slice(&frame_length.to_be_bytes());
    encoded.extend_from_slice(frame.as_bytes());
    let authenticator =
        DataProtection::authenticate_object_key(key, &encoded).map_err(map_frame_failure)?;
    let temporary = frontier_temporary_name(id);
    match unix_fs::unlinkat(directory, &temporary, rustix::fs::AtFlags::empty()) {
        Ok(()) | Err(rustix::io::Errno::NOENT) => {},
        Err(error) => return Err(map_errno(error)),
    }
    emit_event(LedgerFileEvent::WriteFrontier)
        .map_err(|failure| LedgerFailure::post_mutation(failure.code()))?;
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
        file.write_all(&encoded[..partial])
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

fn read_frontier(
    directory: &File,
    id: SegmentId,
    key: &ObjectDataKey,
) -> Result<Option<PublishedFrontier>, LedgerFailure> {
    let file = match unix_fs::openat(
        directory,
        frontier_name(id),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(file) => File::from(file),
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => return Err(map_errno(error)),
    };
    let mut reader = file;
    let mut prefix = [0_u8; FRONTIER_PREFIX_BYTES];
    reader.read_exact(&mut prefix).map_err(map_integrity_read)?;
    if prefix.get(..8) != Some(FRONTIER_MAGIC.as_slice())
        || prefix.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
    {
        return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
    }
    if prefix.get(10..12) != Some(1_u16.to_be_bytes().as_slice()) {
        return Err(LedgerFailure::new(LedgerFailureCode::UnsupportedFormat));
    }
    let frame_bytes = usize::try_from(u32::from_be_bytes(
        prefix
            .get(12..16)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?,
    ))
    .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    if frame_bytes == 0 || frame_bytes > MAX_FRONTIER_FRAME_BYTES as usize {
        return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
    }
    let mut frame = vec![0_u8; frame_bytes];
    reader.read_exact(&mut frame).map_err(map_integrity_read)?;
    let mut trailing = [0_u8; 1];
    if reader.read(&mut trailing).map_err(map_io_error)? != 0 {
        return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
    }
    let limits = FrameLimits::new(MAX_FRONTIER_FRAME_BYTES).map_err(map_frame_failure)?;
    let mut opened = None;
    for candidate in 0..=u64::try_from(MAX_RECOVERED_BLOCKS)
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?
    {
        let context = key
            .object
            .frame(
                SegmentFramePurpose::DurabilityFrontier,
                FrameSequence::new(
                    u64::MAX
                        .checked_sub(candidate)
                        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?,
                ),
            )
            .map_err(map_frame_failure)?;
        match DataProtection::open_frame(key, context, &frame, limits) {
            Ok(verified) => {
                opened = Some((candidate, verified));
                break;
            },
            Err(failure) if failure.code() == FrameFailureCode::AuthenticationFailed => {},
            Err(failure) => return Err(map_frame_failure(failure)),
        }
    }
    let (frame_sequence, verified) =
        opened.ok_or_else(|| LedgerFailure::new(LedgerFailureCode::AuthenticationFailed))?;
    let plaintext = verified.as_plaintext();
    if plaintext.len() != FRONTIER_PLAINTEXT_BYTES {
        return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
    }
    let mut authenticated = Vec::with_capacity(FRONTIER_PREFIX_BYTES + frame.len());
    authenticated.extend_from_slice(&prefix);
    authenticated.extend_from_slice(&frame);
    let authenticator =
        DataProtection::authenticate_object_key(key, &authenticated).map_err(map_frame_failure)?;
    let durable_bytes = read_u64(plaintext, 0)?;
    let next_sequence = read_u64(plaintext, 8)?;
    if next_sequence != frame_sequence {
        return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
    }
    let position = position_from_value(read_u64(plaintext, 16)?)?;
    Ok(Some(PublishedFrontier {
        durable_bytes,
        next_sequence,
        position,
        authenticator,
    }))
}

pub(super) fn segment_name(id: SegmentId) -> String {
    format!("{}.segment", super::io::hex(id.to_bytes()))
}

pub(super) fn frontier_name(id: SegmentId) -> String {
    format!("{}.frontier", super::io::hex(id.to_bytes()))
}

pub(super) fn frontier_temporary_name(id: SegmentId) -> String {
    format!("{}.frontier.tmp", super::io::hex(id.to_bytes()))
}

fn read_u64(bytes: &[u8], start: usize) -> Result<u64, LedgerFailure> {
    bytes
        .get(start..start + 8)
        .and_then(|value| value.try_into().ok())
        .map(u64::from_be_bytes)
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))
}

fn map_integrity_read(error: std::io::Error) -> LedgerFailure {
    let storage = map_io_error(error);
    if storage.code() == LedgerFailureCode::StorageExhausted {
        storage
    } else {
        LedgerFailure::new(LedgerFailureCode::IntegrityCorruption)
    }
}
