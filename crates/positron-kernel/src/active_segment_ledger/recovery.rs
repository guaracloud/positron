use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::num::NonZeroU64;

use positron_domain::routing::CommitPosition;
use rustix::fs::{self as unix_fs, Mode, OFlags};

use crate::data_protection::{
    DataProtection, FrameLimits, FrameSequence, ObjectDataKey, SegmentFramePurpose,
};

use super::fault::{LedgerFileEvent, emit_event, injected_partial_write_length};
use super::format::{SegmentMetadata, position_from_value};
use super::io::{open_regular, synchronize};
use super::{
    CommittedBlock, LedgerFailure, LedgerFailureCode, MAX_ENCODED_FRAME_BYTES,
    MAX_RETAINED_BLOCK_BYTES, SegmentId, map_frame_failure,
};

const FRONTIER_MAGIC: &[u8; 8] = b"PFRONT01";
const FRONTIER_PREFIX_BYTES: usize = 8 + 2 + 16 + 8 + 8 + 8;
const FRONTIER_BYTES: usize = FRONTIER_PREFIX_BYTES + 32;
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
    let file_length = file
        .metadata()
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::StorageUnavailable))?
        .len();
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
            file.set_len(header_length)
                .map_err(|_| LedgerFailure::new(LedgerFailureCode::StorageUnavailable))?;
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
        file.set_len(durable_bytes)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::StorageUnavailable))?;
        synchronize(&file)?;
    }
    file.seek(SeekFrom::Start(header_length))
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::StorageUnavailable))?;
    let blocks = read_blocks(
        &mut file,
        durable_bytes - header_length,
        metadata.base_position,
        metadata.id,
        authenticator,
        key,
    )?;
    if blocks.len() != usize::try_from(next_sequence).unwrap_or(usize::MAX)
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
        file.read_exact(&mut length)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?;
        let frame_bytes = usize::try_from(u32::from_be_bytes(length))
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        if frame_bytes > MAX_ENCODED_FRAME_BYTES as usize {
            return Err(LedgerFailure::new(LedgerFailureCode::LimitExceeded));
        }
        let mut frame = vec![0_u8; frame_bytes];
        file.read_exact(&mut frame)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?;
        let sequence = u64::try_from(blocks.len())
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        let context = key
            .object
            .frame(
                SegmentFramePurpose::StoreBlock,
                FrameSequence::new(sequence),
            )
            .map_err(map_frame_failure)?;
        let verified = DataProtection::open_frame(
            key,
            context,
            &frame,
            FrameLimits::new(MAX_ENCODED_FRAME_BYTES).map_err(map_frame_failure)?,
        )
        .map_err(map_frame_failure)?;
        plaintext_bytes = plaintext_bytes
            .checked_add(verified.as_plaintext().len())
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
            position,
            payload: verified.as_plaintext().to_vec(),
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
    let mut prefix = Vec::with_capacity(FRONTIER_PREFIX_BYTES);
    prefix.extend_from_slice(FRONTIER_MAGIC);
    prefix.extend_from_slice(&1_u16.to_be_bytes());
    prefix.extend_from_slice(&id.to_bytes());
    prefix.extend_from_slice(&durable_bytes.to_be_bytes());
    prefix.extend_from_slice(&next_sequence.to_be_bytes());
    prefix.extend_from_slice(&position.value().to_be_bytes());
    let authenticator =
        DataProtection::authenticate_object_key(key, &prefix).map_err(map_frame_failure)?;
    let mut encoded = prefix;
    encoded.extend_from_slice(&authenticator);
    let temporary = frontier_temporary_name(id);
    match unix_fs::unlinkat(directory, &temporary, rustix::fs::AtFlags::empty()) {
        Ok(()) | Err(rustix::io::Errno::NOENT) => {},
        Err(_) => return Err(LedgerFailure::new(LedgerFailureCode::StorageUnavailable)),
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
    .map_err(|_| LedgerFailure::new(LedgerFailureCode::StorageUnavailable))?;
    use std::io::Write;
    if let Some(partial) =
        injected_partial_write_length(LedgerFileEvent::PartialFrontierWrite, encoded.len())
    {
        file.write_all(&encoded[..partial])
            .map_err(|_| LedgerFailure::post_mutation(LedgerFailureCode::StorageUnavailable))?;
        return Err(LedgerFailure::post_mutation(
            LedgerFailureCode::StorageUnavailable,
        ));
    }
    file.write_all(&encoded)
        .map_err(|_| LedgerFailure::post_mutation(LedgerFailureCode::StorageUnavailable))?;
    emit_event(LedgerFileEvent::SynchronizeFrontier)
        .map_err(|failure| LedgerFailure::post_mutation(failure.code()))?;
    synchronize(&file).map_err(|failure| LedgerFailure::post_mutation(failure.code()))?;
    emit_event(LedgerFileEvent::RenameFrontier)
        .map_err(|failure| LedgerFailure::post_mutation(failure.code()))?;
    unix_fs::renameat(directory, &temporary, directory, frontier_name(id))
        .map_err(|_| LedgerFailure::post_mutation(LedgerFailureCode::StorageUnavailable))?;
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
        Err(_) => return Err(LedgerFailure::new(LedgerFailureCode::StorageUnavailable)),
    };
    let mut encoded = [0_u8; FRONTIER_BYTES];
    let mut reader = file;
    reader
        .read_exact(&mut encoded)
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?;
    let mut trailing = [0_u8; 1];
    if reader
        .read(&mut trailing)
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::StorageUnavailable))?
        != 0
    {
        return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
    }
    if encoded.get(..8) != Some(FRONTIER_MAGIC.as_slice())
        || encoded.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
        || encoded.get(10..26) != Some(id.to_bytes().as_slice())
    {
        return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
    }
    let prefix: &[u8; FRONTIER_PREFIX_BYTES] = encoded
        .get(..FRONTIER_PREFIX_BYTES)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?;
    let authenticator: &[u8; 32] = encoded
        .get(FRONTIER_PREFIX_BYTES..)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?;
    DataProtection::verify_object_authentication(key, prefix, authenticator)
        .map_err(map_frame_failure)?;
    let durable_bytes = read_u64(&encoded, 26)?;
    let next_sequence = read_u64(&encoded, 34)?;
    let position = position_from_value(read_u64(&encoded, 42)?)?;
    Ok(Some(PublishedFrontier {
        durable_bytes,
        next_sequence,
        position,
        authenticator: *authenticator,
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
