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
use super::io::{map_errno, map_integrity_read, map_io_error, open_regular, synchronize};
use super::receipt::receipt_authenticator;
use super::{
    CommittedBlock, LedgerFailure, LedgerFailureCode, MAX_ENCODED_FRAME_BYTES,
    MAX_RETAINED_BLOCK_BYTES, SegmentId, StoreBlockIdentity, map_frame_failure,
};
const FRONTIER_MAGIC: &[u8; 8] = b"PFRONT02";
const FRONTIER_PREFIX_BYTES: usize = 8 + 2 + 2 + 4;
const FRONTIER_PLAINTEXT_BYTES: usize = 8 + 8 + 8;
const MAX_FRONTIER_FRAME_BYTES: u32 = 512;
const MAX_RECOVERED_BLOCKS: usize = 1_024;

mod publication;
pub(super) use publication::publish_frontier;

pub(super) struct RecoveryState {
    pub(super) frontier: CommitPosition,
    pub(super) blocks: Vec<CommittedBlock>,
}

#[derive(Clone, Copy)]
pub(super) enum RecoveryMode {
    Repair,
    Observe,
}
struct PublishedFrontier {
    durable_bytes: u64,
    next_sequence: u64,
    position: CommitPosition,
}

#[cfg(test)]
pub(super) fn recover(
    segment_directory: &File,
    frontier_directory: &File,
    metadata: SegmentMetadata,
    key: &ObjectDataKey,
    header_bytes: usize,
    allow_post_frontier_truncation: bool,
) -> Result<RecoveryState, LedgerFailure> {
    recover_with_mode(
        segment_directory,
        frontier_directory,
        metadata,
        key,
        header_bytes,
        RecoveryMode::Repair,
        allow_post_frontier_truncation,
    )
}

pub(super) fn recover_with_mode(
    segment_directory: &File,
    frontier_directory: &File,
    metadata: SegmentMetadata,
    key: &ObjectDataKey,
    header_bytes: usize,
    mode: RecoveryMode,
    allow_post_frontier_truncation: bool,
) -> Result<RecoveryState, LedgerFailure> {
    let may_repair = matches!(mode, RecoveryMode::Repair) && allow_post_frontier_truncation;
    let mut file = open_regular(segment_directory, &segment_name(metadata.id), may_repair)?;
    let frontier = read_frontier(frontier_directory, metadata.id, key)?;
    let file_length = file.metadata().map_err(map_io_error)?.len();
    let header_length = u64::try_from(header_bytes)
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let Some(PublishedFrontier {
        durable_bytes,
        next_sequence,
        position,
    }) = frontier
    else {
        if file_length < header_length {
            return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
        }
        if file_length > header_length {
            if matches!(mode, RecoveryMode::Observe) {
                return Ok(RecoveryState {
                    frontier: metadata.base_position,
                    blocks: Vec::new(),
                });
            }
            if !may_repair {
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
        if matches!(mode, RecoveryMode::Observe) {
            // The authenticated durability frontier bounds the read. Bytes after
            // it are an unacknowledged tail and remain untouched by observers.
        } else if !may_repair {
            return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
        } else {
            emit_event(LedgerFileEvent::TruncatePostFrontier)?;
            file.set_len(durable_bytes).map_err(map_io_error)?;
            synchronize(&file)?;
        }
    }
    file.seek(SeekFrom::Start(header_length))
        .map_err(map_io_error)?;
    let blocks = read_blocks(
        &mut file,
        durable_bytes - header_length,
        metadata.base_position,
        metadata.id,
        header_length,
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
    header_bytes: u64,
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
        let content_digest = DataProtection::hash(payload)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::StorageUnavailable))?;
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
        consumed = consumed
            .checked_add(4)
            .and_then(|value| value.checked_add(frame_bytes as u64))
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        if consumed > encoded_bytes {
            return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
        }
        let durable_bytes = header_bytes
            .checked_add(consumed)
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        let frontier_authenticator = receipt_authenticator(
            key,
            durable_bytes,
            sequence
                .checked_add(1)
                .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?,
            position,
        )?;
        blocks.push(CommittedBlock {
            identity,
            position,
            payload: payload.to_vec(),
            content_digest,
            segment,
            frontier_authenticator,
        });
    }
    Ok(blocks)
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
