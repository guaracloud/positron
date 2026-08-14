use std::fs::File;
use std::io::{Read, Write};
use std::sync::Arc;

use rustix::fs::{self as unix_fs, AtFlags, Dir, Mode, OFlags};

use crate::OwnedPrimaryDataVolume;
use crate::catalog::{CatalogSnapshot, InstanceId};
use crate::data_protection::{
    DataProtection, FrameLimits, FrameSequence, ObjectDataKey, SegmentFramePurpose,
};

use super::fault::{
    LedgerFileEvent, LedgerOperationFaultSource, emit_event, emit_injected_event,
    injected_partial_write_length,
};
use super::format::{
    SegmentMetadata, SegmentState, decode_header, decode_metadata, encode_header, encode_metadata,
};
use super::io::{map_errno, map_io_error, open_or_create_directory, open_regular, synchronize};
use super::recovery::frontier_temporary_name;
use super::recovery::{
    RecoveryState, frontier_name, publish_frontier_with_operation_fault, recover, segment_name,
};
use super::{
    LedgerFailure, LedgerFailureCode, SegmentId, SegmentProtectionKey, SegmentScope,
    map_frame_failure, object_context,
};

mod append;
#[cfg(test)]
pub(super) use append::write_segment_bytes;

const MAX_SEGMENTS: usize = 1_024;
const MAX_HEADER_BYTES: usize = 512;
const MAX_ENCRYPTED_METADATA_BYTES: u32 = 256;

pub(super) enum AppendFailure {
    RejectedBeforeMutation(LedgerFailure),
    SegmentMutated(LedgerFailure),
}

#[derive(Clone, Copy)]
pub(super) enum SegmentMutation {
    NotStarted,
    BytesWritten,
}

impl SegmentMutation {
    fn failure(self, failure: LedgerFailure) -> AppendFailure {
        match self {
            Self::NotStarted => AppendFailure::RejectedBeforeMutation(failure),
            Self::BytesWritten => {
                let failure = match failure.completion_state() {
                    super::LedgerCompletionState::CommitAmbiguous => failure,
                    super::LedgerCompletionState::RejectedBeforeMutation
                    | super::LedgerCompletionState::RecoveryRequired => {
                        LedgerFailure::post_mutation(failure.code())
                    },
                };
                AppendFailure::SegmentMutated(failure)
            },
        }
    }
}

pub(super) struct LedgerStorage {
    active: File,
    sealed: File,
    current: Option<SegmentMetadata>,
    fault_scope: Option<SegmentScope>,
    fault_source: Option<Arc<dyn LedgerOperationFaultSource>>,
}

impl LedgerStorage {
    pub(super) fn open(volume: &OwnedPrimaryDataVolume) -> Result<Self, LedgerFailure> {
        let segments = open_or_create_directory(&volume._root, "segments")?;
        let active = open_or_create_directory(&segments, "active")?;
        let sealed = open_or_create_directory(&segments, "sealed")?;
        synchronize(&segments)?;
        synchronize(&volume._root)?;
        Ok(Self {
            active,
            sealed,
            current: None,
            fault_scope: None,
            fault_source: None,
        })
    }

    pub(super) fn open_with_operation_faults(
        volume: &OwnedPrimaryDataVolume,
        scope: SegmentScope,
        source: Arc<dyn LedgerOperationFaultSource>,
    ) -> Result<Self, LedgerFailure> {
        let mut storage = Self::open(volume)?;
        storage.fault_scope = Some(scope);
        storage.fault_source = Some(source);
        Ok(storage)
    }

    pub(super) fn catalog_segments(
        &self,
        snapshot: &CatalogSnapshot,
        scope: SegmentScope,
    ) -> Result<Vec<SegmentMetadata>, LedgerFailure> {
        let mut all_segments = Vec::new();
        for plaintext in snapshot.plaintext_objects() {
            if let Some(metadata) = decode_metadata(plaintext)? {
                all_segments.push(metadata);
            }
        }
        self.reject_unpublished_entries(&all_segments)?;
        let mut segments: Vec<_> = all_segments
            .into_iter()
            .filter(|metadata| metadata.scope == scope)
            .collect();
        if segments
            .iter()
            .filter(|metadata| metadata.state == SegmentState::Active)
            .count()
            > 1
        {
            return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
        }
        segments.sort_by_key(|metadata| metadata.base_position);
        Ok(segments)
    }

    fn reject_unpublished_entries(
        &self,
        metadata: &[SegmentMetadata],
    ) -> Result<(), LedgerFailure> {
        for (directory, active_namespace) in [(&self.active, true), (&self.sealed, false)] {
            let mut entries = Dir::read_from(directory).map_err(map_errno)?;
            let mut count = 0_usize;
            let mut removed = false;
            while let Some(entry) = entries.read() {
                let entry = entry.map_err(map_errno)?;
                let name = entry.file_name().to_bytes();
                if name == b"." || name == b".." {
                    continue;
                }
                count = count
                    .checked_add(1)
                    .filter(|count| *count <= MAX_SEGMENTS * 2)
                    .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
                let published = metadata.iter().any(|segment| {
                    name == segment_name(segment.id).as_bytes()
                        || name == frontier_name(segment.id).as_bytes()
                        || (active_namespace
                            && segment.state == SegmentState::Active
                            && name == frontier_temporary_name(segment.id).as_bytes())
                });
                if !published {
                    if active_namespace && recognized_ledger_name(name) {
                        unix_fs::unlinkat(directory, name, AtFlags::empty()).map_err(map_errno)?;
                        removed = true;
                    } else {
                        return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
                    }
                }
            }
            if removed {
                synchronize(directory)?;
            }
        }
        Ok(())
    }

    pub(super) fn create_active(
        &mut self,
        metadata: SegmentMetadata,
        protection: &SegmentProtectionKey,
        instance: InstanceId,
    ) -> Result<ObjectDataKey, LedgerFailure> {
        if metadata.state != SegmentState::Active {
            return Err(LedgerFailure::new(LedgerFailureCode::InvalidInput));
        }
        let object = object_context(metadata.scope, metadata.id)?;
        let key = DataProtection::random_key(object).map_err(map_frame_failure)?;
        let wrapped = DataProtection::wrap_segment_key_with_route(
            &protection.key,
            &key,
            instance.to_bytes(),
            protection.route,
        )
        .map_err(map_frame_failure)?;
        let metadata_context = object
            .frame(SegmentFramePurpose::SegmentMetadata, FrameSequence::new(0))
            .map_err(map_frame_failure)?;
        let encrypted_metadata = DataProtection::protect_frame(
            &key,
            metadata_context,
            &encode_metadata(metadata),
            FrameLimits::new(MAX_ENCRYPTED_METADATA_BYTES).map_err(map_frame_failure)?,
        )
        .map_err(map_frame_failure)?;
        let header = encode_header(protection.route, &wrapped, encrypted_metadata.as_bytes())?;
        emit_event(LedgerFileEvent::CreateSegment)?;
        let mut file = unix_fs::openat(
            &self.active,
            segment_name(metadata.id),
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map(File::from)
        .map_err(map_errno)?;
        emit_event(LedgerFileEvent::WriteSegmentHeader)
            .map_err(|failure| LedgerFailure::post_mutation(failure.code()))?;
        if let Some(length) =
            injected_partial_write_length(LedgerFileEvent::PartialSegmentHeaderWrite, header.len())
        {
            file.write_all(&header[..length])
                .map_err(|error| LedgerFailure::post_mutation(map_io_error(error).code()))?;
            return Err(LedgerFailure::post_mutation(
                LedgerFailureCode::StorageUnavailable,
            ));
        }
        file.write_all(&header)
            .map_err(|error| LedgerFailure::post_mutation(map_io_error(error).code()))?;
        emit_event(LedgerFileEvent::SynchronizeSegmentHeader)
            .map_err(|failure| LedgerFailure::post_mutation(failure.code()))?;
        synchronize(&file).map_err(|failure| LedgerFailure::post_mutation(failure.code()))?;
        emit_event(LedgerFileEvent::SynchronizeSegmentDirectory)
            .map_err(|failure| LedgerFailure::post_mutation(failure.code()))?;
        synchronize(&self.active)
            .map_err(|failure| LedgerFailure::post_mutation(failure.code()))?;
        self.current = Some(metadata);
        Ok(key)
    }

    pub(super) fn recover_segment(
        &self,
        metadata: SegmentMetadata,
        protection: &SegmentProtectionKey,
        instance: InstanceId,
    ) -> Result<(ObjectDataKey, RecoveryState), LedgerFailure> {
        let catalog_active = metadata.state == SegmentState::Active;
        if catalog_active {
            match unix_fs::unlinkat(
                &self.active,
                frontier_temporary_name(metadata.id),
                AtFlags::empty(),
            ) {
                Ok(()) => synchronize(&self.active)?,
                Err(rustix::io::Errno::NOENT) => {},
                Err(error) => return Err(map_errno(error)),
            }
        }
        let active_exists = entry_exists(&self.active, &segment_name(metadata.id))?;
        let sealed_exists = entry_exists(&self.sealed, &segment_name(metadata.id))?;
        let (directory, recoverable_tail) = match (active_exists, sealed_exists, catalog_active) {
            (true, false, true) => (&self.active, true),
            (false, true, true) => (&self.sealed, true),
            (false, true, false) => (&self.sealed, false),
            _ => return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption)),
        };
        let active_frontier = entry_exists(&self.active, &frontier_name(metadata.id))?;
        let sealed_frontier = entry_exists(&self.sealed, &frontier_name(metadata.id))?;
        let frontier_directory = match (active_frontier, sealed_frontier, catalog_active) {
            (true, false, true) => &self.active,
            (false, true, _) => &self.sealed,
            (false, false, _) => directory,
            _ => return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption)),
        };
        let mut file = open_regular(directory, &segment_name(metadata.id), recoverable_tail)?;
        let mut header = vec![0_u8; MAX_HEADER_BYTES];
        let bytes = file.read(&mut header).map_err(map_io_error)?;
        header.truncate(bytes);
        let decoded = decode_header(&header)?;
        if decoded.route != protection.route {
            return Err(LedgerFailure::new(LedgerFailureCode::AuthenticationFailed));
        }
        let object = object_context(metadata.scope, metadata.id)?;
        let key = DataProtection::unwrap_segment_key_with_route(
            &protection.key,
            decoded.wrapped_key,
            instance.to_bytes(),
            object,
            decoded.route,
        )
        .map_err(map_frame_failure)?;
        let metadata_context = object
            .frame(SegmentFramePurpose::SegmentMetadata, FrameSequence::new(0))
            .map_err(map_frame_failure)?;
        let verified_metadata = DataProtection::open_frame(
            &key,
            metadata_context,
            decoded.encrypted_metadata,
            FrameLimits::new(MAX_ENCRYPTED_METADATA_BYTES).map_err(map_frame_failure)?,
        )
        .map_err(map_frame_failure)?;
        let physical_metadata = decode_metadata(verified_metadata.as_plaintext())?
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::AuthenticationFailed))?;
        if physical_metadata.state != SegmentState::Active
            || physical_metadata.scope != metadata.scope
            || physical_metadata.id != metadata.id
            || physical_metadata.base_position != metadata.base_position
        {
            return Err(LedgerFailure::new(LedgerFailureCode::AuthenticationFailed));
        }
        let state = recover(
            directory,
            frontier_directory,
            metadata,
            &key,
            decoded.encoded_bytes,
            recoverable_tail,
        )?;
        Ok((key, state))
    }

    pub(super) fn seal(&self, metadata: SegmentMetadata) -> Result<(), LedgerFailure> {
        let active_exists = entry_exists(&self.active, &segment_name(metadata.id))?;
        let sealed_exists = entry_exists(&self.sealed, &segment_name(metadata.id))?;
        match (active_exists, sealed_exists) {
            (true, false) => {
                emit_event(LedgerFileEvent::RenameSealSegment)?;
                unix_fs::renameat(
                    &self.active,
                    segment_name(metadata.id),
                    &self.sealed,
                    segment_name(metadata.id),
                )
                .map_err(map_errno)?;
            },
            (false, true) => {},
            _ => return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption)),
        }
        let active_frontier = entry_exists(&self.active, &frontier_name(metadata.id))?;
        let sealed_frontier = entry_exists(&self.sealed, &frontier_name(metadata.id))?;
        match (active_frontier, sealed_frontier) {
            (true, false) => {
                emit_event(LedgerFileEvent::RenameSealFrontier)
                    .map_err(|failure| LedgerFailure::post_mutation(failure.code()))?;
                unix_fs::renameat(
                    &self.active,
                    frontier_name(metadata.id),
                    &self.sealed,
                    frontier_name(metadata.id),
                )
                .map_err(|error| LedgerFailure::post_mutation(map_errno(error).code()))?;
            },
            (false, true) | (false, false) => {},
            (true, true) => {
                return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
            },
        }
        emit_event(LedgerFileEvent::SynchronizeSealedDirectory)
            .map_err(|failure| LedgerFailure::post_mutation(failure.code()))?;
        synchronize(&self.sealed)
            .map_err(|failure| LedgerFailure::post_mutation(failure.code()))?;
        emit_event(LedgerFileEvent::SynchronizeActiveDirectory)
            .map_err(|failure| LedgerFailure::post_mutation(failure.code()))?;
        synchronize(&self.active).map_err(|failure| LedgerFailure::post_mutation(failure.code()))
    }

    pub(super) fn metadata_object(&self, metadata: SegmentMetadata) -> Vec<u8> {
        encode_metadata(metadata)
    }

    pub(super) fn is_scope_metadata(&self, bytes: &[u8], scope: SegmentScope) -> bool {
        decode_metadata(bytes)
            .ok()
            .flatten()
            .is_some_and(|metadata| metadata.scope == scope)
    }

    pub(super) fn set_current(&mut self, metadata: SegmentMetadata) {
        self.current = Some(metadata);
    }

    pub(super) fn segment_id(&self) -> Result<SegmentId, LedgerFailure> {
        self.current
            .map(|metadata| metadata.id)
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))
    }

    pub(super) fn current_metadata(&self) -> Result<SegmentMetadata, LedgerFailure> {
        self.current
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))
    }
}

pub(super) fn recognized_ledger_name(name: &[u8]) -> bool {
    [b".segment".as_slice(), b".frontier", b".frontier.tmp"]
        .iter()
        .filter_map(|suffix| name.strip_suffix(*suffix))
        .any(|prefix| prefix.len() == 32 && prefix.iter().all(u8::is_ascii_hexdigit))
}

pub(super) fn entry_exists(directory: &File, name: &str) -> Result<bool, LedgerFailure> {
    match unix_fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => Ok(true),
        Err(rustix::io::Errno::NOENT) => Ok(false),
        Err(error) => Err(map_errno(error)),
    }
}
