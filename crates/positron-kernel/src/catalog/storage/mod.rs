use std::collections::BTreeMap;
use std::fs::File;
use std::sync::Arc;

use crate::data_protection::DataProtection;
use rustix::fs::{self as unix_fs, Dir};

use crate::OwnedPrimaryDataVolume;

use super::codec::MAX_AUDIT_RECORD_BYTES;
use super::types::{
    CatalogFailure, CatalogFailureCode, CatalogGenerationId, CatalogObjectId, CatalogSecret,
    CatalogWrappingKey, FormatEpoch, GovernanceAuditRecord, InstanceId, MAX_CATALOG_OBJECT_BYTES,
    TransactionId,
};

mod artifact;
pub(crate) mod fault;
mod inspection;
mod io;
mod marker;

#[cfg(test)]
mod tests;

use artifact::{ArtifactKind, open_artifact, protect_artifact, rewrap_artifact_envelope};
use fault::{CatalogFileEvent, emit_event};
use io::{
    entry_exists, open_or_create_directory, read_exact_file, synchronize, synchronize_named_file,
    write_new_file, write_transaction_file,
};
pub(super) use marker::MARKER_BYTES;
use marker::{MarkerDecode, decode_marker, encode_marker};

#[cfg(any(test, feature = "test-support"))]
pub(crate) use fault::after_ambiguous_publication;
#[cfg(any(test, fuzzing, feature = "test-support"))]
pub(crate) use fault::before_lease_marker_basis;
#[cfg(any(test, fuzzing))]
pub(crate) use fault::with_catalog_fault;
#[cfg(test)]
pub(crate) use fault::with_catalog_fault_after;
#[cfg(feature = "test-support")]
pub use fault::{
    CatalogPublicationFault, with_catalog_generation_ambiguity_hook_after,
    with_catalog_publication_fault_after, with_catalog_publication_fault_sequence_after,
    with_catalog_publication_hook_after,
};

pub(super) const FRAME_OVERHEAD_BYTES: usize = 315;
const MAX_COMMIT_FRAME_BYTES: usize = 262_144;
const MAX_AUDIT_FRAME_BYTES: usize = MAX_AUDIT_RECORD_BYTES + FRAME_OVERHEAD_BYTES;
pub(super) const MAX_GENERATIONS: usize = 65_536;
const MAX_GENERATION_DIRECTORY_NAME_BYTES: usize = MAX_GENERATIONS * 128;

pub(super) struct CatalogStorage {
    _catalog: File,
    objects: File,
    audit: File,
    commits: File,
    generations: File,
    staging: File,
}

pub(super) struct MarkerScan {
    pub(super) verified: BTreeMap<CatalogGenerationId, u64>,
    pub(super) authentication_failures: usize,
}

impl CatalogStorage {
    pub(super) fn rewrap_object(
        &self,
        current: &CatalogWrappingKey,
        replacement: &CatalogWrappingKey,
        instance: InstanceId,
        identity: CatalogObjectId,
        format_epoch: FormatEpoch,
    ) -> Result<(), CatalogFailure> {
        let name = object_name(format_epoch, identity);
        self.rewrap_named(
            &self.objects,
            &name,
            MAX_CATALOG_OBJECT_BYTES + FRAME_OVERHEAD_BYTES,
            current,
            replacement,
            instance,
            ArtifactKind::Object,
            identity.0,
            format_epoch,
        )
    }

    pub(super) fn rewrap_audit(
        &self,
        current: &CatalogWrappingKey,
        replacement: &CatalogWrappingKey,
        instance: InstanceId,
        position: u64,
        hash: [u8; 32],
    ) -> Result<(), CatalogFailure> {
        let name = audit_name(position, hash);
        self.rewrap_named(
            &self.audit,
            &name,
            MAX_AUDIT_FRAME_BYTES,
            current,
            replacement,
            instance,
            ArtifactKind::Audit,
            hash,
            FormatEpoch(1),
        )
    }

    pub(super) fn rewrap_commit(
        &self,
        current: &CatalogWrappingKey,
        replacement: &CatalogWrappingKey,
        instance: InstanceId,
        generation: CatalogGenerationId,
    ) -> Result<(), CatalogFailure> {
        let name = commit_name(generation);
        self.rewrap_named(
            &self.commits,
            &name,
            MAX_COMMIT_FRAME_BYTES,
            current,
            replacement,
            instance,
            ArtifactKind::Commit,
            generation.0,
            FormatEpoch(1),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn rewrap_named(
        &self,
        directory: &File,
        name: &str,
        maximum: usize,
        current: &CatalogWrappingKey,
        replacement: &CatalogWrappingKey,
        instance: InstanceId,
        kind: ArtifactKind,
        identity: [u8; 32],
        format_epoch: FormatEpoch,
    ) -> Result<(), CatalogFailure> {
        let encoded = read_exact_file(directory, name, maximum)?;
        match rewrap_artifact_envelope(
            replacement,
            replacement,
            instance,
            kind,
            identity,
            format_epoch,
            &encoded,
        ) {
            Ok(_) => {
                emit_event(CatalogFileEvent::SynchronizeRewrap)?;
                synchronize_named_file(directory, name)?;
                emit_event(CatalogFileEvent::SynchronizeRewrapDirectory)?;
                return synchronize(directory);
            },
            Err(failure) if failure.code() == CatalogFailureCode::AuthenticationFailed => {},
            Err(failure) => return Err(failure),
        }
        let rewrapped = rewrap_artifact_envelope(
            current,
            replacement,
            instance,
            kind,
            identity,
            format_epoch,
            &encoded,
        )?;
        let temporary_name = format!("rewrap-{}-{name}", kind.tag());
        write_transaction_file(
            &self.staging,
            &temporary_name,
            &rewrapped,
            CatalogFileEvent::PartialRewrapWrite,
        )?;
        emit_event(CatalogFileEvent::SynchronizeRewrap)?;
        synchronize_named_file(&self.staging, &temporary_name)?;
        synchronize(&self.staging)?;
        unix_fs::renameat(&self.staging, &temporary_name, directory, name)
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::StorageUnavailable))?;
        let published = read_exact_file(directory, name, maximum)?;
        rewrap_artifact_envelope(
            replacement,
            replacement,
            instance,
            kind,
            identity,
            format_epoch,
            &published,
        )?;
        emit_event(CatalogFileEvent::SynchronizeRewrap)?;
        synchronize_named_file(directory, name)?;
        emit_event(CatalogFileEvent::SynchronizeRewrapDirectory)?;
        synchronize(directory)
    }

    pub(super) fn confirm_publication(
        &self,
        secret: &CatalogSecret,
        instance: InstanceId,
        record: &super::codec::CommitRecord,
        audit: Option<&GovernanceAuditRecord>,
    ) -> Result<(), CatalogFailure> {
        for identity in &record.objects {
            let name = object_name(record.format_epoch, *identity);
            self.read_object(secret, instance, *identity, record.format_epoch)?;
            synchronize_existing(
                &self.objects,
                &name,
                CatalogFileEvent::SynchronizeObjectDirectory,
            )?;
        }
        if let Some(audit) = audit {
            let name = audit_name(audit.position, audit.hash);
            self.read_audit(secret, instance, audit.position, audit.hash)?;
            synchronize_existing(
                &self.audit,
                &name,
                CatalogFileEvent::SynchronizeAuditDirectory,
            )?;
        }
        let commit = commit_name(record.generation);
        self.read_commit(secret, instance, record.generation)?;
        synchronize_existing(
            &self.commits,
            &commit,
            CatalogFileEvent::SynchronizeCommitDirectory,
        )?;
        self.publish_marker(&self.staging, secret, record.number, record.generation)
    }

    pub(super) fn open(volume: &OwnedPrimaryDataVolume) -> Result<Self, CatalogFailure> {
        let catalog = open_or_create_directory(&volume._root, "catalog")?;
        let objects = open_or_create_directory(&catalog, "objects")?;
        let audit = open_or_create_directory(&catalog, "governance-audit")?;
        let commits = open_or_create_directory(&catalog, "commits")?;
        let generations = open_or_create_directory(&catalog, "generations")?;
        let staging = open_or_create_directory(&catalog, "staging")?;
        synchronize(&catalog)?;
        synchronize(&volume._root)?;
        Ok(Self {
            _catalog: catalog,
            objects,
            audit,
            commits,
            generations,
            staging,
        })
    }

    pub(super) fn open_transaction(
        &self,
        transaction: TransactionId,
        digest: [u8; 32],
    ) -> Result<File, CatalogFailure> {
        let name = hex(&transaction.0);
        let directory = open_or_create_directory(&self.staging, &name)?;
        if entry_exists(&directory, "transaction.digest")? {
            let existing = read_exact_file(&directory, "transaction.digest", 32)?;
            if existing.as_slice() != digest {
                return Err(CatalogFailure::new(CatalogFailureCode::IdempotencyConflict));
            }
        } else {
            write_new_file(&directory, "transaction.digest", &digest)?;
        }
        emit_event(CatalogFileEvent::SynchronizeTransactionDigest)?;
        synchronize_named_file(&directory, "transaction.digest")?;
        emit_event(CatalogFileEvent::SynchronizeTransactionDirectory)?;
        synchronize(&directory)?;
        synchronize(&self.staging)?;
        Ok(directory)
    }

    pub(super) fn publish_object(
        &self,
        transaction: &File,
        secret: &CatalogSecret,
        instance: InstanceId,
        identity: CatalogObjectId,
        format_epoch: FormatEpoch,
        plaintext: &[u8],
    ) -> Result<(), CatalogFailure> {
        let name = object_name(format_epoch, identity);
        if authenticate_existing(
            &self.objects,
            &name,
            CatalogFileEvent::SynchronizeObjectDirectory,
            plaintext,
            || self.read_object(secret, instance, identity, format_epoch),
        )? {
            return Ok(());
        }
        emit_event(CatalogFileEvent::WriteObject)?;
        let protected = protect_artifact(
            secret,
            instance,
            ArtifactKind::Object,
            identity.0,
            format_epoch,
            plaintext,
        )?;
        write_transaction_file(
            transaction,
            &name,
            &protected,
            CatalogFileEvent::PartialObjectWrite,
        )?;
        emit_event(CatalogFileEvent::SynchronizeObject)?;
        synchronize_named_file(transaction, &name)?;
        synchronize(transaction)?;
        unix_fs::renameat(transaction, &name, &self.objects, &name)
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::StorageUnavailable))?;
        emit_event(CatalogFileEvent::SynchronizeObjectDirectory)?;
        synchronize(&self.objects)
    }

    pub(super) fn read_object(
        &self,
        secret: &CatalogSecret,
        instance: InstanceId,
        identity: CatalogObjectId,
        format_epoch: FormatEpoch,
    ) -> Result<Arc<[u8]>, CatalogFailure> {
        let encoded = read_exact_file(
            &self.objects,
            object_name(format_epoch, identity),
            MAX_CATALOG_OBJECT_BYTES + FRAME_OVERHEAD_BYTES,
        )?;
        let plaintext = open_artifact(
            secret,
            instance,
            ArtifactKind::Object,
            identity.0,
            format_epoch,
            &encoded,
        )?;
        let digest = DataProtection::hash(&plaintext)
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::StorageUnavailable))?;
        if CatalogObjectId(digest) != identity {
            return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
        }
        Ok(Arc::from(plaintext))
    }

    pub(super) fn publish_audit(
        &self,
        transaction: &File,
        secret: &CatalogSecret,
        instance: InstanceId,
        record: &GovernanceAuditRecord,
        plaintext: &[u8],
    ) -> Result<(), CatalogFailure> {
        emit_event(CatalogFileEvent::ReserveAudit)?;
        let name = audit_name(record.position, record.hash);
        if authenticate_existing(
            &self.audit,
            &name,
            CatalogFileEvent::SynchronizeAuditDirectory,
            plaintext,
            || self.read_audit(secret, instance, record.position, record.hash),
        )? {
            return Ok(());
        }
        emit_event(CatalogFileEvent::WriteAudit)?;
        let protected = protect_artifact(
            secret,
            instance,
            ArtifactKind::Audit,
            record.hash,
            FormatEpoch(1),
            plaintext,
        )?;
        write_transaction_file(
            transaction,
            &name,
            &protected,
            CatalogFileEvent::PartialAuditWrite,
        )?;
        emit_event(CatalogFileEvent::SynchronizeAudit)?;
        synchronize_named_file(transaction, &name)?;
        synchronize(transaction)?;
        unix_fs::renameat(transaction, &name, &self.audit, &name)
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::StorageUnavailable))?;
        emit_event(CatalogFileEvent::SynchronizeAuditDirectory)?;
        synchronize(&self.audit)
    }

    pub(super) fn read_audit(
        &self,
        secret: &CatalogSecret,
        instance: InstanceId,
        position: u64,
        hash: [u8; 32],
    ) -> Result<Vec<u8>, CatalogFailure> {
        let encoded = read_exact_file(
            &self.audit,
            audit_name(position, hash),
            MAX_AUDIT_FRAME_BYTES,
        )?;
        open_artifact(
            secret,
            instance,
            ArtifactKind::Audit,
            hash,
            FormatEpoch(1),
            &encoded,
        )
    }

    pub(super) fn publish_commit(
        &self,
        transaction: &File,
        secret: &CatalogSecret,
        instance: InstanceId,
        generation: CatalogGenerationId,
        plaintext: &[u8],
    ) -> Result<(), CatalogFailure> {
        let name = commit_name(generation);
        if authenticate_existing(
            &self.commits,
            &name,
            CatalogFileEvent::SynchronizeCommitDirectory,
            plaintext,
            || self.read_commit(secret, instance, generation),
        )? {
            return Ok(());
        }
        emit_event(CatalogFileEvent::WriteCommit)?;
        let protected = protect_artifact(
            secret,
            instance,
            ArtifactKind::Commit,
            generation.0,
            FormatEpoch(1),
            plaintext,
        )?;
        write_transaction_file(
            transaction,
            &name,
            &protected,
            CatalogFileEvent::PartialCommitWrite,
        )?;
        emit_event(CatalogFileEvent::SynchronizeCommit)?;
        synchronize_named_file(transaction, &name)?;
        synchronize(transaction)?;
        unix_fs::renameat(transaction, &name, &self.commits, &name)
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::StorageUnavailable))?;
        emit_event(CatalogFileEvent::SynchronizeCommitDirectory)?;
        synchronize(&self.commits)
    }

    pub(super) fn read_commit(
        &self,
        secret: &CatalogSecret,
        instance: InstanceId,
        generation: CatalogGenerationId,
    ) -> Result<Vec<u8>, CatalogFailure> {
        let encoded = read_exact_file(
            &self.commits,
            commit_name(generation),
            MAX_COMMIT_FRAME_BYTES,
        )?;
        open_artifact(
            secret,
            instance,
            ArtifactKind::Commit,
            generation.0,
            FormatEpoch(1),
            &encoded,
        )
    }

    pub(super) fn publish_marker(
        &self,
        transaction: &File,
        secret: &CatalogSecret,
        number: u64,
        generation: CatalogGenerationId,
    ) -> Result<(), CatalogFailure> {
        let final_name = marker_name(number, generation);
        if entry_exists(&self.generations, &final_name)? {
            let encoded = read_exact_file(&self.generations, &final_name, MARKER_BYTES)?;
            match decode_marker(secret, &encoded)? {
                MarkerDecode::Published(observed_number, observed_generation)
                    if observed_number == number && observed_generation == generation => {},
                MarkerDecode::AuthenticationFailed => {
                    return Err(CatalogFailure::new(
                        CatalogFailureCode::AuthenticationFailed,
                    ));
                },
                MarkerDecode::Unsupported => {
                    return Err(CatalogFailure::new(CatalogFailureCode::UnsupportedFormat));
                },
                MarkerDecode::Published(_, _) | MarkerDecode::Corrupt => {
                    return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
                },
            }
            return synchronize_existing(
                &self.generations,
                &final_name,
                CatalogFileEvent::SynchronizeGenerationDirectory,
            );
        }
        let marker = encode_marker(secret, number, generation)?;
        emit_event(CatalogFileEvent::WriteMarker)?;
        write_transaction_file(
            transaction,
            "commit.marker",
            &marker,
            CatalogFileEvent::PartialMarkerWrite,
        )?;
        emit_event(CatalogFileEvent::SynchronizeMarker)?;
        synchronize_named_file(transaction, "commit.marker")?;
        synchronize(transaction)?;
        emit_event(CatalogFileEvent::RenameMarker)?;
        unix_fs::renameat(transaction, "commit.marker", &self.generations, &final_name)
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::StorageUnavailable))?;
        emit_event(CatalogFileEvent::SynchronizeGenerationDirectory)?;
        synchronize(&self.generations)
    }

    pub(super) fn markers(&self, secret: &CatalogSecret) -> Result<MarkerScan, CatalogFailure> {
        let mut markers = BTreeMap::new();
        let mut authentication_failures = 0_usize;
        let mut entry_count = 0_usize;
        let mut name_bytes = 0_usize;
        let mut directory = Dir::read_from(&self.generations)
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::StorageUnavailable))?;
        while let Some(entry) = directory.read() {
            let entry =
                entry.map_err(|_| CatalogFailure::new(CatalogFailureCode::StorageUnavailable))?;
            let name = entry.file_name();
            if name.to_bytes() == b"." || name.to_bytes() == b".." {
                continue;
            }
            reserve_directory_entry(&mut entry_count, &mut name_bytes, name.to_bytes().len())?;
            let encoded = read_exact_file(&self.generations, name, MARKER_BYTES)?;
            if encoded.len() < MARKER_BYTES {
                if canonical_marker_prefix(secret, name.to_bytes(), &encoded)? {
                    continue;
                }
                return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
            }
            match decode_marker(secret, &encoded)? {
                MarkerDecode::Published(number, generation) => {
                    if name.to_bytes() != marker_name(number, generation).as_bytes() {
                        return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
                    }
                    if markers.insert(generation, number).is_some() {
                        return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
                    }
                },
                MarkerDecode::AuthenticationFailed => authentication_failures += 1,
                MarkerDecode::Corrupt => {
                    return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
                },
                MarkerDecode::Unsupported => {
                    return Err(CatalogFailure::new(CatalogFailureCode::UnsupportedFormat));
                },
            }
        }
        Ok(MarkerScan {
            verified: markers,
            authentication_failures,
        })
    }
}

fn canonical_marker_prefix(
    secret: &CatalogSecret,
    name: &[u8],
    encoded: &[u8],
) -> Result<bool, CatalogFailure> {
    if encoded.is_empty() || encoded.len() >= MARKER_BYTES {
        return Ok(false);
    }
    let Some(number_bytes) = name.get(..20) else {
        return Ok(false);
    };
    if name.get(20) != Some(&b'-') || name.get(85..) != Some(b".marker") || name.len() != 92 {
        return Ok(false);
    }
    let mut number = 0_u64;
    for byte in number_bytes {
        let Some(digit) = byte.checked_sub(b'0').filter(|digit| *digit <= 9) else {
            return Ok(false);
        };
        let Some(next) = number
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(digit)))
        else {
            return Ok(false);
        };
        number = next;
    }
    let Some(identity_hex) = name.get(21..85) else {
        return Ok(false);
    };
    let mut identity = [0_u8; 32];
    for (destination, pair) in identity.iter_mut().zip(identity_hex.chunks_exact(2)) {
        let Some(high) = hex_value(pair.first().copied()) else {
            return Ok(false);
        };
        let Some(low) = hex_value(pair.get(1).copied()) else {
            return Ok(false);
        };
        *destination = (high << 4) | low;
    }
    let generation = CatalogGenerationId(identity);
    if number == 0
        || generation == CatalogGenerationId::ORIGIN
        || marker_name(number, generation).as_bytes() != name
    {
        return Ok(false);
    }
    Ok(encode_marker(secret, number, generation)?.starts_with(encoded))
}

fn hex_value(value: Option<u8>) -> Option<u8> {
    match value? {
        value @ b'0'..=b'9' => Some(value - b'0'),
        value @ b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn synchronize_existing(
    directory: &File,
    name: &str,
    directory_event: CatalogFileEvent,
) -> Result<(), CatalogFailure> {
    synchronize_named_file(directory, name)?;
    emit_event(directory_event)?;
    synchronize(directory)
}

fn authenticate_existing<T: AsRef<[u8]>>(
    directory: &File,
    name: &str,
    directory_event: CatalogFileEvent,
    expected: &[u8],
    authenticate: impl FnOnce() -> Result<T, CatalogFailure>,
) -> Result<bool, CatalogFailure> {
    if !entry_exists(directory, name)? {
        return Ok(false);
    }
    if authenticate()?.as_ref() != expected {
        return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
    }
    synchronize_existing(directory, name, directory_event)?;
    Ok(true)
}

fn reserve_directory_entry(
    count: &mut usize,
    total_name_bytes: &mut usize,
    name_bytes: usize,
) -> Result<(), CatalogFailure> {
    *count = count
        .checked_add(1)
        .filter(|count| *count <= MAX_GENERATIONS)
        .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
    *total_name_bytes = total_name_bytes
        .checked_add(name_bytes)
        .filter(|bytes| *bytes <= MAX_GENERATION_DIRECTORY_NAME_BYTES)
        .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
    Ok(())
}

fn object_name(format_epoch: FormatEpoch, identity: CatalogObjectId) -> String {
    format!("{:010}-{}.frame", format_epoch.0, hex(&identity.0))
}

fn audit_name(position: u64, hash: [u8; 32]) -> String {
    format!("{position:020}-{}.frame", hex(&hash))
}

fn commit_name(identity: CatalogGenerationId) -> String {
    format!("{}.frame", hex(&identity.0))
}

fn marker_name(number: u64, identity: CatalogGenerationId) -> String {
    format!("{number:020}-{}.marker", hex(&identity.0))
}

fn hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(hex_digit(byte >> 4));
        encoded.push(hex_digit(byte & 0x0f));
    }
    encoded
}

fn hex_digit(value: u8) -> char {
    let nibble = value & 0x0f;
    if nibble < 10 {
        char::from(b'0' + nibble)
    } else {
        char::from(b'a' + (nibble - 10))
    }
}
