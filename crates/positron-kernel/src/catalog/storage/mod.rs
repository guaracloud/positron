use std::collections::BTreeMap;
use std::fs::File;
use std::sync::Arc;

use rustix::fs::{self as unix_fs, Dir};
use sha2::{Digest, Sha256};

use crate::OwnedPrimaryDataVolume;

use super::codec::MAX_AUDIT_RECORD_BYTES;
use super::types::{
    CatalogFailure, CatalogFailureCode, CatalogGenerationId, CatalogObjectId, CatalogSecret,
    FormatEpoch, GovernanceAuditRecord, MAX_CATALOG_OBJECT_BYTES, TransactionId,
};

mod artifact;
pub(crate) mod fault;
mod io;
mod marker;

#[cfg(test)]
mod tests;

use artifact::{ArtifactKind, open_artifact, protect_artifact};
use fault::{CatalogFileEvent, emit_event};
use io::{
    entry_exists, open_or_create_directory, read_exact_file, synchronize, synchronize_named_file,
    write_new_file, write_transaction_file,
};
use marker::{MARKER_BYTES, MarkerDecode, decode_marker, encode_marker};

#[cfg(any(test, fuzzing))]
pub(crate) use fault::with_catalog_fault;

const FRAME_OVERHEAD_BYTES: usize = 93;
const MAX_COMMIT_FRAME_BYTES: usize = 262_144;
const MAX_AUDIT_FRAME_BYTES: usize = MAX_AUDIT_RECORD_BYTES + FRAME_OVERHEAD_BYTES;
const MAX_MARKERS: usize = 65_536;

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
            synchronize(&directory)?;
            synchronize(&self.staging)?;
        }
        Ok(directory)
    }

    pub(super) fn publish_object(
        &self,
        transaction: &File,
        secret: &CatalogSecret,
        identity: CatalogObjectId,
        format_epoch: FormatEpoch,
        plaintext: &[u8],
    ) -> Result<(), CatalogFailure> {
        let name = object_name(format_epoch, identity);
        if entry_exists(&self.objects, &name)? {
            let observed = self.read_object(secret, identity, format_epoch)?;
            return if observed.as_ref() == plaintext {
                Ok(())
            } else {
                Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption))
            };
        }
        emit_event(CatalogFileEvent::WriteObject)?;
        let protected = protect_artifact(
            secret,
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
            ArtifactKind::Object,
            identity.0,
            format_epoch,
            &encoded,
        )?;
        if CatalogObjectId(Sha256::digest(&plaintext).into()) != identity {
            return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
        }
        Ok(Arc::from(plaintext))
    }

    pub(super) fn publish_audit(
        &self,
        transaction: &File,
        secret: &CatalogSecret,
        record: &GovernanceAuditRecord,
        plaintext: &[u8],
    ) -> Result<(), CatalogFailure> {
        emit_event(CatalogFileEvent::ReserveAudit)?;
        let name = audit_name(record.position, record.hash);
        if entry_exists(&self.audit, &name)? {
            let observed = self.read_audit(secret, record.position, record.hash)?;
            return if observed == plaintext {
                Ok(())
            } else {
                Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption))
            };
        }
        emit_event(CatalogFileEvent::WriteAudit)?;
        let protected = protect_artifact(
            secret,
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
        position: u64,
        hash: [u8; 32],
    ) -> Result<Vec<u8>, CatalogFailure> {
        let encoded = read_exact_file(
            &self.audit,
            audit_name(position, hash),
            MAX_AUDIT_FRAME_BYTES,
        )?;
        open_artifact(secret, ArtifactKind::Audit, hash, FormatEpoch(1), &encoded)
    }

    pub(super) fn publish_commit(
        &self,
        transaction: &File,
        secret: &CatalogSecret,
        generation: CatalogGenerationId,
        plaintext: &[u8],
    ) -> Result<(), CatalogFailure> {
        let name = commit_name(generation);
        if entry_exists(&self.commits, &name)? {
            let observed = self.read_commit(secret, generation)?;
            return if observed == plaintext {
                Ok(())
            } else {
                Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption))
            };
        }
        emit_event(CatalogFileEvent::WriteCommit)?;
        let protected = protect_artifact(
            secret,
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
        generation: CatalogGenerationId,
    ) -> Result<Vec<u8>, CatalogFailure> {
        let encoded = read_exact_file(
            &self.commits,
            commit_name(generation),
            MAX_COMMIT_FRAME_BYTES,
        )?;
        open_artifact(
            secret,
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
            return Ok(());
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
        let mut directory = Dir::read_from(&self.generations)
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::StorageUnavailable))?;
        while let Some(entry) = directory.read() {
            let entry =
                entry.map_err(|_| CatalogFailure::new(CatalogFailureCode::StorageUnavailable))?;
            let name = entry.file_name();
            if name.to_bytes() == b"." || name.to_bytes() == b".." {
                continue;
            }
            if markers.len() == MAX_MARKERS {
                return Err(CatalogFailure::new(CatalogFailureCode::LimitExceeded));
            }
            let encoded = match read_exact_file(&self.generations, name, MARKER_BYTES) {
                Ok(encoded) => encoded,
                Err(failure) if failure.code == CatalogFailureCode::IntegrityCorruption => {
                    continue;
                },
                Err(failure) => return Err(failure),
            };
            match decode_marker(secret, &encoded)? {
                MarkerDecode::Published(number, generation) => {
                    if markers.insert(generation, number).is_some() {
                        return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
                    }
                },
                MarkerDecode::Torn => {},
                MarkerDecode::AuthenticationFailed => authentication_failures += 1,
            }
        }
        Ok(MarkerScan {
            verified: markers,
            authentication_failures,
        })
    }
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
