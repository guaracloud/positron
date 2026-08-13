use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest, Sha256};

use crate::{MountQualification, PrimaryDataVolume};

use super::super::codec::{
    CommitRecord, encode_commit, generation_identity, object_set_digest, prepare_audit,
    transaction_digest,
};
use super::super::recover;
use super::super::types::{
    AuditFrontier, CatalogFailureCode, CatalogGenerationId, CatalogObjectId, CatalogSecret,
    FormatEpoch, InstanceId, TransactionId,
};
use super::artifact::{ArtifactKind, open_artifact, protect_artifact, rewrap_artifact_envelope};
use super::fault::{CatalogFileEvent, with_catalog_fault};
use super::io::{
    entry_exists, open_or_create_directory, read_exact_file, write_new_file, write_transaction_file,
};
use super::marker::{MarkerDecode, decode_marker, encode_marker};
use super::{
    CatalogStorage, MAX_GENERATION_DIRECTORY_NAME_BYTES, MAX_GENERATIONS, marker_name, object_name,
    reserve_directory_entry,
};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

struct TemporaryRoot(PathBuf);

impl TemporaryRoot {
    fn new() -> Result<Self, std::io::Error> {
        let sequence = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "positron-catalog-storage-test-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TemporaryRoot {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.0) {
            eprintln!("failed to remove catalog storage test root: {error}");
        }
    }
}

fn secret(byte: u8) -> CatalogSecret {
    CatalogSecret::from_owned(Box::new([byte.wrapping_add(1); 32]), Box::new([byte; 32]))
}

fn transaction(last: u8) -> TransactionId {
    let mut bytes = [0_u8; 16];
    bytes[15] = last;
    TransactionId(bytes)
}

fn instance(last: u8) -> InstanceId {
    let mut bytes = [0_u8; 16];
    bytes[15] = last;
    InstanceId(bytes)
}

fn base_record(
    number: u64,
    predecessor: CatalogGenerationId,
    instance: InstanceId,
    transaction: TransactionId,
) -> CommitRecord {
    let objects = vec![CatalogObjectId([0x71; 32])];
    let format_epoch = FormatEpoch(1);
    CommitRecord {
        generation: CatalogGenerationId::ORIGIN,
        number,
        predecessor,
        instance,
        format_epoch,
        transaction,
        transaction_digest: transaction_digest(format_epoch, &objects, None)
            .expect("test transaction digest"),
        object_set_digest: object_set_digest(&objects).expect("test object-set digest"),
        audit_frontier: AuditFrontier::ORIGIN,
        objects,
    }
}

fn publish_record(
    storage: &CatalogStorage,
    staging: &File,
    secret: &CatalogSecret,
    mut record: CommitRecord,
) -> Result<CatalogGenerationId, super::super::types::CatalogFailure> {
    let encoded = encode_commit(&record);
    let generation = generation_identity(&encoded)?;
    record.generation = generation;
    storage.publish_commit(staging, secret, record.instance, generation, &encoded)?;
    storage.publish_marker(staging, secret, record.number, generation)?;
    Ok(generation)
}

mod artifact;
mod io;
mod marker;
