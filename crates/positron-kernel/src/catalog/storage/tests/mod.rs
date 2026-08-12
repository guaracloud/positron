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
use super::CatalogStorage;
use super::artifact::{ArtifactKind, open_artifact, protect_artifact};
use super::fault::{CatalogFileEvent, with_catalog_fault};
use super::io::{
    entry_exists, open_or_create_directory, read_exact_file, write_new_file, write_transaction_file,
};
use super::marker::{MarkerDecode, decode_marker, encode_marker};

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
    CatalogSecret::from_owned(Box::new([byte; 32]))
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
        transaction_digest: transaction_digest(format_epoch, &objects, None),
        object_set_digest: object_set_digest(&objects),
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
    let generation = generation_identity(&encoded);
    record.generation = generation;
    storage.publish_commit(staging, secret, generation, &encoded)?;
    storage.publish_marker(staging, secret, record.number, generation)?;
    Ok(generation)
}

#[test]
fn protected_artifacts_bind_kind_identity_epoch_and_secret() {
    let identity = [0x31; 32];
    let epoch = FormatEpoch(4);
    for kind in [
        ArtifactKind::Object,
        ArtifactKind::Audit,
        ArtifactKind::Commit,
    ] {
        let first = protect_artifact(&secret(1), kind, identity, epoch, b"plaintext")
            .expect("valid artifact must protect");
        let second = protect_artifact(&secret(1), kind, identity, epoch, b"plaintext")
            .expect("valid artifact must protect");
        assert_ne!(first, second, "each protection attempt needs fresh salt");
        assert_eq!(
            open_artifact(&secret(1), kind, identity, epoch, &first)
                .expect("matching context must open"),
            b"plaintext"
        );

        for failure in [
            open_artifact(&secret(2), kind, identity, epoch, &first),
            open_artifact(&secret(1), kind, [0x32; 32], epoch, &first),
            open_artifact(&secret(1), kind, identity, FormatEpoch(5), &first),
        ] {
            assert_eq!(
                failure.expect_err("context substitution must fail").code(),
                CatalogFailureCode::AuthenticationFailed
            );
        }

        let other_kind = match kind {
            ArtifactKind::Object => ArtifactKind::Audit,
            ArtifactKind::Audit | ArtifactKind::Commit => ArtifactKind::Object,
        };
        assert_eq!(
            open_artifact(&secret(1), other_kind, identity, epoch, &first)
                .expect_err("artifact kind substitution must fail")
                .code(),
            CatalogFailureCode::IntegrityCorruption
        );

        for length in 0..25 {
            assert_eq!(
                open_artifact(&secret(1), kind, identity, epoch, &first[..length])
                    .expect_err("truncated header must fail")
                    .code(),
                CatalogFailureCode::IntegrityCorruption
            );
        }
        let mut corrupt = first;
        corrupt[0] ^= 1;
        assert_eq!(
            open_artifact(&secret(1), kind, identity, epoch, &corrupt)
                .expect_err("corrupt magic must fail")
                .code(),
            CatalogFailureCode::IntegrityCorruption
        );
    }

    assert_eq!(
        protect_artifact(
            &secret(1),
            ArtifactKind::Object,
            identity,
            FormatEpoch(0),
            b"plaintext",
        )
        .expect_err("zero artifact epoch must fail")
        .code(),
        CatalogFailureCode::IntegrityCorruption
    );
}

#[test]
fn markers_distinguish_published_torn_and_unauthenticated_records() {
    let generation = CatalogGenerationId([0x41; 32]);
    let published = encode_marker(&secret(3), 9, generation).expect("marker must encode");
    assert!(matches!(
        decode_marker(&secret(3), &published).expect("marker must decode"),
        MarkerDecode::Published(9, observed) if observed == generation
    ));
    for length in 0..published.len() {
        assert!(matches!(
            decode_marker(&secret(3), &published[..length]).expect("torn marker is classified"),
            MarkerDecode::Torn
        ));
    }

    let mut bad_magic = published;
    bad_magic[0] ^= 1;
    assert!(matches!(
        decode_marker(&secret(3), &bad_magic).expect("invalid marker is classified"),
        MarkerDecode::Torn
    ));
    assert!(matches!(
        decode_marker(&secret(4), &published).expect("wrong key is classified"),
        MarkerDecode::AuthenticationFailed
    ));

    for marker in [
        encode_marker(&secret(3), 0, generation).expect("marker must encode"),
        encode_marker(&secret(3), 9, CatalogGenerationId::ORIGIN).expect("marker must encode"),
    ] {
        assert!(matches!(
            decode_marker(&secret(3), &marker).expect("sentinel marker is classified"),
            MarkerDecode::Torn
        ));
    }
}

#[test]
fn descriptor_relative_io_rejects_aliases_and_enforces_exact_bounded_files()
-> Result<(), Box<dyn std::error::Error>> {
    let root = TemporaryRoot::new()?;
    let root_file = File::open(root.path())?;
    let directory = open_or_create_directory(&root_file, "child")?;
    drop(open_or_create_directory(&root_file, "child")?);

    assert!(!entry_exists(&directory, "payload")?);
    write_new_file(&directory, "payload", b"complete")?;
    assert!(entry_exists(&directory, "payload")?);
    assert_eq!(read_exact_file(&directory, "payload", 8)?, b"complete");
    assert_eq!(
        write_new_file(&directory, "payload", b"replacement")
            .expect_err("immutable file replacement must fail")
            .code(),
        CatalogFailureCode::StorageUnavailable
    );
    assert_eq!(
        read_exact_file(&directory, "payload", 7)
            .expect_err("read limit must be enforced")
            .code(),
        CatalogFailureCode::IntegrityCorruption
    );
    assert_eq!(
        read_exact_file(&directory, "missing", 8)
            .expect_err("missing file must fail")
            .code(),
        CatalogFailureCode::StorageUnavailable
    );

    write_new_file(&directory, "empty", b"")?;
    assert_eq!(
        read_exact_file(&directory, "empty", 8)
            .expect_err("empty persistent file must fail")
            .code(),
        CatalogFailureCode::IntegrityCorruption
    );

    fs::hard_link(
        root.path().join("child/payload"),
        root.path().join("child/alias"),
    )?;
    assert_eq!(
        read_exact_file(&directory, "payload", 8)
            .expect_err("multiply linked file must fail")
            .code(),
        CatalogFailureCode::IntegrityCorruption
    );

    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("payload", root.path().join("child/symlink"))?;
        assert_eq!(
            read_exact_file(&directory, "symlink", 8)
                .expect_err("symlink must fail")
                .code(),
            CatalogFailureCode::StorageUnavailable
        );
    }

    write_new_file(&directory, "staging", b"residue")?;
    write_transaction_file(
        &directory,
        "staging",
        b"replacement",
        CatalogFileEvent::PartialObjectWrite,
    )?;
    assert_eq!(read_exact_file(&directory, "staging", 11)?, b"replacement");
    let failure = with_catalog_fault(CatalogFileEvent::PartialObjectWrite, || {
        write_transaction_file(
            &directory,
            "partial",
            b"replacement",
            CatalogFileEvent::PartialObjectWrite,
        )
    })
    .expect_err("partial write fault must fail");
    assert_eq!(failure.code(), CatalogFailureCode::StorageUnavailable);

    assert_eq!(
        open_or_create_directory(&root_file, "missing/present")
            .expect_err("nested missing parent must fail")
            .code(),
        CatalogFailureCode::StorageUnavailable
    );
    Ok(())
}

#[test]
fn immutable_storage_reuses_only_byte_identical_reserved_artifacts()
-> Result<(), Box<dyn std::error::Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let storage = CatalogStorage::open(&volume)?;
    let digest = [0x21; 32];
    let transaction_id = transaction(1);
    let staging = storage.open_transaction(transaction_id, digest)?;
    drop(storage.open_transaction(transaction_id, digest)?);
    assert_eq!(
        storage
            .open_transaction(transaction_id, [0x22; 32])
            .expect_err("transaction digest substitution must fail")
            .code(),
        CatalogFailureCode::IdempotencyConflict
    );

    let plaintext = b"immutable object";
    let object_id = CatalogObjectId(Sha256::digest(plaintext).into());
    let epoch = FormatEpoch(1);
    storage.publish_object(&staging, &secret(5), object_id, epoch, plaintext)?;
    assert_eq!(
        storage.read_object(&secret(5), object_id, epoch)?.as_ref(),
        plaintext
    );
    storage.publish_object(&staging, &secret(5), object_id, epoch, plaintext)?;
    assert_eq!(
        storage
            .publish_object(&staging, &secret(5), object_id, epoch, b"substitution")
            .expect_err("reserved object substitution must fail")
            .code(),
        CatalogFailureCode::IntegrityCorruption
    );

    let (audit, encoded_audit) = prepare_audit(AuditFrontier::ORIGIN, transaction_id, b"redacted")?;
    storage.publish_audit(&staging, &secret(5), &audit, &encoded_audit)?;
    assert_eq!(
        storage.read_audit(&secret(5), audit.position(), audit.record_hash())?,
        encoded_audit
    );
    storage.publish_audit(&staging, &secret(5), &audit, &encoded_audit)?;
    assert_eq!(
        storage
            .publish_audit(&staging, &secret(5), &audit, b"substitution")
            .expect_err("reserved audit substitution must fail")
            .code(),
        CatalogFailureCode::IntegrityCorruption
    );

    let generation = CatalogGenerationId([0x51; 32]);
    storage.publish_commit(&staging, &secret(5), generation, b"commit")?;
    assert_eq!(storage.read_commit(&secret(5), generation)?, b"commit");
    storage.publish_commit(&staging, &secret(5), generation, b"commit")?;
    assert_eq!(
        storage
            .publish_commit(&staging, &secret(5), generation, b"substitution")
            .expect_err("reserved commit substitution must fail")
            .code(),
        CatalogFailureCode::IntegrityCorruption
    );

    storage.publish_marker(&staging, &secret(5), 1, generation)?;
    storage.publish_marker(&staging, &secret(5), 1, generation)?;
    let markers = storage.markers(&secret(5))?;
    assert_eq!(markers.verified.get(&generation), Some(&1));
    assert_eq!(markers.authentication_failures, 0);
    Ok(())
}

#[test]
fn marker_scan_ignores_torn_entries_but_counts_authenticated_shape_failures()
-> Result<(), Box<dyn std::error::Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let storage = CatalogStorage::open(&volume)?;
    write_new_file(&storage.generations, "short.marker", b"torn")?;
    let generation = CatalogGenerationId([0x61; 32]);
    let marker = encode_marker(&secret(7), 1, generation)?;
    write_new_file(&storage.generations, "wrong-key.marker", &marker)?;

    let scan = storage.markers(&secret(8))?;
    assert!(scan.verified.is_empty());
    assert_eq!(scan.authentication_failures, 1);
    Ok(())
}

#[test]
fn recovery_rejects_authenticated_but_semantically_inconsistent_records()
-> Result<(), Box<dyn std::error::Error>> {
    {
        let root = TemporaryRoot::new()?;
        let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
        let storage = CatalogStorage::open(&volume)?;
        let key = secret(6);
        let record = base_record(1, CatalogGenerationId::ORIGIN, instance(1), transaction(1));
        let staging = storage.open_transaction(record.transaction, record.transaction_digest)?;
        publish_record(&storage, &staging, &key, record)?;
        assert_eq!(
            recover(&storage, &key, instance(2))
                .err()
                .expect("instance substitution must fail")
                .code(),
            CatalogFailureCode::IntegrityCorruption
        );
    }

    {
        let root = TemporaryRoot::new()?;
        let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
        let storage = CatalogStorage::open(&volume)?;
        let key = secret(6);
        let record = base_record(
            1,
            CatalogGenerationId([0x72; 32]),
            instance(1),
            transaction(2),
        );
        let staging = storage.open_transaction(record.transaction, record.transaction_digest)?;
        publish_record(&storage, &staging, &key, record)?;
        assert_eq!(
            recover(&storage, &key, instance(1))
                .err()
                .expect("non-origin first predecessor must fail")
                .code(),
            CatalogFailureCode::IntegrityCorruption
        );
    }

    {
        let root = TemporaryRoot::new()?;
        let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
        let storage = CatalogStorage::open(&volume)?;
        let key = secret(6);
        let record = base_record(
            2,
            CatalogGenerationId([0x73; 32]),
            instance(1),
            transaction(3),
        );
        let staging = storage.open_transaction(record.transaction, record.transaction_digest)?;
        publish_record(&storage, &staging, &key, record)?;
        assert_eq!(
            recover(&storage, &key, instance(1))
                .err()
                .expect("missing predecessor marker must fail")
                .code(),
            CatalogFailureCode::IntegrityCorruption
        );
    }

    {
        let root = TemporaryRoot::new()?;
        let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
        let storage = CatalogStorage::open(&volume)?;
        let key = secret(6);
        let mut record = base_record(1, CatalogGenerationId::ORIGIN, instance(1), transaction(4));
        record.transaction_digest = [0x74; 32];
        let staging = storage.open_transaction(record.transaction, record.transaction_digest)?;
        publish_record(&storage, &staging, &key, record)?;
        assert_eq!(
            recover(&storage, &key, instance(1))
                .err()
                .expect("transaction digest mismatch must fail")
                .code(),
            CatalogFailureCode::IntegrityCorruption
        );
    }

    {
        let root = TemporaryRoot::new()?;
        let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
        let storage = CatalogStorage::open(&volume)?;
        let key = secret(6);
        let mut record = base_record(1, CatalogGenerationId::ORIGIN, instance(1), transaction(5));
        record.audit_frontier = AuditFrontier {
            position: 2,
            hash: [0x75; 32],
        };
        let staging = storage.open_transaction(record.transaction, record.transaction_digest)?;
        publish_record(&storage, &staging, &key, record)?;
        assert_eq!(
            recover(&storage, &key, instance(1))
                .err()
                .expect("audit frontier gap must fail")
                .code(),
            CatalogFailureCode::IntegrityCorruption
        );
    }

    {
        let root = TemporaryRoot::new()?;
        let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
        let storage = CatalogStorage::open(&volume)?;
        let key = secret(6);
        let (audit, encoded_audit) =
            prepare_audit(AuditFrontier::ORIGIN, transaction(6), b"redacted")?;
        let mut record = base_record(1, CatalogGenerationId::ORIGIN, instance(1), transaction(7));
        record.audit_frontier = AuditFrontier {
            position: audit.position(),
            hash: audit.record_hash(),
        };
        let staging = storage.open_transaction(record.transaction, record.transaction_digest)?;
        storage.publish_audit(&staging, &key, &audit, &encoded_audit)?;
        publish_record(&storage, &staging, &key, record)?;
        assert_eq!(
            recover(&storage, &key, instance(1))
                .err()
                .expect("audit transaction substitution must fail")
                .code(),
            CatalogFailureCode::IntegrityCorruption
        );
    }

    {
        let root = TemporaryRoot::new()?;
        let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
        let storage = CatalogStorage::open(&volume)?;
        let key = secret(6);
        let first = base_record(1, CatalogGenerationId::ORIGIN, instance(1), transaction(8));
        let first_staging =
            storage.open_transaction(first.transaction, first.transaction_digest)?;
        let first_generation = publish_record(&storage, &first_staging, &key, first)?;
        let mut second = base_record(2, first_generation, instance(1), transaction(9));
        second.objects = vec![CatalogObjectId([0x71; 32]), CatalogObjectId([0x71; 32])];
        second.object_set_digest = object_set_digest(&second.objects);
        second.transaction_digest = transaction_digest(second.format_epoch, &second.objects, None);
        let second_staging =
            storage.open_transaction(second.transaction, second.transaction_digest)?;
        publish_record(&storage, &second_staging, &key, second)?;
        assert_eq!(
            recover(&storage, &key, instance(1))
                .err()
                .expect("duplicate published object identities must fail")
                .code(),
            CatalogFailureCode::IntegrityCorruption
        );
    }
    Ok(())
}
