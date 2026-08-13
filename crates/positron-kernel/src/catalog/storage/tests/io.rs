use super::*;

#[test]
fn marker_decoder_distinguishes_complete_shape_format_and_authentication() {
    let generation = CatalogGenerationId([0x41; 32]);
    let published = encode_marker(&secret(3), 9, generation).expect("marker must encode");
    assert!(matches!(
        decode_marker(&secret(3), &published).expect("marker must decode"),
        MarkerDecode::Published(9, observed) if observed == generation
    ));
    for length in 0..published.len() {
        assert!(matches!(
            decode_marker(&secret(3), &published[..length]).expect("short marker is classified"),
            MarkerDecode::Corrupt
        ));
    }

    let mut bad_magic = published;
    bad_magic[0] ^= 1;
    assert!(matches!(
        decode_marker(&secret(3), &bad_magic).expect("invalid marker is classified"),
        MarkerDecode::Corrupt
    ));
    let mut unsupported_version = published;
    unsupported_version[9] = 2;
    assert!(matches!(
        decode_marker(&secret(3), &unsupported_version)
            .expect("unknown marker version is classified"),
        MarkerDecode::Unsupported
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
            MarkerDecode::Corrupt
        ));
    }
}

#[test]
fn generation_enumeration_bounds_every_entry_before_classification() {
    let mut count = MAX_GENERATIONS - 1;
    let mut name_bytes = MAX_GENERATION_DIRECTORY_NAME_BYTES - 1;
    reserve_directory_entry(&mut count, &mut name_bytes, 1)
        .expect("the exact enumeration boundary is accepted");
    assert_eq!(count, MAX_GENERATIONS);
    assert_eq!(name_bytes, MAX_GENERATION_DIRECTORY_NAME_BYTES);
    assert_eq!(
        reserve_directory_entry(&mut count, &mut name_bytes, 1)
            .expect_err("one unrelated directory entry past the bound must be refused")
            .code(),
        CatalogFailureCode::LimitExceeded
    );
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
        CatalogFailureCode::IntegrityCorruption
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
            CatalogFailureCode::IntegrityCorruption
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
    storage.publish_object(
        &staging,
        &secret(5),
        instance(1),
        object_id,
        epoch,
        plaintext,
    )?;
    assert_eq!(
        storage
            .read_object(&secret(5), instance(1), object_id, epoch)?
            .as_ref(),
        plaintext
    );
    storage.publish_object(
        &staging,
        &secret(5),
        instance(1),
        object_id,
        epoch,
        plaintext,
    )?;
    assert_eq!(
        storage
            .publish_object(
                &staging,
                &secret(5),
                instance(1),
                object_id,
                epoch,
                b"substitution",
            )
            .expect_err("reserved object substitution must fail")
            .code(),
        CatalogFailureCode::IntegrityCorruption
    );

    let (audit, encoded_audit) = prepare_audit(AuditFrontier::ORIGIN, transaction_id, b"redacted")?;
    storage.publish_audit(&staging, &secret(5), instance(1), &audit, &encoded_audit)?;
    assert_eq!(
        storage.read_audit(
            &secret(5),
            instance(1),
            audit.position(),
            audit.record_hash(),
        )?,
        encoded_audit
    );
    storage.publish_audit(&staging, &secret(5), instance(1), &audit, &encoded_audit)?;
    assert_eq!(
        storage
            .publish_audit(&staging, &secret(5), instance(1), &audit, b"substitution",)
            .expect_err("reserved audit substitution must fail")
            .code(),
        CatalogFailureCode::IntegrityCorruption
    );

    let generation = CatalogGenerationId([0x51; 32]);
    storage.publish_commit(&staging, &secret(5), instance(1), generation, b"commit")?;
    assert_eq!(
        storage.read_commit(&secret(5), instance(1), generation)?,
        b"commit"
    );
    storage.publish_commit(&staging, &secret(5), instance(1), generation, b"commit")?;
    assert_eq!(
        storage
            .publish_commit(
                &staging,
                &secret(5),
                instance(1),
                generation,
                b"substitution",
            )
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
