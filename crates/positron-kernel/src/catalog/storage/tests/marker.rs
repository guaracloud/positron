use super::*;

#[test]
fn marker_scan_ignores_only_short_torn_entries_and_counts_authentication_failures()
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
fn marker_scan_rejects_oversized_complete_entries() -> Result<(), Box<dyn std::error::Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let storage = CatalogStorage::open(&volume)?;
    write_new_file(
        &storage.generations,
        "oversized.marker",
        &[0_u8; super::super::marker::MARKER_BYTES + 1],
    )?;
    let failure = match storage.markers(&secret(8)) {
        Ok(_) => panic!("oversized marker must fence"),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), CatalogFailureCode::IntegrityCorruption);
    Ok(())
}

#[test]
fn marker_scan_rejects_one_generation_published_at_two_numbers()
-> Result<(), Box<dyn std::error::Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let storage = CatalogStorage::open(&volume)?;
    let generation = CatalogGenerationId([0x63; 32]);
    write_new_file(
        &storage.generations,
        &marker_name(1, generation),
        &encode_marker(&secret(8), 1, generation)?,
    )?;
    write_new_file(
        &storage.generations,
        &marker_name(2, generation),
        &encode_marker(&secret(8), 2, generation)?,
    )?;

    let failure = match storage.markers(&secret(8)) {
        Ok(_) => return Err("one immutable generation cannot have two publication numbers".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), CatalogFailureCode::IntegrityCorruption);
    Ok(())
}

#[test]
fn marker_scan_fails_closed_on_an_unreadable_directory_entry()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::symlink;

    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let storage = CatalogStorage::open(&volume)?;
    symlink(
        "missing-marker-target",
        root.path().join("catalog/generations/link.marker"),
    )?;

    let failure = match storage.markers(&secret(8)) {
        Ok(_) => return Err("an unreadable generation entry cannot be ignored".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), CatalogFailureCode::IntegrityCorruption);
    Ok(())
}

#[test]
fn existing_marker_retry_classifies_authentication_format_and_shape_failures()
-> Result<(), Box<dyn std::error::Error>> {
    let generation = CatalogGenerationId([0x64; 32]);
    for (replacement, expected) in [
        (
            encode_marker(&secret(9), 1, generation)?.to_vec(),
            CatalogFailureCode::AuthenticationFailed,
        ),
        (
            {
                let mut marker = encode_marker(&secret(8), 1, generation)?.to_vec();
                marker[9] = 2;
                marker
            },
            CatalogFailureCode::UnsupportedFormat,
        ),
        (
            {
                let mut marker = encode_marker(&secret(8), 1, generation)?.to_vec();
                marker[0] ^= 1;
                marker
            },
            CatalogFailureCode::IntegrityCorruption,
        ),
    ] {
        let root = TemporaryRoot::new()?;
        let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
        let storage = CatalogStorage::open(&volume)?;
        write_new_file(
            &storage.generations,
            &marker_name(1, generation),
            &replacement,
        )?;
        assert_eq!(
            storage
                .publish_marker(&storage.staging, &secret(8), 1, generation)
                .expect_err("an existing invalid marker must fail closed")
                .code(),
            expected
        );
    }
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
            CatalogFailureCode::AuthenticationFailed
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
        storage.publish_audit(&staging, &key, instance(1), &audit, &encoded_audit)?;
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
        second.object_set_digest = object_set_digest(&second.objects)?;
        second.transaction_digest = transaction_digest(second.format_epoch, &second.objects, None)?;
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
