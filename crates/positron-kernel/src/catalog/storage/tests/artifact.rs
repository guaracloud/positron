use super::*;

#[test]
fn protected_artifacts_bind_kind_identity_epoch_and_secret() {
    let identity = [0x31; 32];
    let epoch = FormatEpoch(4);
    for kind in [
        ArtifactKind::Object,
        ArtifactKind::Audit,
        ArtifactKind::Commit,
    ] {
        let first = protect_artifact(&secret(1), instance(1), kind, identity, epoch, b"plaintext")
            .expect("valid artifact must protect");
        let second = protect_artifact(&secret(1), instance(1), kind, identity, epoch, b"plaintext")
            .expect("valid artifact must protect");
        assert_ne!(first, second, "each protection attempt needs fresh salt");
        assert_ne!(
            &first[39..71],
            &second[39..71],
            "each artifact needs an independent immutable child-key identity"
        );
        assert_eq!(
            open_artifact(&secret(1), instance(1), kind, identity, epoch, &first)
                .expect("matching context must open"),
            b"plaintext"
        );

        for failure in [
            open_artifact(&secret(2), instance(1), kind, identity, epoch, &first),
            open_artifact(&secret(1), instance(1), kind, [0x32; 32], epoch, &first),
            open_artifact(
                &secret(1),
                instance(1),
                kind,
                identity,
                FormatEpoch(5),
                &first,
            ),
            open_artifact(&secret(1), instance(2), kind, identity, epoch, &first),
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
            open_artifact(&secret(1), instance(1), other_kind, identity, epoch, &first)
                .expect_err("artifact kind substitution must fail")
                .code(),
            CatalogFailureCode::IntegrityCorruption
        );

        for offset in [31_usize, 39, 78, 79, 111] {
            let mut corrupt_envelope = first.clone();
            corrupt_envelope[offset] ^= 1;
            assert_eq!(
                open_artifact(
                    &secret(1),
                    instance(1),
                    kind,
                    identity,
                    epoch,
                    &corrupt_envelope,
                )
                .expect_err("outer or wrapped envelope substitution must fail")
                .code(),
                CatalogFailureCode::AuthenticationFailed
            );
        }

        for length in 0..247 {
            assert_eq!(
                open_artifact(
                    &secret(1),
                    instance(1),
                    kind,
                    identity,
                    epoch,
                    &first[..length]
                )
                .expect_err("truncated header must fail")
                .code(),
                CatalogFailureCode::IntegrityCorruption
            );
        }
        let mut corrupt = first;
        corrupt[0] ^= 1;
        assert_eq!(
            open_artifact(&secret(1), instance(1), kind, identity, epoch, &corrupt)
                .expect_err("corrupt magic must fail")
                .code(),
            CatalogFailureCode::IntegrityCorruption
        );
        corrupt[0] ^= 1;
        corrupt[14] ^= 1;
        assert_eq!(
            open_artifact(&secret(1), instance(1), kind, identity, epoch, &corrupt)
                .expect_err("unknown wrapping algorithm must fail")
                .code(),
            CatalogFailureCode::UnsupportedFormat
        );
    }

    assert_eq!(
        protect_artifact(
            &secret(1),
            instance(1),
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
fn authenticated_object_bytes_must_match_their_content_identity()
-> Result<(), Box<dyn std::error::Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let storage = CatalogStorage::open(&volume)?;
    let identity = CatalogObjectId([0x35; 32]);
    let epoch = FormatEpoch(2);
    let protected = protect_artifact(
        &secret(2),
        instance(2),
        ArtifactKind::Object,
        identity.0,
        epoch,
        b"authenticated bytes with a different digest",
    )?;
    write_new_file(&storage.objects, &object_name(epoch, identity), &protected)?;

    assert_eq!(
        storage
            .read_object(&secret(2), instance(2), identity, epoch)
            .expect_err("the authenticated object identity must remain content-addressed")
            .code(),
        CatalogFailureCode::IntegrityCorruption
    );
    Ok(())
}

#[test]
fn root_rotation_rewraps_only_the_dek_envelope() {
    let current = CatalogSecret::from_owned_at_epoch(
        Box::new([0x10; 32]),
        Box::new([0x11; 32]),
        [0x21; 16],
        7,
    )
    .expect("valid current root epoch");
    let replacement = CatalogSecret::from_owned_at_epoch(
        Box::new([0x10; 32]),
        Box::new([0x12; 32]),
        [0x22; 16],
        8,
    )
    .expect("valid replacement root epoch");
    let identity = [0x31; 32];
    let epoch = FormatEpoch(4);
    let encoded = protect_artifact(
        &current,
        instance(3),
        ArtifactKind::Object,
        identity,
        epoch,
        b"ciphertext remains immutable",
    )
    .expect("artifact protects");
    let rewrapped = rewrap_artifact_envelope(
        &current.wrapping,
        &replacement.wrapping,
        instance(3),
        ArtifactKind::Object,
        identity,
        epoch,
        &encoded,
    )
    .expect("root rotation rewraps the envelope");

    assert_eq!(&encoded[247..], &rewrapped[247..]);
    assert_eq!(
        open_artifact(
            &replacement,
            instance(3),
            ArtifactKind::Object,
            identity,
            epoch,
            &rewrapped,
        )
        .expect("replacement epoch opens the unchanged ciphertext"),
        b"ciphertext remains immutable"
    );
    assert_eq!(
        open_artifact(
            &current,
            instance(3),
            ArtifactKind::Object,
            identity,
            epoch,
            &rewrapped,
        )
        .expect_err("retired routing identity must fail closed")
        .code(),
        CatalogFailureCode::AuthenticationFailed
    );
    let wrong_current = CatalogSecret::from_owned_at_epoch(
        Box::new([0x10; 32]),
        Box::new([0x11; 32]),
        [0x23; 16],
        7,
    )
    .expect("valid alternate routing identity");
    assert_eq!(
        rewrap_artifact_envelope(
            &wrong_current.wrapping,
            &replacement.wrapping,
            instance(3),
            ArtifactKind::Object,
            identity,
            epoch,
            &encoded,
        )
        .expect_err("rewrap must authenticate the current provider routing identity")
        .code(),
        CatalogFailureCode::AuthenticationFailed
    );
    assert_eq!(
        rewrap_artifact_envelope(
            &current.wrapping,
            &replacement.wrapping,
            instance(4),
            ArtifactKind::Object,
            identity,
            epoch,
            &encoded,
        )
        .expect_err("rewrap must authenticate the complete envelope context")
        .code(),
        CatalogFailureCode::AuthenticationFailed
    );
}

#[test]
fn stored_rewrap_rejects_corruption_wrong_predecessor_and_partial_replacement()
-> Result<(), Box<dyn std::error::Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let storage = CatalogStorage::open(&volume)?;
    let current = CatalogSecret::from_owned_at_epoch(
        Box::new([0x40; 32]),
        Box::new([0x41; 32]),
        [0x42; 16],
        7,
    )?;
    let replacement = CatalogSecret::from_owned_at_epoch(
        Box::new([0x40; 32]),
        Box::new([0x43; 32]),
        [0x44; 16],
        8,
    )?;
    let plaintext = b"stored rewrap boundary";
    let identity = CatalogObjectId(Sha256::digest(plaintext).into());
    let epoch = FormatEpoch(1);
    let transaction = storage.open_transaction(transaction(31), [0x51; 32])?;
    storage.publish_object(
        &transaction,
        &current,
        instance(3),
        identity,
        epoch,
        plaintext,
    )?;

    let wrong = secret(0x52);
    assert_eq!(
        storage
            .rewrap_object(
                &wrong.wrapping,
                &replacement.wrapping,
                instance(3),
                identity,
                epoch,
            )
            .expect_err("an unrelated predecessor cannot rewrap a stored artifact")
            .code(),
        CatalogFailureCode::AuthenticationFailed
    );
    let partial = with_catalog_fault(CatalogFileEvent::PartialRewrapWrite, || {
        storage.rewrap_object(
            &current.wrapping,
            &replacement.wrapping,
            instance(3),
            identity,
            epoch,
        )
    })
    .expect_err("a partial replacement must remain retryable");
    assert_eq!(partial.code(), CatalogFailureCode::StorageUnavailable);
    storage.rewrap_object(
        &current.wrapping,
        &replacement.wrapping,
        instance(3),
        identity,
        epoch,
    )?;

    let path = root
        .path()
        .join("catalog/objects")
        .join(object_name(epoch, identity));
    let mut corrupted = fs::read(&path)?;
    corrupted[0] ^= 1;
    fs::write(path, corrupted)?;
    assert_eq!(
        storage
            .rewrap_object(
                &current.wrapping,
                &replacement.wrapping,
                instance(3),
                identity,
                epoch,
            )
            .expect_err("a corrupt successor artifact must fail closed")
            .code(),
        CatalogFailureCode::IntegrityCorruption
    );
    Ok(())
}
