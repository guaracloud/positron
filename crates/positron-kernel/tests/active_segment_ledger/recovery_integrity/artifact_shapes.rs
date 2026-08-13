use super::*;

#[test]
fn sealed_segments_reject_bytes_beyond_their_frontier() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new(0x6a)?;
    let catalog = fixture.catalog()?;
    let ledger = fixture.open(&catalog, [0x7a; 32])?;
    let receipt = ledger.append(prepared(7, b"sealed-exact")?)?;
    ledger.seal()?;
    let mut file = OpenOptions::new()
        .append(true)
        .open(sealed_segment(fixture.root.path(), receipt.segment_id()))?;
    file.write_all(b"forbidden-tail")?;
    file.sync_all()?;
    assert_eq!(
        fixture
            .open(&catalog, [0x7a; 32])
            .expect_err("sealed immutable")
            .code(),
        LedgerFailureCode::IntegrityCorruption
    );
    Ok(())
}

#[test]
fn recovery_rejects_missing_multiply_linked_and_duplicated_segment_artifacts()
-> Result<(), Box<dyn Error>> {
    for mutation in 0..3 {
        let fixture = Fixture::new(0x6b + mutation)?;
        let catalog = fixture.catalog()?;
        let ledger = fixture.open(&catalog, [0x7b; 32])?;
        let receipt = ledger.append(prepared(8, b"safe-path")?)?;
        drop(ledger);
        let active = active_segment(fixture.root.path(), receipt.segment_id());
        match mutation {
            0 => fs::remove_file(&active)?,
            1 => fs::hard_link(&active, fixture.root.path().join("extra-hard-link"))?,
            _ => {
                fs::copy(
                    &active,
                    sealed_segment(fixture.root.path(), receipt.segment_id()),
                )?;
            },
        }
        assert_eq!(
            fixture
                .open(&catalog, [0x7b; 32])
                .expect_err("unsafe topology")
                .code(),
            LedgerFailureCode::IntegrityCorruption
        );
    }
    Ok(())
}

#[test]
fn recovery_rejects_a_frontier_present_in_both_lifecycle_directories() -> Result<(), Box<dyn Error>>
{
    let fixture = Fixture::new(0x6e)?;
    let catalog = fixture.catalog()?;
    let ledger = fixture.open(&catalog, [0x7e; 32])?;
    let receipt = ledger.append(prepared(9, b"one-frontier")?)?;
    drop(ledger);
    fs::copy(
        active_frontier(fixture.root.path(), receipt.segment_id()),
        sealed_frontier(fixture.root.path(), receipt.segment_id()),
    )?;
    assert_eq!(
        fixture
            .open(&catalog, [0x7e; 32])
            .expect_err("duplicate frontier")
            .code(),
        LedgerFailureCode::IntegrityCorruption
    );
    Ok(())
}

#[test]
fn an_empty_sealed_segment_rejects_unpublished_tail_bytes() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new(0x6f)?;
    let catalog = fixture.catalog()?;
    let segment = fixture.open(&catalog, [0x7f; 32])?.seal()?.segment_id();
    let mut file = OpenOptions::new()
        .append(true)
        .open(sealed_segment(fixture.root.path(), segment))?;
    file.write_all(b"no-frontier-tail")?;
    file.sync_all()?;
    assert_eq!(
        fixture
            .open(&catalog, [0x7f; 32])
            .expect_err("tail rejected")
            .code(),
        LedgerFailureCode::IntegrityCorruption
    );
    Ok(())
}

#[test]
fn recovery_rejects_unsafe_temporary_and_unpublished_artifact_shapes() -> Result<(), Box<dyn Error>>
{
    let fixture = Fixture::new(0x70)?;
    let catalog = fixture.catalog()?;
    let ledger = fixture.open(&catalog, [0x80; 32])?;
    let segment = ledger
        .append(prepared(10, b"temporary-shape")?)?
        .segment_id();
    drop(ledger);
    fs::create_dir(
        fixture
            .root
            .path()
            .join("segments/active")
            .join(format!("{}.frontier.tmp", hex(segment.to_bytes()))),
    )?;
    assert_eq!(
        fixture
            .open(&catalog, [0x80; 32])
            .expect_err("unsafe temporary")
            .code(),
        LedgerFailureCode::StorageUnavailable
    );
    for (seed, directory, name, expected) in [
        (
            0x71,
            "active",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.segment",
            LedgerFailureCode::StorageUnavailable,
        ),
        (
            0x72,
            "sealed",
            "unknown-artifact",
            LedgerFailureCode::IntegrityCorruption,
        ),
    ] {
        let fixture = Fixture::new(seed)?;
        let catalog = fixture.catalog()?;
        drop(fixture.open(&catalog, [0x81; 32])?);
        fs::create_dir(
            fixture
                .root
                .path()
                .join("segments")
                .join(directory)
                .join(name),
        )?;
        assert_eq!(
            fixture
                .open(&catalog, [0x81; 32])
                .expect_err("unsafe unpublished")
                .code(),
            expected
        );
    }
    Ok(())
}
