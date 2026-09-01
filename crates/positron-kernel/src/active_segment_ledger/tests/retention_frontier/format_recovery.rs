use super::*;

#[test]
fn authenticated_v1_and_v2_segments_remain_readable_but_retention_ineligible()
-> Result<(), Box<dyn Error>> {
    for format_version in [1_u16, 2_u16] {
        assert_legacy_segment_compatibility(format_version)?;
    }
    Ok(())
}

#[test]
fn authenticated_v3_frontier_rejects_an_outer_selector_downgrade() -> Result<(), Box<dyn Error>> {
    assert_frontier_selector_flip_is_corruption(3, 2, b"selector-downgrade", 0x40, 38)
}

#[test]
fn authenticated_v2_frontier_rejects_an_outer_selector_upgrade() -> Result<(), Box<dyn Error>> {
    let mut crafted_legacy_payload = Vec::from([2_u8]);
    crafted_legacy_payload.extend_from_slice(&4_000_000_000_i64.to_be_bytes());
    crafted_legacy_payload.extend_from_slice(b"selector-upgrade");
    assert_frontier_selector_flip_is_corruption(2, 3, &crafted_legacy_payload, 0x43, 39)
}

#[test]
fn authenticated_v3_frontier_rejects_inner_selector_sequence_and_empty_complete_mismatch()
-> Result<(), Box<dyn Error>> {
    for (frontier, discriminator, shard) in [
        (
            AuthenticatedFrontierFixture {
                inner_version: 2,
                frame_sequence: 1,
                next_sequence: 1,
                retention_tag: 2,
            },
            0x49,
            40,
        ),
        (
            AuthenticatedFrontierFixture {
                inner_version: 3,
                frame_sequence: 1,
                next_sequence: 2,
                retention_tag: 2,
            },
            0x4a,
            41,
        ),
        (
            AuthenticatedFrontierFixture {
                inner_version: 3,
                frame_sequence: 0,
                next_sequence: 0,
                retention_tag: 2,
            },
            0x4b,
            42,
        ),
    ] {
        assert_invalid_authenticated_v3_frontier(frontier, discriminator, shard)?;
    }
    Ok(())
}

fn assert_invalid_authenticated_v3_frontier(
    frontier: AuthenticatedFrontierFixture,
    discriminator: u8,
    shard: u32,
) -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let instance = InstanceId::new([discriminator; 16])?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(
            Box::new([discriminator.wrapping_add(1); 32]),
            Box::new([discriminator.wrapping_add(2); 32]),
        ),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(shard)?);
    let (retention_time, _) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(5_000_000_000));
    let protection = || SegmentProtectionKey::from_owned(Box::new([discriminator; 32]));
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        protection(),
    )?;
    let segment = ledger.active_segment_id()?;
    drop(ledger.begin_store_block(
        preparation_capacity(&authority, tenant)?,
        StoreBlockIdentity::new([discriminator.wrapping_add(3); 16])?,
    )?);
    drop(ledger);
    write_authenticated_segment_fixture(AuthenticatedSegmentFixture {
        root: root.path(),
        instance,
        scope,
        segment,
        wrapping: protection(),
        identity: StoreBlockIdentity::new([discriminator.wrapping_add(4); 16])?,
        payload: b"invalid-authenticated-frontier",
        format_version: 3,
        block_tag: Some(2),
        block_time: Some(4_000_000_000),
        frontier_time: Some(4_000_000_000),
        frontier,
    })?;

    let failure = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        protection(),
    )
    .expect_err("authenticated frontier semantics must be internally consistent");
    assert_eq!(failure.code(), LedgerFailureCode::IntegrityCorruption);
    Ok(())
}

fn assert_frontier_selector_flip_is_corruption(
    stored_version: u16,
    selected_version: u16,
    payload: &[u8],
    discriminator: u8,
    shard: u32,
) -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let instance = InstanceId::new([discriminator; 16])?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(
            Box::new([discriminator.wrapping_add(1); 32]),
            Box::new([discriminator.wrapping_add(2); 32]),
        ),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(shard)?);
    let (retention_time, _) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(5_000_000_000));
    let protection = || SegmentProtectionKey::from_owned(Box::new([discriminator; 32]));
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        protection(),
    )?;
    let segment = ledger.active_segment_id()?;
    drop(ledger.begin_store_block(
        preparation_capacity(&authority, tenant)?,
        StoreBlockIdentity::new([discriminator.wrapping_add(3); 16])?,
    )?);
    drop(ledger);

    write_authenticated_segment_fixture(AuthenticatedSegmentFixture {
        root: root.path(),
        instance,
        scope,
        segment,
        wrapping: protection(),
        identity: StoreBlockIdentity::new([discriminator.wrapping_add(4); 16])?,
        payload,
        format_version: stored_version,
        block_tag: (stored_version == 3).then_some(2),
        block_time: (stored_version == 3).then_some(4_000_000_000),
        frontier_time: (stored_version >= 2).then_some(4_000_000_000),
        frontier: AuthenticatedFrontierFixture::valid(stored_version),
    })?;
    replace_outer_frontier_selector(root.path(), segment, selected_version)?;

    let failure = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        protection(),
    )
    .expect_err("the active-segment format selector must be authenticated");
    assert_eq!(failure.code(), LedgerFailureCode::IntegrityCorruption);
    Ok(())
}

fn replace_outer_frontier_selector(
    root: &Path,
    segment: SegmentId,
    selected_version: u16,
) -> Result<(), Box<dyn Error>> {
    let frontier_name = format!(
        "{}.frontier",
        segment
            .to_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    let frontier_path = root.join("segments/active").join(frontier_name);
    let mut encoded = fs::read(&frontier_path)?;
    let selector = encoded.get_mut(10..12).ok_or("frontier selector missing")?;
    selector.copy_from_slice(&selected_version.to_be_bytes());
    fs::write(frontier_path, encoded)?;
    Ok(())
}

#[test]
fn authenticated_v3_segment_rejects_a_false_frontier_aggregate() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let instance = InstanceId::new([0x31; 16])?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x32; 32]), Box::new([0x33; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(35)?);
    let (retention_time, _) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(5_000_000_000));
    let protection = || SegmentProtectionKey::from_owned(Box::new([0x35; 32]));
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        protection(),
    )?;
    let segment = ledger.active_segment_id()?;
    drop(ledger.begin_store_block(
        preparation_capacity(&authority, tenant)?,
        StoreBlockIdentity::new([0x36; 16])?,
    )?);
    drop(ledger);

    write_authenticated_segment_fixture(AuthenticatedSegmentFixture {
        root: root.path(),
        instance,
        scope,
        segment,
        wrapping: protection(),
        identity: StoreBlockIdentity::new([0x37; 16])?,
        payload: b"authenticated-v3",
        format_version: 3,
        block_tag: Some(2),
        block_time: Some(4_000_000_000),
        frontier_time: Some(3_000_000_000),
        frontier: AuthenticatedFrontierFixture::valid(3),
    })?;

    let failure = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        protection(),
    )
    .expect_err("the authenticated frontier must equal the folded exact block times");
    assert_eq!(failure.code(), LedgerFailureCode::IntegrityCorruption);
    Ok(())
}

#[test]
fn authenticated_v3_blocks_reject_empty_and_unknown_retention_tags() -> Result<(), Box<dyn Error>> {
    for (tag, instant, discriminator, shard) in [(0, 0, 0x38, 36), (3, 4_000_000_000, 0x39, 37)] {
        assert_invalid_v3_block_tag(tag, instant, discriminator, shard)?;
    }
    Ok(())
}

fn assert_invalid_v3_block_tag(
    tag: u8,
    instant: i64,
    discriminator: u8,
    shard: u32,
) -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let instance = InstanceId::new([discriminator; 16])?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(
            Box::new([discriminator.wrapping_add(1); 32]),
            Box::new([discriminator.wrapping_add(2); 32]),
        ),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(shard)?);
    let (retention_time, _) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(5_000_000_000));
    let protection = || SegmentProtectionKey::from_owned(Box::new([discriminator; 32]));
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        protection(),
    )?;
    let segment = ledger.active_segment_id()?;
    drop(ledger.begin_store_block(
        preparation_capacity(&authority, tenant)?,
        StoreBlockIdentity::new([discriminator.wrapping_add(3); 16])?,
    )?);
    drop(ledger);
    write_authenticated_segment_fixture(AuthenticatedSegmentFixture {
        root: root.path(),
        instance,
        scope,
        segment,
        wrapping: protection(),
        identity: StoreBlockIdentity::new([discriminator.wrapping_add(4); 16])?,
        payload: b"invalid-v3-retention-tag",
        format_version: 3,
        block_tag: Some(tag),
        block_time: Some(instant),
        frontier_time: Some(4_000_000_000),
        frontier: AuthenticatedFrontierFixture::valid(3),
    })?;
    let failure = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        protection(),
    )
    .expect_err("v3 block retention tags must be complete and recognized");
    assert_eq!(failure.code(), LedgerFailureCode::IntegrityCorruption);
    Ok(())
}

fn assert_legacy_segment_compatibility(format_version: u16) -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let instance = InstanceId::new([format_version as u8; 16])?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0xc2; 32]), Box::new([0xc3; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    install_governance_policy(&catalog, instance, tenant, 1, format_version as u8 + 0x50)?;
    let scope = SegmentScope::new(
        tenant,
        SignalKind::Logs,
        VirtualShardId::new(u32::from(format_version) + 20)?,
    );
    let (retention_time, _) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(3_000_000_000));
    let protection = || SegmentProtectionKey::from_owned(Box::new([0xc4; 32]));
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        protection(),
    )?;
    let segment = ledger.active_segment_id()?;
    let identity = StoreBlockIdentity::new([format_version as u8 + 0x40; 16])?;
    let payload = format!("legacy-v{format_version}").into_bytes();
    drop(ledger.begin_store_block(preparation_capacity(&authority, tenant)?, identity)?);
    drop(ledger);

    write_authenticated_segment_fixture(AuthenticatedSegmentFixture {
        root: root.path(),
        instance,
        scope,
        segment,
        wrapping: protection(),
        identity,
        payload: &payload,
        format_version,
        block_tag: None,
        block_time: None,
        frontier_time: (format_version == 2).then_some(1),
        frontier: AuthenticatedFrontierFixture::valid(format_version),
    })?;

    let reopened = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        protection(),
    )?;
    let snapshot = reopened.snapshot()?;
    assert_eq!(snapshot.blocks().len(), 1);
    assert_eq!(snapshot.blocks()[0].payload(), payload);
    assert_eq!(
        snapshot.blocks()[0]
            .authenticate_ingest_time(UnixNanoseconds::new(1))
            .expect_err("legacy observations cannot authenticate retention time")
            .code(),
        LedgerFailureCode::UnsupportedFormat
    );
    drop(snapshot);
    reopened.seal()?;
    let active = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        protection(),
    )?;
    assert_eq!(active.snapshot()?.blocks()[0].payload(), payload);
    let failure = active
        .begin_retention()?
        .commit()
        .expect_err("legacy retention evidence cannot authorize destruction");
    assert_eq!(failure.code(), LedgerFailureCode::UnsupportedFormat);
    assert_eq!(active.snapshot()?.blocks().len(), 1);
    Ok(())
}

struct AuthenticatedSegmentFixture<'fixture> {
    root: &'fixture Path,
    instance: InstanceId,
    scope: SegmentScope,
    segment: SegmentId,
    wrapping: SegmentProtectionKey,
    identity: StoreBlockIdentity,
    payload: &'fixture [u8],
    format_version: u16,
    block_tag: Option<u8>,
    block_time: Option<i64>,
    frontier_time: Option<i64>,
    frontier: AuthenticatedFrontierFixture,
}

#[derive(Clone, Copy)]
struct AuthenticatedFrontierFixture {
    inner_version: u16,
    frame_sequence: u64,
    next_sequence: u64,
    retention_tag: u8,
}

impl AuthenticatedFrontierFixture {
    const fn valid(format_version: u16) -> Self {
        Self {
            inner_version: format_version,
            frame_sequence: 1,
            next_sequence: 1,
            retention_tag: 2,
        }
    }
}

fn write_authenticated_segment_fixture(
    fixture: AuthenticatedSegmentFixture<'_>,
) -> Result<(), Box<dyn Error>> {
    let AuthenticatedSegmentFixture {
        root,
        instance,
        scope,
        segment,
        wrapping,
        identity,
        payload,
        format_version,
        block_tag,
        block_time,
        frontier_time,
        frontier,
    } = fixture;
    let segment_name = format!(
        "{}.segment",
        segment
            .to_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    let frontier_name = segment_name.replace(".segment", ".frontier");
    let active = root.join("segments/active");
    let segment_path = active.join(segment_name);
    let frontier_path = active.join(frontier_name);
    let original_segment = fs::read(&segment_path)?;
    let header = decode_header(&original_segment)?;
    let object = object_context(scope, segment)?;
    let key = DataProtection::unwrap_segment_key_with_route(
        &wrapping.key,
        header.wrapped_key,
        instance.to_bytes(),
        object,
        header.route,
    )?;
    let mut plaintext = Vec::with_capacity(25 + payload.len());
    plaintext.extend_from_slice(&identity.to_bytes());
    if format_version == 3 {
        plaintext.push(block_tag.ok_or("v3 block fixture requires retention tag")?);
        plaintext.extend_from_slice(
            &block_time
                .ok_or("v3 block fixture requires exact time")?
                .to_be_bytes(),
        );
    }
    plaintext.extend_from_slice(payload);
    let frame = DataProtection::protect_frame(
        &key,
        object.frame(SegmentFramePurpose::StoreBlock, FrameSequence::new(1))?,
        &plaintext,
        FrameLimits::new(1_048_576)?,
    )?;
    let frame_length = u32::try_from(frame.as_bytes().len())?;
    let mut encoded_segment = original_segment
        .get(..header.encoded_bytes)
        .ok_or("segment header length exceeds fixture")?
        .to_vec();
    encoded_segment.extend_from_slice(&frame_length.to_be_bytes());
    encoded_segment.extend_from_slice(frame.as_bytes());
    fs::write(&segment_path, &encoded_segment)?;

    let durable_bytes = u64::try_from(encoded_segment.len())?;
    let mut frontier_plaintext = Vec::with_capacity(if format_version == 1 {
        24
    } else {
        33 + usize::from(format_version == 3) * 2
    });
    if format_version == 3 {
        frontier_plaintext.extend_from_slice(&frontier.inner_version.to_be_bytes());
    }
    frontier_plaintext.extend_from_slice(&durable_bytes.to_be_bytes());
    frontier_plaintext.extend_from_slice(&frontier.next_sequence.to_be_bytes());
    frontier_plaintext.extend_from_slice(&CommitPosition::origin().next()?.value().to_be_bytes());
    if format_version >= 2 {
        frontier_plaintext.push(frontier.retention_tag);
        frontier_plaintext.extend_from_slice(
            &frontier_time
                .ok_or("frontier fixture requires retention time")?
                .to_be_bytes(),
        );
    }
    let frontier_frame = DataProtection::protect_frame(
        &key,
        object.frame(
            SegmentFramePurpose::DurabilityFrontier,
            FrameSequence::new(u64::MAX - frontier.frame_sequence),
        )?,
        &frontier_plaintext,
        FrameLimits::new(512)?,
    )?;
    let frontier_length = u32::try_from(frontier_frame.as_bytes().len())?;
    let mut encoded_frontier = Vec::with_capacity(16 + frontier_frame.as_bytes().len());
    encoded_frontier.extend_from_slice(b"PFRONT02");
    encoded_frontier.extend_from_slice(&1_u16.to_be_bytes());
    encoded_frontier.extend_from_slice(&format_version.to_be_bytes());
    encoded_frontier.extend_from_slice(&frontier_length.to_be_bytes());
    encoded_frontier.extend_from_slice(frontier_frame.as_bytes());
    fs::write(frontier_path, encoded_frontier)?;
    Ok(())
}

#[test]
fn nonempty_scope_without_persisted_frontier_stays_readable_but_retention_unavailable()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x81; 16])?,
        CatalogSecret::from_owned(Box::new([0x82; 32]), Box::new([0x83; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(8)?);
    let key = || SegmentProtectionKey::from_owned(Box::new([0x84; 32]));
    let (initial_time, _) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(5_000_000_000));
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &initial_time,
        &catalog,
        scope,
        key(),
    )?;
    let first = ledger.begin_store_block(
        preparation_capacity(&authority, tenant)?,
        StoreBlockIdentity::new([0x85; 16])?,
    )?;
    ledger.append(first.finish(b"preexisting".to_vec())?)?;
    drop(ledger);

    let basis = catalog.pin()?;
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0x86; 16])?,
            FormatEpoch::CATALOG_V1,
            copied_non_frontier_objects(&basis)?,
        )?,
        None,
    )?;

    let (restarted_time, _) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(i64::MAX / 2));
    let restarted = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &restarted_time,
        &catalog,
        scope,
        key(),
    )?;
    assert_eq!(restarted.snapshot()?.blocks().len(), 1);
    let failure = match restarted.begin_retention() {
        Ok(_) => return Err("missing durable trust authorized destructive retention".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), LedgerFailureCode::UnsupportedFormat);

    let second = restarted.begin_store_block(
        preparation_capacity(&authority, tenant)?,
        StoreBlockIdentity::new([0x87; 16])?,
    )?;
    restarted.append(second.finish(b"new".to_vec())?)?;
    assert_eq!(restarted.snapshot()?.blocks().len(), 2);
    assert!(
        catalog
            .pin()?
            .plaintext_objects()
            .all(|bytes| !bytes.starts_with(b"PRETFR01"))
    );
    let failure = match restarted.begin_retention() {
        Ok(_) => return Err("later ingest established trust for preexisting data".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), LedgerFailureCode::UnsupportedFormat);
    Ok(())
}

#[test]
fn retention_ledger_rejects_generic_prepared_block_before_any_mutation()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x88; 16])?,
        CatalogSecret::from_owned(Box::new([0x89; 32]), Box::new([0x8a; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(19)?);
    let (retention_time, _) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(9_000_000_000));
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x8b; 32])),
    )?;
    let generation = catalog.pin()?.number();
    let baseline = authority.governor().inspect()?;
    let generic = PreparedStoreBlock::new_with_preparation_capacity(
        scope,
        StoreBlockIdentity::new([0x8c; 16])?,
        b"generic".to_vec(),
        preparation_capacity(&authority, tenant)?,
    )?;
    let failure = ledger
        .append(generic)
        .expect_err("generic preparation must not enter a retention-enabled ledger");
    assert_eq!(failure.code(), LedgerFailureCode::UnsupportedFormat);
    assert_eq!(
        failure.completion_state(),
        LedgerCompletionState::RejectedBeforeMutation
    );
    assert_eq!(catalog.pin()?.number(), generation);
    assert!(
        catalog
            .pin()?
            .plaintext_objects()
            .all(|bytes| !bytes.starts_with(b"PRETFR01"))
    );
    assert!(ledger.snapshot()?.blocks().is_empty());
    let after = authority.governor().inspect()?;
    assert_eq!(after.outstanding_total(), baseline.outstanding_total());
    for dimension in ResourceDimension::ALL {
        assert_eq!(after.usage(dimension), baseline.usage(dimension));
    }
    Ok(())
}
