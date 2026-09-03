use super::*;
use crate::{
    SpanObservationDetails, SpanResourceMetadata, SpanScopeMetadata, SpanStatus, SpanStatusCode,
};

#[test]
fn malformed_trace_block_fails_closed_without_a_partial_result() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x19; 16])?,
        CatalogSecret::from_owned(Box::new([0x29; 32]), Box::new([0x39; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(9)?;
    let scope = SegmentScope::new(tenant, SignalKind::Traces, shard);
    let (retention, _) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(100));
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x59; 32])),
    )?;
    let store = TraceStore::new();
    let observation = SpanObservation::checked_native(
        [0x71; 16],
        [0x72; 8],
        None,
        "valid-prefix".to_owned(),
        EventTime::missing(),
        EventTime::missing(),
        Vec::new(),
        SpanKind::Internal,
        SamplingDecision::Unknown,
        positron_policy::PolicyProvenance::new(1, [0x86; 32], Vec::new()).unwrap(),
    )?;
    let clock = LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100)));
    let stored = StoredSpanObservation::new(observation, clock.assign_ingest_time()?);
    let mut malformed = codec::encode_block(tenant, std::slice::from_ref(&stored))?;
    malformed.push(0xff);
    let preparation = ledger.begin_store_block(
        preparation_capacity(&authority, tenant)?,
        positron_kernel::StoreBlockIdentity::new([0x73; 16])?,
    )?;
    ledger.append(preparation.finish(malformed)?)?;
    let snapshot = ledger.snapshot()?;
    let block = snapshot.blocks().first().ok_or("missing malformed block")?;
    let cancellation = NeverCancelled;
    let observer = NeverObserved;
    let failure =
        match codec::BlockDecode::observed(tenant, block.payload(), &cancellation, &observer)?
            .decode_after(block, 0, 1, &cancellation)
        {
            Ok(_) => return Err("the decoder accepted trailing bytes".into()),
            Err(failure) => failure,
        };
    assert_eq!(failure.code(), TraceStoreFailureCode::MalformedBlock);
    let failure = store
        .scan(
            authority.governor(),
            tenant,
            &ledger.snapshot()?,
            TraceScan::all(ScanLimit::new(1)?),
        )
        .expect_err("malformed native block must not yield a partial observation");
    assert_eq!(failure.code(), TraceStoreFailureCode::MalformedBlock);
    Ok(())
}

#[test]
fn malformed_trace_record_shapes_fail_closed_at_their_boundaries() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x20; 16])?,
        CatalogSecret::from_owned(Box::new([0x30; 32]), Box::new([0x40; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let profile = ValueLimitProfile::release_1_system_maximum();
    let attributes = vec![
        AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Record,
            "key".to_owned(),
            vec![CandidateAttributeValue::boolean(true)],
        )
        .validate(profile)?,
    ];
    let observation = SpanObservation::checked_native(
        [0x71; 16],
        [0x72; 8],
        None,
        "valid".to_owned(),
        positron_domain::time::EventTime::missing(),
        positron_domain::time::EventTime::missing(),
        attributes,
        SpanKind::Internal,
        SamplingDecision::Unknown,
        positron_policy::PolicyProvenance::new(1, [1; 32], Vec::new())?,
    )?;
    let stored = StoredSpanObservation::new(
        observation,
        LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100)))
            .assign_ingest_time()?,
    );
    let valid = codec::encode_block(tenant, std::slice::from_ref(&stored))?;
    let wrong_tenant = codec::encode_block(
        TenantId::from_bytes([0x42; 16])?,
        std::slice::from_ref(&stored),
    )?;
    let mut trailing = valid.clone();
    trailing.push(0xff);
    let truncated = valid
        .get(..valid.len().saturating_sub(3))
        .ok_or("trace fixture was unexpectedly short")?
        .to_vec();
    let mut aggregate_occurrences = valid.clone();
    aggregate_occurrences
        .get_mut(66..68)
        .ok_or("trace fixture attribute count offset")?
        .copy_from_slice(&2_u16.to_be_bytes());
    aggregate_occurrences
        .get_mut(76..78)
        .ok_or("trace fixture occurrence count offset")?
        .copy_from_slice(&1_024_u16.to_be_bytes());
    aggregate_occurrences.splice(80..80, std::iter::repeat_n(0_u8, 1_023));
    let second_set = [3_u8, 0, 0, 0, 1, b'x', 0, 1, 0];
    aggregate_occurrences.splice(1_103..1_103, second_set);
    let mut too_deep_value = vec![0_u8];
    for _ in 0..129 {
        let mut array = vec![6_u8, 0, 1];
        array.append(&mut too_deep_value);
        too_deep_value = array;
    }
    let mut too_deep = valid.clone();
    too_deep.splice(78..80, too_deep_value);
    let cases = vec![
        (
            "wrong magic",
            replaced_byte(&valid, 0, 0xff)?,
            TraceStoreFailureCode::MalformedBlock,
        ),
        (
            "wrong version",
            replaced_bytes(&valid, 8, [0, 3])?,
            TraceStoreFailureCode::MalformedBlock,
        ),
        (
            "wrong tenant",
            wrong_tenant,
            TraceStoreFailureCode::PhysicalScopeMismatch,
        ),
        (
            "zero records",
            replaced_bytes(&valid, 26, [0, 0])?,
            TraceStoreFailureCode::MalformedBlock,
        ),
        (
            "too many records",
            replaced_bytes(&valid, 26, [4, 1])?,
            TraceStoreFailureCode::MalformedBlock,
        ),
        (
            "unknown parent marker",
            replaced_byte(&valid, 52, 9)?,
            TraceStoreFailureCode::MalformedBlock,
        ),
        (
            "unknown span kind",
            replaced_byte(&valid, 53, 9)?,
            TraceStoreFailureCode::MalformedBlock,
        ),
        (
            "unknown sampling decision",
            replaced_byte(&valid, 54, 9)?,
            TraceStoreFailureCode::MalformedBlock,
        ),
        (
            "unknown source time quality",
            replaced_byte(&valid, 55, 9)?,
            TraceStoreFailureCode::MalformedBlock,
        ),
        (
            "invalid span name",
            replaced_byte(&valid, 61, 0xff)?,
            TraceStoreFailureCode::MalformedBlock,
        ),
        (
            "unknown attribute namespace",
            replaced_byte(&valid, 68, 9)?,
            TraceStoreFailureCode::MalformedBlock,
        ),
        (
            "log-only stream attribute namespace",
            replaced_byte(&valid, 68, 4)?,
            TraceStoreFailureCode::MalformedBlock,
        ),
        (
            "empty occurrence set",
            replaced_bytes(&valid, 76, [0, 0])?,
            TraceStoreFailureCode::MalformedBlock,
        ),
        (
            "unknown native value",
            replaced_byte(&valid, 78, 9)?,
            TraceStoreFailureCode::MalformedBlock,
        ),
        (
            "invalid native boolean",
            replaced_byte(&valid, 79, 9)?,
            TraceStoreFailureCode::MalformedBlock,
        ),
        (
            "invalid policy provenance",
            replaced_bytes(&valid, valid.len().saturating_sub(42), [0; 32])?,
            TraceStoreFailureCode::MalformedBlock,
        ),
        (
            "truncated block",
            truncated,
            TraceStoreFailureCode::MalformedBlock,
        ),
        (
            "trailing bytes",
            trailing,
            TraceStoreFailureCode::MalformedBlock,
        ),
        (
            "aggregate namespace occurrences",
            aggregate_occurrences,
            TraceStoreFailureCode::MalformedBlock,
        ),
        (
            "nested value beyond the depth bound",
            too_deep,
            TraceStoreFailureCode::MalformedBlock,
        ),
    ];

    for (index, (description, bytes, expected)) in cases.into_iter().enumerate() {
        let shard = VirtualShardId::new(u32::try_from(index + 20)?)?;
        let scope = SegmentScope::new(tenant, SignalKind::Traces, shard);
        let ledger = ActiveSegmentLedger::open(
            &authority,
            &catalog,
            scope,
            SegmentProtectionKey::from_owned(Box::new([u8::try_from(index + 0x61)?; 32])),
        )?;
        ledger.append(positron_kernel::PreparedStoreBlock::new(
            scope,
            positron_kernel::StoreBlockIdentity::new([u8::try_from(index + 0x71)?; 16])?,
            bytes,
        )?)?;
        let failure = TraceStore::new()
            .scan(
                authority.governor(),
                tenant,
                &ledger.snapshot()?,
                TraceScan::all(ScanLimit::new(1)?),
            )
            .expect_err(description);
        assert_eq!(failure.code(), expected, "{description}");
    }
    Ok(())
}

#[test]
fn malformed_v2_detail_framing_is_typed_and_atomic() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x21; 16])?,
        CatalogSecret::from_owned(Box::new([0x31; 32]), Box::new([0x41; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let details = SpanObservationDetails::checked(
        "trace-state".to_owned(),
        0x0102_0304,
        SpanStatus::checked(SpanStatusCode::Error, "failed".to_owned())?,
        Vec::new(),
        Vec::new(),
        1,
        2,
        3,
        SpanResourceMetadata::checked(4, "resource-schema".to_owned())?,
        SpanScopeMetadata::checked(
            "scope".to_owned(),
            "1.0".to_owned(),
            5,
            "scope-schema".to_owned(),
        )?,
    )?;
    let observation = SpanObservation::checked_native_with_details(
        [0x51; 16],
        [0x52; 8],
        None,
        "detail-boundary".to_owned(),
        EventTime::missing(),
        EventTime::missing(),
        Vec::new(),
        SpanKind::Internal,
        SamplingDecision::Unknown,
        positron_policy::PolicyProvenance::new(3, [0x61; 32], Vec::new())?,
        details,
    )?;
    let stored = StoredSpanObservation::new(
        observation,
        LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100)))
            .assign_ingest_time()?,
    );
    let valid = codec::encode_block(tenant, std::slice::from_ref(&stored))?;
    let offsets = detail_offsets(&valid)?;
    let mut cases = Vec::new();
    cases.push((
        "unknown status code",
        replaced_byte(&valid, offsets.status_tag, 9)?,
    ));
    let mut invalid_utf8 = valid.clone();
    *invalid_utf8
        .get_mut(offsets.trace_state_start)
        .ok_or("trace state fixture offset")? = 0xff;
    cases.push(("invalid detail UTF-8", invalid_utf8));
    cases.push((
        "too many events",
        replaced_bytes(&valid, offsets.events_count, [4, 1])?,
    ));
    cases.push((
        "too many links",
        replaced_bytes(&valid, offsets.links_count, [4, 1])?,
    ));
    cases.push((
        "truncated detail",
        valid
            .get(..valid.len().saturating_sub(3))
            .ok_or("detail fixture was unexpectedly short")?
            .to_vec(),
    ));
    let mut trailing = valid.clone();
    trailing.push(0xff);
    cases.push(("trailing detail bytes", trailing));

    for (index, (description, bytes)) in cases.into_iter().enumerate() {
        let case_shard = VirtualShardId::new(u32::try_from(41 + index)?)?;
        let case_scope = SegmentScope::new(tenant, SignalKind::Traces, case_shard);
        let ledger = ActiveSegmentLedger::open(
            &authority,
            &catalog,
            case_scope,
            SegmentProtectionKey::from_owned(Box::new([u8::try_from(0x71 + index)?; 32])),
        )?;
        ledger.append(positron_kernel::PreparedStoreBlock::new(
            case_scope,
            positron_kernel::StoreBlockIdentity::new([u8::try_from(0x81 + index)?; 16])?,
            bytes,
        )?)?;
        let snapshot = ledger.snapshot()?;
        let before = authority.governor().inspect()?.outstanding_total();
        let failure = TraceStore::new()
            .scan(
                authority.governor(),
                tenant,
                &snapshot,
                TraceScan::all(ScanLimit::new(1)?),
            )
            .expect_err(description);
        assert_eq!(failure.code(), TraceStoreFailureCode::MalformedBlock);
        assert_eq!(
            authority.governor().inspect()?.outstanding_total(),
            before,
            "{description} must not strand scan admission"
        );
    }
    Ok(())
}

struct DetailOffsets {
    trace_state_start: usize,
    status_tag: usize,
    events_count: usize,
    links_count: usize,
}

fn detail_offsets(bytes: &[u8]) -> Result<DetailOffsets, Box<dyn Error>> {
    let mut offset = 28_usize;
    offset = offset
        .checked_add(16 + 8 + 3)
        .ok_or("record prefix offset overflow")?;
    for _ in 0..2 {
        offset = offset.checked_add(1).ok_or("time offset overflow")?;
    }
    let name_length = usize::try_from(read_u32(bytes, offset)?)?;
    offset = offset
        .checked_add(4 + name_length + 2)
        .ok_or("name offset overflow")?;
    let trace_state_length = usize::try_from(read_u32(bytes, offset)?)?;
    let trace_state_start = offset.checked_add(4).ok_or("trace state offset overflow")?;
    offset = trace_state_start
        .checked_add(trace_state_length)
        .ok_or("trace state length overflow")?;
    let status_tag = offset.checked_add(4).ok_or("flags offset overflow")?;
    offset = status_tag.checked_add(1).ok_or("status offset overflow")?;
    let status_message_length = usize::try_from(read_u32(bytes, offset)?)?;
    offset = offset
        .checked_add(4 + status_message_length + 4 * 4)
        .ok_or("status metadata offset overflow")?;
    for _ in 0..2 {
        let length = usize::try_from(read_u32(bytes, offset)?)?;
        offset = offset
            .checked_add(4 + length)
            .ok_or("scope metadata offset overflow")?;
    }
    let scope_version_length = usize::try_from(read_u32(bytes, offset)?)?;
    offset = offset
        .checked_add(4 + scope_version_length + 4)
        .ok_or("scope version offset overflow")?;
    let scope_schema_length = usize::try_from(read_u32(bytes, offset)?)?;
    offset = offset
        .checked_add(4 + scope_schema_length)
        .ok_or("scope schema offset overflow")?;
    let events_count = offset;
    let event_count = usize::from(read_u16(bytes, events_count)?);
    if event_count != 0 {
        return Err("detail fixture unexpectedly contains events".into());
    }
    let links_count = events_count.checked_add(2).ok_or("links offset overflow")?;
    Ok(DetailOffsets {
        trace_state_start,
        status_tag,
        events_count,
        links_count,
    })
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, Box<dyn Error>> {
    Ok(u16::from_be_bytes(
        bytes
            .get(offset..offset + 2)
            .ok_or("fixture u16 offset")?
            .try_into()?,
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, Box<dyn Error>> {
    Ok(u32::from_be_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or("fixture u32 offset")?
            .try_into()?,
    ))
}
