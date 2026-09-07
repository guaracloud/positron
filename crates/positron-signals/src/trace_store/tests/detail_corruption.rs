use super::*;
use crate::{
    SpanAttributeSet, SpanEvent, SpanLink, SpanObservationDetails, SpanObservationDetailsInput,
    SpanResourceMetadata, SpanScopeMetadata, SpanStatus, SpanStatusCode,
};

#[test]
fn public_scan_rejects_corrupt_detail_occurrences_atomically() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xa1; 16])?,
        CatalogSecret::from_owned(Box::new([0xa2; 32]), Box::new([0xa3; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(21)?;
    let scope = SegmentScope::new(tenant, SignalKind::Traces, shard);
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0xa5; 32])),
    )?;
    let profile = ValueLimitProfile::release_1_system_maximum();
    let event_attributes = vec![SpanAttributeSet::checked(
        "event.attribute".to_owned(),
        vec![CandidateAttributeValue::boolean(true)],
        profile,
    )?];
    let link_attributes = vec![SpanAttributeSet::checked(
        "link.attribute".to_owned(),
        vec![CandidateAttributeValue::signed_integer(7)],
        profile,
    )?];
    let details = SpanObservationDetails::checked(SpanObservationDetailsInput {
        trace_state: "trace-state".to_owned(),
        flags: 0x401,
        status: SpanStatus::checked(SpanStatusCode::Error, "status".to_owned())?,
        events: vec![SpanEvent::checked(
            EventTime::missing(),
            "event".to_owned(),
            event_attributes,
            2,
        )?],
        links: vec![SpanLink::checked(
            [0xb1; 16],
            [0xb2; 8],
            "link-state".to_owned(),
            0x402,
            link_attributes,
            3,
        )?],
        dropped_attributes_count: 4,
        dropped_events_count: 5,
        dropped_links_count: 6,
        resource: SpanResourceMetadata::checked(7, "resource-schema".to_owned())?,
        scope: SpanScopeMetadata::checked(
            "scope".to_owned(),
            "1.0".to_owned(),
            8,
            "scope-schema".to_owned(),
        )?,
    })?;
    let observation = SpanObservation::checked_native_with_details(
        [0xb3; 16],
        [0xb4; 8],
        None,
        "corruptible".to_owned(),
        EventTime::missing(),
        EventTime::missing(),
        Vec::new(),
        SpanKind::Internal,
        SamplingDecision::Unknown,
        positron_policy::PolicyProvenance::new(1, [0xb5; 32], Vec::new())?,
        details,
    )?;
    let clock = LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100)));
    let store = TraceStore::new();
    let prepared = store.prepare_unretained_for_test(
        preparation_capacity(&authority, tenant)?,
        &clock,
        tenant,
        shard,
        StoreBlockIdentity::new([0xb6; 16])?,
        vec![observation],
    )?;
    ledger.append(prepared.into_store_block())?;

    let mut corrupt = ledger
        .snapshot()?
        .blocks()
        .first()
        .ok_or("missing valid detail block")?
        .payload()
        .to_vec();
    let offset = event_occurrence_offset("corruptible");
    corrupt
        .get_mut(offset..offset + 2)
        .ok_or("missing event occurrence count")?
        .copy_from_slice(&0_u16.to_be_bytes());
    ledger.append(PreparedStoreBlock::new(
        scope,
        StoreBlockIdentity::new([0xb7; 16])?,
        corrupt,
    )?)?;

    let before = authority.governor().inspect()?.outstanding_total();
    let failure = store
        .scan(
            authority.governor(),
            tenant,
            &ledger.snapshot()?,
            TraceScan::all(ScanLimit::new(2)?),
        )
        .expect_err("zero detail occurrences must fail the complete scan");
    assert_eq!(failure.code(), TraceStoreFailureCode::MalformedBlock);
    assert_eq!(
        authority.governor().inspect()?.outstanding_total(),
        before,
        "failed detail recovery must release scan admission"
    );
    Ok(())
}

#[test]
fn public_scan_rejects_authenticated_empty_event_detail_names_atomically()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xc1; 16])?,
        CatalogSecret::from_owned(Box::new([0xc2; 32]), Box::new([0xc3; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let details = SpanObservationDetails::checked(SpanObservationDetailsInput {
        trace_state: String::new(),
        flags: 0,
        status: SpanStatus::checked(SpanStatusCode::Unset, String::new())?,
        events: vec![SpanEvent::checked(
            EventTime::missing(),
            "x".to_owned(),
            vec![SpanAttributeSet::checked(
                "y".to_owned(),
                vec![CandidateAttributeValue::boolean(true)],
                ValueLimitProfile::release_1_system_maximum(),
            )?],
            0,
        )?],
        links: Vec::new(),
        dropped_attributes_count: 0,
        dropped_events_count: 0,
        dropped_links_count: 0,
        resource: SpanResourceMetadata::checked(0, String::new())?,
        scope: SpanScopeMetadata::checked(String::new(), String::new(), 0, String::new())?,
    })?;
    let observation = SpanObservation::checked_native_with_details(
        [0xc5; 16],
        [0xc6; 8],
        None,
        "semantic-detail".to_owned(),
        EventTime::missing(),
        EventTime::missing(),
        Vec::new(),
        SpanKind::Internal,
        SamplingDecision::Unknown,
        positron_policy::PolicyProvenance::new(1, [0xc7; 32], Vec::new())?,
        details,
    )?;
    let stored = StoredSpanObservation::new(
        observation,
        LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100)))
            .assign_ingest_time()?,
    );
    let valid = codec::encode_block(tenant, std::slice::from_ref(&stored))?;
    let event_name_length = 28
        + 16
        + 8
        + 3
        + 2
        + 4
        + "semantic-detail".len()
        + 2
        + 4
        + 4
        + 1
        + 4
        + 4 * 4
        + 4
        + 4
        + 4
        + 4
        + 4
        + 2
        + 1;
    let event_attribute_name_length = event_name_length + 4 + 1 + 4 + 2;
    for (index, (description, offset)) in [
        ("event name", event_name_length),
        ("event attribute key", event_attribute_name_length),
    ]
    .into_iter()
    .enumerate()
    {
        if valid.get(offset..offset + 4) != Some(&1_u32.to_be_bytes()) {
            return Err(format!("{description} fixture unexpectedly changed").into());
        }
        let mut malformed = replaced_bytes(&valid, offset, 0_u32.to_be_bytes())?;
        malformed.drain(offset + 4..offset + 5);
        let scope = SegmentScope::new(
            tenant,
            SignalKind::Traces,
            VirtualShardId::new(u32::try_from(22 + index)?)?,
        );
        let ledger = ActiveSegmentLedger::open(
            &authority,
            &catalog,
            scope,
            SegmentProtectionKey::from_owned(Box::new([u8::try_from(0xc4 + index)?; 32])),
        )?;
        ledger.append(PreparedStoreBlock::new(
            scope,
            StoreBlockIdentity::new([u8::try_from(0xc8 + index)?; 16])?,
            malformed,
        )?)?;

        let before = authority.governor().inspect()?.outstanding_total();
        let failure = TraceStore::new()
            .scan(
                authority.governor(),
                tenant,
                &ledger.snapshot()?,
                TraceScan::all(ScanLimit::new(1)?),
            )
            .expect_err("an empty semantic detail name must be rejected during replay");
        assert_eq!(failure.code(), TraceStoreFailureCode::MalformedBlock);
        assert_eq!(
            authority.governor().inspect()?.outstanding_total(),
            before,
            "{description} rejection must release scan admission"
        );
    }
    Ok(())
}

fn event_occurrence_offset(record_name: &str) -> usize {
    let mut offset = 28_usize;
    offset += 16 + 8 + 1 + 1 + 1 + 1 + 1;
    offset += 4 + record_name.len() + 2;
    offset += 4 + "trace-state".len();
    offset += 4 + 1 + 4 + "status".len() + 4 * 4;
    offset += 4 + "resource-schema".len();
    offset += 4 + "scope".len();
    offset += 4 + "1.0".len() + 4;
    offset += 4 + "scope-schema".len();
    offset += 2 + 1 + 4 + "event".len() + 4 + 2 + 4 + "event.attribute".len();
    offset
}
