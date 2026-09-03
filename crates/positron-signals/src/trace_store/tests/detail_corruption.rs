use super::*;
use crate::{
    SpanAttributeSet, SpanEvent, SpanLink, SpanObservationDetails, SpanResourceMetadata,
    SpanScopeMetadata, SpanStatus, SpanStatusCode,
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
    let details = SpanObservationDetails::checked(
        "trace-state".to_owned(),
        0x401,
        SpanStatus::checked(SpanStatusCode::Error, "status".to_owned())?,
        vec![SpanEvent::checked(
            EventTime::missing(),
            "event".to_owned(),
            event_attributes,
            2,
        )?],
        vec![SpanLink::checked(
            [0xb1; 16],
            [0xb2; 8],
            "link-state".to_owned(),
            0x402,
            link_attributes,
            3,
        )?],
        4,
        5,
        6,
        SpanResourceMetadata::checked(7, "resource-schema".to_owned())?,
        SpanScopeMetadata::checked(
            "scope".to_owned(),
            "1.0".to_owned(),
            8,
            "scope-schema".to_owned(),
        )?,
    )?;
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
