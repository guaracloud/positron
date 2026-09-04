use super::super::*;
use crate::{
    SpanAttributeSet, SpanEvent, SpanLink, SpanObservationDetails, SpanResourceMetadata,
    SpanScopeMetadata, SpanStatus, SpanStatusCode,
};

#[test]
fn scan_detail_retention_holds_governor_reservation_until_result_drop() -> Result<(), Box<dyn Error>>
{
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x94; 16])?,
        CatalogSecret::from_owned(Box::new([0xa4; 32]), Box::new([0xb4; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(14)?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Traces, shard),
        SegmentProtectionKey::from_owned(Box::new([0xc4; 32])),
    )?;
    let profile = ValueLimitProfile::release_1_system_maximum();
    let event_attribute = SpanAttributeSet::checked(
        "event.attribute".to_owned(),
        vec![CandidateAttributeValue::string("event-value".to_owned())],
        profile,
    )?;
    let link_attribute = SpanAttributeSet::checked(
        "link.attribute".to_owned(),
        vec![CandidateAttributeValue::bytes(vec![1, 2, 3, 4])],
        profile,
    )?;
    let details = SpanObservationDetails::checked(
        "vendor=trace".to_owned(),
        0x0301,
        SpanStatus::checked(SpanStatusCode::Error, "failed".to_owned())?,
        vec![SpanEvent::checked(
            EventTime::missing(),
            "exception".to_owned(),
            vec![event_attribute],
            1,
        )?],
        vec![SpanLink::checked(
            [0x11; 16],
            [0x22; 8],
            "vendor=link".to_owned(),
            0x0402,
            vec![link_attribute],
            2,
        )?],
        3,
        4,
        5,
        SpanResourceMetadata::checked(6, "https://resource".to_owned())?,
        SpanScopeMetadata::checked(
            "instrumentation".to_owned(),
            "1.0".to_owned(),
            7,
            "https://scope".to_owned(),
        )?,
    )?;
    let observation = SpanObservation::checked_native_with_details(
        [0x31; 16],
        [0x32; 8],
        None,
        "detailed".to_owned(),
        EventTime::missing(),
        EventTime::missing(),
        Vec::new(),
        SpanKind::Server,
        SamplingDecision::Sampled,
        positron_policy::PolicyProvenance::new(2, [0x33; 32], vec!["trace.rule".to_owned()])?,
        details,
    )?;
    let store = TraceStore::new();
    ledger.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
                tenant,
                shard,
                positron_kernel::StoreBlockIdentity::new([0xd4; 16])?,
                vec![observation],
            )?
            .into_store_block(),
    )?;

    let baseline = authority.governor().inspect()?.outstanding_total();
    let first = store.scan_observed_with_profile(
        &profile,
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::all(ScanLimit::new(1)?),
        &NeverCancelled,
        &NeverObserved,
    )?;
    let retained = first.retained_size_bytes();
    assert!(
        retained > 512,
        "v2 detail and provenance storage is charged"
    );
    assert!(authority.governor().inspect()?.outstanding_total() > baseline);
    drop(first);
    assert_eq!(
        authority.governor().inspect()?.outstanding_total(),
        baseline
    );
    Ok(())
}
