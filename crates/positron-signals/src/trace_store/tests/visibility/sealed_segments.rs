use super::super::*;
use std::collections::BTreeMap;

#[test]
fn sealed_and_successor_active_segments_have_equivalent_trace_scan_visibility()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x15; 16])?,
        CatalogSecret::from_owned(Box::new([0x25; 32]), Box::new([0x35; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(5)?;
    let (retention_time, _) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(100));
    let key = || SegmentProtectionKey::from_owned(Box::new([0x55; 32]));
    let profile = ValueLimitProfile::release_1_system_maximum();
    let boundary_key = "k".repeat(SpanObservation::MAX_NAME_BYTES);
    let boundary_attributes = || {
        vec![
            AttributeOccurrenceSetCandidate::new(
                AttributeNamespace::Resource,
                boundary_key.clone(),
                vec![CandidateAttributeValue::boolean(true)],
            )
            .validate(profile)
            .expect("the exact Release 1 key boundary is valid"),
        ]
    };
    assert!(
        AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Resource,
            "k".repeat(SpanObservation::MAX_NAME_BYTES + 1),
            vec![CandidateAttributeValue::boolean(true)],
        )
        .validate(profile)
        .is_err()
    );
    let first = SpanObservation::checked_native(
        [0x11; 16],
        [0x22; 8],
        None,
        "sealed".to_owned(),
        EventTime::received(UnixNanoseconds::new(10), SourceTimeQuality::Usable).unwrap(),
        EventTime::missing(),
        boundary_attributes(),
        SpanKind::Internal,
        SamplingDecision::Unknown,
        positron_policy::PolicyProvenance::new(1, [0x78; 32], Vec::new()).unwrap(),
    )?;
    let second = SpanObservation::checked_native(
        [0x11; 16],
        [0x23; 8],
        Some([0x22; 8]),
        "active".to_owned(),
        EventTime::received(UnixNanoseconds::new(11), SourceTimeQuality::Usable).unwrap(),
        EventTime::received(UnixNanoseconds::new(12), SourceTimeQuality::Usable).unwrap(),
        boundary_attributes(),
        SpanKind::Client,
        SamplingDecision::NotSampled,
        positron_policy::PolicyProvenance::new(1, [0x79; 32], Vec::new()).unwrap(),
    )?;
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Traces, shard),
        key(),
    )?;
    let store = TraceStore::new();
    ledger.append(
        store
            .prepare(
                ledger.begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    positron_kernel::StoreBlockIdentity::new([0x65; 16])?,
                )?,
                vec![first.clone()],
            )?
            .into_store_block(),
    )?;
    ledger.seal()?;
    let successor = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Traces, shard),
        key(),
    )?;
    successor.append(
        store
            .prepare(
                successor.begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    positron_kernel::StoreBlockIdentity::new([0x66; 16])?,
                )?,
                vec![second.clone()],
            )?
            .into_store_block(),
    )?;
    let result = store.scan_physical(
        authority.governor(),
        tenant,
        &successor.snapshot()?,
        TraceScan::all(ScanLimit::new(2)?),
    )?;
    assert!(result.complete());
    assert_eq!(
        result
            .observations()
            .iter()
            .map(|observation| observation.observation().name())
            .collect::<Vec<_>>(),
        vec!["sealed", "active"]
    );
    assert!(result.observations().iter().all(|observation| {
        observation
            .observation()
            .attributes()
            .first()
            .is_some_and(|attribute| attribute.key().len() == SpanObservation::MAX_NAME_BYTES)
    }));
    drop(result);
    let logical = store.search(
        authority.governor(),
        tenant,
        &successor.snapshot()?,
        TraceSearch::all(ScanLimit::new(2)?),
    )?;
    assert!(logical.complete());
    assert_eq!(logical.spans().len(), 2);
    assert_eq!(
        logical
            .spans()
            .iter()
            .map(|span| span.span_id())
            .collect::<Vec<_>>(),
        vec![[0x22; 8], [0x23; 8]]
    );
    drop(logical);

    let before_compaction = successor.snapshot()?;
    let physical = store.scan_physical(
        authority.governor(),
        tenant,
        &before_compaction,
        TraceScan::all(ScanLimit::new(2)?),
    )?;
    let mut ingest_times = BTreeMap::new();
    for observation in physical.observations() {
        ingest_times.insert(
            observation.commit_position(),
            observation.stored().ingest_time(),
        );
    }
    drop(physical);
    let before_search = store.search(
        authority.governor(),
        tenant,
        &before_compaction,
        TraceSearch::all(ScanLimit::new(2)?),
    )?;
    assert!(before_search.complete());
    assert_eq!(before_search.spans().len(), 2);
    drop(before_search);
    let active = successor.active_segment_id()?;
    let compaction_blocks = before_compaction
        .blocks()
        .iter()
        .filter(|block| block.segment_id() != active)
        .map(|block| {
            let ingest_time = ingest_times
                .get(&block.position())
                .copied()
                .ok_or("compaction input lacks a retained trace ingest time")?;
            Ok(positron_kernel::CompactionBlock::new(
                before_compaction.scope(),
                block.segment_id(),
                block.identity(),
                block.position(),
                block.payload().to_vec(),
                block.content_digest()?,
                ingest_time,
            )?)
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let preparation = successor.prepare_compaction(&before_compaction)?;
    successor.compact_sealed_with_cancellation(compaction_blocks, preparation, || false)?;
    let old_snapshot = store.search(
        authority.governor(),
        tenant,
        &before_compaction,
        TraceSearch::all(ScanLimit::new(2)?),
    )?;
    assert!(old_snapshot.complete());
    assert_eq!(old_snapshot.spans().len(), 2);
    drop(old_snapshot);
    drop(before_compaction);
    let after_compaction = store.search(
        authority.governor(),
        tenant,
        &successor.snapshot()?,
        TraceSearch::all(ScanLimit::new(2)?),
    )?;
    assert!(after_compaction.complete());
    assert_eq!(after_compaction.spans().len(), 2);
    assert_eq!(
        after_compaction
            .spans()
            .iter()
            .map(|span| span.span_id())
            .collect::<Vec<_>>(),
        vec![[0x22; 8], [0x23; 8]]
    );
    let by_id = store.trace_by_id(
        authority.governor(),
        tenant,
        &successor.snapshot()?,
        [0x11; 16],
        TraceSearch::all(ScanLimit::new(2)?),
    )?;
    assert!(by_id.complete());
    assert_eq!(by_id.spans().len(), 2);
    Ok(())
}
