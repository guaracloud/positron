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
    let conflict = SpanObservation::checked_native(
        [0x11; 16],
        [0x22; 8],
        None,
        "sealed-conflict".to_owned(),
        EventTime::received(UnixNanoseconds::new(10), SourceTimeQuality::Usable).unwrap(),
        EventTime::missing(),
        Vec::new(),
        SpanKind::Internal,
        SamplingDecision::Unknown,
        positron_policy::PolicyProvenance::new(1, [0x80; 32], Vec::new()).unwrap(),
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
                vec![first.clone(), conflict.clone()],
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
        TraceScan::all(ScanLimit::new(3)?),
    )?;
    assert!(result.complete());
    assert_eq!(
        result
            .observations()
            .iter()
            .map(|observation| observation.observation().name())
            .collect::<Vec<_>>(),
        vec!["sealed", "sealed-conflict", "active"]
    );
    assert_eq!(
        result
            .observations()
            .iter()
            .map(|observation| {
                observation
                    .observation()
                    .attributes()
                    .first()
                    .is_some_and(|attribute| {
                        attribute.key().len() == SpanObservation::MAX_NAME_BYTES
                    })
            })
            .collect::<Vec<_>>(),
        vec![true, false, true]
    );
    drop(result);
    let logical = store.search(
        authority.governor(),
        tenant,
        &successor.snapshot()?,
        TraceSearch::all(ScanLimit::new(3)?),
    )?;
    assert!(logical.complete());
    assert_eq!(logical.spans().len(), 2);
    assert_eq!(
        logical
            .spans()
            .iter()
            .map(|span| (
                span.span_id(),
                span.observation_count(),
                span.variants().len()
            ))
            .collect::<Vec<_>>(),
        vec![([0x22; 8], 2, 2), ([0x23; 8], 1, 1)]
    );
    drop(logical);

    let assert_exact_predicate_results =
        |snapshot: &positron_kernel::LedgerSnapshot<'_>| -> Result<(), Box<dyn Error>> {
            let predicate = || -> Result<_, Box<dyn Error>> {
                let value = boundary_attributes()
                    .into_iter()
                    .next()
                    .ok_or("missing retained predicate attribute")?
                    .occurrence(0)
                    .ok_or("missing retained predicate value")?
                    .try_clone()?;
                Ok(TraceSearch::all(ScanLimit::new(3)?).with_attribute_equals(
                    AttributeNamespace::Resource,
                    boundary_key.clone(),
                    value,
                )?)
            };
            let search = store.search(authority.governor(), tenant, snapshot, predicate()?)?;
            assert!(search.complete());
            assert_eq!(
                search
                    .spans()
                    .iter()
                    .map(|span| {
                        (
                            span.trace_id(),
                            span.span_id(),
                            span.observation_count(),
                            span.conflicted(),
                            span.variants()
                                .iter()
                                .map(|variant| {
                                    (
                                        variant.observation().observation().name(),
                                        variant.observation_count(),
                                    )
                                })
                                .collect::<Vec<_>>(),
                        )
                    })
                    .collect::<Vec<_>>(),
                vec![
                    (
                        [0x11; 16],
                        [0x22; 8],
                        2,
                        true,
                        vec![("sealed", 1), ("sealed-conflict", 1)],
                    ),
                    ([0x11; 16], [0x23; 8], 1, false, vec![("active", 1)]),
                ]
            );
            let by_id = store.trace_by_id(
                authority.governor(),
                tenant,
                snapshot,
                [0x11; 16],
                predicate()?,
            )?;
            assert!(by_id.complete());
            assert_eq!(
                by_id
                    .spans()
                    .iter()
                    .map(|span| {
                        (
                            span.span_id(),
                            span.observation_count(),
                            span.conflicted(),
                            span.variants()
                                .iter()
                                .map(|variant| {
                                    (
                                        variant.observation().observation().name(),
                                        variant.observation_count(),
                                    )
                                })
                                .collect::<Vec<_>>(),
                        )
                    })
                    .collect::<Vec<_>>(),
                vec![
                    (
                        [0x22; 8],
                        2,
                        true,
                        vec![("sealed", 1), ("sealed-conflict", 1)],
                    ),
                    ([0x23; 8], 1, false, vec![("active", 1)]),
                ]
            );
            Ok(())
        };

    let before_compaction = successor.snapshot()?;
    let physical = store.scan_physical(
        authority.governor(),
        tenant,
        &before_compaction,
        TraceScan::all(ScanLimit::new(3)?),
    )?;
    let mut ingest_times = BTreeMap::new();
    for observation in physical.observations() {
        ingest_times.insert(
            observation.commit_position(),
            observation.stored().ingest_time(),
        );
    }
    drop(physical);
    assert_exact_predicate_results(&before_compaction)?;
    assert_exact_predicate_results(&before_compaction)?;
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
    assert_exact_predicate_results(&before_compaction)?;
    assert_exact_predicate_results(&before_compaction)?;
    drop(before_compaction);
    let after_compaction = successor.snapshot()?;
    assert_exact_predicate_results(&after_compaction)?;
    assert_exact_predicate_results(&after_compaction)?;
    Ok(())
}
