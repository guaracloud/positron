use super::super::*;
use crate::{TraceServiceIdentity, TraceStoreFailure};
use std::collections::BTreeMap;

#[test]
fn service_relationships_preserve_native_snapshot_outcomes_across_compaction()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x81; 16])?,
        CatalogSecret::from_owned(Box::new([0x82; 32]), Box::new([0x83; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(81)?;
    let scope = SegmentScope::new(tenant, SignalKind::Traces, shard);
    let (retention_time, _) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(100));
    let key = || SegmentProtectionKey::from_owned(Box::new([0x84; 32]));
    let attributes = |service: &str, namespace: Option<&str>| {
        let profile = ValueLimitProfile::release_1_system_maximum();
        let mut values = vec![
            AttributeOccurrenceSetCandidate::new(
                AttributeNamespace::Resource,
                "service.name".to_owned(),
                vec![CandidateAttributeValue::string(service.to_owned())],
            )
            .validate(profile)
            .map_err(TraceStoreFailure::domain)?,
        ];
        if let Some(namespace) = namespace {
            values.push(
                AttributeOccurrenceSetCandidate::new(
                    AttributeNamespace::Resource,
                    "service.namespace".to_owned(),
                    vec![CandidateAttributeValue::string(namespace.to_owned())],
                )
                .validate(profile)
                .map_err(TraceStoreFailure::domain)?,
            );
        }
        Ok::<_, TraceStoreFailure>(values)
    };
    let observation = |span_id, parent_span_id, start, end, name, service, namespace, sampling| {
        SpanObservation::checked_native(
            [0x85; 16],
            span_id,
            parent_span_id,
            name,
            EventTime::received(UnixNanoseconds::new(start), SourceTimeQuality::Usable)
                .map_err(TraceStoreFailure::domain)?,
            EventTime::received(UnixNanoseconds::new(end), SourceTimeQuality::Usable)
                .map_err(TraceStoreFailure::domain)?,
            attributes(service, namespace)?,
            SpanKind::Internal,
            sampling,
            positron_policy::PolicyProvenance::new(1, [0x86; 32], Vec::new())?,
        )
    };
    let store = TraceStore::new();

    let first = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    first.append(
        store
            .prepare(
                first.begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    StoreBlockIdentity::new([0x87; 16])?,
                )?,
                vec![observation(
                    [0x11; 8],
                    None,
                    1,
                    90,
                    "checkout-root".to_owned(),
                    "checkout",
                    Some("storefront"),
                    SamplingDecision::Sampled,
                )?],
            )?
            .into_store_block(),
    )?;
    first.seal()?;

    let second = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let inventory_call = observation(
        [0x12; 8],
        Some([0x11; 8]),
        10,
        50,
        "inventory-call".to_owned(),
        "inventory",
        None,
        SamplingDecision::NotSampled,
    )?;
    second.append(
        store
            .prepare(
                second.begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    StoreBlockIdentity::new([0x88; 16])?,
                )?,
                vec![inventory_call.clone(), inventory_call],
            )?
            .into_store_block(),
    )?;
    second.seal()?;

    let active = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    active.append(
        store
            .prepare(
                active.begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    StoreBlockIdentity::new([0x89; 16])?,
                )?,
                vec![
                    observation(
                        [0x12; 8],
                        Some([0x99; 8]),
                        10,
                        50,
                        "later-conflict".to_owned(),
                        "billing",
                        Some("payments"),
                        SamplingDecision::Sampled,
                    )?,
                    observation(
                        [0x13; 8],
                        Some([0x12; 8]),
                        20,
                        30,
                        "cache-read".to_owned(),
                        "cache",
                        Some("inventory"),
                        SamplingDecision::Unknown,
                    )?,
                ],
            )?
            .into_store_block(),
    )?;

    let assert_public_outcomes =
        |snapshot: &positron_kernel::LedgerSnapshot<'_>| -> Result<(), Box<dyn Error>> {
            let mut trace = store.trace_by_id(
                authority.governor(),
                tenant,
                snapshot,
                [0x85; 16],
                TraceSearch::all(ScanLimit::new(8)?),
            )?;
            assert!(trace.complete());
            assert_eq!(
                trace
                    .spans()
                    .iter()
                    .map(|span| (span.span_id(), span.observation_count(), span.conflicted()))
                    .collect::<Vec<_>>(),
                vec![
                    ([0x11; 8], 1, false),
                    ([0x12; 8], 3, true),
                    ([0x13; 8], 1, false),
                ]
            );
            let conflicted = trace.spans().get(1).ok_or("missing conflicted span")?;
            assert_eq!(
                conflicted
                    .variants()
                    .iter()
                    .map(|variant| {
                        (
                            variant.observation().observation().name(),
                            variant.observation_count(),
                        )
                    })
                    .collect::<Vec<_>>(),
                vec![("inventory-call", 2), ("later-conflict", 1)]
            );
            assert_eq!(
                conflicted
                    .structural_representative()
                    .ok_or("conflicted span lacks a representative")?
                    .observation()
                    .name(),
                "inventory-call"
            );

            let structure = trace.analyze_structure(&NeverCancelled, &NeverObserved)?;
            assert!(!structure.complete());
            let incompleteness = structure.incompleteness();
            assert_eq!(incompleteness.scan(), TraceIncompleteness::None);
            assert_eq!(incompleteness.missing_parents(), 0);
            assert_eq!(incompleteness.conflicts(), 1);
            assert_eq!(incompleteness.cycle_members(), 0);
            assert_eq!(incompleteness.invalid_durations(), 0);
            assert_eq!(incompleteness.temporal_inconsistencies(), 0);
            assert!(!incompleteness.filtered());
            assert!(!incompleteness.ambiguous_roots());

            let relationships = structure.service_relationships();
            assert!(!relationships.complete());
            assert_eq!(relationships.edges().len(), 2);
            let first_edge = relationships.edges().first().ok_or("missing first edge")?;
            assert_eq!(first_edge.parent_span_id(), [0x11; 8]);
            assert_eq!(first_edge.child_span_id(), [0x12; 8]);
            assert_eq!(first_edge.parent_service(), Some("checkout"));
            assert_eq!(first_edge.child_service(), Some("inventory"));
            assert_eq!(first_edge.parent_service_namespace(), Some("storefront"));
            assert_eq!(first_edge.child_service_namespace(), None);
            assert_eq!(
                first_edge.parent_identity(),
                TraceServiceIdentity::Exact("checkout")
            );
            assert_eq!(
                first_edge.child_identity(),
                TraceServiceIdentity::Exact("inventory")
            );
            assert_eq!(first_edge.parent_sampling(), SamplingDecision::Sampled);
            assert_eq!(first_edge.child_sampling(), SamplingDecision::NotSampled);

            let second_edge = relationships.edges().get(1).ok_or("missing second edge")?;
            assert_eq!(second_edge.parent_span_id(), [0x12; 8]);
            assert_eq!(second_edge.child_span_id(), [0x13; 8]);
            assert_eq!(second_edge.parent_service(), Some("inventory"));
            assert_eq!(second_edge.child_service(), Some("cache"));
            assert_eq!(second_edge.parent_service_namespace(), None);
            assert_eq!(second_edge.child_service_namespace(), Some("inventory"));
            assert_eq!(
                second_edge.parent_identity(),
                TraceServiceIdentity::Exact("inventory")
            );
            assert_eq!(
                second_edge.child_identity(),
                TraceServiceIdentity::Exact("cache")
            );
            assert_eq!(second_edge.parent_sampling(), SamplingDecision::NotSampled);
            assert_eq!(second_edge.child_sampling(), SamplingDecision::Unknown);
            Ok(())
        };

    let before_compaction = active.snapshot()?;
    assert_public_outcomes(&before_compaction)?;
    let physical = store.scan_physical(
        authority.governor(),
        tenant,
        &before_compaction,
        TraceScan::all(ScanLimit::new(8)?),
    )?;
    let mut ingest_times = BTreeMap::new();
    for observation in physical.observations() {
        ingest_times.insert(
            observation.commit_position(),
            observation.stored().ingest_time(),
        );
    }
    drop(physical);
    let active_segment = active.active_segment_id()?;
    let compaction_blocks = before_compaction
        .blocks()
        .iter()
        .filter(|block| block.segment_id() != active_segment)
        .map(|block| {
            let ingest_time = ingest_times
                .get(&block.position())
                .copied()
                .ok_or("compaction input lacks authenticated ingest time")?;
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
    let preparation = active.prepare_compaction(&before_compaction)?;
    active.compact_sealed_with_cancellation(compaction_blocks, preparation, || false)?;

    assert_public_outcomes(&before_compaction)?;
    drop(before_compaction);
    let after_compaction = active.snapshot()?;
    assert_public_outcomes(&after_compaction)?;
    Ok(())
}
