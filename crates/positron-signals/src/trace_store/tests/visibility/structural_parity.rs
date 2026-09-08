use super::super::*;
use crate::{TraceParentRelation, TraceStoreFailure};
use std::collections::BTreeMap;

#[test]
fn structural_results_preserve_exact_snapshot_semantics_across_compaction()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x61; 16])?,
        CatalogSecret::from_owned(Box::new([0x62; 32]), Box::new([0x63; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(61)?;
    let scope = SegmentScope::new(tenant, SignalKind::Traces, shard);
    let (retention_time, _) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(100));
    let key = || SegmentProtectionKey::from_owned(Box::new([0x64; 32]));
    let observation = |trace_id, span_id, parent_span_id, start, end, name| {
        SpanObservation::checked_native(
            trace_id,
            span_id,
            parent_span_id,
            name,
            EventTime::received(UnixNanoseconds::new(start), SourceTimeQuality::Usable)
                .map_err(TraceStoreFailure::domain)?,
            EventTime::received(UnixNanoseconds::new(end), SourceTimeQuality::Usable)
                .map_err(TraceStoreFailure::domain)?,
            Vec::new(),
            SpanKind::Internal,
            SamplingDecision::Sampled,
            positron_policy::PolicyProvenance::new(1, [0x65; 32], Vec::new())?,
        )
    };
    let incomplete_trace = [0x66; 16];
    let complete_trace = [0x67; 16];
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
                    StoreBlockIdentity::new([0x68; 16])?,
                )?,
                vec![
                    observation(
                        incomplete_trace,
                        [0x11; 8],
                        None,
                        1,
                        101,
                        "incomplete-root".to_owned(),
                    )?,
                    observation(
                        incomplete_trace,
                        [0x12; 8],
                        Some([0x11; 8]),
                        10,
                        30,
                        "first-child-representative".to_owned(),
                    )?,
                    observation(
                        complete_trace,
                        [0x21; 8],
                        None,
                        1,
                        51,
                        "complete-root".to_owned(),
                    )?,
                    observation(
                        complete_trace,
                        [0x22; 8],
                        Some([0x21; 8]),
                        11,
                        21,
                        "first-complete-child".to_owned(),
                    )?,
                ],
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
    second.append(
        store
            .prepare(
                second.begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    StoreBlockIdentity::new([0x69; 16])?,
                )?,
                vec![
                    observation(
                        incomplete_trace,
                        [0x12; 8],
                        Some([0x98; 8]),
                        10,
                        30,
                        "later-conflicting-parent".to_owned(),
                    )?,
                    observation(
                        incomplete_trace,
                        [0x13; 8],
                        Some([0x99; 8]),
                        40,
                        50,
                        "orphan".to_owned(),
                    )?,
                ],
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
                    StoreBlockIdentity::new([0x6a; 16])?,
                )?,
                vec![
                    observation(
                        incomplete_trace,
                        [0x14; 8],
                        Some([0x11; 8]),
                        60,
                        90,
                        "active-child".to_owned(),
                    )?,
                    observation(
                        complete_trace,
                        [0x23; 8],
                        Some([0x21; 8]),
                        26,
                        41,
                        "second-complete-child".to_owned(),
                    )?,
                ],
            )?
            .into_store_block(),
    )?;

    let assert_public_outcomes =
        |snapshot: &positron_kernel::LedgerSnapshot<'_>| -> Result<(), Box<dyn Error>> {
            let mut incomplete = store.trace_by_id(
                authority.governor(),
                tenant,
                snapshot,
                incomplete_trace,
                TraceSearch::all(ScanLimit::new(8)?),
            )?;
            let incomplete = incomplete.analyze_structure(&NeverCancelled, &NeverObserved)?;
            assert!(!incomplete.complete());
            assert_eq!(incomplete.roots(), &[[0x11; 8]]);
            assert_eq!(incomplete.orphans(), &[[0x13; 8]]);
            assert!(incomplete.cycles().is_empty());
            assert_eq!(
                incomplete
                    .spans()
                    .iter()
                    .map(|span| {
                        (
                            span.span_id(),
                            span.parent_span_id(),
                            span.relation(),
                            span.conflicted(),
                            span.cycle_member(),
                        )
                    })
                    .collect::<Vec<_>>(),
                vec![
                    ([0x11; 8], None, TraceParentRelation::Root, false, false,),
                    (
                        [0x12; 8],
                        Some([0x11; 8]),
                        TraceParentRelation::Child,
                        true,
                        false,
                    ),
                    (
                        [0x13; 8],
                        Some([0x99; 8]),
                        TraceParentRelation::Orphan,
                        false,
                        false,
                    ),
                    (
                        [0x14; 8],
                        Some([0x11; 8]),
                        TraceParentRelation::Child,
                        false,
                        false,
                    ),
                ]
            );
            let incomplete_reasons = incomplete.incompleteness();
            assert_eq!(incomplete_reasons.scan(), TraceIncompleteness::None);
            assert_eq!(incomplete_reasons.missing_parents(), 1);
            assert_eq!(incomplete_reasons.conflicts(), 1);
            assert_eq!(incomplete_reasons.cycle_members(), 0);
            assert_eq!(incomplete_reasons.invalid_durations(), 0);
            assert_eq!(incomplete_reasons.temporal_inconsistencies(), 0);
            assert!(!incomplete_reasons.ambiguous_roots());
            assert!(incomplete.critical_path().is_none());

            let mut complete = store.trace_by_id(
                authority.governor(),
                tenant,
                snapshot,
                complete_trace,
                TraceSearch::all(ScanLimit::new(8)?),
            )?;
            let complete = complete.analyze_structure(&NeverCancelled, &NeverObserved)?;
            assert!(complete.complete());
            assert_eq!(complete.roots(), &[[0x21; 8]]);
            assert!(complete.orphans().is_empty());
            assert!(complete.cycles().is_empty());
            assert_eq!(
                complete
                    .spans()
                    .iter()
                    .map(|span| (span.span_id(), span.parent_span_id(), span.relation()))
                    .collect::<Vec<_>>(),
                vec![
                    ([0x21; 8], None, TraceParentRelation::Root),
                    ([0x22; 8], Some([0x21; 8]), TraceParentRelation::Child,),
                    ([0x23; 8], Some([0x21; 8]), TraceParentRelation::Child,),
                ]
            );
            let critical_path = complete.critical_path().ok_or("critical path is present")?;
            assert_eq!(critical_path.duration_nanos(), 50);
            assert_eq!(
                critical_path
                    .fragments()
                    .iter()
                    .map(|fragment| {
                        (
                            fragment.span_id(),
                            fragment.start().value(),
                            fragment.end().value(),
                        )
                    })
                    .collect::<Vec<_>>(),
                vec![
                    ([0x21; 8], 1, 11),
                    ([0x22; 8], 11, 21),
                    ([0x21; 8], 21, 26),
                    ([0x23; 8], 26, 41),
                    ([0x21; 8], 41, 51),
                ]
            );
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
