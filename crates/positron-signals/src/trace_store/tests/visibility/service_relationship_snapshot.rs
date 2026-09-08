use super::super::*;
use crate::{
    TraceServiceIdentityState, TraceServiceRelationshipSnapshotLimitation, TraceStoreFailure,
};

#[test]
fn snapshot_service_relationships_aggregate_two_traces_with_pair_provenance()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xa1; 16])?,
        CatalogSecret::from_owned(Box::new([0xa2; 32]), Box::new([0xa3; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(91)?;
    let scope = SegmentScope::new(tenant, SignalKind::Traces, shard);
    let (retention_time, _) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(100));
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0xa4; 32])),
    )?;
    let service = |name: &str, namespace: &str| {
        let profile = ValueLimitProfile::release_1_system_maximum();
        [("service.name", name), ("service.namespace", namespace)]
            .into_iter()
            .map(|(key, value)| {
                AttributeOccurrenceSetCandidate::new(
                    AttributeNamespace::Resource,
                    key.to_owned(),
                    vec![CandidateAttributeValue::string(value.to_owned())],
                )
                .validate(profile)
                .map_err(TraceStoreFailure::domain)
            })
            .collect::<Result<Vec<_>, _>>()
    };
    let span = |trace_id, span_id, parent_span_id, service_name, namespace, start| {
        SpanObservation::checked_native(
            trace_id,
            span_id,
            parent_span_id,
            "fixture".to_owned(),
            EventTime::received(UnixNanoseconds::new(start), SourceTimeQuality::Usable)
                .map_err(TraceStoreFailure::domain)?,
            EventTime::received(
                UnixNanoseconds::new(start + if parent_span_id.is_some() { 10 } else { 100 }),
                SourceTimeQuality::Usable,
            )
            .map_err(TraceStoreFailure::domain)?,
            service(service_name, namespace)?,
            SpanKind::Internal,
            SamplingDecision::Sampled,
            positron_policy::PolicyProvenance::new(1, [0xa5; 32], Vec::new())?,
        )
    };
    let first_trace = [0xb1; 16];
    let second_trace = [0xb2; 16];
    let store = TraceStore::new();
    ledger.append(
        store
            .prepare(
                ledger.begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    StoreBlockIdentity::new([0xa6; 16])?,
                )?,
                vec![
                    span(first_trace, [0x11; 8], None, "checkout", "storefront", 10)?,
                    span(
                        first_trace,
                        [0x12; 8],
                        Some([0x11; 8]),
                        "inventory",
                        "warehouse",
                        11,
                    )?,
                    span(second_trace, [0x21; 8], None, "checkout", "storefront", 30)?,
                    span(
                        second_trace,
                        [0x22; 8],
                        Some([0x21; 8]),
                        "inventory",
                        "warehouse",
                        31,
                    )?,
                ],
            )?
            .into_store_block(),
    )?;
    let snapshot = ledger.snapshot()?;

    let relationships = store.service_relationships(
        authority.governor(),
        tenant,
        &snapshot,
        TraceScan::all(ScanLimit::new(8)?),
    )?;

    assert!(relationships.snapshot_complete());
    assert!(relationships.relationships_complete());
    assert_eq!(
        relationships.incompleteness().scan(),
        TraceIncompleteness::None
    );
    assert!(relationships.incompleteness().traces().is_empty());
    let pairs = relationships.pairs();
    assert_eq!(pairs.len(), 1);
    let pair = &pairs[0];
    assert_eq!(pair.parent_service(), Some("checkout"));
    assert_eq!(pair.parent_service_namespace(), Some("storefront"));
    assert_eq!(pair.child_service(), Some("inventory"));
    assert_eq!(pair.child_service_namespace(), Some("warehouse"));
    assert_eq!(pair.parent_identity(), TraceServiceIdentityState::Exact);
    assert_eq!(
        pair.parent_service_namespace_identity(),
        TraceServiceIdentityState::Exact
    );
    assert_eq!(pair.child_identity(), TraceServiceIdentityState::Exact);
    assert_eq!(
        pair.child_service_namespace_identity(),
        TraceServiceIdentityState::Exact
    );
    assert_eq!(pair.parent_sampling_count(SamplingDecision::Sampled), 2);
    assert_eq!(pair.parent_sampling_count(SamplingDecision::NotSampled), 0);
    assert_eq!(pair.parent_sampling_count(SamplingDecision::Unknown), 0);
    assert_eq!(pair.child_sampling_count(SamplingDecision::Sampled), 2);
    assert_eq!(pair.child_sampling_count(SamplingDecision::NotSampled), 0);
    assert_eq!(pair.child_sampling_count(SamplingDecision::Unknown), 0);
    assert_eq!(pair.edge_count(), 2);
    assert_eq!(pair.trace_ids(), &[first_trace, second_trace]);
    drop(relationships);

    let byte_limited = store.service_relationships(
        authority.governor(),
        tenant,
        &snapshot,
        TraceScan::all(ScanLimit::new(8)?).with_scanned_bytes(0),
    )?;
    assert!(!byte_limited.snapshot_complete());
    assert_eq!(
        byte_limited.incompleteness().scan(),
        TraceIncompleteness::ScannedBytesLimit,
    );
    drop(byte_limited);

    let result_limited = store.service_relationships(
        authority.governor(),
        tenant,
        &snapshot,
        TraceScan::all(ScanLimit::new(3)?),
    )?;
    assert!(!result_limited.snapshot_complete());
    assert!(!result_limited.relationships_complete());
    assert_eq!(
        result_limited.incompleteness().scan(),
        TraceIncompleteness::ResultLimit,
    );
    assert_eq!(result_limited.pairs().len(), 1);
    assert_eq!(result_limited.pairs()[0].edge_count(), 1);
    assert_eq!(result_limited.pairs()[0].trace_ids(), &[first_trace]);
    drop(result_limited);

    let cancelled = store
        .service_relationships_observed(
            authority.governor(),
            tenant,
            &snapshot,
            TraceScan::all(ScanLimit::new(8)?),
            &AlwaysCancelled,
            &NeverObserved,
        )
        .expect_err("cancelled snapshot derivation must fail before producing evidence");
    assert_eq!(cancelled.code(), TraceStoreFailureCode::Cancelled);
    let exhausted = store
        .service_relationships_observed(
            authority.governor(),
            tenant,
            &snapshot,
            TraceScan::all(ScanLimit::new(8)?),
            &NeverCancelled,
            &WorkBudgetExhausted,
        )
        .expect_err("one observer governs physical scan and aggregate derivation");
    assert_eq!(exhausted.code(), TraceStoreFailureCode::BudgetExhausted);

    let conflicted_trace = [0xb3; 16];
    ledger.append(
        store
            .prepare(
                ledger.begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    StoreBlockIdentity::new([0xa7; 16])?,
                )?,
                vec![
                    span(
                        conflicted_trace,
                        [0x31; 8],
                        None,
                        "checkout",
                        "storefront",
                        50,
                    )?,
                    span(
                        conflicted_trace,
                        [0x31; 8],
                        None,
                        "checkout",
                        "storefront",
                        50,
                    )?,
                    span(
                        conflicted_trace,
                        [0x32; 8],
                        Some([0x31; 8]),
                        "inventory",
                        "warehouse",
                        51,
                    )?,
                    span(
                        conflicted_trace,
                        [0x32; 8],
                        Some([0x31; 8]),
                        "billing",
                        "finance",
                        51,
                    )?,
                ],
            )?
            .into_store_block(),
    )?;
    let conflicted_snapshot = ledger.snapshot()?;
    let conflicted = store.service_relationships(
        authority.governor(),
        tenant,
        &conflicted_snapshot,
        TraceScan::all(ScanLimit::new(16)?),
    )?;
    assert!(conflicted.snapshot_complete());
    assert!(!conflicted.relationships_complete());
    assert_eq!(conflicted.pairs().len(), 1);
    assert_eq!(conflicted.pairs()[0].child_service(), Some("inventory"));
    assert_eq!(conflicted.pairs()[0].edge_count(), 3);
    assert_eq!(
        conflicted.pairs()[0].trace_ids(),
        &[first_trace, second_trace, conflicted_trace],
    );
    assert_eq!(conflicted.incompleteness().traces().len(), 1);
    assert_eq!(
        conflicted.incompleteness().traces()[0].trace_id(),
        conflicted_trace
    );
    assert_eq!(conflicted.incompleteness().traces()[0].conflicts(), 1);
    drop(conflicted);

    let orphan_trace = [0xb4; 16];
    ledger.append(
        store
            .prepare(
                ledger.begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    StoreBlockIdentity::new([0xa8; 16])?,
                )?,
                vec![span(
                    orphan_trace,
                    [0x41; 8],
                    Some([0x40; 8]),
                    "payments",
                    "finance",
                    70,
                )?],
            )?
            .into_store_block(),
    )?;
    let orphan_snapshot = ledger.snapshot()?;
    let orphaned = store.service_relationships(
        authority.governor(),
        tenant,
        &orphan_snapshot,
        TraceScan::all(ScanLimit::new(20)?),
    )?;
    assert!(orphaned.snapshot_complete());
    assert!(!orphaned.relationships_complete());
    assert_eq!(orphaned.pairs()[0].edge_count(), 3);
    let missing = orphaned
        .incompleteness()
        .traces()
        .iter()
        .find(|facts| facts.trace_id() == orphan_trace)
        .ok_or("missing orphan trace incompleteness")?;
    assert_eq!(missing.missing_parents(), 1);
    assert_eq!(missing.conflicts(), 0);
    assert_eq!(missing.cycle_members(), 0);
    assert_eq!(missing.invalid_durations(), 0);
    assert_eq!(missing.temporal_inconsistencies(), 0);
    assert!(!missing.ambiguous_roots());
    Ok(())
}

#[test]
fn ranged_service_relationships_preserve_selected_evidence_without_claiming_the_snapshot()
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
    let shard = VirtualShardId::new(92)?;
    let (retention_time, _) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(100));
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Traces, shard),
        SegmentProtectionKey::from_owned(Box::new([0xc4; 32])),
    )?;
    let service = |name: &str| {
        AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Resource,
            "service.name".to_owned(),
            vec![CandidateAttributeValue::string(name.to_owned())],
        )
        .validate(ValueLimitProfile::release_1_system_maximum())
        .map_err(TraceStoreFailure::domain)
    };
    let span = |trace_id, span_id, parent_span_id, service_name| {
        SpanObservation::checked_native(
            trace_id,
            span_id,
            parent_span_id,
            "range-fixture".to_owned(),
            EventTime::received(UnixNanoseconds::new(1), SourceTimeQuality::Usable)
                .map_err(TraceStoreFailure::domain)?,
            EventTime::received(UnixNanoseconds::new(2), SourceTimeQuality::Usable)
                .map_err(TraceStoreFailure::domain)?,
            vec![service(service_name)?],
            SpanKind::Internal,
            SamplingDecision::Sampled,
            positron_policy::PolicyProvenance::new(1, [0xc5; 32], Vec::new())?,
        )
    };
    let store = TraceStore::new();
    let append_trace =
        |trace_id, parent_service, child_service, identity| -> Result<_, Box<dyn Error>> {
            Ok(ledger.append(
                store
                    .prepare(
                        ledger.begin_store_block(
                            preparation_capacity(&authority, tenant)?,
                            StoreBlockIdentity::new([identity; 16])?,
                        )?,
                        vec![
                            span(trace_id, [0x01; 8], None, parent_service)?,
                            span(trace_id, [0x02; 8], Some([0x01; 8]), child_service)?,
                        ],
                    )?
                    .into_store_block(),
            )?)
        };
    let first = append_trace([0xd1; 16], "checkout", "inventory", 0xd4)?;
    let second = append_trace([0xd2; 16], "payments", "ledger", 0xd5)?;
    let third = append_trace([0xd3; 16], "search", "catalog", 0xd6)?;
    let snapshot = ledger.snapshot()?;

    let after = store.service_relationships(
        authority.governor(),
        tenant,
        &snapshot,
        TraceScan::after(ScanLimit::new(8)?, first.position()),
    )?;
    assert!(after.selected_range_complete());
    assert!(!after.snapshot_complete());
    assert!(!after.relationships_complete());
    assert_eq!(
        after.snapshot_limitation(),
        Some(TraceServiceRelationshipSnapshotLimitation::SelectedRange)
    );
    assert_eq!(after.selection().after_position(), Some(first.position()));
    assert_eq!(after.selection().after_record(), None);
    assert_eq!(after.selection().frontier(), snapshot.frontier());
    assert!(after.scanned_bytes() > 0);
    assert!(after.decoded_observations() > 0);
    assert_eq!(
        after
            .pairs()
            .iter()
            .map(|pair| (pair.parent_service(), pair.child_service()))
            .collect::<Vec<_>>(),
        vec![
            (Some("payments"), Some("ledger")),
            (Some("search"), Some("catalog"))
        ]
    );

    let through = store.service_relationships(
        authority.governor(),
        tenant,
        &snapshot,
        TraceScan::through(ScanLimit::new(8)?, second.position()),
    )?;
    assert!(through.selected_range_complete());
    assert!(!through.snapshot_complete());
    assert!(!through.relationships_complete());
    assert_eq!(
        through.snapshot_limitation(),
        Some(TraceServiceRelationshipSnapshotLimitation::SelectedRange)
    );
    assert_eq!(through.selection().after_position(), None);
    assert_eq!(through.selection().after_record(), None);
    assert_eq!(through.selection().frontier(), second.position());
    assert_eq!(
        through
            .pairs()
            .iter()
            .map(|pair| (pair.parent_service(), pair.child_service()))
            .collect::<Vec<_>>(),
        vec![
            (Some("checkout"), Some("inventory")),
            (Some("payments"), Some("ledger"))
        ]
    );

    let between = store.service_relationships(
        authority.governor(),
        tenant,
        &snapshot,
        TraceScan::between(ScanLimit::new(8)?, first.position(), second.position()),
    )?;
    assert!(between.selected_range_complete());
    assert!(!between.snapshot_complete());
    assert!(!between.relationships_complete());
    assert_eq!(
        between.snapshot_limitation(),
        Some(TraceServiceRelationshipSnapshotLimitation::SelectedRange)
    );
    assert_eq!(between.selection().after_position(), Some(first.position()));
    assert_eq!(between.selection().after_record(), None);
    assert_eq!(between.selection().frontier(), second.position());
    assert_eq!(between.pairs().len(), 1);
    assert_eq!(between.pairs()[0].parent_service(), Some("payments"));
    assert_eq!(between.pairs()[0].child_service(), Some("ledger"));
    assert_eq!(third.position(), snapshot.frontier());
    Ok(())
}
