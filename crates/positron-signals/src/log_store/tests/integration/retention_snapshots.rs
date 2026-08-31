use super::*;

#[test]
fn retention_keeps_an_existing_snapshot_readable_while_new_snapshots_exclude_it()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x1a; 16])?,
        CatalogSecret::from_owned(Box::new([0x2a; 32]), Box::new([0x3a; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(10)?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, shard);
    let retention_time = RetentionTimeAuthority::establish()?;
    let store = LogStore::new();
    let PolicyEvaluation::Accepted(evaluated) = IngestPolicy::preserving(1)?.evaluate(
        NativeLogCandidate::new(
            None,
            None,
            Some(positron_domain::value::CandidateAttributeValue::string(
                "snapshot remains valid".to_owned(),
            )),
            vec![],
            LogMetadata::empty(),
        ),
        PolicyReceiver::OtlpGrpc,
    )?
    else {
        return Err("preserving policy rejected the snapshot fixture".into());
    };
    let record =
        LogRecord::checked_evaluated(ValueLimitProfile::release_1_system_maximum(), *evaluated)?;
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x5a; 32])),
    )?;
    ledger.append(
        store
            .prepare(
                ledger.begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    StoreBlockIdentity::new([0x6a; 16])?,
                )?,
                vec![record.clone()],
            )?
            .into_store_block(),
    )?;
    ledger.append(
        store
            .prepare(
                ledger.begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    StoreBlockIdentity::new([0x7a; 16])?,
                )?,
                vec![record],
            )?
            .into_store_block(),
    )?;
    ledger.seal()?;
    std::thread::sleep(std::time::Duration::from_millis(1_050));
    let active = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x5a; 32])),
    )?;
    let previous = active.snapshot()?;
    assert_eq!(previous.blocks().len(), 2);
    let before = authority
        .governor()
        .inspect()?
        .outstanding_for(WorkClass::DurabilityRecovery);
    let cancelled = store
        .enforce_retention_observed(
            &active,
            tenant,
            LogRetentionPolicy::new(1)?,
            &CancelledRetention,
            &RetentionObserver,
        )
        .expect_err("cancelled retention must not publish deletion");
    assert_eq!(
        cancelled.code(),
        positron_signals::LogStoreFailureCode::Cancelled
    );
    assert_eq!(
        authority
            .governor()
            .inspect()?
            .outstanding_for(WorkClass::DurabilityRecovery),
        before
    );
    assert_eq!(active.snapshot()?.blocks().len(), 2);
    let lease_now = u64::try_from(
        retention_clock()
            .assign_ingest_time()?
            .instant()
            .value()
            .checked_div(1_000_000_000)
            .ok_or("snapshot lease seconds")?,
    )?;
    let lease = active.create_snapshot_lease(lease_now, lease_now + 100)?;
    let lease_identity = lease.identity();
    let outcome = store.enforce_retention(&active, tenant, LogRetentionPolicy::new(1)?)?;
    assert_eq!(outcome.expired_segments(), 1);
    assert_eq!(outcome.reclaimed_segments(), 0);
    let old_result = store.scan(
        authority.governor(),
        tenant,
        &previous,
        LogScan::all(ScanLimit::new(1)?),
    )?;
    assert_eq!(old_result.records().len(), 1);
    let current_result = store.scan(
        authority.governor(),
        tenant,
        &active.snapshot()?,
        LogScan::all(ScanLimit::new(1)?),
    )?;
    assert!(current_result.records().is_empty());
    drop(lease);
    drop(previous);
    drop(active);
    let active = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x5a; 32])),
    )?;
    let resume_now = active.snapshot_lease_time()?.max(lease_now);
    let basis = catalog.pin()?;
    let original_objects = basis
        .object_identities()
        .map(|identity| {
            basis
                .object(identity)
                .map_err(Box::<dyn Error>::from)?
                .map(<[u8]>::to_vec)
                .ok_or_else(|| "catalog object disappeared from its pinned snapshot".into())
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let mut changed = false;
    let substituted_objects = original_objects
        .iter()
        .map(|bytes| {
            let mut bytes = bytes.clone();
            if bytes.starts_with(b"PSLEASE1") {
                let block_identity = bytes
                    .get_mut(113..129)
                    .ok_or("snapshot lease block identity is missing")?;
                block_identity.copy_from_slice(&[0xab; 16]);
                changed = true;
            }
            CatalogObject::new(bytes).map_err(Into::into)
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    if !changed {
        return Err("snapshot lease catalog object is missing".into());
    }
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0xac; 16])?,
            FormatEpoch::CATALOG_V1,
            substituted_objects,
        )?,
        None,
    )?;
    drop(basis);
    let substituted = active
        .resume_snapshot_lease(lease_identity, resume_now)
        .expect_err("authenticated lease block substitution must fail closed");
    assert_eq!(
        substituted.code(),
        positron_kernel::LedgerFailureCode::IntegrityCorruption
    );
    let replacement_basis = catalog.pin()?;
    let restored = original_objects
        .iter()
        .cloned()
        .map(CatalogObject::new)
        .collect::<Result<Vec<_>, _>>()?;
    catalog.commit(
        replacement_basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0xad; 16])?,
            FormatEpoch::CATALOG_V1,
            restored,
        )?,
        None,
    )?;
    drop(replacement_basis);
    let ordered_basis = catalog.pin()?;
    let mut reordered = false;
    let reordered_objects = original_objects
        .iter()
        .map(|bytes| {
            let mut bytes = bytes.clone();
            if bytes.starts_with(b"PSLEASE1") {
                let first = bytes
                    .get(113..153)
                    .ok_or("first snapshot lease block is missing")?
                    .to_vec();
                let second = bytes
                    .get(153..193)
                    .ok_or("second snapshot lease block is missing")?
                    .to_vec();
                bytes
                    .get_mut(113..153)
                    .ok_or("first snapshot lease block is missing")?
                    .copy_from_slice(&second);
                bytes
                    .get_mut(153..193)
                    .ok_or("second snapshot lease block is missing")?
                    .copy_from_slice(&first);
                reordered = true;
            }
            CatalogObject::new(bytes).map_err(Box::<dyn Error>::from)
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    if !reordered {
        return Err("two-block snapshot lease catalog object is missing".into());
    }
    catalog.commit(
        ordered_basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0xae; 16])?,
            FormatEpoch::CATALOG_V1,
            reordered_objects,
        )?,
        None,
    )?;
    drop(ordered_basis);
    let reordered = active
        .resume_snapshot_lease(lease_identity, resume_now)
        .expect_err("authenticated lease block reordering must fail closed");
    assert_eq!(
        reordered.code(),
        positron_kernel::LedgerFailureCode::IntegrityCorruption
    );
    let rewind_basis = catalog.pin()?;
    let mut rewound = false;
    let rewind_objects = original_objects
        .iter()
        .map(|bytes| {
            let mut bytes = bytes.clone();
            if bytes.starts_with(b"PSLEASE1") {
                bytes
                    .get_mut(87..95)
                    .ok_or("snapshot lease frontier is missing")?
                    .copy_from_slice(&1_u64.to_be_bytes());
                rewound = true;
            }
            CatalogObject::new(bytes).map_err(Box::<dyn Error>::from)
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    if !rewound {
        return Err("snapshot lease frontier is missing".into());
    }
    catalog.commit(
        rewind_basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0xaf; 16])?,
            FormatEpoch::CATALOG_V1,
            rewind_objects,
        )?,
        None,
    )?;
    drop(rewind_basis);
    let rewound = active
        .resume_snapshot_lease(lease_identity, resume_now)
        .expect_err("authenticated snapshot frontier rewind must fail closed");
    assert_eq!(
        rewound.code(),
        positron_kernel::LedgerFailureCode::IntegrityCorruption
    );
    let final_basis = catalog.pin()?;
    let final_objects = original_objects
        .into_iter()
        .map(CatalogObject::new)
        .collect::<Result<Vec<_>, _>>()?;
    catalog.commit(
        final_basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0xb0; 16])?,
            FormatEpoch::CATALOG_V1,
            final_objects,
        )?,
        None,
    )?;
    drop(final_basis);
    let resumed = active.resume_snapshot_lease(lease_identity, resume_now)?;
    let resumed_result = store.scan(
        authority.governor(),
        tenant,
        resumed.snapshot(),
        LogScan::all(ScanLimit::new(1)?),
    )?;
    assert_eq!(resumed_result.records().len(), 1);
    drop(resumed);
    let sealed_entries =
        std::fs::read_dir(root.path().join("segments/sealed"))?.collect::<Result<Vec<_>, _>>()?;
    assert!(!sealed_entries.is_empty());
    active.release_snapshot_lease(lease_identity)?;
    let outcome = store.enforce_retention(&active, tenant, LogRetentionPolicy::new(1)?)?;
    assert_eq!(outcome.expired_segments(), 1);
    assert_eq!(outcome.reclaimed_segments(), 2);
    let sealed_entries =
        std::fs::read_dir(root.path().join("segments/sealed"))?.collect::<Result<Vec<_>, _>>()?;
    assert!(sealed_entries.is_empty());
    Ok(())
}
