use super::*;

#[test]
fn installed_class_selection_dispatches_supported_work_and_leaves_other_classes_queued()
-> Result<(), Box<dyn std::error::Error>> {
    let root = CatalogRoot::new()?;
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = crate::catalog::tests::support::establish_catalog_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new(nonzero_id(66))?,
        CatalogSecret::from_owned(Box::new([0x67; 32]), Box::new([0x68; 32])),
    )?;
    let initial = CatalogProposal::new(
        TransactionId::new(nonzero_id(69))?,
        FormatEpoch::CATALOG_V1,
        vec![CatalogObject::new(b"class selection basis".to_vec())?],
    )?;
    catalog.commit(catalog.pin()?.identity(), initial, None)?;

    let coordinator = MaintenanceCoordinator::new();
    let unsupported = MaintenanceTask::new(
        MaintenanceTaskId::new(nonzero_id(70)).expect("unsupported task identity"),
        MaintenanceTaskClass::SchemaPromotion,
    );
    let unsupported_id = unsupported.identity();
    coordinator
        .submit_and_persist(&catalog, unsupported, 1)
        .expect("unsupported task persists");
    let lease = crate::SnapshotLeaseId::new([71; 16])?;
    let scope = MaintenanceScope::segment(
        TenantId::from_bytes([0x43; 16])?,
        SignalKind::Logs,
        VirtualShardId::new(1)?,
    );
    let lease_object = CatalogObject::new(b"class selection lease binding".to_vec())?.identity();
    let supported = snapshot_lease_expiry_task(lease, scope, lease_object);
    let supported_id = supported.identity();
    coordinator
        .submit_and_persist(&catalog, supported, 1)
        .expect("supported task persists");

    let execution = coordinator
        .start_next_with_reservation_and_persist_for_classes(
            &catalog,
            &authority,
            10,
            false,
            &[MaintenanceTaskClass::SnapshotLeaseExpiry],
        )
        .expect("installed handler selection")
        .expect("the installed handler selects its eligible task");
    assert_eq!(execution.task().identity(), supported_id);
    assert_eq!(
        coordinator
            .status(unsupported_id)
            .expect("unsupported task")
            .phase(),
        MaintenanceTaskPhase::Queued,
        "the worker must not mark an unsupported class Running"
    );
    Ok(())
}

#[test]
fn prepared_lease_expiry_cancellation_blocks_dispatch_before_its_install()
-> Result<(), Box<dyn std::error::Error>> {
    let root = CatalogRoot::new()?;
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = crate::catalog::tests::support::establish_catalog_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new(nonzero_id(70))?,
        CatalogSecret::from_owned(Box::new([0x71; 32]), Box::new([0x72; 32])),
    )?;
    let initial = CatalogProposal::new(
        TransactionId::new(nonzero_id(71))?,
        FormatEpoch::CATALOG_V1,
        vec![CatalogObject::new(b"cancellation dispatch basis".to_vec())?],
    )?;
    catalog.commit(catalog.pin()?.identity(), initial, None)?;

    let coordinator = MaintenanceCoordinator::new();
    let lease = crate::SnapshotLeaseId::new([73; 16])?;
    let scope = MaintenanceScope::segment(
        TenantId::from_bytes([90; 16])?,
        SignalKind::Logs,
        VirtualShardId::new(1)?,
    );
    let lease_object = CatalogObject::new(b"immutable lease binding".to_vec())?.identity();
    let task = snapshot_lease_expiry_task(lease, scope, lease_object);
    let identity = task.identity();
    coordinator
        .submit_and_persist(&catalog, task, 1)
        .expect("expiry task persists");
    let durable = coordinator
        .durable_records()
        .expect("durable records")
        .into_iter()
        .next()
        .expect("one durable expiry task");
    let cancellation = coordinator
        .prepare_snapshot_lease_expiry_cancellation(
            lease,
            scope,
            lease_object,
            7,
            10,
            durable.as_bytes(),
        )
        .expect("cancellation preparation")
        .expect("queued expiry task prepares cancellation");

    assert_eq!(
        coordinator
            .cancel_and_persist(&catalog, identity)
            .expect_err("a prepared cancellation owns the task transition"),
        MaintenanceFailure::PreconditionFailed
    );
    assert_eq!(
        coordinator.status(identity).expect("queued task").phase(),
        MaintenanceTaskPhase::Queued
    );

    assert!(
        coordinator
            .start_next(10, false)
            .expect("scheduler admission")
            .is_none(),
        "the prepared cancellation retains the queued descriptor until publication resolves"
    );
    assert_eq!(
        coordinator.status(identity).expect("queued task").phase(),
        MaintenanceTaskPhase::Queued
    );

    cancellation
        .install(&coordinator)
        .expect("installation owns the same queued task");
    assert_eq!(
        coordinator
            .status(identity)
            .expect("cancelled task")
            .phase(),
        MaintenanceTaskPhase::Cancelled
    );
    Ok(())
}

#[test]
fn prepared_running_lease_expiry_completion_blocks_cancellation_before_publication()
-> Result<(), Box<dyn std::error::Error>> {
    let root = CatalogRoot::new()?;
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = crate::catalog::tests::support::establish_catalog_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new(nonzero_id(74))?,
        CatalogSecret::from_owned(Box::new([0x75; 32]), Box::new([0x76; 32])),
    )?;
    let initial = CatalogProposal::new(
        TransactionId::new(nonzero_id(75))?,
        FormatEpoch::CATALOG_V1,
        vec![CatalogObject::new(
            b"running completion dispatch basis".to_vec(),
        )?],
    )?;
    catalog.commit(catalog.pin()?.identity(), initial, None)?;
    let coordinator = MaintenanceCoordinator::new();
    let lease = crate::SnapshotLeaseId::new([77; 16])?;
    let scope = MaintenanceScope::segment(
        TenantId::from_bytes([0x43; 16])?,
        SignalKind::Logs,
        VirtualShardId::new(1)?,
    );
    let lease_object = CatalogObject::new(b"running immutable lease binding".to_vec())?.identity();
    let task = snapshot_lease_expiry_task(lease, scope, lease_object);
    let identity = task.identity();
    coordinator
        .submit_and_persist(&catalog, task, 1)
        .expect("expiry task persists");
    let execution = coordinator
        .start_next_with_reservation_and_persist(&catalog, &authority, 10, false)
        .expect("dispatch")
        .expect("due expiry execution");
    let durable = coordinator
        .durable_records()
        .expect("durable records")
        .into_iter()
        .next()
        .ok_or("running durable expiry task")?;
    let completion = execution
        .prepare_running_snapshot_lease_expiry_completion(
            &coordinator,
            SnapshotLeaseExpiryBinding::new(lease, scope, lease_object, 7, 10, durable.as_bytes()),
        )
        .expect("running completion preparation");

    assert_eq!(
        coordinator
            .cancel_and_persist(&catalog, identity)
            .expect_err("prepared completion owns the Running transition"),
        MaintenanceFailure::PreconditionFailed
    );
    assert_eq!(
        coordinator.status(identity).expect("running task").phase(),
        MaintenanceTaskPhase::Running
    );
    assert_eq!(
        coordinator
            .checkpoint(
                identity,
                MaintenanceCheckpoint::new(1, 0, vec![1]).expect("checkpoint"),
            )
            .expect_err("prepared completion fences direct test-model checkpoints"),
        MaintenanceFailure::PreconditionFailed
    );
    assert_eq!(
        coordinator
            .complete(identity, true)
            .expect_err("prepared completion fences direct test-model terminalization"),
        MaintenanceFailure::PreconditionFailed
    );
    assert_eq!(
        execution
            .checkpoint_and_persist(
                &coordinator,
                &catalog,
                MaintenanceCheckpoint::new(1, 0, vec![1]).expect("checkpoint"),
            )
            .expect_err("prepared completion fences handler checkpoints"),
        MaintenanceFailure::PreconditionFailed
    );
    assert_eq!(
        execution
            .complete_and_persist(&coordinator, &catalog, true)
            .expect_err("prepared completion fences generic terminalization"),
        MaintenanceFailure::PreconditionFailed
    );
    coordinator.recover_after_crash().expect("crash recovery");
    assert!(
        coordinator
            .start_next(10, false)
            .expect("recovered scheduling")
            .is_some(),
        "crash recovery drops the prepared transition reservation"
    );
    completion
        .discard(&coordinator)
        .expect("discard prepared completion");
    coordinator
        .cancel_and_persist(&catalog, identity)
        .expect("cancellation after discarded completion");
    assert!(
        coordinator
            .status(identity)
            .expect("running cancellation")
            .cancellation_requested()
    );
    Ok(())
}

#[test]
fn ordinary_submissions_never_evict_a_terminal_reserved_for_lease_publication()
-> Result<(), Box<dyn std::error::Error>> {
    let coordinator = MaintenanceCoordinator::new();
    let lease = crate::SnapshotLeaseId::new([74, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        .expect("lease identity");
    let scope = MaintenanceScope::segment(
        TenantId::from_bytes([90; 16]).expect("tenant"),
        SignalKind::Logs,
        VirtualShardId::new(1).expect("shard"),
    );
    let lease_object = CatalogObject::new(b"reserved lease binding".to_vec())
        .expect("catalog object")
        .identity();
    let reserved = MaintenanceTaskId::new([1; 16]).expect("reserved task identity");
    {
        let mut state = coordinator.state.lock().expect("coordinator state");
        for raw in 1..=u8::try_from(MAX_MAINTENANCE_TASKS).expect("task count") {
            let task = catalog_task(raw);
            let identity = task.identity();
            state.tasks.insert(
                identity,
                TaskState {
                    task,
                    phase: MaintenanceTaskPhase::Cancelled,
                    submitted_at: u64::from(raw),
                    checkpoint: None,
                    pause_until: None,
                    cancellation_requested: false,
                    dispatches: 0,
                    terminal_order: Some(u64::from(raw)),
                    active_dispatch: None,
                },
            );
        }
        state.next_terminal_order = u64::from(MAX_MAINTENANCE_TASKS as u32) + 1;
    }
    let root = CatalogRoot::new()?;
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = crate::catalog::tests::support::establish_catalog_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new(nonzero_id(75))?,
        CatalogSecret::from_owned(Box::new([0x76; 32]), Box::new([0x77; 32])),
    )?;
    let records = coordinator
        .durable_records()
        .expect("terminal records encode for catalog");
    let objects = records
        .into_iter()
        .map(|record| CatalogObject::new(record.as_bytes().to_vec()))
        .collect::<Result<Vec<_>, _>>()?;
    let initial = CatalogProposal::new(
        TransactionId::new(nonzero_id(76))?,
        FormatEpoch::CATALOG_V1,
        objects,
    )?;
    catalog.commit(catalog.pin()?.identity(), initial, None)?;

    let submission = coordinator
        .prepare_snapshot_lease_expiry(lease, scope, lease_object, 7, 10)
        .expect("lease publication reserves the oldest terminal");
    assert_eq!(submission.reclaimed_task_identity(), Some(reserved));

    let ordinary = catalog_task(200);
    coordinator
        .submit_at(ordinary.clone(), 11)
        .expect("another terminal is reclaimed for ordinary work");
    assert!(
        coordinator.status(reserved).is_ok(),
        "the lease draft still owns its selected terminal record"
    );
    assert!(coordinator.status(ordinary.identity()).is_ok());
    let persisted = catalog_task(201);
    coordinator
        .submit_and_persist(&catalog, persisted.clone(), 12)
        .expect("persistent submission reclaims a different terminal");
    assert!(
        coordinator.status(reserved).is_ok(),
        "persistent submission also preserves the lease draft's terminal"
    );
    assert!(coordinator.status(persisted.identity()).is_ok());
    submission
        .discard(&coordinator)
        .expect("discard lease submission");
    Ok(())
}
