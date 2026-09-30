use super::*;

#[test]
fn generic_submission_cannot_persist_a_retention_publication()
-> Result<(), Box<dyn std::error::Error>> {
    let root = CatalogRoot::new()?;
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = crate::catalog::tests::support::establish_catalog_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new(nonzero_id(0x70))?,
        CatalogSecret::from_owned(Box::new([0x71; 32]), Box::new([0x72; 32])),
    )?;
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new(nonzero_id(0x73))?,
            FormatEpoch::CATALOG_V1,
            vec![CatalogObject::new(b"publication ingress basis".to_vec())?],
        )?,
        None,
    )?;
    let coordinator = MaintenanceCoordinator::new();
    let task = retention_publication_task(0x74);
    let identity = task.identity();

    assert_eq!(
        coordinator
            .submit_and_persist(&catalog, task, 1)
            .expect_err("Retention Publication has one typed durable ingress"),
        MaintenanceFailure::InvalidInput
    );
    assert_eq!(
        coordinator
            .status(identity)
            .expect_err("generic submission must not install state"),
        MaintenanceFailure::UnknownTask
    );
    assert!(
        MaintenanceCoordinator::restore_from_catalog(&catalog)
            .expect("empty Catalog restores")
            .durable_records()
            .expect("restored records")
            .is_empty(),
        "generic submission must not publish an orphan task record"
    );
    Ok(())
}

fn retention_publication_task(identity: u8) -> MaintenanceTask {
    let tenant = TenantId::from_bytes([0x74; 16]).expect("tenant");
    MaintenanceTask::with_contract(
        MaintenanceTaskId::new([identity; 16]).expect("identity"),
        MaintenanceTaskClass::RetentionPublication,
        MaintenanceScope::segment(
            tenant,
            SignalKind::Logs,
            VirtualShardId::new(3).expect("shard"),
        ),
        MaintenanceTrigger::AgeDerived,
        MaintenancePreconditions::new(1, 1).expect("preconditions"),
        vec![MaintenanceObjectId::new([0x75; 32]).expect("input")],
        vec![MaintenanceObjectId::new([0x76; 32]).expect("output")],
        ResourceAmounts::new([1; 11]),
    )
    .expect("publication task")
}

#[test]
fn restore_requires_the_typed_retention_publication_checkpoint() {
    let task = retention_publication_task(0x77);
    for checkpoint in [
        None,
        Some(
            MaintenanceCheckpoint::new(1, 0, b"forged checkpoint".to_vec())
                .expect("forged fixture checkpoint"),
        ),
        Some(
            MaintenanceCheckpoint::new(2, 0, retention_publication_checkpoint_bytes(12))
                .expect("wrong sequence fixture checkpoint"),
        ),
    ] {
        let record = encode_record(&TaskState {
            task: task.clone(),
            phase: MaintenanceTaskPhase::Queued,
            submitted_at: 1,
            checkpoint,
            pause_until: None,
            cancellation_requested: false,
            dispatches: 0,
            terminal_order: None,
            active_dispatch: None,
        })
        .expect("durable fixture record");
        match MaintenanceCoordinator::restore([record]) {
            Err(failure) => assert_eq!(failure, MaintenanceFailure::InvalidInput),
            Ok(_) => panic!("Retention Publication must retain its typed durable proof"),
        }
    }

    let record = encode_record(&TaskState {
        task: task.clone(),
        phase: MaintenanceTaskPhase::Queued,
        submitted_at: 1,
        checkpoint: Some(
            MaintenanceCheckpoint::new(1, 0, retention_publication_checkpoint_bytes(12))
                .expect("valid fixture checkpoint"),
        ),
        pause_until: None,
        cancellation_requested: false,
        dispatches: 0,
        terminal_order: None,
        active_dispatch: None,
    })
    .expect("valid durable fixture record");
    let restored = MaintenanceCoordinator::restore([record]).expect("valid typed record restores");
    assert_eq!(
        restored
            .status(task.identity())
            .expect("restored task")
            .phase(),
        MaintenanceTaskPhase::Queued
    );
}

fn retention_publication_checkpoint_bytes(frontier: i64) -> Vec<u8> {
    let mut bytes = b"RTPFR001".to_vec();
    bytes.extend_from_slice(&frontier.to_be_bytes());
    bytes
}

#[test]
fn generic_completion_cannot_terminalize_a_retention_publication()
-> Result<(), Box<dyn std::error::Error>> {
    let root = CatalogRoot::new()?;
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = crate::catalog::tests::support::establish_catalog_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new(nonzero_id(0x78))?,
        CatalogSecret::from_owned(Box::new([0x79; 32]), Box::new([0x7a; 32])),
    )?;
    let coordinator = MaintenanceCoordinator::new();
    let task = retention_publication_task(0x7b);
    let dispatch = MaintenanceDispatch {
        coordinator_id: coordinator.coordinator_id,
        identity: task.identity(),
        attempt: 1,
    };
    let running = TaskState {
        task: task.clone(),
        phase: MaintenanceTaskPhase::Running,
        submitted_at: 1,
        checkpoint: Some(
            MaintenanceCheckpoint::new(1, 0, retention_publication_checkpoint_bytes(12))
                .expect("valid checkpoint"),
        ),
        pause_until: None,
        cancellation_requested: false,
        dispatches: 1,
        terminal_order: None,
        active_dispatch: Some(dispatch),
    };
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new(nonzero_id(0x7c))?,
            FormatEpoch::CATALOG_V1,
            vec![CatalogObject::new(
                encode_record(&running)
                    .expect("durable running record")
                    .as_bytes()
                    .to_vec(),
            )?],
        )?,
        None,
    )?;
    coordinator
        .state
        .lock()
        .expect("coordinator state")
        .tasks
        .insert(task.identity(), running);

    assert_eq!(
        coordinator
            .complete_and_persist_dispatch(&catalog, dispatch, true)
            .expect_err("only the atomic Publication/Reclamation transition may terminalize"),
        MaintenanceFailure::InvalidTransition
    );
    assert_eq!(
        coordinator
            .status(task.identity())
            .expect("running task")
            .phase(),
        MaintenanceTaskPhase::Running
    );
    assert_eq!(
        MaintenanceCoordinator::restore_from_catalog(&catalog)
            .expect("durable running record restores")
            .status(task.identity())
            .expect("durable running task")
            .phase(),
        MaintenanceTaskPhase::Queued,
        "restart recovery must see the unchanged durable running record"
    );
    Ok(())
}

#[test]
fn retention_publication_completion_refuses_a_full_registry_without_corrupting_reopen()
-> Result<(), Box<dyn std::error::Error>> {
    let coordinator = MaintenanceCoordinator::new();
    let tenant = TenantId::from_bytes([0x71; 16])?;
    let scope = MaintenanceScope::segment(tenant, SignalKind::Logs, VirtualShardId::new(1)?);
    let publication = MaintenanceTask::with_contract(
        MaintenanceTaskId::new([0x80; 16]).expect("publication identity"),
        MaintenanceTaskClass::RetentionPublication,
        scope,
        MaintenanceTrigger::AgeDerived,
        MaintenancePreconditions::new(1, 1).expect("preconditions"),
        vec![MaintenanceObjectId::new([0x81; 32]).expect("publication input")],
        vec![MaintenanceObjectId::new([0x82; 32]).expect("publication output")],
        ResourceAmounts::new([1; 11]),
    )
    .expect("publication task");
    let reclamation = MaintenanceTask::with_contract(
        MaintenanceTaskId::new([0x83; 16]).expect("reclamation identity"),
        MaintenanceTaskClass::RetentionReclamation,
        scope,
        MaintenanceTrigger::AgeDerived,
        publication.preconditions(),
        publication.outputs().to_vec(),
        Vec::new(),
        publication.reservations(),
    )
    .expect("reclamation task");
    let dispatch = MaintenanceDispatch {
        coordinator_id: coordinator.coordinator_id,
        identity: publication.identity(),
        attempt: 1,
    };
    let publication_state = TaskState {
        task: publication.clone(),
        phase: MaintenanceTaskPhase::Running,
        submitted_at: 1,
        checkpoint: Some(
            MaintenanceCheckpoint::new(1, 0, retention_publication_checkpoint_bytes(12))
                .expect("valid publication checkpoint"),
        ),
        pause_until: None,
        cancellation_requested: false,
        dispatches: 1,
        terminal_order: None,
        active_dispatch: Some(dispatch),
    };
    {
        let mut state = coordinator.state.lock().expect("coordinator state");
        for raw in 1..=127_u8 {
            let task = catalog_task(raw);
            state.tasks.insert(
                task.identity(),
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
        state
            .tasks
            .insert(publication.identity(), publication_state.clone());
        state.next_terminal_order = 128;
    }

    let root = CatalogRoot::new()?;
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = crate::catalog::tests::support::establish_catalog_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new(nonzero_id(0x84))?,
        CatalogSecret::from_owned(Box::new([0x85; 32]), Box::new([0x86; 32])),
    )?;
    let objects = coordinator
        .durable_records()
        .expect("full registry records")
        .into_iter()
        .map(|record| CatalogObject::new(record.as_bytes().to_vec()))
        .collect::<Result<Vec<_>, _>>()?;
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new(nonzero_id(0x87))?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    assert_eq!(
        MaintenanceCoordinator::restore_from_catalog(&catalog)
            .expect("full registry restores before completion")
            .durable_records()
            .expect("restored durable records")
            .len(),
        MAX_MAINTENANCE_TASKS
    );

    let durable = encode_record(&publication_state).expect("running publication record");
    match coordinator.prepare_running_retention_publication_completion(
        dispatch,
        RetentionPublicationBinding::new(&publication, reclamation, durable.as_bytes()),
    ) {
        Err(error) => assert_eq!(error, MaintenanceFailure::CapacityExceeded),
        Ok(completion) => {
            completion.discard(&coordinator);
            panic!("a terminal publication plus queued reclamation cannot exceed 128 tasks");
        },
    }
    assert_eq!(
        MaintenanceCoordinator::restore_from_catalog(&catalog)
            .expect("rejected completion leaves the durable registry reopenable")
            .durable_records()
            .expect("restored durable records")
            .len(),
        MAX_MAINTENANCE_TASKS
    );
    Ok(())
}

#[test]
fn retention_publication_refuses_a_successor_with_nonpublication_bindings() {
    let coordinator = MaintenanceCoordinator::new();
    let tenant = TenantId::from_bytes([0x91; 16]).expect("tenant");
    let scope = MaintenanceScope::segment(
        tenant,
        SignalKind::Logs,
        VirtualShardId::new(2).expect("shard"),
    );
    let publication = MaintenanceTask::with_contract(
        MaintenanceTaskId::new([0x92; 16]).expect("publication identity"),
        MaintenanceTaskClass::RetentionPublication,
        scope,
        MaintenanceTrigger::AgeDerived,
        MaintenancePreconditions::new(1, 1).expect("preconditions"),
        vec![MaintenanceObjectId::new([0x93; 32]).expect("input")],
        vec![MaintenanceObjectId::new([0x94; 32]).expect("output")],
        ResourceAmounts::new([1; 11]),
    )
    .expect("publication");
    let dispatch = MaintenanceDispatch {
        coordinator_id: coordinator.coordinator_id,
        identity: publication.identity(),
        attempt: 1,
    };
    let running = TaskState {
        task: publication.clone(),
        phase: MaintenanceTaskPhase::Running,
        submitted_at: 1,
        checkpoint: Some(
            MaintenanceCheckpoint::new(1, 0, retention_publication_checkpoint_bytes(12))
                .expect("valid publication checkpoint"),
        ),
        pause_until: None,
        cancellation_requested: false,
        dispatches: 1,
        terminal_order: None,
        active_dispatch: Some(dispatch),
    };
    let durable = encode_record(&running).expect("durable record");
    coordinator
        .state
        .lock()
        .expect("coordinator state")
        .tasks
        .insert(publication.identity(), running);
    let malformed = MaintenanceTask::with_contract(
        MaintenanceTaskId::new([0x95; 16]).expect("reclamation identity"),
        MaintenanceTaskClass::RetentionReclamation,
        scope,
        MaintenanceTrigger::AgeDerived,
        publication.preconditions(),
        vec![MaintenanceObjectId::new([0x96; 32]).expect("wrong input")],
        Vec::new(),
        publication.reservations(),
    )
    .expect("malformed reclamation");
    match coordinator.prepare_running_retention_publication_completion(
        dispatch,
        RetentionPublicationBinding::new(&publication, malformed, durable.as_bytes()),
    ) {
        Err(error) => assert_eq!(error, MaintenanceFailure::PreconditionFailed),
        Ok(completion) => {
            completion.discard(&coordinator);
            panic!("reclamation must consume exactly the publication outputs");
        },
    }
    assert_eq!(
        coordinator
            .status(publication.identity())
            .expect("publication status")
            .phase(),
        MaintenanceTaskPhase::Running
    );
}
