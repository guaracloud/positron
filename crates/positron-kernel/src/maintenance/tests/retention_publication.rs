use super::*;

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
        checkpoint: None,
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
        checkpoint: None,
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
