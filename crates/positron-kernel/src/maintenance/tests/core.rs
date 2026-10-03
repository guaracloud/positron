use super::*;

#[test]
fn governance_audit_checkpoint_binding_rejects_malformed_checkpoints() {
    let valid = GovernanceAuditCheckpointBinding::new(1, [1; 32], [2; 32])
        .expect("nonzero binding")
        .checkpoint()
        .expect("bounded checkpoint");
    assert!(GovernanceAuditCheckpointBinding::from_checkpoint(Some(&valid)).is_ok());

    for checkpoint in [
        None,
        Some(MaintenanceCheckpoint::new(2, 0, valid.opaque_progress().to_vec()).expect("shape")),
        Some(MaintenanceCheckpoint::new(1, 1, valid.opaque_progress().to_vec()).expect("shape")),
        Some(MaintenanceCheckpoint::new(1, 0, vec![0; 79]).expect("shape")),
        Some(MaintenanceCheckpoint::new(1, 0, vec![0; 80]).expect("shape")),
    ] {
        assert_eq!(
            GovernanceAuditCheckpointBinding::from_checkpoint(checkpoint.as_ref()),
            Err(MaintenanceFailure::InvalidInput)
        );
    }
}

#[test]
fn generic_submission_cannot_persist_a_compaction_without_its_typed_binding()
-> Result<(), Box<dyn std::error::Error>> {
    let root = CatalogRoot::new()?;
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = crate::catalog::tests::support::establish_catalog_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new(nonzero_id(0x57))?,
        CatalogSecret::from_owned(Box::new([0x58; 32]), Box::new([0x59; 32])),
    )?;
    let coordinator = MaintenanceCoordinator::new();
    let task = task(
        0x5a,
        MaintenanceTaskClass::Compaction,
        MaintenanceTrigger::Event,
        MaintenancePriority::Required,
        Vec::new(),
    );
    assert_eq!(
        coordinator
            .submit_and_persist(&catalog, task, 1)
            .expect_err("generic ingress must not create an unbound compaction"),
        MaintenanceFailure::InvalidInput
    );
    assert!(
        coordinator
            .durable_records()
            .expect("refused ingress has no durable task record")
            .is_empty()
    );
    Ok(())
}
