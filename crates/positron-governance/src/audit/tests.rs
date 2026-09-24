use positron_domain::identity::{PrincipalId, TenantId, TenantSlug};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use super::{
    CatalogRootRotationStage, GovernanceAuditEntry, InitializationAuditEntry,
    schema_checkpoint_audit_intent,
};
use crate::{
    ApiKeyLifecycleAction, ConfigurationAuditOutcome, ConfigurationAuditRequest,
    DurableOperationKind, DurableOperationPhase, DurableOperationStatus, InitialAuditContext,
    InitialGovernanceIntent, InitialTenantIntent, ListenerTransportAuditEntry,
    ListenerTransportAuditRequest, ListenerTransportConfigurationProvenance, ResourceGeneration,
};

#[test]
fn legacy_durable_operation_audit_remains_readable() {
    let transaction = [0x11; 16];
    let mut intent = b"POSOPA01".to_vec();
    intent.extend_from_slice(&[0x22; 16]);
    intent.push(1); // catalog-format migration
    intent.push(4); // failed
    intent.push(3); // draining
    intent.extend_from_slice(&7_u64.to_be_bytes());

    let entry = GovernanceAuditEntry::decode_fields(5, transaction, &intent)
        .expect("legacy durable-operation audit");
    let GovernanceAuditEntry::DurableOperation(operation) = entry else {
        panic!("typed durable audit");
    };
    assert_eq!(operation.operation_id().to_bytes(), [0x22; 16]);
    assert_eq!(operation.acting_principal(), None);
    assert_eq!(operation.applicable_tenant(), None);
    assert_eq!(
        operation.action(),
        DurableOperationKind::CatalogFormatMigration
    );
    assert_eq!(operation.outcome(), DurableOperationStatus::Failed);
    assert_eq!(operation.phase, DurableOperationPhase::Draining);
    assert_eq!(operation.request_id(), None);
    assert_eq!(operation.accepted_generation(), None);
    assert_eq!(operation.progress_percent(), None);
    assert_eq!(operation.revision, 7);

    let mut malformed = intent;
    malformed[8..24].fill(0);
    assert!(GovernanceAuditEntry::decode_fields(5, transaction, &malformed).is_err());
}

#[test]
fn durable_operation_audit_rejects_a_structurally_valid_unbound_transaction() {
    let mut intent = b"POSOPA02".to_vec();
    intent.extend_from_slice(&[0x22; 16]); // operation
    intent.extend_from_slice(&[0x33; 16]); // creator
    intent.push(0); // system-wide
    intent.push(1); // catalog-format migration
    intent.push(2); // running
    intent.push(2); // preflight
    intent.extend_from_slice(&[0x44; 16]); // idempotency key
    intent.extend_from_slice(&7_u64.to_be_bytes()); // accepted generation
    intent.push(10); // progress
    intent.extend_from_slice(&2_u64.to_be_bytes()); // revision

    assert!(
        GovernanceAuditEntry::decode_fields(5, [0x55; 16], &intent).is_err(),
        "a durable-operation audit must bind its transaction to its canonical request"
    );
}

#[test]
fn historical_v3_catalog_migration_audit_without_a_target_remains_readable() {
    // This is a valid POSOPA03 record emitted before durable-operation audit
    // records carried an explicit target identity. Its operation and transition
    // identities are fixed historical bytes, derived by the shipped V3 format.
    let operation_id = [
        0x5a, 0xdf, 0xcf, 0xc8, 0xda, 0x52, 0x9c, 0x99, 0x90, 0xd7, 0xbc, 0xed, 0x8a, 0xa1, 0x82,
        0x31,
    ];
    let transaction = [
        0xc0, 0x3c, 0xe7, 0xee, 0x48, 0x6b, 0x9a, 0x31, 0xf5, 0x77, 0xf7, 0x88, 0xbf, 0x20, 0x3d,
        0x77,
    ];
    let mut intent = b"POSOPA03".to_vec();
    intent.extend_from_slice(&operation_id);
    intent.extend_from_slice(&[0x61; 16]); // historical actor
    intent.push(0); // system-wide
    intent.push(1); // catalog-format migration
    intent.push(2); // running
    intent.push(2); // preflight
    intent.extend_from_slice(&[0x62; 16]); // historical idempotency key
    intent.extend_from_slice(&7_u64.to_be_bytes());
    intent.push(10); // progress
    intent.extend_from_slice(&2_u64.to_be_bytes()); // revision
    intent.push(0); // no cancellation key
    intent.extend_from_slice(&[0; 16]);

    let entry = GovernanceAuditEntry::decode_fields(5, transaction, &intent)
        .expect("historical target-less catalog migration audit");
    let GovernanceAuditEntry::DurableOperation(operation) = entry else {
        panic!("typed durable audit");
    };
    assert_eq!(operation.operation_id().to_bytes(), operation_id);
    assert_eq!(
        operation.action(),
        DurableOperationKind::CatalogFormatMigration
    );
    assert_eq!(operation.applicable_tenant(), None);

    intent[41] = 2; // query export cannot use the target-less historical format
    assert!(GovernanceAuditEntry::decode_fields(5, transaction, &intent).is_err());
}

#[test]
fn query_export_audit_binds_its_tenant_and_full_request_digest() {
    let principal = PrincipalId::from_bytes([0x31; 16]).expect("principal");
    let tenant = TenantId::from_bytes([0x32; 16]).expect("tenant");
    let key = crate::AdministrativeIdempotencyKey::new([0x33; 16]).expect("key");
    let digest = [0x34; 32];
    let request = crate::DurableOperationRequest::query_export(
        principal, tenant, key, [0x35; 16], 7, 1, digest,
    )
    .expect("query export request");
    let operation_id = request.operation_id();
    let transaction =
        crate::durable_operation_administration::transition_transaction_bytes(operation_id, 2)
            .expect("transition transaction");
    let mut intent = b"POSOPA05".to_vec();
    intent.extend_from_slice(&operation_id.to_bytes());
    intent.extend_from_slice(&principal.to_bytes());
    intent.extend_from_slice(&[0x35; 16]);
    intent.push(1);
    intent.extend_from_slice(&tenant.to_bytes());
    intent.push(2); // query export
    intent.push(2); // running
    intent.push(2); // preflight
    intent.extend_from_slice(&key.to_bytes());
    intent.extend_from_slice(&7_u64.to_be_bytes());
    intent.extend_from_slice(&digest);
    intent.push(10); // progress
    intent.extend_from_slice(&2_u64.to_be_bytes());
    intent.push(0); // no cancellation key
    intent.extend_from_slice(&[0; 16]);

    let entry = GovernanceAuditEntry::decode_fields(6, transaction, &intent)
        .expect("tenant-bound query-export audit");
    let GovernanceAuditEntry::DurableOperation(audit) = entry else {
        panic!("typed durable audit");
    };
    assert_eq!(audit.operation_id(), operation_id);
    assert_eq!(audit.applicable_tenant(), Some(tenant));
    assert_eq!(audit.request_id(), Some(key));

    let mut changed_digest = intent;
    changed_digest[100] ^= 1;
    assert!(GovernanceAuditEntry::decode_fields(6, transaction, &changed_digest).is_err());
}

#[test]
fn legacy_query_export_audit_without_its_tenant_and_digest_fails_closed() {
    let mut intent = b"POSOPA04".to_vec();
    intent.extend_from_slice(&[0x41; 16]);
    intent.extend_from_slice(&[0x42; 16]);
    intent.extend_from_slice(&[0x43; 16]);
    intent.push(0); // old records carry no tenant
    intent.push(2); // query export
    intent.push(2); // running
    intent.push(2); // preflight
    intent.extend_from_slice(&[0x44; 16]);
    intent.extend_from_slice(&7_u64.to_be_bytes());
    intent.push(10);
    intent.extend_from_slice(&2_u64.to_be_bytes());
    intent.push(0);
    intent.extend_from_slice(&[0; 16]);

    assert!(GovernanceAuditEntry::decode_fields(6, [0x45; 16], &intent).is_err());
}

#[test]
fn public_plaintext_api_transport_audit_is_redacted_exact_and_strict() {
    let transaction = [19; 16];
    let mut intent = b"POSTPT01".to_vec();
    intent.extend_from_slice(&transaction);
    let entry = GovernanceAuditEntry::decode_fields(7, transaction, &intent)
        .expect("plaintext transport audit");
    let transport = entry
        .as_listener_transport()
        .expect("typed transport audit");
    assert_eq!(entry.action(), "listener.api-transport.plaintext-opt-out");
    assert_eq!(entry.outcome(), "active");
    assert_eq!(transport, &ListenerTransportAuditEntry::new(7, transaction));
    assert!(!format!("{entry:?} {entry}").contains("Bearer"));

    for malformed in [
        b"POSTPT00".as_slice(),
        b"POSTPT01".as_slice(),
        b"POSTPT01\0".as_slice(),
    ] {
        assert!(GovernanceAuditEntry::decode_fields(7, transaction, malformed).is_err());
    }
    let mut trailing = intent;
    trailing.push(0);
    assert!(GovernanceAuditEntry::decode_fields(7, transaction, &trailing).is_err());
}

#[test]
fn version_two_plaintext_transport_audit_binds_target_provenance_and_request_identity() {
    let instance = [19; 16];
    let request = ListenerTransportAuditRequest::configuration_file(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 23)),
        8_080,
    ));
    let transaction = request.transaction_id_for(instance);
    let intent = crate::audit::plaintext_api_transport_audit_intent_v2(instance, request);

    let entry = GovernanceAuditEntry::decode_fields(8, transaction, &intent)
        .expect("bound plaintext transport audit");
    let transport = entry
        .as_listener_transport()
        .expect("typed transport audit");
    assert_eq!(transport.instance_id(), instance);
    assert_eq!(transport.listener_target(), Some(request.listener_target()));
    assert_eq!(
        transport.configuration_provenance(),
        Some(ListenerTransportConfigurationProvenance::ConfigurationFile)
    );
    assert_eq!(transport.request_id(), Some(transaction));
    assert_eq!(
        transport.request_digest(),
        Some(request.digest_for(instance))
    );
    assert!(transport.is_configuration_file_intent());

    let changed_target = ListenerTransportAuditRequest::configuration_file(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 23)),
        8_081,
    ));
    assert_ne!(changed_target.transaction_id_for(instance), transaction);
    assert_ne!(
        changed_target.digest_for(instance),
        request.digest_for(instance)
    );

    let mut changed_encoded_target = intent;
    changed_encoded_target[30] = 24;
    assert!(GovernanceAuditEntry::decode_fields(8, transaction, &changed_encoded_target).is_err());
}

#[test]
fn api_key_lifecycle_audit_is_redacted_exact_and_strict() {
    let transaction = [9; 16];
    let mut intent = b"POSKEY01".to_vec();
    intent.push(2);
    intent.extend_from_slice(&[1; 16]);
    intent.extend_from_slice(&[2; 16]);
    intent.extend_from_slice(&[3; 16]);
    intent.push(2);
    intent.extend_from_slice(&77_u64.to_be_bytes());
    intent.extend_from_slice(&4_u64.to_be_bytes());
    intent.extend_from_slice(&5_u64.to_be_bytes());
    intent.extend_from_slice(&transaction);
    let entry = GovernanceAuditEntry::decode_fields(6, transaction, &intent).expect("audit");
    let lifecycle = entry.as_api_key_lifecycle().expect("typed lifecycle audit");
    assert_eq!(entry.action(), "api-key.rotate");
    assert_eq!(lifecycle.action(), ApiKeyLifecycleAction::Rotate);
    assert_eq!(lifecycle.actor_id().to_bytes(), [1; 16]);
    assert_eq!(lifecycle.principal_id().to_bytes(), [2; 16]);
    assert_eq!(lifecycle.target_principal_id().to_bytes(), [3; 16]);
    assert_eq!(lifecycle.scope(), positron_domain::identity::Scope::Query);
    assert_eq!(lifecycle.expires_at_unix_seconds(), Some(77));
    assert_eq!(
        lifecycle.expected_generation(),
        ResourceGeneration::new(4).expect("generation")
    );
    assert_eq!(
        lifecycle.generation(),
        ResourceGeneration::new(5).expect("generation")
    );
    assert_eq!(lifecycle.idempotency_key().to_bytes(), transaction);
    assert!(!format!("{entry:?}").contains("pos_"));

    for offset in [8, 73, 81] {
        let mut malformed = intent.clone();
        malformed[offset] = 0;
        assert!(GovernanceAuditEntry::decode_fields(6, transaction, &malformed).is_err());
    }
    let mut trailing = intent;
    trailing.push(0);
    assert!(GovernanceAuditEntry::decode_fields(6, transaction, &trailing).is_err());
}

#[test]
fn version_two_lifecycle_audits_bind_the_canonical_request_digest() {
    let transaction = [9; 16];
    let request_digest = [41; 32];
    let mut api_key = b"POSKEY02".to_vec();
    api_key.push(2);
    api_key.extend_from_slice(&[1; 16]);
    api_key.extend_from_slice(&[2; 16]);
    api_key.extend_from_slice(&[3; 16]);
    api_key.push(2);
    api_key.extend_from_slice(&77_u64.to_be_bytes());
    api_key.extend_from_slice(&4_u64.to_be_bytes());
    api_key.extend_from_slice(&5_u64.to_be_bytes());
    api_key.extend_from_slice(&transaction);
    api_key.extend_from_slice(&request_digest);
    let entry = GovernanceAuditEntry::decode_fields(6, transaction, &api_key).expect("audit");
    assert_eq!(
        entry
            .as_api_key_lifecycle()
            .expect("typed lifecycle audit")
            .request_digest(),
        Some(request_digest)
    );
    assert_eq!(entry.tenant_id(), None);

    let tenant = TenantId::from_bytes([42; 16]).expect("tenant");
    let mut api_key_v3 = api_key.clone();
    api_key_v3[..8].copy_from_slice(b"POSKEY03");
    api_key_v3.push(1);
    api_key_v3.extend_from_slice(&tenant.to_bytes());
    let entry = GovernanceAuditEntry::decode_fields(6, transaction, &api_key_v3)
        .expect("tenant-bound API key audit");
    assert_eq!(entry.tenant_id(), Some(tenant));
    assert_eq!(
        entry
            .as_api_key_lifecycle()
            .expect("typed lifecycle audit")
            .request_digest(),
        Some(request_digest)
    );
    let mut malformed_tenant_scope = api_key_v3.clone();
    malformed_tenant_scope[130] = 2;
    assert!(GovernanceAuditEntry::decode_fields(6, transaction, &malformed_tenant_scope).is_err());
    assert!(GovernanceAuditEntry::decode_fields(6, transaction, &api_key_v3[..130]).is_err());

    let mut lifecycle = b"POSTEN02".to_vec();
    lifecycle.extend_from_slice(&1_725_000_002_u64.to_be_bytes());
    lifecycle.extend_from_slice(&transaction);
    lifecycle.extend_from_slice(&[1; 16]);
    lifecycle.extend_from_slice(&[2; 16]);
    lifecycle.extend_from_slice(&1_u8.to_be_bytes());
    lifecycle.extend_from_slice(&2_u8.to_be_bytes());
    lifecycle.extend_from_slice(&4_u64.to_be_bytes());
    lifecycle.extend_from_slice(&5_u64.to_be_bytes());
    lifecycle.extend_from_slice(&request_digest);
    let entry = GovernanceAuditEntry::decode_fields(7, transaction, &lifecycle).expect("audit");
    assert_eq!(
        entry
            .as_tenant_lifecycle()
            .expect("typed lifecycle audit")
            .request_digest(),
        Some(request_digest)
    );

    for malformed in [
        &api_key[..api_key.len() - 1],
        &lifecycle[..lifecycle.len() - 1],
    ] {
        assert!(GovernanceAuditEntry::decode_fields(6, transaction, malformed).is_err());
    }
}

fn audit_intent() -> Vec<u8> {
    InitialGovernanceIntent::create_tenant(
        InitialTenantIntent::new(
            [1; 16],
            TenantId::from_bytes([2; 16]).expect("tenant"),
            TenantSlug::parse_canonical("default").expect("slug"),
            "Default tenant",
            PrincipalId::from_bytes([3; 16]).expect("principal"),
            [4; 32],
            [5; 32],
            PrincipalId::from_bytes([12; 16]).expect("ingest principal"),
            [13; 32],
            [14; 32],
            PrincipalId::from_bytes([15; 16]).expect("query principal"),
            [16; 32],
            [17; 32],
            [6; 32],
            [7; 32],
            vec![8; 64],
            vec![9; 48],
            1,
            1,
            1,
            [1; 11],
            InitialAuditContext::new(1_725_000_001, [11; 16], true).expect("audit context"),
        )
        .expect("intent"),
    )
    .expect("governance")
    .into_parts()
    .1
}

#[test]
fn committed_initial_audit_has_typed_redacted_meaning() {
    let entry = InitializationAuditEntry::decode_intent(7, &audit_intent()).expect("audit");
    assert_eq!(entry.position(), 7);
    assert_eq!(entry.principal_id().to_bytes(), [3; 16]);
    assert_eq!(entry.tenant_id().map(TenantId::to_bytes), Some([2; 16]));
    assert_eq!(entry.action(), "instance.initialize");
    assert_eq!(entry.outcome(), "succeeded");
    assert_eq!(entry.ingest_time_unix_seconds(), 1_725_000_001);
    assert_eq!(entry.target(), [1; 16]);
    assert_eq!(entry.request_id(), [11; 16]);
    assert_eq!(entry.metadata().initialization_mode(), "non-interactive");
    assert_eq!(entry.metadata().tenant_slug(), "default");
    assert_eq!(
        entry.metadata().external_tenant_alias(),
        Some("trace-external")
    );
}

#[test]
fn audit_decoder_rejects_truncation_corruption_and_trailing_data() {
    let intent = audit_intent();
    for length in [0, 7, 8, 24, 40, intent.len() - 1] {
        assert!(InitializationAuditEntry::decode_intent(1, &intent[..length]).is_err());
    }
    let mut corrupt = intent.clone();
    corrupt[0] ^= 1;
    assert!(InitializationAuditEntry::decode_intent(1, &corrupt).is_err());
    let mut trailing = intent;
    trailing.push(0);
    assert!(InitializationAuditEntry::decode_intent(1, &trailing).is_err());

    for range in [8..16, 70..86, 96..112] {
        let mut zeroed = audit_intent();
        zeroed[range].fill(0);
        assert!(InitializationAuditEntry::decode_intent(1, &zeroed).is_err());
    }
    for (offset, value) in [(32, 2), (69, 2), (112, 2)] {
        let mut invalid_tag = audit_intent();
        invalid_tag[offset] = value;
        assert!(InitializationAuditEntry::decode_intent(1, &invalid_tag).is_err());
    }
    for meaning in [b"instance.initialize".as_slice(), b"succeeded"] {
        let mut unsupported = audit_intent();
        let offset = unsupported
            .windows(meaning.len())
            .position(|window| window == meaning)
            .expect("known meaning");
        unsupported[offset] ^= 1;
        assert!(InitializationAuditEntry::decode_intent(1, &unsupported).is_err());
    }
}

#[test]
fn audit_schema_router_returns_one_typed_redacted_rotation_entry_or_refuses() {
    let mut valid = b"catalog-root-rotation-v1\0completed\0".to_vec();
    valid.extend_from_slice(&[1; 16]);
    valid.extend_from_slice(&2_u64.to_be_bytes());
    valid.extend_from_slice(b"sensitive operator context");
    let entry = GovernanceAuditEntry::decode_fields(8, [3; 16], &valid).expect("rotation");
    let rotation = entry.as_catalog_root_rotation().expect("typed rotation");
    assert_eq!(entry.position(), 8);
    assert_eq!(rotation.stage(), CatalogRootRotationStage::Completed);
    assert_eq!(rotation.action(), "catalog.root-rotation.completed");
    assert_eq!(rotation.provider_key_reference(), [1; 16]);
    assert_eq!(rotation.key_epoch(), 2);
    assert_eq!(rotation.transaction_id(), [3; 16]);
    assert_eq!(rotation.outcome(), "committed");
    assert!(!format!("{entry:?} {entry}").contains("sensitive operator context"));

    for corrupt in [
        b"unknown-audit-v1\0completed\0".as_slice(),
        b"catalog-root-rotation-v1\0unknown\0".as_slice(),
        b"catalog-root-rotation-v1\0completed\0".as_slice(),
    ] {
        assert!(GovernanceAuditEntry::decode_fields(1, [1; 16], corrupt).is_err());
    }
    let mut zero_epoch = valid.clone();
    let epoch_start = b"catalog-root-rotation-v1\0completed\0".len() + 16;
    zero_epoch[epoch_start..epoch_start + 8].fill(0);
    assert!(GovernanceAuditEntry::decode_fields(1, [1; 16], &zero_epoch).is_err());
    let mut zero_provider = valid;
    zero_provider[epoch_start - 16..epoch_start].fill(0);
    assert!(GovernanceAuditEntry::decode_fields(1, [1; 16], &zero_provider).is_err());
}

#[test]
fn schema_checkpoint_audit_is_typed_tenant_bound_and_strict() {
    let tenant = TenantId::from_bytes([21; 16]).expect("tenant");
    let transaction = [22; 16];
    let intent = schema_checkpoint_audit_intent(tenant, b"bounded checkpoint").expect("intent");
    let entry = GovernanceAuditEntry::decode_fields(9, transaction, &intent).expect("entry");
    let checkpoint = entry.as_schema_checkpoint().expect("checkpoint");
    assert_eq!(entry.action(), "schema-checkpoint.replace");
    assert_eq!(entry.outcome(), "succeeded");
    assert_eq!(checkpoint.position(), 9);
    assert_eq!(checkpoint.transaction_id(), transaction);
    assert_eq!(checkpoint.tenant_id(), tenant);
    assert_ne!(checkpoint.checkpoint_digest(), [0; 32]);

    for length in [0, 7, 8, intent.len() - 1] {
        assert!(GovernanceAuditEntry::decode_fields(9, transaction, &intent[..length]).is_err());
    }
    let mut trailing = intent;
    trailing.push(0);
    assert!(GovernanceAuditEntry::decode_fields(9, transaction, &trailing).is_err());
}

#[test]
fn tenant_retention_audit_is_typed_redacted_and_strict() {
    let transaction = [23; 16];
    let mut intent = b"POSTRT01".to_vec();
    intent.extend_from_slice(&1_725_000_002_u64.to_be_bytes());
    intent.extend_from_slice(&transaction);
    intent.extend_from_slice(&[24; 16]);
    intent.extend_from_slice(&[25; 16]);
    intent.extend_from_slice(&1_u64.to_be_bytes());
    intent.extend_from_slice(&2_u64.to_be_bytes());
    intent.extend_from_slice(&86_400_u64.to_be_bytes());
    intent.extend_from_slice(&[26; 32]);

    let entry = GovernanceAuditEntry::decode_fields(10, transaction, &intent).expect("entry");
    let retention = entry
        .as_tenant_retention_update()
        .expect("retention update");
    assert_eq!(entry.action(), "tenant.retention.update");
    assert_eq!(entry.outcome(), "succeeded");
    assert_eq!(retention.position(), 10);
    assert_eq!(retention.actor_id().to_bytes(), [24; 16]);
    assert_eq!(retention.tenant_id().to_bytes(), [25; 16]);
    assert_eq!(
        retention.expected_generation(),
        ResourceGeneration::new(1).expect("generation")
    );
    assert_eq!(
        retention.generation(),
        ResourceGeneration::new(2).expect("generation")
    );
    assert_eq!(retention.idempotency_key().to_bytes(), transaction);
    assert_eq!(retention.request_digest(), [26; 32]);
    assert!(
        !format!("{entry:?} {entry}").contains("86400"),
        "the audit must not disclose the requested retention duration"
    );

    for length in [0, 7, 8, intent.len() - 1] {
        assert!(GovernanceAuditEntry::decode_fields(10, transaction, &intent[..length]).is_err());
    }
    let mut zero_digest = intent.clone();
    let digest_start = zero_digest.len() - 32;
    zero_digest[digest_start..].fill(0);
    assert!(GovernanceAuditEntry::decode_fields(10, transaction, &zero_digest).is_err());
    let mut mismatched_generation = intent.clone();
    let generation_start = 8 + 8 + 16 + 16 + 16 + 8;
    mismatched_generation[generation_start..generation_start + 8]
        .copy_from_slice(&1_u64.to_be_bytes());
    assert!(GovernanceAuditEntry::decode_fields(10, transaction, &mismatched_generation).is_err());
    let mut trailing = intent;
    trailing.push(0);
    assert!(GovernanceAuditEntry::decode_fields(10, transaction, &trailing).is_err());
}

#[test]
fn configuration_audit_binds_the_fenced_drift_to_one_catalog_generation() {
    let request = ConfigurationAuditRequest::new(
        ConfigurationAuditOutcome::FencedDrift,
        1_725_000_000,
        PrincipalId::from_bytes([0x31; 16]).expect("principal"),
        None,
        [0x32; 16],
        [0x33; 16],
        42,
        1,
        [0x41; 32],
        [0x42; 32],
    )
    .expect("valid configuration audit request");
    let encoded = request.encode();
    let entry = GovernanceAuditEntry::decode_fields(9, request.transaction_id(), &encoded)
        .expect("typed configuration audit");
    let configuration = entry.as_configuration().expect("configuration entry");
    assert_eq!(entry.action(), "configuration.reload");
    assert_eq!(entry.outcome(), "rejected");
    assert_eq!(configuration.position(), 9);
    assert_eq!(
        configuration.outcome(),
        ConfigurationAuditOutcome::FencedDrift
    );
    assert_eq!(configuration.catalog_generation(), 42);
    assert_eq!(configuration.ingest_time_unix_seconds(), 1_725_000_000);
    assert_eq!(configuration.principal().to_bytes(), [0x31; 16]);
    assert_eq!(configuration.applicable_tenant(), None);
    assert_eq!(configuration.target(), [0x32; 16]);
    assert_eq!(configuration.request_id(), [0x33; 16]);
    assert_eq!(configuration.active_digest(), [0x41; 32]);
    assert_eq!(configuration.candidate_digest(), [0x42; 32]);

    let mut wrong_digest = encoded;
    let digest_start = wrong_digest.len() - 32;
    wrong_digest[digest_start] ^= 1;
    assert!(
        GovernanceAuditEntry::decode_fields(9, request.transaction_id(), &wrong_digest).is_err()
    );
}
