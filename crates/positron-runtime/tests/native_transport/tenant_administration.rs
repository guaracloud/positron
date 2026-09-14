use super::*;

#[test]
fn api_client_manages_a_tenant_bound_key_lifecycle() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_test_guard();
    let roots = TestRoots::new("tenant-key-client")?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        positron_runtime::InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let initialized = InstanceBootstrap::reopen(&paths)?;
    let system = initialized.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let tenant = initialized
        .create_tenant_generated(
            system,
            positron_governance::TenantCreateConfiguration::new(
                TenantSlug::parse_canonical("client-key-tenant")?,
                "Client key tenant",
                2_592_000,
                1,
                [
                    32_000_000, 32, 32, 5_000_000, 2_048, 32, 32, 32, 32, 32, 2_000_000,
                ],
            ),
            AdministrativeIdempotencyKey::new([0x89; 16])?,
        )
        .map_err(|failure| format!("tenant creation: {failure:?}"))?
        .tenant_id();
    drop(initialized);

    let host = NativeHost::new(bindings(&roots, "tenant-key-client")?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    let api = address(
        &process.bound_endpoints(),
        positron_runtime::ListenerRole::Api,
    )?;
    let client = positron_api::api_keys::ApiKeyServiceClient::new(
        positron_api::api_keys::ApiKeyTransport::PlaintextOptOut { endpoint: api },
    )?;
    let target = positron_api::api_keys::ApiKeyRequest::create_for_tenant(
        positron_api::api_keys::KeyScope::Ingest,
        tenant.to_canonical_text(),
        None,
        1,
        "88888888-8888-8888-8888-88888888888a".to_owned(),
    );
    let mut created = client
        .manage(claim.secret(), &target)
        .map_err(|failure| format!("target create: {failure:?}"))?;
    let principal = created.principal.clone().ok_or("created principal")?;
    let secret = created.secret.take().ok_or("one-time tenant secret")?;
    let replay = client
        .manage(claim.secret(), &target)
        .map_err(|failure| format!("target replay: {failure:?}"))?;
    assert_eq!(replay.principal.as_deref(), Some(principal.as_str()));
    assert!(
        replay.secret.is_none(),
        "replay must never redisplay a secret"
    );
    assert!(
        client
            .manage(
                claim.secret(),
                &positron_api::api_keys::ApiKeyRequest::create_for_tenant(
                    positron_api::api_keys::KeyScope::Query,
                    "99999999-9999-9999-9999-999999999999".to_owned(),
                    None,
                    1,
                    "99999999-9999-9999-9999-99999999999a".to_owned(),
                ),
            )
            .is_err(),
        "an unknown tenant must not create an orphan credential"
    );
    let default_created = client
        .manage(
            claim.secret(),
            &positron_api::api_keys::ApiKeyRequest::create(
                positron_api::api_keys::KeyScope::TenantAdministration,
                None,
                1,
                "88888888-8888-8888-8888-88888888888b".to_owned(),
            ),
        )
        .map_err(|failure| format!("legacy default create: {failure:?}"))?;
    assert!(
        default_created.secret.is_some(),
        "omitting target_tenant retains the default credential lifecycle"
    );
    let replay_after_unrelated_mutation = client
        .manage(claim.secret(), &target)
        .map_err(|failure| format!("target replay after mutation: {failure:?}"))?;
    assert_eq!(
        replay_after_unrelated_mutation.principal.as_deref(),
        Some(principal.as_str())
    );
    assert!(
        replay_after_unrelated_mutation.secret.is_none(),
        "an exact retry after unrelated mutation must not redisplay the tenant secret"
    );
    let listed = client
        .manage(
            claim.secret(),
            &positron_api::api_keys::ApiKeyRequest::list_for_tenant(tenant.to_canonical_text()),
        )
        .map_err(|failure| format!("target list: {failure:?}"))?;
    assert_eq!(listed.keys.len(), 1);
    assert_eq!(listed.keys[0].principal, principal);
    assert!(listed.keys[0].active);
    assert_eq!(listed.keys[0].generation, 2);
    let rotation = positron_api::api_keys::ApiKeyRequest::mutation_for_tenant(
        positron_api::api_keys::KeyAction::Rotate,
        principal.clone(),
        tenant.to_canonical_text(),
        2,
        "88888888-8888-8888-8888-88888888888c".to_owned(),
    )?;
    let mut rotated = client
        .manage(claim.secret(), &rotation)
        .map_err(|failure| format!("target rotate: {failure:?}"))?;
    let successor = rotated.principal.clone().ok_or("rotated principal")?;
    let successor_secret = rotated.secret.take().ok_or("rotated secret")?;
    let rotation_replay = client
        .manage(claim.secret(), &rotation)
        .map_err(|failure| format!("target rotation replay: {failure:?}"))?;
    assert_eq!(
        rotation_replay.principal.as_deref(),
        Some(successor.as_str())
    );
    assert!(rotation_replay.secret.is_none());
    client
        .manage(
            claim.secret(),
            &positron_api::api_keys::ApiKeyRequest::mutation_for_tenant(
                positron_api::api_keys::KeyAction::Revoke,
                principal.clone(),
                tenant.to_canonical_text(),
                3,
                "88888888-8888-8888-8888-88888888888d".to_owned(),
            )?,
        )
        .map_err(|failure| format!("target revoke: {failure:?}"))?;
    let after_revoke = client
        .manage(
            claim.secret(),
            &positron_api::api_keys::ApiKeyRequest::list_for_tenant(tenant.to_canonical_text()),
        )
        .map_err(|failure| format!("target list after revoke: {failure:?}"))?;
    assert_eq!(after_revoke.keys.len(), 2);
    assert!(
        after_revoke
            .keys
            .iter()
            .any(|key| { key.principal == principal && !key.active && key.generation == 4 })
    );
    assert!(
        after_revoke
            .keys
            .iter()
            .any(|key| { key.principal == successor && key.active && key.generation == 4 })
    );
    assert_status(
        http(
            address(
                &process.bound_endpoints(),
                positron_runtime::ListenerRole::OtlpHttp,
            )?,
            "POST",
            "/v1/logs",
            &[
                ("Authorization", &format!("Bearer {secret}")),
                ("Content-Type", "application/x-protobuf"),
            ],
            &otlp_body("tenant-key-revoked"),
        )?,
        401,
    );
    assert_status(
        http(
            address(
                &process.bound_endpoints(),
                positron_runtime::ListenerRole::OtlpHttp,
            )?,
            "POST",
            "/v1/logs",
            &[
                ("Authorization", &format!("Bearer {successor_secret}")),
                ("Content-Type", "application/x-protobuf"),
            ],
            &otlp_body("tenant-key-client"),
        )?,
        200,
    );
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    Ok(())
}

#[test]
fn tenant_quota_client_updates_a_bound_tenant_with_replay_and_redacted_stale_details()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_test_guard();
    let roots = TestRoots::new("tenant-quota-client")?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        positron_runtime::InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let initialized = InstanceBootstrap::reopen(&paths)?;
    let system = initialized.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let tenant = initialized
        .create_tenant_generated(
            system,
            positron_governance::TenantCreateConfiguration::new(
                TenantSlug::parse_canonical("client-quota-tenant")?,
                "Client quota tenant",
                2_592_000,
                1,
                [
                    32_000_000, 32, 32, 5_000_000, 2_048, 32, 32, 32, 32, 32, 2_000_000,
                ],
            ),
            AdministrativeIdempotencyKey::new([0x99; 16])?,
        )?
        .tenant_id();
    let administrator = initialized.create_api_key_for_tenant(
        system,
        tenant,
        positron_domain::identity::Scope::TenantAdministration,
        None,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0x9a; 16])?,
    )?;
    let administrator_secret = administrator
        .secret()
        .ok_or("tenant administration secret")?
        .to_owned();
    drop(initialized);

    let host = NativeHost::new(bindings(&roots, "tenant-quota-client")?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    let api = address(
        &process.bound_endpoints(),
        positron_runtime::ListenerRole::Api,
    )?;
    let client = positron_api::tenant_quotas::TenantQuotaServiceClient::new(
        positron_api::tenant_quotas::TenantQuotaTransport::PlaintextOptOut { endpoint: api },
    )?;
    let resources = positron_api::tenant_quotas::TenantQuotaResources {
        memory_bytes: 3,
        queue_slots: 3,
        task_slots: 3,
        buffer_cache_bytes: 3,
        batch_items: 3,
        lease_slots: 3,
        retry_slots: 3,
        io_permits: 3,
        cpu_work_units: 3,
        file_descriptors: 3,
        disk_headroom_bytes: 3,
    };
    let request = positron_api::tenant_quotas::TenantQuotaUpdateRequest::new(
        tenant.to_canonical_text(),
        1,
        "98989898-9898-9898-9898-98989898989a".to_owned(),
        1,
        resources,
    );
    let created = client
        .update(&administrator_secret, &request)
        .map_err(|failure| format!("quota update: {failure:?}"))?;
    assert_eq!(created.resource_generation, 2);
    assert_eq!(
        client
            .update(&administrator_secret, &request)
            .map_err(|failure| format!("quota replay: {failure:?}"))?
            .resource_generation,
        2
    );
    assert!(matches!(
        client.update(
            &administrator_secret,
            &positron_api::tenant_quotas::TenantQuotaUpdateRequest::new(
                tenant.to_canonical_text(),
                1,
                "98989898-9898-9898-9898-98989898989a".to_owned(),
                1,
                positron_api::tenant_quotas::TenantQuotaResources {
                    memory_bytes: 4,
                    ..resources
                },
            ),
        ),
        Err(positron_api::tenant_quotas::TenantQuotaServiceClientFailure::IdempotencyConflict)
    ));
    assert!(matches!(
        client.update(
            &administrator_secret,
            &positron_api::tenant_quotas::TenantQuotaUpdateRequest::new(
                tenant.to_canonical_text(),
                1,
                "98989898-9898-9898-9898-98989898989b".to_owned(),
                1,
                positron_api::tenant_quotas::TenantQuotaResources {
                    memory_bytes: 4,
                    ..resources
                },
            ),
        ),
        Err(positron_api::tenant_quotas::TenantQuotaServiceClientFailure::StaleGeneration {
            resource_generation: 2,
            ref semantic_diff,
        }) if semantic_diff == "memory_bytes"
    ));
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    Ok(())
}

#[test]
fn tenant_lifecycle_client_transitions_replays_and_redacts_conflicts()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_test_guard();
    let roots = TestRoots::new("tenant-lifecycle-client")?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        positron_runtime::InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let initialized = InstanceBootstrap::reopen(&paths)?;
    let tenant = initialized.default_tenant_id().to_canonical_text();
    drop(initialized);

    let host = NativeHost::new(bindings(&roots, "tenant-lifecycle-client")?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    let api = address(
        &process.bound_endpoints(),
        positron_runtime::ListenerRole::Api,
    )?;
    assert_status(
        http(
            api,
            "POST",
            positron_api::tenant_lifecycle::HTTP_PATH,
            &[("Content-Type", "application/json")],
            br#"{"unknown":"unauthorized bodies stay unread"}"#,
        )?,
        401,
    );
    let client = positron_api::tenant_lifecycle::TenantLifecycleServiceClient::new(
        positron_api::tenant_lifecycle::TenantLifecycleTransport::PlaintextOptOut { endpoint: api },
    )?;
    let read_only = positron_api::tenant_lifecycle::TenantLifecycleTransitionRequest::new(
        tenant.clone(),
        positron_api::tenant_lifecycle::TenantLifecycleState::ReadOnly,
        1,
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa".to_owned(),
    );
    let first = client.transition(claim.secret(), &read_only)?;
    assert_eq!(
        first.to,
        positron_api::tenant_lifecycle::TenantLifecycleState::ReadOnly
    );
    assert_eq!(first.lifecycle_generation, 2);

    let reopened = positron_api::tenant_lifecycle::TenantLifecycleTransitionRequest::new(
        tenant.clone(),
        positron_api::tenant_lifecycle::TenantLifecycleState::Active,
        2,
        "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb".to_owned(),
    );
    let second = client.transition(claim.secret(), &reopened)?;
    assert_eq!(second.lifecycle_generation, 3);
    assert_eq!(
        client.transition(claim.secret(), &read_only)?,
        first,
        "an exact retry resolves the committed result after a later successor"
    );
    let changed_same_key = positron_api::tenant_lifecycle::TenantLifecycleTransitionRequest::new(
        tenant.clone(),
        positron_api::tenant_lifecycle::TenantLifecycleState::Active,
        2,
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa".to_owned(),
    );
    assert_eq!(
        client.transition(claim.secret(), &changed_same_key),
        Err(
            positron_api::tenant_lifecycle::TenantLifecycleServiceClientFailure::IdempotencyConflict
        )
    );

    let stale_same = positron_api::tenant_lifecycle::TenantLifecycleTransitionRequest::new(
        tenant.clone(),
        positron_api::tenant_lifecycle::TenantLifecycleState::Active,
        2,
        "cccccccc-cccc-cccc-cccc-cccccccccccc".to_owned(),
    );
    assert_eq!(
        client.transition(claim.secret(), &stale_same),
        Err(
            positron_api::tenant_lifecycle::TenantLifecycleServiceClientFailure::StaleGeneration {
                lifecycle_generation: 3,
                semantic_diff: "lifecycle generation changed".to_owned(),
            }
        )
    );
    let stale_different = positron_api::tenant_lifecycle::TenantLifecycleTransitionRequest::new(
        tenant.clone(),
        positron_api::tenant_lifecycle::TenantLifecycleState::Suspended,
        2,
        "dddddddd-dddd-dddd-dddd-dddddddddddd".to_owned(),
    );
    assert_eq!(
        client.transition(claim.secret(), &stale_different),
        Err(
            positron_api::tenant_lifecycle::TenantLifecycleServiceClientFailure::StaleGeneration {
                lifecycle_generation: 3,
                semantic_diff: "lifecycle state changed".to_owned(),
            }
        )
    );
    let invalid = positron_api::tenant_lifecycle::TenantLifecycleTransitionRequest::new(
        tenant.clone(),
        positron_api::tenant_lifecycle::TenantLifecycleState::Active,
        3,
        "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee".to_owned(),
    );
    assert_eq!(
        client.transition(claim.secret(), &invalid),
        Err(positron_api::tenant_lifecycle::TenantLifecycleServiceClientFailure::InvalidTransition)
    );
    let purged = positron_api::tenant_lifecycle::TenantLifecycleTransitionRequest::new(
        tenant.clone(),
        positron_api::tenant_lifecycle::TenantLifecycleState::Purged,
        3,
        "ffffffff-ffff-ffff-ffff-ffffffffffff".to_owned(),
    );
    assert_eq!(
        client.transition(claim.secret(), &purged),
        Err(
            positron_api::tenant_lifecycle::TenantLifecycleServiceClientFailure::PurgeCompletionUnavailable
        )
    );
    let unknown = positron_api::tenant_lifecycle::TenantLifecycleTransitionRequest::new(
        "11111111-1111-1111-1111-111111111111".to_owned(),
        positron_api::tenant_lifecycle::TenantLifecycleState::ReadOnly,
        1,
        "12121212-1212-1212-1212-121212121212".to_owned(),
    );
    assert_eq!(
        client.transition(claim.secret(), &unknown),
        Err(positron_api::tenant_lifecycle::TenantLifecycleServiceClientFailure::TenantUnavailable)
    );
    let stale_raw = http(
        api,
        "POST",
        positron_api::tenant_lifecycle::HTTP_PATH,
        &[
            ("Authorization", &format!("Bearer {}", claim.secret())),
            ("Content-Type", "application/json"),
        ],
        &stale_same.encode()?,
    )?;
    assert_status(stale_raw.clone(), 409);
    assert!(stale_raw.contains("lifecycle generation changed"));
    assert!(!stale_raw.contains(&tenant));
    assert!(!stale_raw.contains("aaaaaaaa"));
    assert_status(
        http(
            api,
            "POST",
            positron_api::tenant_aliases::HTTP_PATH,
            &[("Content-Type", "application/json")],
            br#"{"tenant":"never-decoded","external_alias":"secret-alias","expected_generation":0,"idempotency_key":"never-decoded"}"#,
        )?,
        401,
    );
    let alias_request = format!(
        "{{\"tenant\":\"{tenant}\",\"external_alias\":\"loki.native-alias\",\"expected_generation\":1,\"idempotency_key\":\"99999999-9999-9999-9999-999999999999\"}}"
    );
    let alias_raw = http(
        api,
        "POST",
        positron_api::tenant_aliases::HTTP_PATH,
        &[
            ("Authorization", &format!("Bearer {}", claim.secret())),
            ("Content-Type", "application/json"),
        ],
        alias_request.as_bytes(),
    )?;
    assert_status(alias_raw.clone(), 200);
    assert!(alias_raw.contains("\"alias_generation\":2"));
    assert!(!alias_raw.contains("loki.native-alias"));
    assert!(!alias_raw.contains(claim.secret()));
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    Ok(())
}

#[test]
fn system_administrator_manages_explicit_tenants_over_the_public_http_routes()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_test_guard();
    let roots = TestRoots::new("tenant-svc")?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        positron_runtime::InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let initialized = InstanceBootstrap::reopen(&paths)?;
    drop(initialized);
    let host = NativeHost::new(bindings(&roots, "tenant-svc")?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    let api = address(
        &process.bound_endpoints(),
        positron_runtime::ListenerRole::Api,
    )?;
    let authorization = format!("Bearer {}", claim.secret());
    let creation = r#"{"slug":"public-tenant","display_name":"Public tenant","retention_seconds":2592000,"weight":1,"memory_bytes":32000000,"queue_slots":32,"task_slots":32,"buffer_cache_bytes":5000000,"batch_items":2048,"lease_slots":32,"retry_slots":32,"io_permits":32,"cpu_work_units":32,"file_descriptors":32,"disk_headroom_bytes":2000000,"idempotency_key":"abababab-abab-abab-abab-abababababab"}"#;
    let created = http(
        api,
        "POST",
        positron_api::tenant_service::CREATE_HTTP_PATH,
        &[
            ("Authorization", &authorization),
            ("Content-Type", "application/json"),
        ],
        creation.as_bytes(),
    )?;
    assert_status(created.clone(), 200);
    assert!(created.contains("\"resource_generation\":2"), "{created}");
    let created_body = created
        .split_once("\r\n\r\n")
        .ok_or("tenant create response body")?
        .1;
    let tenant =
        positron_api::tenant_service::TenantCreateResponse::decode(created_body.as_bytes())?.tenant;
    let replay = http(
        api,
        "POST",
        positron_api::tenant_service::CREATE_HTTP_PATH,
        &[
            ("Authorization", &authorization),
            ("Content-Type", "application/json"),
        ],
        creation.as_bytes(),
    )?;
    assert_status(replay.clone(), 200);
    let replay_body = replay
        .split_once("\r\n\r\n")
        .ok_or("tenant create replay response body")?
        .1;
    assert_eq!(
        positron_api::tenant_service::TenantCreateResponse::decode(replay_body.as_bytes())?.tenant,
        tenant
    );
    let inspection = http(
        api,
        "POST",
        positron_api::tenant_service::INSPECT_HTTP_PATH,
        &[
            ("Authorization", &authorization),
            ("Content-Type", "application/json"),
        ],
        format!(r#"{{"tenant":"{tenant}"}}"#).as_bytes(),
    )?;
    assert_status(inspection.clone(), 200);
    assert!(inspection.contains("\"slug\":\"public-tenant\""));
    assert!(!inspection.contains("secret"));
    let listed = http(
        api,
        "POST",
        positron_api::tenant_service::LIST_HTTP_PATH,
        &[
            ("Authorization", &authorization),
            ("Content-Type", "application/json"),
        ],
        br#"{}"#,
    )?;
    assert_status(listed.clone(), 200);
    assert!(listed.contains(&tenant));
    let renamed = http(
        api,
        "POST",
        positron_api::tenant_service::UPDATE_DISPLAY_NAME_HTTP_PATH,
        &[("Authorization", &authorization), ("Content-Type", "application/json")],
        format!(r#"{{"tenant":"{tenant}","expected_display_generation":1,"display_name":"Renamed public tenant","idempotency_key":"acacacac-acac-acac-acac-acacacacacac"}}"#).as_bytes(),
    )?;
    assert_status(renamed.clone(), 200);
    assert!(renamed.contains("\"display_generation\":2"));
    let stale = http(
        api,
        "POST",
        positron_api::tenant_service::UPDATE_DISPLAY_NAME_HTTP_PATH,
        &[("Authorization", &authorization), ("Content-Type", "application/json")],
        format!(r#"{{"tenant":"{tenant}","expected_display_generation":1,"display_name":"Another label","idempotency_key":"adadadad-adad-adad-adad-adadadadadad"}}"#).as_bytes(),
    )?;
    assert_status(stale.clone(), 409);
    assert!(stale.contains("\"display_generation\":2"));
    assert!(stale.contains("\"semantic_diff\":\"display_name\""));
    let malformed = http(
        api,
        "POST",
        positron_api::tenant_service::CREATE_HTTP_PATH,
        &[
            ("Authorization", "Bearer invalid"),
            ("Content-Type", "application/json"),
        ],
        br#"{"malformed":true}"#,
    )?;
    assert_status(malformed, 401);
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    Ok(())
}
