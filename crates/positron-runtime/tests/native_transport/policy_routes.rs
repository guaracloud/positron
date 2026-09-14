use super::*;

#[test]
fn tenant_policy_preview_is_authorized_before_decode_and_never_activates()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_test_guard();
    let roots = TestRoots::new("tenant-policy-preview")?;
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
                TenantSlug::parse_canonical("client-policy-tenant")?,
                "Client policy tenant",
                2_592_000,
                1,
                [
                    32_000_000, 32, 32, 5_000_000, 2_048, 32, 32, 32, 32, 32, 2_000_000,
                ],
            ),
            AdministrativeIdempotencyKey::new([0x9c; 16])?,
        )?
        .tenant_id();
    let administrator = initialized.create_api_key_for_tenant(
        system,
        tenant,
        positron_domain::identity::Scope::TenantAdministration,
        None,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0x9d; 16])?,
    )?;
    let administrator_secret = administrator
        .secret()
        .ok_or("tenant administration secret")?
        .to_owned();
    drop(initialized);

    let host = NativeHost::new(bindings(&roots, "tenant-policy-preview")?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths.clone(), InitializationMode::ExistingOnly),
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
            positron_api::policy::HTTP_VALIDATE_PATH,
            &[("Content-Type", "application/json")],
            br#"{"unknown":"the policy body must remain unread"}"#,
        )?,
        401,
    );
    let client = positron_api::policy::PolicyPreviewServiceClient::new(
        positron_api::policy::PolicyPreviewTransport::PlaintextOptOut { endpoint: api },
    )?;
    let request = positron_api::policy::PolicyPreviewRequest::new(
        r#"{"generation":17,"rules":[]}"#.to_owned(),
    );
    assert_eq!(
        client.validate(claim.secret(), &request),
        Err(positron_api::policy::PolicyPreviewServiceClientFailure::AuthenticationRejected)
    );
    let preview = client.validate(&administrator_secret, &request)?;
    assert_eq!(preview.policy_generation, 17);
    assert_eq!(preview.rule_count, 0);
    assert_eq!(
        client.validate(&administrator_secret, &request)?,
        preview,
        "non-mutating validation must not activate the prospective candidate"
    );
    let policy_test_body = br#"{"policy_json":"{\"generation\":18,\"rules\":[{\"id\":\"reject-secret\",\"predicates\":[{\"body_exact_text\":\"secret-canary\"}],\"action\":\"reject\"}]}","candidate_json":"{\"receiver\":\"otlp_http_json\",\"signal\":\"logs\",\"body\":\"secret-canary\",\"attributes\":[]}"}"#;
    assert_status(
        http(
            api,
            "POST",
            positron_api::policy::HTTP_TEST_PATH,
            &[
                ("Authorization", &format!("Bearer {}", claim.secret())),
                ("Content-Type", "application/json"),
            ],
            br#"{"unknown":"candidate body must remain unread"}"#,
        )?,
        401,
    );
    let test_client = positron_api::policy::PolicyTestServiceClient::new(
        positron_api::policy::PolicyPreviewTransport::PlaintextOptOut { endpoint: api },
    )?;
    assert_eq!(
        test_client.test(
            claim.secret(),
            &positron_api::policy::PolicyTestRequest::new(
                "{\"generation\":18,\"rules\":[]}".to_owned(),
                "{\"receiver\":\"otlp_http_json\",\"signal\":\"logs\",\"attributes\":[]}"
                    .to_owned(),
            ),
        ),
        Err(positron_api::policy::PolicyTestServiceClientFailure::AuthenticationRejected)
    );
    let raw = http(
        api,
        "POST",
        positron_api::policy::HTTP_TEST_PATH,
        &[
            ("Authorization", &format!("Bearer {administrator_secret}")),
            ("Content-Type", "application/json"),
        ],
        policy_test_body,
    )?;
    assert_status(raw.clone(), 200);
    assert!(raw.contains("\"accepted\":false"));
    assert!(raw.contains("\"applied_rule_count\":1"));
    assert!(!raw.contains("secret-canary"));
    assert!(!raw.contains("reject-secret"));
    let policy_diff_body = br#"{"before_policy_json":"{\"generation\":18,\"rules\":[{\"id\":\"before-secret\",\"predicates\":[{\"body_exact_text\":\"before-canary\"}],\"action\":\"reject\"}]}","after_policy_json":"{\"generation\":19,\"rules\":[{\"id\":\"after-secret\",\"predicates\":[{\"body_exact_text\":\"after-canary\"}],\"action\":\"reject\"}]}"}"#;
    assert_status(
        http(
            api,
            "POST",
            positron_api::policy::HTTP_DIFF_PATH,
            &[("Content-Type", "application/json")],
            br#"{"unknown":"policy bodies must remain unread before authorization"}"#,
        )?,
        401,
    );
    let diff_client = positron_api::policy::PolicyDiffServiceClient::new(
        positron_api::policy::PolicyPreviewTransport::PlaintextOptOut { endpoint: api },
    )?;
    assert_eq!(
        diff_client.diff(
            claim.secret(),
            &positron_api::policy::PolicyDiffRequest::new(
                "{\"generation\":18,\"rules\":[]}".to_owned(),
                "{\"generation\":19,\"rules\":[]}".to_owned(),
            ),
        ),
        Err(positron_api::policy::PolicyDiffServiceClientFailure::AuthenticationRejected)
    );
    let raw = http(
        api,
        "POST",
        positron_api::policy::HTTP_DIFF_PATH,
        &[
            ("Authorization", &format!("Bearer {administrator_secret}")),
            ("Content-Type", "application/json"),
        ],
        policy_diff_body,
    )?;
    assert_status(raw.clone(), 200);
    assert!(raw.contains("\"generation_changed\""));
    assert!(raw.contains("\"rule_added\""));
    assert!(raw.contains("\"rule_removed\""));
    assert!(!raw.contains("before-secret"));
    assert!(!raw.contains("after-secret"));
    assert!(!raw.contains("before-canary"));
    assert!(!raw.contains("after-canary"));
    assert_eq!(
        http(
            api,
            "POST",
            positron_api::policy::HTTP_DIFF_PATH,
            &[
                ("Authorization", &format!("Bearer {administrator_secret}")),
                ("Content-Type", "application/json"),
            ],
            policy_diff_body,
        )?,
        raw,
        "policy diff is prospective and non-mutating"
    );
    assert_status(
        http(
            api,
            "POST",
            positron_api::policy::HTTP_EXPLAIN_PATH,
            &[("Content-Type", "application/json")],
            br#"{"unknown":"candidate stays unread before authentication"}"#,
        )?,
        401,
    );
    let raw = http(
        api,
        "POST",
        positron_api::policy::HTTP_EXPLAIN_PATH,
        &[
            ("Authorization", &format!("Bearer {administrator_secret}")),
            ("Content-Type", "application/json"),
        ],
        policy_test_body,
    )?;
    assert_status(raw.clone(), 200);
    assert!(raw.contains("\"outcome\":\"rejected\""));
    assert!(raw.contains("matched rule action=reject"));
    assert!(!raw.contains("reject-secret"));
    assert!(!raw.contains("secret-canary"));
    let activate_first = br#"{"policy_json":"{\"generation\":2,\"rules\":[{\"id\":\"reject-first\",\"predicates\":[{\"receiver\":\"otlp_http_json\"}],\"action\":\"reject\"}]}","expected_generation":1,"idempotency_key":"01010101-0101-0101-0101-010101010101"}"#;
    assert_status(
        http(
            api,
            "POST",
            positron_api::policy::HTTP_ACTIVATE_PATH,
            &[("Content-Type", "application/json")],
            br#"{"unknown":"candidate remains unread before authentication"}"#,
        )?,
        401,
    );
    let activate_client = positron_api::policy::PolicyActivateServiceClient::new(
        positron_api::policy::PolicyPreviewTransport::PlaintextOptOut { endpoint: api },
    )?;
    assert_eq!(
        activate_client.activate(
            claim.secret(),
            &positron_api::policy::PolicyActivateRequest::new(
                "{\"generation\":2,\"rules\":[]}".to_owned(),
                1,
                "01010101-0101-0101-0101-010101010101".to_owned(),
            ),
        ),
        Err(positron_api::policy::PolicyActivateServiceClientFailure::AuthenticationRejected)
    );
    let activated = http(
        api,
        "POST",
        positron_api::policy::HTTP_ACTIVATE_PATH,
        &[
            ("Authorization", &format!("Bearer {administrator_secret}")),
            ("Content-Type", "application/json"),
        ],
        activate_first,
    )?;
    assert_status(activated.clone(), 200);
    assert!(activated.contains("\"resource_generation\":2"));
    assert!(activated.contains("\"audit_position\":"));
    assert!(!activated.contains("reject-first"));
    let stale = http(
        api,
        "POST",
        positron_api::policy::HTTP_ACTIVATE_PATH,
        &[
            ("Authorization", &format!("Bearer {administrator_secret}")),
            ("Content-Type", "application/json"),
        ],
        br#"{"policy_json":"{\"generation\":2,\"rules\":[]}","expected_generation":1,"idempotency_key":"02020202-0202-0202-0202-020202020202"}"#,
    )?;
    assert_status(stale.clone(), 409);
    assert!(stale.contains("\"resource_generation\":2"));
    assert!(stale.contains("\"semantic_diff\":\"policy generation changed\""));
    let changed_replay = http(
        api,
        "POST",
        positron_api::policy::HTTP_ACTIVATE_PATH,
        &[
            ("Authorization", &format!("Bearer {administrator_secret}")),
            ("Content-Type", "application/json"),
        ],
        br#"{"policy_json":"{\"generation\":2,\"rules\":[]}","expected_generation":1,"idempotency_key":"01010101-0101-0101-0101-010101010101"}"#,
    )?;
    assert_status(changed_replay, 409);
    let activate_second = br#"{"policy_json":"{\"generation\":3,\"rules\":[]}","expected_generation":2,"idempotency_key":"03030303-0303-0303-0303-030303030303"}"#;
    assert_status(
        http(
            api,
            "POST",
            positron_api::policy::HTTP_ACTIVATE_PATH,
            &[
                ("Authorization", &format!("Bearer {administrator_secret}")),
                ("Content-Type", "application/json"),
            ],
            activate_second,
        )?,
        200,
    );
    assert_eq!(
        http(
            api,
            "POST",
            positron_api::policy::HTTP_ACTIVATE_PATH,
            &[
                ("Authorization", &format!("Bearer {administrator_secret}")),
                ("Content-Type", "application/json"),
            ],
            activate_first,
        )?,
        activated,
        "an exact activation retry resolves its durable original receipt after a later update"
    );
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    let reopened_host = NativeHost::new(bindings(&roots, "tenant-policy-preview-reopened")?);
    let reopened = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
        HostInputs::new(&reopened_host, &reopened_host),
    )?;
    let reopened_api = address(
        &reopened.bound_endpoints(),
        positron_runtime::ListenerRole::Api,
    )?;
    assert_eq!(
        http(
            reopened_api,
            "POST",
            positron_api::policy::HTTP_ACTIVATE_PATH,
            &[
                ("Authorization", &format!("Bearer {administrator_secret}")),
                ("Content-Type", "application/json"),
            ],
            activate_first,
        )?,
        activated,
        "an exact activation retry survives reopen after a later update"
    );
    assert_eq!(
        reopened.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    Ok(())
}

#[test]
fn configured_tls_api_listener_serves_policy_test_through_the_generated_client()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_test_guard();
    let roots = TestRoots::new("tls-policy-test")?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        positron_runtime::InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let certificate = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/native_transport/fixtures/api-test-cert.pem"
    ));
    let private_key = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/native_transport/fixtures/api-test-key.pem"
    ));
    let host = NativeHost::new(
        bindings(&roots, "tls-policy-test")?
            .with_api_transport(ApiTransportProfile::tls(certificate.clone(), private_key)?)?,
    );
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    let api = address(
        &process.bound_endpoints(),
        positron_runtime::ListenerRole::Api,
    )?;
    let client = positron_api::policy::PolicyTestServiceClient::new(
        positron_api::policy::PolicyPreviewTransport::Tls {
            endpoint: api,
            server_name: "localhost".to_owned(),
            trust_file: certificate,
        },
    )?;
    assert_eq!(
        client.test(
            claim.secret(),
            &positron_api::policy::PolicyTestRequest::new(
                "{\"generation\":23,\"rules\":[]}".to_owned(),
                "{\"receiver\":\"otlp_http_json\",\"signal\":\"logs\",\"attributes\":[]}"
                    .to_owned(),
            ),
        ),
        Err(positron_api::policy::PolicyTestServiceClientFailure::AuthenticationRejected),
        "the secure Test transport must reach tenant authorization without decoding a system credential as tenant authority"
    );
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    Ok(())
}

#[test]
fn configured_tls_api_listener_reaches_alias_explain_and_activate_before_decoding()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_test_guard();
    let roots = TestRoots::new("tls-api-route-parity")?;
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
                TenantSlug::parse_canonical("tls-route-tenant")?,
                "TLS route tenant",
                2_592_000,
                1,
                [
                    32_000_000, 32, 32, 5_000_000, 2_048, 32, 32, 32, 32, 32, 2_000_000,
                ],
            ),
            AdministrativeIdempotencyKey::new([0xE2; 16])?,
        )?
        .tenant_id();
    let tenant_administrator = initialized.create_api_key_for_tenant(
        system,
        tenant,
        positron_domain::identity::Scope::TenantAdministration,
        None,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xE3; 16])?,
    )?;
    let tenant_administrator_secret = tenant_administrator
        .secret()
        .ok_or("tenant administration secret")?
        .to_owned();
    drop(initialized);

    let certificate = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/native_transport/fixtures/api-test-cert.pem"
    ));
    let private_key = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/native_transport/fixtures/api-test-key.pem"
    ));
    let host = NativeHost::new(
        bindings(&roots, "tls-api-route-parity")?
            .with_api_transport(ApiTransportProfile::tls(certificate.clone(), private_key)?)?,
    );
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    let api = address(
        &process.bound_endpoints(),
        positron_runtime::ListenerRole::Api,
    )?;

    for path in [
        positron_api::tenant_aliases::HTTP_PATH,
        positron_api::policy::HTTP_EXPLAIN_PATH,
        positron_api::policy::HTTP_ACTIVATE_PATH,
    ] {
        assert_status(
            tls_http(
                api,
                &certificate,
                "POST",
                path,
                &[
                    ("Authorization", "Bearer invalid"),
                    ("Content-Type", "application/json"),
                ],
                br#"{"malformed":"body must remain unread"}"#,
            )?,
            401,
        );
    }

    let system_authorization = format!("Bearer {}", claim.secret());
    let alias = tls_http(
        api,
        &certificate,
        "POST",
        positron_api::tenant_aliases::HTTP_PATH,
        &[
            ("Authorization", &system_authorization),
            ("Content-Type", "application/json"),
        ],
        format!(
            r#"{{"tenant":"{}","external_alias":"tls-route-alias","expected_generation":1,"idempotency_key":"e4e4e4e4-e4e4-e4e4-e4e4-e4e4e4e4e4e4"}}"#,
            tenant.to_canonical_text()
        )
        .as_bytes(),
    )?;
    assert_status(alias.clone(), 200);
    assert!(alias.contains("\"alias_generation\":2"));
    assert!(!alias.contains("tls-route-alias"));

    let tenant_authorization = format!("Bearer {tenant_administrator_secret}");
    let explanation = tls_http(
        api,
        &certificate,
        "POST",
        positron_api::policy::HTTP_EXPLAIN_PATH,
        &[
            ("Authorization", &tenant_authorization),
            ("Content-Type", "application/json"),
        ],
        br#"{"policy_json":"{\"generation\":2,\"rules\":[]}","candidate_json":"{\"receiver\":\"otlp_http_json\",\"signal\":\"logs\",\"attributes\":[]}"}"#,
    )?;
    assert_status(explanation.clone(), 200);
    assert!(explanation.contains("\"outcome\":\"accepted\""));

    let activation = tls_http(
        api,
        &certificate,
        "POST",
        positron_api::policy::HTTP_ACTIVATE_PATH,
        &[
            ("Authorization", &tenant_authorization),
            ("Content-Type", "application/json"),
        ],
        br#"{"policy_json":"{\"generation\":2,\"rules\":[]}","expected_generation":1,"idempotency_key":"e5e5e5e5-e5e5-e5e5-e5e5-e5e5e5e5e5e5"}"#,
    )?;
    assert_status(activation.clone(), 200);
    assert!(activation.contains("\"resource_generation\":2"));
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    Ok(())
}

#[test]
fn configured_tls_api_listener_serves_tenant_retention_preview_and_confirmed_update()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_test_guard();
    let roots = TestRoots::new("tls-tenant-retention")?;
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
    let other_tenant = initialized.default_tenant_id();
    let tenant = initialized
        .create_tenant_generated(
            system,
            positron_governance::TenantCreateConfiguration::new(
                TenantSlug::parse_canonical("tls-retention-tenant")?,
                "TLS retention tenant",
                2_592_000,
                1,
                [
                    32_000_000, 32, 32, 5_000_000, 2_048, 32, 32, 32, 32, 32, 2_000_000,
                ],
            ),
            AdministrativeIdempotencyKey::new([0xe8; 16])?,
        )?
        .tenant_id();
    let administrator = initialized.create_api_key_for_tenant(
        system,
        tenant,
        positron_domain::identity::Scope::TenantAdministration,
        None,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xe9; 16])?,
    )?;
    let administrator_secret = administrator
        .secret()
        .ok_or("tenant administration secret")?
        .to_owned();
    initialized.transition_tenant_lifecycle(
        system,
        tenant,
        TenantLifecycleState::ReadOnly,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xed; 16])?,
    )?;
    drop(initialized);

    let certificate = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/native_transport/fixtures/api-test-cert.pem"
    ));
    let private_key = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/native_transport/fixtures/api-test-key.pem"
    ));
    let host = NativeHost::new(
        bindings(&roots, "tls-tenant-retention")?.with_api_transport(ApiTransportProfile::tls(
            certificate.clone(),
            private_key.clone(),
        )?)?,
    );
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths.clone(), InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    let api = address(
        &process.bound_endpoints(),
        positron_runtime::ListenerRole::Api,
    )?;
    for path in [
        positron_api::tenant_retention::PREVIEW_HTTP_PATH,
        positron_api::tenant_retention::UPDATE_HTTP_PATH,
    ] {
        assert_status(
            tls_http(
                api,
                &certificate,
                "POST",
                path,
                &[
                    ("Authorization", "Bearer invalid"),
                    ("Content-Type", "application/json"),
                ],
                br#"{"malformed":"body must remain unread"}"#,
            )?,
            401,
        );
    }

    let preview_body = format!(
        r#"{{"tenant":"{}","proposed_retention_seconds":86400}}"#,
        tenant.to_canonical_text()
    );
    assert_status(
        tls_http(
            api,
            &certificate,
            "POST",
            positron_api::tenant_retention::PREVIEW_HTTP_PATH,
            &[
                ("Authorization", &format!("Bearer {}", claim.secret())),
                ("Content-Type", "application/json"),
            ],
            preview_body.as_bytes(),
        )?,
        401,
    );
    assert_status(
        tls_http(
            api,
            &certificate,
            "POST",
            positron_api::tenant_retention::PREVIEW_HTTP_PATH,
            &[
                ("Authorization", &format!("Bearer {administrator_secret}")),
                ("Content-Type", "application/json"),
            ],
            format!(
                r#"{{"tenant":"{}","proposed_retention_seconds":86400}}"#,
                other_tenant.to_canonical_text()
            )
            .as_bytes(),
        )?,
        401,
    );
    let client = positron_api::tenant_retention::TenantRetentionServiceClient::new(
        positron_api::tenant_retention::TenantRetentionTransport::Tls {
            endpoint: api,
            server_name: "localhost".to_owned(),
            trust_file: certificate.clone(),
        },
    )?;
    let preview = client.preview(
        &administrator_secret,
        &positron_api::tenant_retention::TenantRetentionPreviewRequest::new(
            tenant.to_canonical_text(),
            86_400,
        ),
    )?;
    assert_eq!(preview.tenant, tenant.to_canonical_text());
    let digest = preview.confirmation_digest;
    let evaluation = preview.confirmation_evaluated_at_unix_nanos;
    let reduction = positron_api::tenant_retention::TenantRetentionUpdateRequest::new(
        tenant.to_canonical_text(),
        86_400,
        preview.retention_generation,
        Some(digest.clone()),
        "ebebebeb-ebeb-ebeb-ebeb-ebebebebebeb".to_owned(),
    )
    .with_confirmation_evaluated_at_unix_nanos(evaluation);
    let updated = client.update(&administrator_secret, &reduction)?;
    assert_eq!(updated.retention_generation, 2);
    assert_eq!(client.update(&administrator_secret, &reduction)?, updated);
    let stale_confirmation = tls_http(
        api,
        &certificate,
        "POST",
        positron_api::tenant_retention::UPDATE_HTTP_PATH,
        &[
            ("Authorization", &format!("Bearer {administrator_secret}")),
            ("Content-Type", "application/json"),
        ],
        format!(
            r#"{{"tenant":"{}","proposed_retention_seconds":86400,"expected_generation":1,"confirmation_digest":"{digest}","confirmation_evaluated_at_unix_nanos":{evaluation},"idempotency_key":"ecececec-ecec-ecec-ecec-ecececececec"}}"#,
            tenant.to_canonical_text()
        )
        .as_bytes(),
    )?;
    assert_status(stale_confirmation.clone(), 409);
    assert!(stale_confirmation.contains("\"code\":\"invalid_confirmation\""));
    let stale_generation = tls_http(
        api,
        &certificate,
        "POST",
        positron_api::tenant_retention::UPDATE_HTTP_PATH,
        &[
            ("Authorization", &format!("Bearer {administrator_secret}")),
            ("Content-Type", "application/json"),
        ],
        format!(
            r#"{{"tenant":"{}","proposed_retention_seconds":2700000,"expected_generation":1,"idempotency_key":"f0f0f0f0-f0f0-f0f0-f0f0-f0f0f0f0f0f0"}}"#,
            tenant.to_canonical_text()
        )
        .as_bytes(),
    )?;
    assert_status(stale_generation.clone(), 409);
    assert!(stale_generation.contains("\"code\":\"stale_generation\""));
    assert!(stale_generation.contains("\"retention_generation\":2"));
    assert!(stale_generation.contains("\"semantic_diff\":\"retention_seconds\""));
    let expansion_preview = client.preview(
        &administrator_secret,
        &positron_api::tenant_retention::TenantRetentionPreviewRequest::new(
            tenant.to_canonical_text(),
            2_700_000,
        ),
    )?;
    assert_eq!(expansion_preview.retention_generation, 2);
    let expansion = positron_api::tenant_retention::TenantRetentionUpdateRequest::new(
        tenant.to_canonical_text(),
        2_700_000,
        2,
        None,
        "f1f1f1f1-f1f1-f1f1-f1f1-f1f1f1f1f1f1".to_owned(),
    );
    let expanded = client.update(&administrator_secret, &expansion)?;
    assert_eq!(expanded.retention_generation, 3);
    assert_eq!(client.update(&administrator_secret, &expansion)?, expanded);
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    let reopened = InstanceBootstrap::reopen(&paths)?;
    let system = reopened.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    reopened.transition_tenant_lifecycle(
        system,
        tenant,
        TenantLifecycleState::Suspended,
        ResourceGeneration::new(2)?,
        AdministrativeIdempotencyKey::new([0xee; 16])?,
    )?;
    drop(reopened);
    let suspended_host = NativeHost::new(
        bindings(&roots, "tls-tenant-retention-suspended")?
            .with_api_transport(ApiTransportProfile::tls(certificate.clone(), private_key)?)?,
    );
    let suspended = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
        HostInputs::new(&suspended_host, &suspended_host),
    )?;
    let suspended_api = address(
        &suspended.bound_endpoints(),
        positron_runtime::ListenerRole::Api,
    )?;
    assert_status(
        tls_http(
            suspended_api,
            &certificate,
            "POST",
            positron_api::tenant_retention::PREVIEW_HTTP_PATH,
            &[
                ("Authorization", &format!("Bearer {administrator_secret}")),
                ("Content-Type", "application/json"),
            ],
            preview_body.as_bytes(),
        )?,
        401,
    );
    assert_eq!(
        suspended.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    Ok(())
}
