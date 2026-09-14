use super::*;

#[test]
fn admitted_http_log_request_keeps_captured_policy_after_successor_activation()
-> Result<(), Box<dyn Error>> {
    let roots = TestRoots::new()?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let administrator_secret = claim.secret().to_owned();
    let bearer = claim
        .ingest_secret()
        .ok_or("ingest secret missing")?
        .to_owned();
    let initialized = Arc::new(InstanceBootstrap::reopen(&paths)?);
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let old_policy = IngestPolicy::compile(
        2,
        vec![PolicyRule::new(
            "redact-body",
            Vec::new(),
            PolicyAction::Redact(PolicyTarget::body()),
        )?],
    )?;
    services.activate_ingest_policy(
        initialized.attribute(
            PresentedCredential::parse(&administrator_secret)?,
            RequestedIntent::SystemAdministration,
            CompatibilityHints::none(),
        )?,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xd1; 16])?,
        old_policy.clone(),
    )?;
    let (entered_sender, entered_receiver) = mpsc::sync_channel(1);
    let (resume_sender, resume_receiver) = mpsc::sync_channel(1);
    services.install_ingest_policy_snapshot_test_hook(Arc::new(BlockingCapturedPolicy {
        signal: SignalKind::Logs,
        entered: entered_sender,
        resume: Mutex::new(resume_receiver),
        blocked: AtomicBool::new(false),
    }))?;
    let body = log_request("captured-log").encode_to_vec();
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?;
    let endpoint = listener.local_addr()?;
    let mut client = TcpStream::connect(endpoint)?;
    let (mut server, _) = listener.accept()?;
    client.write_all(&body)?;
    let in_flight = thread::scope(|scope| -> Result<_, Box<dyn Error>> {
        let in_flight_services = services.clone();
        let in_flight_bearer = bearer.clone();
        let handle = scope.spawn(move || {
            receive(
                &mut server,
                RequestHead {
                    method: "POST".to_owned(),
                    path: "/v1/logs".to_owned(),
                    content_length: body.len(),
                    bearer: Some(in_flight_bearer),
                    content_type: Some(ResponseEncoding::Protobuf.content_type().to_owned()),
                    content_encoding: None,
                    tenant_hint: None,
                    forwarded_for: None,
                    forwarded_actor: None,
                },
                &in_flight_services,
            )
        });
        entered_receiver.recv_timeout(Duration::from_secs(2))?;
        services.activate_ingest_policy(
            initialized.attribute(
                PresentedCredential::parse(&administrator_secret)?,
                RequestedIntent::SystemAdministration,
                CompatibilityHints::none(),
            )?,
            ResourceGeneration::new(2)?,
            AdministrativeIdempotencyKey::new([0xd2; 16])?,
            IngestPolicy::compile(
                3,
                vec![PolicyRule::new(
                    "reject-successor",
                    Vec::new(),
                    PolicyAction::Reject,
                )?],
            )?,
        )?;
        resume_sender.send(())?;
        handle
            .join()
            .map_err(|_| std::io::Error::other("in-flight log route panicked"))?
            .map_err(|_| std::io::Error::other("in-flight log route was rejected"))
            .map_err(Into::into)
    })?;
    assert_eq!(in_flight.status(), 200);
    assert!(
        ExportLogsServiceResponse::decode(in_flight.body())?
            .partial_success
            .is_none()
    );
    drop(client);
    assert_log_marker(&initialized, &old_policy)?;

    let later = receive_log_request(
        &services,
        &bearer,
        log_request("successor-log").encode_to_vec(),
    )?;
    assert_eq!(later.status(), 400, "body={:?}", later.body());
    Ok(())
}

#[test]
fn authenticated_http_log_marker_survives_ack_and_runtime_reopen() -> Result<(), Box<dyn Error>> {
    let roots = TestRoots::new()?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let (administrator_secret, bearer) = {
        let claim = InstanceBootstrap::claim(&paths)?;
        (
            claim.secret().to_owned(),
            claim
                .ingest_secret()
                .ok_or("ingest secret missing")?
                .to_owned(),
        )
    };
    let initialized = Arc::new(InstanceBootstrap::reopen(&paths)?);
    let administrator = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let policy = IngestPolicy::compile(
        2,
        vec![PolicyRule::new(
            "redact-body",
            Vec::new(),
            PolicyAction::Redact(PolicyTarget::body()),
        )?],
    )?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    services.activate_ingest_policy(
        administrator,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xb7; 16])?,
        policy.clone(),
    )?;

    let body = ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            scope_logs: vec![ScopeLogs {
                log_records: vec![LogRecord {
                    body: Some(string_value("log-body")),
                    attributes: vec![
                        attribute("secret", string_value("source-secret")),
                        attribute("null", AnyValue { value: None }),
                        attribute("lookalike", string_value("[REDACTED]")),
                    ],
                    ..LogRecord::default()
                }],
                ..ScopeLogs::default()
            }],
            ..ResourceLogs::default()
        }],
    }
    .encode_to_vec();
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?;
    let endpoint = listener.local_addr()?;
    let mut client = TcpStream::connect(endpoint)?;
    let (mut server, _) = listener.accept()?;
    client.write_all(&body)?;
    let response = receive(
        &mut server,
        RequestHead {
            method: "POST".to_owned(),
            path: "/v1/logs".to_owned(),
            content_length: body.len(),
            bearer: Some(bearer.clone()),
            content_type: Some(ResponseEncoding::Protobuf.content_type().to_owned()),
            content_encoding: None,
            tenant_hint: None,
            forwarded_for: None,
            forwarded_actor: None,
        },
        &services,
    )
    .map_err(|_| "log HTTP response was rejected")?;
    assert_eq!(
        response.status(),
        200,
        "status={} body={:?}",
        response.status(),
        response.body()
    );
    let decoded = ExportLogsServiceResponse::decode(response.body())?;
    assert!(decoded.partial_success.is_none());
    drop(client);
    drop(services);
    drop(initialized);

    let reopened = InstanceBootstrap::reopen(&paths)?;
    assert_log_marker(&reopened, &policy)?;
    Ok(())
}

#[test]
fn authenticated_http_log_attribute_marker_reports_insufficient_governor_headroom()
-> Result<(), Box<dyn Error>> {
    let roots = TestRoots::new()?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize_with_max_registered_tenants(
        &paths,
        InitializationPlan::non_interactive(),
        1,
    )?);
    let (administrator_secret, bearer) = {
        let claim = InstanceBootstrap::claim(&paths)?;
        (
            claim.secret().to_owned(),
            claim
                .ingest_secret()
                .ok_or("ingest secret missing")?
                .to_owned(),
        )
    };
    let initialized = Arc::new(InstanceBootstrap::reopen_with_max_registered_tenants(
        &paths, 1,
    )?);
    let administrator = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let path = PolicyAttributePath::new(AttributeNamespace::Record, "secret")?;
    let policy = IngestPolicy::compile(
        2,
        vec![PolicyRule::new(
            "redact-secret",
            Vec::new(),
            PolicyAction::Redact(PolicyTarget::attribute(path)),
        )?],
    )?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    services.activate_ingest_policy(
        administrator,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xba; 16])?,
        policy.clone(),
    )?;

    let before = initialized.resource_governor().inspect()?;
    assert_eq!(
        before.ordinary_capacity(ResourceDimension::CpuWorkUnits),
        32,
        "this headroom scenario registers one 32-unit tenant CPU quota"
    );
    assert_eq!(
        before.pool_capacity(OrdinaryPool::Shared, ResourceDimension::CpuWorkUnits),
        12,
        "ordinary pool policy reserves 8+6+4+2 CPU units"
    );
    assert_eq!(
        before.pool_capacity(OrdinaryPool::Ingest, ResourceDimension::CpuWorkUnits),
        6,
        "ingest class headroom is fixed by the runtime bootstrap policy"
    );
    let body = ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            scope_logs: vec![ScopeLogs {
                log_records: vec![LogRecord {
                    attributes: vec![
                        attribute("secret", string_value("source-secret")),
                        attribute("null", AnyValue { value: None }),
                        attribute("lookalike", string_value("[REDACTED]")),
                    ],
                    ..LogRecord::default()
                }],
                ..ScopeLogs::default()
            }],
            ..ResourceLogs::default()
        }],
    }
    .encode_to_vec();
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?;
    let endpoint = listener.local_addr()?;
    let mut client = TcpStream::connect(endpoint)?;
    let (mut server, _) = listener.accept()?;
    client.write_all(&body)?;
    let response = receive(
        &mut server,
        RequestHead {
            method: "POST".to_owned(),
            path: "/v1/logs".to_owned(),
            content_length: body.len(),
            bearer: Some(bearer.clone()),
            content_type: Some(ResponseEncoding::Protobuf.content_type().to_owned()),
            content_encoding: None,
            tenant_hint: None,
            forwarded_for: None,
            forwarded_actor: None,
        },
        &services,
    )
    .map_err(|_| "log HTTP response was rejected")?;
    assert_eq!(
        response.status(),
        200,
        "status={} body={:?}",
        response.status(),
        response.body()
    );
    let decoded = ExportLogsServiceResponse::decode(response.body())?;
    assert!(decoded.partial_success.is_none());

    // A source-shaped record near the bounded native value limit must retain
    // the typed retry outcome: candidate-aware admission is not a universal
    // capacity exemption for expensive policy work.
    let expensive_value = "x".repeat(500_000);
    let expensive_body = ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            scope_logs: vec![ScopeLogs {
                log_records: vec![LogRecord {
                    attributes: vec![attribute("secret", string_value(&expensive_value))],
                    ..LogRecord::default()
                }],
                ..ScopeLogs::default()
            }],
            ..ResourceLogs::default()
        }],
    }
    .encode_to_vec();
    let expensive_listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?;
    let expensive_endpoint = expensive_listener.local_addr()?;
    let mut expensive_client = TcpStream::connect(expensive_endpoint)?;
    let (mut expensive_server, _) = expensive_listener.accept()?;
    expensive_client.write_all(&expensive_body)?;
    let expensive_response = receive(
        &mut expensive_server,
        RequestHead {
            method: "POST".to_owned(),
            path: "/v1/logs".to_owned(),
            content_length: expensive_body.len(),
            bearer: Some(bearer),
            content_type: Some(ResponseEncoding::Protobuf.content_type().to_owned()),
            content_encoding: None,
            tenant_hint: None,
            forwarded_for: None,
            forwarded_actor: None,
        },
        &services,
    )
    .map_err(|_| "expensive log HTTP response was rejected")?;
    assert_eq!(expensive_response.status(), 429);
    assert_eq!(expensive_response.retry_after_seconds(), Some(1));
    drop(expensive_client);
    drop(client);
    drop(services);
    drop(initialized);

    let reopened = InstanceBootstrap::reopen_with_max_registered_tenants(&paths, 1)?;
    assert_log_attribute_marker(&reopened, &policy)?;
    Ok(())
}
