use super::*;

#[test]
fn admitted_http_trace_request_keeps_captured_policy_after_successor_activation()
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
    let path = PolicyAttributePath::new(AttributeNamespace::Record, "secret")?;
    let old_policy = IngestPolicy::compile(
        2,
        vec![PolicyRule::new(
            "redact-secret",
            vec![],
            PolicyAction::Redact(PolicyTarget::attribute(path)),
        )?],
    )?;
    services.activate_ingest_policy(
        initialized.attribute(
            PresentedCredential::parse(&administrator_secret)?,
            RequestedIntent::SystemAdministration,
            CompatibilityHints::none(),
        )?,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xd3; 16])?,
        old_policy.clone(),
    )?;
    let (entered_sender, entered_receiver) = mpsc::sync_channel(1);
    let (resume_sender, resume_receiver) = mpsc::sync_channel(1);
    services.install_ingest_policy_snapshot_test_hook(Arc::new(BlockingCapturedPolicy {
        signal: SignalKind::Traces,
        entered: entered_sender,
        resume: Mutex::new(resume_receiver),
        blocked: AtomicBool::new(false),
    }))?;
    let body = trace_request(0xd4, 0xd5, "captured-trace").encode_to_vec();
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?;
    let endpoint = listener.local_addr()?;
    let mut client = TcpStream::connect(endpoint)?;
    let (mut server, _) = listener.accept()?;
    client.write_all(&body)?;
    let in_flight = thread::scope(|scope| -> Result<_, Box<dyn Error>> {
        let in_flight_services = services.clone();
        let in_flight_bearer = bearer.clone();
        let handle = scope.spawn(move || {
            receive_traces(
                &mut server,
                RequestHead {
                    method: "POST".to_owned(),
                    path: "/v1/traces".to_owned(),
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
            AdministrativeIdempotencyKey::new([0xd6; 16])?,
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
            .map_err(|_| std::io::Error::other("in-flight trace route panicked"))?
            .map_err(|_| std::io::Error::other("in-flight trace route was rejected"))
            .map_err(Into::into)
    })?;
    assert_eq!(in_flight.status(), 200);
    assert!(
        ExportTraceServiceResponse::decode(in_flight.body())?
            .partial_success
            .is_none()
    );
    drop(client);
    assert_trace_marker(&initialized, &old_policy)?;

    let later = receive_trace_request(
        &services,
        &bearer,
        trace_request(0xd7, 0xd8, "successor-trace").encode_to_vec(),
    )?;
    assert_eq!(later.status(), 200, "body={:?}", later.body());
    assert_eq!(
        ExportTraceServiceResponse::decode(later.body())?
            .partial_success
            .ok_or("successor trace policy did not reject")?
            .rejected_spans,
        1
    );
    Ok(())
}

#[test]
fn authenticated_http_trace_marker_survives_ack_and_runtime_reopen() -> Result<(), Box<dyn Error>> {
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
        AdministrativeIdempotencyKey::new([0xb8; 16])?,
        policy.clone(),
    )?;

    let body = ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            scope_spans: vec![ScopeSpans {
                spans: vec![Span {
                    trace_id: vec![0x41; 16],
                    span_id: vec![0x42; 8],
                    name: "http-marker".to_owned(),
                    attributes: vec![attribute("secret", string_value("source-secret"))],
                    ..Span::default()
                }],
                ..ScopeSpans::default()
            }],
            ..ResourceSpans::default()
        }],
    }
    .encode_to_vec();
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?;
    let endpoint = listener.local_addr()?;
    let mut client = TcpStream::connect(endpoint)?;
    let (mut server, _) = listener.accept()?;
    client.write_all(&body)?;
    let response = receive_traces(
        &mut server,
        RequestHead {
            method: "POST".to_owned(),
            path: "/v1/traces".to_owned(),
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
    .map_err(|_| "trace HTTP response was rejected")?;
    assert_eq!(
        response.status(),
        200,
        "status={} body={:?}",
        response.status(),
        response.body()
    );
    let decoded = ExportTraceServiceResponse::decode(response.body())?;
    assert!(decoded.partial_success.is_none());

    let expensive_value = "x".repeat(65_536);
    let expensive_attributes = (0..8)
        .map(|_| attribute("secret", string_value(&expensive_value)))
        .collect();
    let expensive_body = ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            scope_spans: vec![ScopeSpans {
                spans: vec![Span {
                    trace_id: vec![0x43; 16],
                    span_id: vec![0x44; 8],
                    name: "expensive-http-marker".to_owned(),
                    attributes: expensive_attributes,
                    ..Span::default()
                }],
                ..ScopeSpans::default()
            }],
            ..ResourceSpans::default()
        }],
    }
    .encode_to_vec();
    let expensive_listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?;
    let expensive_endpoint = expensive_listener.local_addr()?;
    let mut expensive_client = TcpStream::connect(expensive_endpoint)?;
    let (mut expensive_server, _) = expensive_listener.accept()?;
    expensive_client.write_all(&expensive_body)?;
    let expensive_response = receive_traces(
        &mut expensive_server,
        RequestHead {
            method: "POST".to_owned(),
            path: "/v1/traces".to_owned(),
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
    .map_err(|_| "expensive trace HTTP response was rejected")?;
    assert_eq!(expensive_response.status(), 429);
    assert_eq!(expensive_response.retry_after_seconds(), Some(1));
    drop(expensive_client);
    drop(client);
    drop(services);
    drop(initialized);

    let reopened = InstanceBootstrap::reopen(&paths)?;
    assert_trace_marker(&reopened, &policy)?;
    Ok(())
}
