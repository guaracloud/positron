#[test]
fn generated_validation_fixtures_execute_through_the_public_resolver() -> Result<(), Box<dyn Error>>
{
    let fixture_document = include_str!("../../../../configuration/validation-fixtures.json");
    let fixtures = parse_generated_configuration_fixtures(fixture_document)?;
    assert_eq!(
        fixtures
            .iter()
            .map(|fixture| fixture.class.as_str())
            .collect::<Vec<_>>(),
        ["positive", "boundary", "negative", "adversarial"]
    );
    assert_eq!(
        json_unsigned_field(fixture_document, "maximum_document_bytes")?,
        16_384
    );
    assert_eq!(
        generated_json_schema(),
        include_str!("../../../../configuration/schema.json")
    );
    assert_eq!(
        generated_reference(),
        include_str!("../../../../configuration/reference.md")
    );
    let example = generated_example();
    assert_eq!(
        example,
        include_str!("../../../../configuration/example.toml")
    );
    inputs(Some(&example), [], []).and_then(resolve)?;

    for fixture in fixtures {
        let result = inputs(Some(&fixture.document), [], []).and_then(resolve);
        match fixture.expected {
            None => {
                result.map_err(|error| {
                    io::Error::other(format!(
                        "generated fixture `{}` was rejected: {error}",
                        fixture.id
                    ))
                })?;
            },
            Some(expected) => {
                let error = result.err().ok_or_else(|| {
                    io::Error::other(format!(
                        "generated fixture `{}` was unexpectedly accepted",
                        fixture.id
                    ))
                })?;
                assert_eq!(error.code(), expected, "{}", fixture.id);
                assert_eq!(
                    error.source(),
                    FailureSource::ConfigurationDocument,
                    "{}",
                    fixture.id
                );
            },
        }
    }
    Ok(())
}

#[test]
fn generated_schema_covers_every_canonical_setting_with_its_declared_constraints()
-> Result<(), Box<dyn Error>> {
    let schema: serde_json::Value = serde_json::from_str(&generated_json_schema())?;
    let properties = schema
        .get("properties")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| io::Error::other("generated schema is missing root properties"))?;

    for definition in setting_definitions() {
        let property = schema_property(properties, definition.path())?;
        match definition.domain() {
            ValueDomain::ExactUnsignedInteger(value) => {
                assert_eq!(
                    property.get("const").and_then(serde_json::Value::as_u64),
                    Some(u64::from(value))
                );
            },
            ValueDomain::StringEnumeration(values) => {
                let generated_values =
                    property
                        .get("enum")
                        .and_then(serde_json::Value::as_array)
                        .ok_or_else(|| io::Error::other("generated enum is missing"))?;
                assert_eq!(generated_values.len(), values.len());
                for expected in values {
                    assert!(
                        generated_values
                            .iter()
                            .any(|value| value.as_str() == Some(*expected))
                    );
                }
            },
            ValueDomain::UnsignedIntegerRange(minimum, maximum) => {
                assert_eq!(
                    property.get("type").and_then(serde_json::Value::as_str),
                    Some("integer")
                );
                assert_eq!(
                    property.get("minimum").and_then(serde_json::Value::as_u64),
                    Some(u64::from(minimum))
                );
                assert_eq!(
                    property.get("maximum").and_then(serde_json::Value::as_u64),
                    Some(u64::from(maximum))
                );
            },
            ValueDomain::LoopbackSocketAddress(maximum) => {
                assert_eq!(
                    property
                        .get("maxLength")
                        .and_then(serde_json::Value::as_u64),
                    Some(maximum as u64)
                );
                assert_eq!(
                    property
                        .get("x-positron-address-scope")
                        .and_then(serde_json::Value::as_str),
                    Some("loopback-only")
                );
            },
            ValueDomain::SocketAddress(maximum) => {
                assert_eq!(
                    property
                        .get("maxLength")
                        .and_then(serde_json::Value::as_u64),
                    Some(maximum as u64)
                );
                assert_eq!(
                    property
                        .get("x-positron-address-scope")
                        .and_then(serde_json::Value::as_str),
                    Some("tls-or-explicit-plaintext-opt-out-off-loopback")
                );
            },
            ValueDomain::AbsolutePath(maximum) | ValueDomain::ProtectedAbsolutePath(maximum) => {
                assert_eq!(
                    property
                        .get("maxLength")
                        .and_then(serde_json::Value::as_u64),
                    Some(maximum as u64)
                );
            },
            ValueDomain::ExportDestinations(maximum, maximum_name_bytes, maximum_tenants) => {
                assert_eq!(
                    property.get("maxItems").and_then(serde_json::Value::as_u64),
                    Some(maximum as u64)
                );
                let item_properties = property
                    .get("items")
                    .and_then(|items| items.get("properties"))
                    .and_then(serde_json::Value::as_object)
                    .ok_or_else(|| {
                        io::Error::other("generated export destination item is missing properties")
                    })?;
                assert_eq!(
                    item_properties
                        .get("name")
                        .and_then(|name| name.get("maxLength"))
                        .and_then(serde_json::Value::as_u64),
                    Some(maximum_name_bytes as u64)
                );
                assert_eq!(
                    item_properties
                        .get("allowed_tenants")
                        .and_then(|tenants| tenants.get("maxItems"))
                        .and_then(serde_json::Value::as_u64),
                    Some(maximum_tenants as u64)
                );
                assert_eq!(
                    item_properties
                        .get("identity")
                        .and_then(|identity| identity.get("not"))
                        .and_then(|not| not.get("const"))
                        .and_then(serde_json::Value::as_str),
                    Some("00000000000000000000000000000000")
                );
            },
            ValueDomain::TrustedProxyCidrs(maximum, maximum_entry_bytes) => {
                assert_eq!(
                    property.get("type").and_then(serde_json::Value::as_str),
                    Some("array")
                );
                assert_eq!(
                    property.get("maxItems").and_then(serde_json::Value::as_u64),
                    Some(maximum as u64)
                );
                let items = property.get("items").ok_or_else(|| {
                    io::Error::other("generated trusted proxy CIDR items missing")
                })?;
                assert_eq!(
                    items.get("type").and_then(serde_json::Value::as_str),
                    Some("string")
                );
                assert_eq!(
                    items.get("maxLength").and_then(serde_json::Value::as_u64),
                    Some(maximum_entry_bytes as u64)
                );
                assert_eq!(
                    items
                        .get("x-positron-address-kind")
                        .and_then(serde_json::Value::as_str),
                    Some("literal-ip-cidr")
                );
            },
        }
        assert_eq!(
            property
                .get("writeOnly")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            definition.secrecy() == SecrecyClass::SecretBearing,
            "{}",
            definition.path()
        );
    }
    Ok(())
}

fn schema_property<'a>(
    root: &'a serde_json::Map<String, serde_json::Value>,
    path: &str,
) -> Result<&'a serde_json::Value, Box<dyn Error>> {
    let mut segments = path.split('.');
    let Some(first) = segments.next() else {
        return Err(io::Error::other("invalid empty setting path").into());
    };
    let mut property = root
        .get(first)
        .ok_or_else(|| io::Error::other(format!("generated schema is missing `{path}`")))?;
    for segment in segments {
        property = property
            .get("properties")
            .and_then(|properties| properties.get(segment))
            .ok_or_else(|| io::Error::other(format!("generated schema is missing `{path}`")))?;
    }
    Ok(property)
}

fn parse_generated_configuration_fixtures(
    document: &str,
) -> Result<Vec<GeneratedConfigurationFixture>, Box<dyn Error>> {
    let mut fixtures = Vec::new();
    for line in document.lines().map(str::trim) {
        if !line.starts_with("{\"id\":") {
            continue;
        }
        let id = config_json_string_field(line, "id")?;
        let class = config_json_string_field(line, "class")?;
        let expected_name = config_json_string_field(line, "expected")?;
        let expected = match expected_name.as_str() {
            "accepted" => None,
            "unknown_setting" => Some(ConfigurationFailureCode::UnknownSetting),
            "resource_limit" => Some(ConfigurationFailureCode::ResourceLimit),
            _ => {
                return Err(io::Error::other(format!(
                    "unknown generated configuration outcome `{expected_name}`"
                ))
                .into());
            },
        };
        let document = match optional_config_json_string_field(line, "toml")? {
            Some(toml) => toml,
            None => {
                let repeated = config_json_string_field(line, "repeat")?;
                let bytes = json_unsigned_field(line, "bytes")?;
                if repeated.len() != 1 {
                    return Err(io::Error::other(
                        "generated repetition recipe must use one ASCII byte",
                    )
                    .into());
                }
                repeated.repeat(bytes)
            },
        };
        fixtures.push(GeneratedConfigurationFixture {
            id,
            class,
            document,
            expected,
        });
    }
    if fixtures.len() != 4 {
        return Err(
            io::Error::other("expected exactly four generated configuration fixtures").into(),
        );
    }
    Ok(fixtures)
}

fn optional_config_json_string_field(
    document: &str,
    field: &str,
) -> Result<Option<String>, Box<dyn Error>> {
    let needle = format!("\"{field}\": \"");
    if !document.contains(&needle) {
        return Ok(None);
    }
    config_json_string_field(document, field).map(Some)
}

fn config_json_string_field(document: &str, field: &str) -> Result<String, Box<dyn Error>> {
    let needle = format!("\"{field}\": \"");
    let start = document
        .find(&needle)
        .map(|offset| offset + needle.len())
        .ok_or_else(|| io::Error::other(format!("missing generated fixture field `{field}`")))?;
    let encoded = document
        .get(start..)
        .ok_or_else(|| io::Error::other(format!("invalid fixture field offset for `{field}`")))?;
    let mut decoded = String::new();
    let mut escaped = false;
    for character in encoded.chars() {
        if escaped {
            decoded.push(match character {
                '"' => '"',
                '\\' => '\\',
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                _ => {
                    return Err(io::Error::other(format!(
                        "unsupported JSON escape in generated fixture field `{field}`"
                    ))
                    .into());
                },
            });
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '"' {
            return Ok(decoded);
        } else {
            decoded.push(character);
        }
    }
    Err(io::Error::other(format!("unterminated generated fixture field `{field}`")).into())
}

fn json_unsigned_field(document: &str, field: &str) -> Result<usize, Box<dyn Error>> {
    let needle = format!("\"{field}\": ");
    let start = document
        .find(&needle)
        .map(|offset| offset + needle.len())
        .ok_or_else(|| io::Error::other(format!("missing generated fixture field `{field}`")))?;
    let encoded = document
        .get(start..)
        .ok_or_else(|| io::Error::other(format!("invalid fixture field offset for `{field}`")))?;
    let digits = encoded
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>();
    if digits.is_empty() {
        return Err(
            io::Error::other(format!("generated fixture field `{field}` is not unsigned")).into(),
        );
    }
    digits
        .parse::<usize>()
        .map_err(|error| io::Error::other(format!("invalid generated integer: {error}")).into())
}

#[test]
fn exposes_the_complete_canonical_setting_contract_and_compiled_defaults()
-> Result<(), ConfigurationFailure> {
    let expected = [
        (
            Setting::SchemaVersion,
            "schema_version",
            SettingKind::Integer,
            "1",
            ValueDomain::ExactUnsignedInteger(1),
            SecrecyClass::Public,
            ProvenancePolicy::ConfigurationFileOnly,
            MutabilityClass::ImmutableAfterInitialization,
        ),
        (
            Setting::DiagnosticsLogLevel,
            "diagnostics.log_level",
            SettingKind::String,
            "info",
            ValueDomain::StringEnumeration(&["error", "warn", "info", "debug"]),
            SecrecyClass::Public,
            ProvenancePolicy::NonSecretOverrides,
            MutabilityClass::LiveReloadable,
        ),
        (
            Setting::RuntimeShutdownGraceSeconds,
            "runtime.shutdown_grace_seconds",
            SettingKind::Integer,
            "30",
            ValueDomain::UnsignedIntegerRange(1, 3600),
            SecrecyClass::Public,
            ProvenancePolicy::NonSecretOverrides,
            MutabilityClass::RestartRequired,
        ),
        (
            Setting::RuntimeMaxRegisteredTenants,
            "runtime.max_registered_tenants",
            SettingKind::Integer,
            "2",
            ValueDomain::UnsignedIntegerRange(1, 1024),
            SecrecyClass::Public,
            ProvenancePolicy::NonSecretOverrides,
            MutabilityClass::RestartRequired,
        ),
        (
            Setting::ListenerControlPath,
            "listener.control_path",
            SettingKind::String,
            "/var/run/positron/control.sock",
            ValueDomain::AbsolutePath(256),
            SecrecyClass::Public,
            ProvenancePolicy::NonSecretOverrides,
            MutabilityClass::DrainAndReload,
        ),
        (
            Setting::ListenerOperationsBindAddress,
            "listener.operations_bind_address",
            SettingKind::String,
            "127.0.0.1:13133",
            ValueDomain::SocketAddress(256),
            SecrecyClass::Public,
            ProvenancePolicy::NonSecretOverrides,
            MutabilityClass::DrainAndReload,
        ),
        (
            Setting::ListenerApiBindAddress,
            "listener.api_bind_address",
            SettingKind::String,
            "127.0.0.1:8080",
            ValueDomain::SocketAddress(256),
            SecrecyClass::Public,
            ProvenancePolicy::NonSecretOverrides,
            MutabilityClass::DrainAndReload,
        ),
        (
            Setting::ListenerApiTransport,
            "listener.api_transport",
            SettingKind::String,
            "tls",
            ValueDomain::StringEnumeration(&["tls", "mtls", "plaintext"]),
            SecrecyClass::Public,
            ProvenancePolicy::ConfigurationFileOnly,
            MutabilityClass::DrainAndReload,
        ),
        (
            Setting::ListenerApiTlsCertificateFile,
            "listener.api_tls_certificate_file",
            SettingKind::String,
            "/var/lib/positron-secrets/api-certificate.pem",
            ValueDomain::ProtectedAbsolutePath(256),
            SecrecyClass::SecretBearing,
            ProvenancePolicy::ProtectedConfigurationFileOnly,
            MutabilityClass::DrainAndReload,
        ),
        (
            Setting::ListenerApiTlsPrivateKeyFile,
            "listener.api_tls_private_key_file",
            SettingKind::String,
            "/var/lib/positron-secrets/api-private-key.pem",
            ValueDomain::ProtectedAbsolutePath(256),
            SecrecyClass::SecretBearing,
            ProvenancePolicy::ProtectedConfigurationFileOnly,
            MutabilityClass::DrainAndReload,
        ),
        (
            Setting::ListenerOtlpGrpcBindAddress,
            "listener.otlp_grpc_bind_address",
            SettingKind::String,
            "127.0.0.1:4317",
            ValueDomain::SocketAddress(256),
            SecrecyClass::Public,
            ProvenancePolicy::NonSecretOverrides,
            MutabilityClass::DrainAndReload,
        ),
        (
            Setting::ListenerOtlpHttpBindAddress,
            "listener.otlp_http_bind_address",
            SettingKind::String,
            "127.0.0.1:4318",
            ValueDomain::SocketAddress(256),
            SecrecyClass::Public,
            ProvenancePolicy::NonSecretOverrides,
            MutabilityClass::DrainAndReload,
        ),
        (
            Setting::ListenerLokiPushBindAddress,
            "listener.loki_push_bind_address",
            SettingKind::String,
            "127.0.0.1:3100",
            ValueDomain::SocketAddress(256),
            SecrecyClass::Public,
            ProvenancePolicy::NonSecretOverrides,
            MutabilityClass::DrainAndReload,
        ),
        (
            Setting::StorageDataDirectory,
            "storage.data_directory",
            SettingKind::String,
            "/var/lib/positron",
            ValueDomain::AbsolutePath(256),
            SecrecyClass::Public,
            ProvenancePolicy::ConfigurationFileOnly,
            MutabilityClass::ImmutableAfterInitialization,
        ),
        (
            Setting::StorageSecretsDirectory,
            "storage.secrets_directory",
            SettingKind::String,
            "/var/lib/positron-secrets",
            ValueDomain::AbsolutePath(256),
            SecrecyClass::Public,
            ProvenancePolicy::ConfigurationFileOnly,
            MutabilityClass::ImmutableAfterInitialization,
        ),
        (
            Setting::SecurityLocalKeyFile,
            "security.local_key_file",
            SettingKind::String,
            "/var/lib/positron-secrets/local-root-key.v1",
            ValueDomain::ProtectedAbsolutePath(256),
            SecrecyClass::SecretBearing,
            ProvenancePolicy::ProtectedConfigurationFileOnly,
            MutabilityClass::ImmutableAfterInitialization,
        ),
        (
            Setting::ExportDestinations,
            "export.destination",
            SettingKind::ExportDestinations,
            "disabled",
            ValueDomain::ExportDestinations(8, 63, 8),
            SecrecyClass::Public,
            ProvenancePolicy::ConfigurationFileOnly,
            MutabilityClass::ImmutableAfterInitialization,
        ),
    ];

    for (setting, path, kind, default, domain, secrecy, provenance, mutability) in expected {
        let definition = setting_definition(setting);
        assert_eq!(definition.setting(), setting);
        assert_eq!(definition.path(), path);
        assert_eq!(definition.kind(), kind);
        assert_eq!(definition.default_value(), default);
        assert_eq!(definition.domain(), domain);
        assert_eq!(definition.secrecy(), secrecy);
        assert_eq!(definition.provenance(), provenance);
        assert_eq!(definition.mutability(), mutability);
        assert_eq!(setting.path(), path);
        assert_eq!(setting.secrecy(), secrecy);
        assert_eq!(setting.mutability(), mutability);
    }

    let effective = inputs(None, [], []).and_then(resolve)?;
    assert_eq!(effective.schema_version(), 1);
    assert_eq!(effective.log_level(), LogLevel::Info);
    assert_eq!(effective.shutdown_grace_seconds(), 30);
    assert_eq!(effective.max_registered_tenants(), 2);
    assert_eq!(effective.control_path(), "/var/run/positron/control.sock");
    assert_eq!(
        effective.operations_bind_address().to_string(),
        "127.0.0.1:13133"
    );
    assert_eq!(effective.api_bind_address().to_string(), "127.0.0.1:8080");
    assert_eq!(
        effective.otlp_grpc_bind_address().to_string(),
        "127.0.0.1:4317"
    );
    assert_eq!(
        effective.otlp_http_bind_address().to_string(),
        "127.0.0.1:4318"
    );
    assert_eq!(
        effective.loki_push_bind_address().to_string(),
        "127.0.0.1:3100"
    );
    for setting in expected.map(|(setting, ..)| setting) {
        assert_eq!(
            effective.source_for(setting.path()),
            Some(SettingSource::CompiledDefault)
        );
    }
    assert_eq!(effective.source_for("unknown.setting"), None);
    assert_eq!(
        effective.redacted_reference(),
        "schema_version = 1\n\n\
         [diagnostics]\nlog_level = \"info\"\n\n\
         [runtime]\nshutdown_grace_seconds = 30\nmax_registered_tenants = 2\n\n\
         [listener]\ncontrol_path = \"/var/run/positron/control.sock\"\n\
         operations_bind_address = \"127.0.0.1:13133\"\n\
         operations_transport = \"tls\"\n\
         operations_accepted_socket_limit = 128\n\
         operations_per_address_accepted_socket_limit = 16\n\
         operations_tls_handshake_limit = 16\n\
         operations_tls_handshake_deadline_seconds = 2\n\
         operations_header_deadline_seconds = 2\n\
         operations_body_deadline_seconds = 2\n\
         operations_request_deadline_seconds = 30\n\
         operations_idle_deadline_seconds = 30\n\
         operations_tls_certificate_file = \"<redacted>\"\n\
         operations_tls_private_key_file = \"<redacted>\"\n\
         operations_tls_client_ca_file = \"<redacted>\"\n\
         api_bind_address = \"127.0.0.1:8080\"\n\
         api_transport = \"tls\"\n\
         api_accepted_socket_limit = 128\n\
         api_per_address_accepted_socket_limit = 16\n\
         api_tls_handshake_limit = 16\n\
         api_tls_handshake_deadline_seconds = 2\n\
         api_header_deadline_seconds = 2\n\
         api_body_deadline_seconds = 2\n\
         api_request_deadline_seconds = 30\n\
         api_idle_deadline_seconds = 30\n\
         api_tls_certificate_file = \"<redacted>\"\n\
         api_tls_private_key_file = \"<redacted>\"\n\
         api_tls_client_ca_file = \"<redacted>\"\n\
         otlp_grpc_bind_address = \"127.0.0.1:4317\"\n\
         otlp_grpc_transport = \"tls\"\n\
         otlp_grpc_accepted_socket_limit = 128\n\
         otlp_grpc_per_address_accepted_socket_limit = 16\n\
         otlp_grpc_tls_handshake_limit = 16\n\
         otlp_grpc_tls_handshake_deadline_seconds = 2\n\
         otlp_grpc_header_deadline_seconds = 2\n\
         otlp_grpc_body_deadline_seconds = 2\n\
         otlp_grpc_request_deadline_seconds = 30\n\
         otlp_grpc_idle_deadline_seconds = 30\n\
         otlp_grpc_tls_certificate_file = \"<redacted>\"\n\
         otlp_grpc_tls_private_key_file = \"<redacted>\"\n\
         otlp_grpc_tls_client_ca_file = \"<redacted>\"\n\
         otlp_http_bind_address = \"127.0.0.1:4318\"\n\
         otlp_http_transport = \"tls\"\n\
         otlp_http_accepted_socket_limit = 128\n\
         otlp_http_per_address_accepted_socket_limit = 16\n\
         otlp_http_tls_handshake_limit = 16\n\
         otlp_http_tls_handshake_deadline_seconds = 2\n\
         otlp_http_header_deadline_seconds = 2\n\
         otlp_http_body_deadline_seconds = 2\n\
         otlp_http_request_deadline_seconds = 30\n\
         otlp_http_idle_deadline_seconds = 30\n\
         otlp_http_tls_certificate_file = \"<redacted>\"\n\
         otlp_http_tls_private_key_file = \"<redacted>\"\n\
         otlp_http_tls_client_ca_file = \"<redacted>\"\n\
         loki_push_bind_address = \"127.0.0.1:3100\"\n\
         loki_push_transport = \"tls\"\n\
         loki_push_accepted_socket_limit = 128\n\
         loki_push_per_address_accepted_socket_limit = 16\n\
         loki_push_tls_handshake_limit = 16\n\
         loki_push_tls_handshake_deadline_seconds = 2\n\
         loki_push_header_deadline_seconds = 2\n\
         loki_push_body_deadline_seconds = 2\n\
         loki_push_request_deadline_seconds = 30\n\
         loki_push_idle_deadline_seconds = 30\n\
         loki_push_tls_certificate_file = \"<redacted>\"\n\
         loki_push_tls_private_key_file = \"<redacted>\"\n\
         loki_push_tls_client_ca_file = \"<redacted>\"\n\n\
         [listener.operations]\ntrusted_proxy_cidrs = []\nforwarded_hops = 0\n\n\
         [listener.api]\ntrusted_proxy_cidrs = []\nforwarded_hops = 0\n\n\
         [listener.otlp_grpc]\ntrusted_proxy_cidrs = []\nforwarded_hops = 0\n\n\
         [listener.otlp_http]\ntrusted_proxy_cidrs = []\nforwarded_hops = 0\n\n\
         [listener.loki_push]\ntrusted_proxy_cidrs = []\nforwarded_hops = 0\n\n\
         [storage]\ndata_directory = \"/var/lib/positron\"\n\
         secrets_directory = \"/var/lib/positron-secrets\"\n\n\
         [security]\nlocal_key_file = \"<redacted>\"\n"
    );
    Ok(())
}
