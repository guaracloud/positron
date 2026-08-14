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
            ValueDomain::LoopbackSocketAddress(256),
            SecrecyClass::Public,
            ProvenancePolicy::NonSecretOverrides,
            MutabilityClass::DrainAndReload,
        ),
        (
            Setting::ListenerApiBindAddress,
            "listener.api_bind_address",
            SettingKind::String,
            "127.0.0.1:8080",
            ValueDomain::LoopbackSocketAddress(256),
            SecrecyClass::Public,
            ProvenancePolicy::NonSecretOverrides,
            MutabilityClass::DrainAndReload,
        ),
        (
            Setting::ListenerOtlpGrpcBindAddress,
            "listener.otlp_grpc_bind_address",
            SettingKind::String,
            "127.0.0.1:4317",
            ValueDomain::LoopbackSocketAddress(256),
            SecrecyClass::Public,
            ProvenancePolicy::NonSecretOverrides,
            MutabilityClass::DrainAndReload,
        ),
        (
            Setting::ListenerOtlpHttpBindAddress,
            "listener.otlp_http_bind_address",
            SettingKind::String,
            "127.0.0.1:4318",
            ValueDomain::LoopbackSocketAddress(256),
            SecrecyClass::Public,
            ProvenancePolicy::NonSecretOverrides,
            MutabilityClass::DrainAndReload,
        ),
        (
            Setting::ListenerLokiPushBindAddress,
            "listener.loki_push_bind_address",
            SettingKind::String,
            "127.0.0.1:3100",
            ValueDomain::LoopbackSocketAddress(256),
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
         [runtime]\nshutdown_grace_seconds = 30\n\n\
         [listener]\ncontrol_path = \"/var/run/positron/control.sock\"\n\
         operations_bind_address = \"127.0.0.1:13133\"\n\
         api_bind_address = \"127.0.0.1:8080\"\n\
         otlp_grpc_bind_address = \"127.0.0.1:4317\"\n\
         otlp_http_bind_address = \"127.0.0.1:4318\"\n\
         loki_push_bind_address = \"127.0.0.1:3100\"\n\n\
         [storage]\ndata_directory = \"/var/lib/positron\"\n\
         secrets_directory = \"/var/lib/positron-secrets\"\n\n\
         [security]\nlocal_key_file = \"<redacted>\"\n"
    );
    Ok(())
}
