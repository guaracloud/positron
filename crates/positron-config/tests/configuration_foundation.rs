//! Public contract tests for the M0 Configuration foundation.

use std::{error::Error, io};

use positron_config::{
    CommandLineOverrides, CompletionState, ConfigurationFailure, ConfigurationFailureCode,
    ConfigurationInputs, ConfigurationPlan, EnvironmentOverrides, FailureSource, LogLevel,
    MutabilityClass, ProvenancePolicy, RetryClass, SecrecyClass, Setting, SettingKind,
    SettingSource, ValueDomain, generated_json_schema, generated_reference, resolve,
    setting_definition,
};

#[derive(Debug)]
struct GeneratedConfigurationFixture {
    id: String,
    class: String,
    document: String,
    expected: Option<ConfigurationFailureCode>,
}

#[test]
fn generated_validation_fixtures_execute_through_the_public_resolver() -> Result<(), Box<dyn Error>>
{
    let fixture_document = include_str!("../../../configuration/validation-fixtures.json");
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
        include_str!("../../../configuration/schema.json")
    );
    assert_eq!(
        generated_reference(),
        include_str!("../../../configuration/reference.md")
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
            Setting::ListenerControlBindAddress,
            "listener.control_bind_address",
            SettingKind::String,
            "127.0.0.1:4317",
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
            "/var/lib/positron-secrets/local-root-key",
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
    assert_eq!(
        effective.control_bind_address().to_string(),
        "127.0.0.1:4317"
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
         [listener]\ncontrol_bind_address = \"127.0.0.1:4317\"\n\n\
         [storage]\ndata_directory = \"/var/lib/positron\"\n\
         secrets_directory = \"/var/lib/positron-secrets\"\n\n\
         [security]\nlocal_key_file = \"<redacted>\"\n"
    );
    Ok(())
}

#[test]
fn resolves_non_secret_settings_in_deterministic_source_precedence_order()
-> Result<(), ConfigurationFailure> {
    let environment =
        EnvironmentOverrides::try_from_pairs([("POSITRON__DIAGNOSTICS__LOG_LEVEL", "warn")])?;
    let command_line = CommandLineOverrides::try_from_pairs([("diagnostics.log_level", "debug")])?;
    let inputs = ConfigurationInputs::try_new(
        Some(
            "schema_version = 1\n\
             [diagnostics]\n\
             log_level = \"error\"\n",
        ),
        environment,
        command_line,
    )?;

    let effective = resolve(inputs)?;

    assert_eq!(effective.log_level(), LogLevel::Debug);
    assert_eq!(
        effective.source_for("diagnostics.log_level"),
        Some(SettingSource::CommandLine)
    );
    assert!(
        effective
            .redacted_reference()
            .contains("log_level = \"debug\"")
    );
    assert!(
        effective
            .redacted_reference()
            .contains("local_key_file = \"<redacted>\"")
    );
    assert!(
        !effective
            .redacted_reference()
            .contains("/var/lib/positron-secrets/local-root-key")
    );
    Ok(())
}

#[test]
fn resolves_every_setting_from_the_canonical_file_with_file_provenance()
-> Result<(), ConfigurationFailure> {
    let effective = inputs(
        Some(
            "schema_version = 1\n\
             [diagnostics]\n\
             log_level = \"error\"\n\
             [runtime]\n\
             shutdown_grace_seconds = 1\n\
             [listener]\n\
             control_bind_address = \"[::1]:4318\"\n\
             [storage]\n\
             data_directory = \"/srv/positron\"\n\
             secrets_directory = \"/srv/positron-secrets\"\n\
             [security]\n\
             local_key_file = \"/srv/positron-secrets/root-key\"\n",
        ),
        [],
        [],
    )
    .and_then(resolve)?;

    assert_eq!(effective.schema_version(), 1);
    assert_eq!(effective.log_level(), LogLevel::Error);
    assert_eq!(effective.shutdown_grace_seconds(), 1);
    assert_eq!(effective.control_bind_address().to_string(), "[::1]:4318");
    for setting in [
        Setting::SchemaVersion,
        Setting::DiagnosticsLogLevel,
        Setting::RuntimeShutdownGraceSeconds,
        Setting::ListenerControlBindAddress,
        Setting::StorageDataDirectory,
        Setting::StorageSecretsDirectory,
        Setting::SecurityLocalKeyFile,
    ] {
        assert_eq!(
            effective.source_for(setting.path()),
            Some(SettingSource::ConfigurationFile)
        );
    }
    let rendered = effective.redacted_reference();
    assert!(rendered.contains("log_level = \"error\""));
    assert!(rendered.contains("shutdown_grace_seconds = 1"));
    assert!(rendered.contains("control_bind_address = \"[::1]:4318\""));
    assert!(rendered.contains("data_directory = \"/srv/positron\""));
    assert!(rendered.contains("secrets_directory = \"/srv/positron-secrets\""));
    assert!(!rendered.contains("root-key"));
    Ok(())
}

#[test]
fn applies_environment_then_command_line_to_every_overrideable_setting()
-> Result<(), ConfigurationFailure> {
    let environment = EnvironmentOverrides::try_from_pairs([
        ("POSITRON__DIAGNOSTICS__LOG_LEVEL", "warn"),
        ("POSITRON__RUNTIME__SHUTDOWN_GRACE_SECONDS", "2"),
        ("POSITRON__LISTENER__CONTROL_BIND_ADDRESS", "127.0.0.1:4319"),
    ])?;
    let environment_effective = resolve(ConfigurationInputs::try_new(
        Some(
            "schema_version = 1\n\
             [diagnostics]\nlog_level = \"error\"\n\
             [runtime]\nshutdown_grace_seconds = 1\n\
             [listener]\ncontrol_bind_address = \"127.0.0.1:4318\"\n",
        ),
        environment.clone(),
        CommandLineOverrides::try_from_pairs([] as [(&str, &str); 0])?,
    )?)?;
    assert_eq!(environment_effective.log_level(), LogLevel::Warn);
    assert_eq!(environment_effective.shutdown_grace_seconds(), 2);
    assert_eq!(
        environment_effective.control_bind_address().to_string(),
        "127.0.0.1:4319"
    );
    for path in [
        "diagnostics.log_level",
        "runtime.shutdown_grace_seconds",
        "listener.control_bind_address",
    ] {
        assert_eq!(
            environment_effective.source_for(path),
            Some(SettingSource::Environment)
        );
    }

    let command_line = CommandLineOverrides::try_from_pairs([
        ("diagnostics.log_level", "debug"),
        ("runtime.shutdown_grace_seconds", "3600"),
        ("listener.control_bind_address", "[::1]:4320"),
    ])?;
    let command_line_effective = resolve(ConfigurationInputs::try_new(
        None,
        environment,
        command_line,
    )?)?;
    assert_eq!(command_line_effective.log_level(), LogLevel::Debug);
    assert_eq!(command_line_effective.shutdown_grace_seconds(), 3600);
    assert_eq!(
        command_line_effective.control_bind_address().to_string(),
        "[::1]:4320"
    );
    for path in [
        "diagnostics.log_level",
        "runtime.shutdown_grace_seconds",
        "listener.control_bind_address",
    ] {
        assert_eq!(
            command_line_effective.source_for(path),
            Some(SettingSource::CommandLine)
        );
    }
    Ok(())
}

#[test]
fn rejects_bounded_conflicting_unknown_and_forbidden_overrides() {
    let duplicate_environment = EnvironmentOverrides::try_from_pairs([
        ("POSITRON__DIAGNOSTICS__LOG_LEVEL", "warn"),
        ("POSITRON__DIAGNOSTICS__LOG_LEVEL", "debug"),
    ]);
    assert!(matches!(
        duplicate_environment,
        Err(error)
            if error.code() == ConfigurationFailureCode::ConflictingSetting
                && error.source() == FailureSource::EnvironmentOverride
    ));

    let duplicate_command_line = CommandLineOverrides::try_from_pairs([
        ("diagnostics.log_level", "warn"),
        ("diagnostics.log_level", "debug"),
    ]);
    assert!(matches!(
        duplicate_command_line,
        Err(error)
            if error.code() == ConfigurationFailureCode::ConflictingSetting
                && error.source() == FailureSource::CommandLineOverride
    ));

    let too_many_environment = EnvironmentOverrides::try_from_pairs(
        (0..17).map(|index| (format!("POSITRON__UNKNOWN__KEY_{index}"), "value")),
    );
    assert!(matches!(
        too_many_environment,
        Err(error)
            if error.code() == ConfigurationFailureCode::ResourceLimit
                && error.source() == FailureSource::EnvironmentOverride
    ));
    let sixteen_environment = EnvironmentOverrides::try_from_pairs(
        (0..16).map(|index| (format!("POSITRON__UNKNOWN__KEY_{index}"), "value")),
    );
    assert!(sixteen_environment.is_ok());

    let long_key = "K".repeat(65);
    let long_environment_key = EnvironmentOverrides::try_from_pairs([(long_key.as_str(), "value")]);
    assert!(matches!(
        long_environment_key,
        Err(error)
            if error.code() == ConfigurationFailureCode::ResourceLimit
                && error.source() == FailureSource::EnvironmentOverride
    ));
    let long_value = "v".repeat(257);
    let long_command_line_value =
        CommandLineOverrides::try_from_pairs([("diagnostics.log_level", long_value.as_str())]);
    assert!(matches!(
        long_command_line_value,
        Err(error)
            if error.code() == ConfigurationFailureCode::ResourceLimit
                && error.source() == FailureSource::CommandLineOverride
    ));

    for key in [
        "DIAGNOSTICS__LOG_LEVEL",
        "POSITRON__",
        "POSITRON__diagnostics__LOG_LEVEL",
        "POSITRON__DIAGNOSTICS____LOG_LEVEL",
        "POSITRON__UNKNOWN__VALUE",
    ] {
        let result = inputs(None, [(key, "warn")], []).and_then(resolve);
        assert!(matches!(
            result,
            Err(error)
                if error.code() == ConfigurationFailureCode::UnknownSetting
                    && error.source() == FailureSource::EnvironmentOverride
        ));
    }

    let unknown_command_line = inputs(None, [], [("unknown.value", "warn")]).and_then(resolve);
    assert!(matches!(
        unknown_command_line,
        Err(error)
            if error.code() == ConfigurationFailureCode::UnknownSetting
                && error.source() == FailureSource::CommandLineOverride
    ));

    for (environment_key, source) in [
        ("POSITRON__SCHEMA_VERSION", FailureSource::SchemaVersion),
        (
            "POSITRON__STORAGE__DATA_DIRECTORY",
            FailureSource::StorageDataDirectory,
        ),
    ] {
        let result = inputs(None, [(environment_key, "1")], []).and_then(resolve);
        assert!(matches!(
            result,
            Err(error)
                if error.code() == ConfigurationFailureCode::UnknownSetting
                    && error.source() == source
        ));
    }

    let protected_command_line =
        inputs(None, [], [("security.local_key_file", "/private/root-key")]).and_then(resolve);
    assert!(matches!(
        protected_command_line,
        Err(error)
            if error.code() == ConfigurationFailureCode::SecretOverrideNotAllowed
                && error.source() == FailureSource::SecurityLocalKeyFile
    ));

    let file_only_command_line = inputs(
        None,
        [],
        [("storage.secrets_directory", "/private/secrets")],
    )
    .and_then(resolve);
    assert!(matches!(
        file_only_command_line,
        Err(error)
            if error.code() == ConfigurationFailureCode::UnknownSetting
                && error.source() == FailureSource::StorageSecretsDirectory
    ));
}

#[test]
fn accepts_exact_source_bounds_and_rejects_only_the_first_excess_byte() {
    let mut exact_document = String::from("schema_version = 1\n#");
    exact_document.push_str(&"x".repeat((16 * 1024) - exact_document.len()));
    let exact_document_result = inputs(Some(&exact_document), [], []).and_then(resolve);
    assert!(exact_document_result.is_ok());

    let oversized_document = format!("{exact_document}x");
    let oversized_document_result = inputs(Some(&oversized_document), [], []);
    assert!(matches!(
        oversized_document_result,
        Err(error)
            if error.code() == ConfigurationFailureCode::ResourceLimit
                && error.source() == FailureSource::ConfigurationDocument
    ));

    let exact_key = "K".repeat(64);
    assert!(EnvironmentOverrides::try_from_pairs([(exact_key.as_str(), "value")]).is_ok());
    let oversized_key = format!("{exact_key}K");
    assert!(matches!(
        EnvironmentOverrides::try_from_pairs([(oversized_key.as_str(), "value")]),
        Err(error)
            if error.code() == ConfigurationFailureCode::ResourceLimit
                && error.source() == FailureSource::EnvironmentOverride
    ));

    let exact_value = "v".repeat(256);
    assert!(
        CommandLineOverrides::try_from_pairs([("diagnostics.log_level", exact_value.as_str())])
            .is_ok()
    );
    let oversized_value = format!("{exact_value}v");
    assert!(matches!(
        CommandLineOverrides::try_from_pairs([(
            "diagnostics.log_level",
            oversized_value.as_str()
        )]),
        Err(error)
            if error.code() == ConfigurationFailureCode::ResourceLimit
                && error.source() == FailureSource::CommandLineOverride
    ));
}

#[test]
fn rejects_secret_and_unsafe_configuration_without_echoing_values() {
    let secret_override = inputs(
        None,
        [("POSITRON__SECURITY__LOCAL_KEY_FILE", "/private/secret")],
        [],
    )
    .and_then(resolve);
    assert!(matches!(
        secret_override,
        Err(error) if error.code() == ConfigurationFailureCode::SecretOverrideNotAllowed
    ));

    let unsafe_roots = inputs(
        Some(
            "schema_version = 1\n\
             [storage]\n\
             data_directory = \"/same\"\n\
             secrets_directory = \"/same\"\n",
        ),
        [],
        [],
    )
    .and_then(resolve);
    assert!(matches!(
        unsafe_roots,
        Err(error) if error.code() == ConfigurationFailureCode::UnsafeCombination
    ));
}

#[test]
fn rejects_empty_unknown_root_table_before_iterating_children() {
    let result = inputs(Some("schema_version = 1\n[unknown]\n"), [], []).and_then(resolve);

    assert!(matches!(
        result,
        Err(error)
            if error.code() == ConfigurationFailureCode::UnknownSetting
                && error.source() == FailureSource::ConfigurationDocument
    ));
}

#[test]
fn rejects_nonempty_unknown_root_table() {
    let result =
        inputs(Some("schema_version = 1\n[unknown]\nvalue = 1\n"), [], []).and_then(resolve);

    assert!(matches!(
        result,
        Err(error)
            if error.code() == ConfigurationFailureCode::UnknownSetting
                && error.source() == FailureSource::ConfigurationDocument
    ));
}

#[test]
fn rejects_unknown_or_non_table_root_sections_before_setting_application() {
    for document in [
        "schema_version = 1\nunknown = 1\n",
        "schema_version = 1\ndiagnostics = 1\n",
        "schema_version = 1\n[diagnostics]\nunknown = \"warn\"\n",
    ] {
        let result = inputs(Some(document), [], []).and_then(resolve);
        assert!(matches!(
            result,
            Err(error)
                if error.code() == ConfigurationFailureCode::UnknownSetting
                    && error.source() == FailureSource::ConfigurationDocument
        ));
    }
}

#[test]
fn accepts_known_empty_root_tables_without_changing_default_values()
-> Result<(), ConfigurationFailure> {
    let default_reference = inputs(None, [], []).and_then(resolve)?.redacted_reference();

    for section in ["diagnostics", "runtime", "listener", "storage", "security"] {
        let document = format!("schema_version = 1\n[{section}]\n");
        let effective = inputs(Some(&document), [], []).and_then(resolve)?;

        assert_eq!(effective.redacted_reference(), default_reference);
    }
    Ok(())
}

#[test]
fn returns_only_checked_mutability_plans_and_rejects_immutable_changes()
-> Result<(), ConfigurationFailure> {
    let current = inputs(None, [], []).and_then(resolve)?;
    let live = inputs(
        Some("schema_version = 1\n[diagnostics]\nlog_level = \"debug\"\n"),
        [],
        [],
    )
    .and_then(resolve)?;
    assert!(matches!(
        current.plan_update(&live)?,
        ConfigurationPlan::PublishLive { changed } if changed == vec![Setting::DiagnosticsLogLevel]
    ));

    let drain = inputs(
        Some(
            "schema_version = 1\n\
             [listener]\n\
             control_bind_address = \"127.0.0.1:4318\"\n",
        ),
        [],
        [],
    )
    .and_then(resolve)?;
    assert!(matches!(
        current.plan_update(&drain)?,
        ConfigurationPlan::DrainThenPublish { changed } if changed == vec![Setting::ListenerControlBindAddress]
    ));

    let restart = inputs(
        Some("schema_version = 1\n[runtime]\nshutdown_grace_seconds = 60\n"),
        [],
        [],
    )
    .and_then(resolve)?;
    assert!(matches!(
        current.plan_update(&restart)?,
        ConfigurationPlan::RestartRequired { changed } if changed == vec![Setting::RuntimeShutdownGraceSeconds]
    ));

    let immutable = inputs(
        Some("schema_version = 1\n[storage]\ndata_directory = \"/different\"\n"),
        [],
        [],
    )
    .and_then(resolve)?;
    assert!(matches!(
        current.plan_update(&immutable),
        Err(error) if error.code() == ConfigurationFailureCode::ImmutableSettingChanged
    ));
    Ok(())
}

#[test]
fn plans_no_change_and_mixed_mutability_with_closed_priority() -> Result<(), ConfigurationFailure> {
    let current = inputs(None, [], []).and_then(resolve)?;
    assert_eq!(current.plan_update(&current)?, ConfigurationPlan::NoChange);

    let live_and_drain = inputs(
        Some(
            "schema_version = 1\n\
             [diagnostics]\nlog_level = \"debug\"\n\
             [listener]\ncontrol_bind_address = \"127.0.0.1:4318\"\n",
        ),
        [],
        [],
    )
    .and_then(resolve)?;
    assert_eq!(
        current.plan_update(&live_and_drain)?,
        ConfigurationPlan::DrainThenPublish {
            changed: vec![
                Setting::DiagnosticsLogLevel,
                Setting::ListenerControlBindAddress,
            ],
        }
    );

    let every_mutable_class = inputs(
        Some(
            "schema_version = 1\n\
             [diagnostics]\nlog_level = \"debug\"\n\
             [runtime]\nshutdown_grace_seconds = 60\n\
             [listener]\ncontrol_bind_address = \"127.0.0.1:4318\"\n",
        ),
        [],
        [],
    )
    .and_then(resolve)?;
    assert_eq!(
        current.plan_update(&every_mutable_class)?,
        ConfigurationPlan::RestartRequired {
            changed: vec![
                Setting::DiagnosticsLogLevel,
                Setting::RuntimeShutdownGraceSeconds,
                Setting::ListenerControlBindAddress,
            ],
        }
    );
    Ok(())
}

#[test]
fn rejects_each_reachable_immutable_change_with_its_semantic_source()
-> Result<(), ConfigurationFailure> {
    let current = inputs(None, [], []).and_then(resolve)?;
    for (document, source) in [
        (
            "schema_version = 1\n[storage]\ndata_directory = \"/different-data\"\n",
            FailureSource::StorageDataDirectory,
        ),
        (
            "schema_version = 1\n[storage]\nsecrets_directory = \"/different-secrets\"\n",
            FailureSource::StorageSecretsDirectory,
        ),
        (
            "schema_version = 1\n[security]\nlocal_key_file = \"/different-secrets/root-key\"\n",
            FailureSource::SecurityLocalKeyFile,
        ),
    ] {
        let candidate = inputs(Some(document), [], []).and_then(resolve)?;
        let result = current.plan_update(&candidate);
        assert!(matches!(
            result,
            Err(error)
                if error.code() == ConfigurationFailureCode::ImmutableSettingChanged
                    && error.source() == source
        ));
    }

    let protected = inputs(
        Some(
            "schema_version = 1\n\
             [security]\n\
             local_key_file = \"/different-secrets/root-key\"\n",
        ),
        [],
        [],
    )
    .and_then(resolve)?;
    assert!(current.local_key_file() != protected.local_key_file());
    let protected_clone = protected.clone();
    assert!(protected.local_key_file() == protected_clone.local_key_file());
    let rendered = format!("{protected:?}");
    assert!(rendered.contains("local_key_file: \"<redacted>\""));
    assert!(!rendered.contains("different-secrets"));
    Ok(())
}

#[test]
fn requires_an_explicit_supported_schema_version_for_file_configuration()
-> Result<(), ConfigurationFailure> {
    let defaults = inputs(None, [], []).and_then(resolve)?;
    assert_eq!(defaults.schema_version(), 1);

    let missing = inputs(Some("[diagnostics]\nlog_level = \"warn\"\n"), [], []).and_then(resolve);
    assert!(matches!(
        missing,
        Err(error) if error.code() == ConfigurationFailureCode::MissingSchemaVersion
    ));

    let present = inputs(
        Some("schema_version = 1\n[diagnostics]\nlog_level = \"warn\"\n"),
        [],
        [],
    )
    .and_then(resolve)?;
    assert_eq!(present.schema_version(), 1);
    assert_eq!(present.log_level(), LogLevel::Warn);

    let unsupported = inputs(Some("schema_version = 2\n"), [], []).and_then(resolve);
    assert!(matches!(
        unsupported,
        Err(error)
            if error.code() == ConfigurationFailureCode::UnsupportedValue
                && error.source() == positron_config::FailureSource::SchemaVersion
    ));
    Ok(())
}

#[test]
fn generated_schema_and_reference_are_deterministic_and_secret_safe() {
    let first_schema = generated_json_schema();
    assert_eq!(first_schema, generated_json_schema());
    assert!(first_schema.contains("\"additionalProperties\": false"));
    assert!(first_schema.contains("\"schema_version\": {\"const\": 1}"));
    assert!(first_schema.contains("\"enum\": [\"error\", \"warn\", \"info\", \"debug\"]"));
    assert!(first_schema.contains("\"minimum\": 1, \"maximum\": 3600"));
    assert!(first_schema.contains("\"maxLength\": 256"));
    assert!(first_schema.contains("\"required\": [\"schema_version\"]"));
    assert!(first_schema.contains("\"writeOnly\": true"));

    let first_reference = generated_reference();
    assert_eq!(first_reference, generated_reference());
    assert!(first_reference.contains(
        "Precedence: compiled defaults, TOML file, non-secret POSITRON__ overrides, then non-secret CLI overrides."
    ));
    for path in [
        "schema_version",
        "diagnostics.log_level",
        "runtime.shutdown_grace_seconds",
        "listener.control_bind_address",
        "storage.data_directory",
        "storage.secrets_directory",
        "security.local_key_file",
    ] {
        assert!(first_reference.contains(&format!("`{path}`")));
    }
    for mutability in [
        "live-reloadable",
        "drain-and-reload",
        "restart-required",
        "immutable after initialization",
    ] {
        assert!(first_reference.contains(mutability));
    }
    assert!(first_reference.contains("secret-bearing (redacted)"));
    assert!(!first_reference.contains("/var/lib/positron-secrets/local-root-key"));
}

#[test]
fn rust_owned_definitions_keep_runtime_and_generated_constraints_in_parity()
-> Result<(), ConfigurationFailure> {
    let shutdown = setting_definition(Setting::RuntimeShutdownGraceSeconds);
    assert_eq!(shutdown.default_value(), "30");
    assert_eq!(
        shutdown.domain(),
        ValueDomain::UnsignedIntegerRange(1, 3600)
    );
    assert_eq!(
        inputs(None, [], [])
            .and_then(resolve)?
            .shutdown_grace_seconds(),
        30
    );
    for value in ["0", "3601"] {
        let rejected = inputs(
            Some(Box::leak(
                format!("schema_version = 1\n[runtime]\nshutdown_grace_seconds = {value}\n")
                    .into_boxed_str(),
            )),
            [],
            [],
        )
        .and_then(resolve);
        assert!(matches!(
            rejected,
            Err(error)
                if error.code() == ConfigurationFailureCode::UnsupportedValue
                    && error.source()
                        == positron_config::FailureSource::RuntimeShutdownGraceSeconds
        ));
    }

    let listener = setting_definition(Setting::ListenerControlBindAddress);
    assert_eq!(listener.domain(), ValueDomain::LoopbackSocketAddress(256));
    let non_loopback = inputs(
        Some(
            "schema_version = 1\n\
             [listener]\n\
             control_bind_address = \"0.0.0.0:4317\"\n",
        ),
        [],
        [],
    )
    .and_then(resolve);
    assert!(matches!(
        non_loopback,
        Err(error)
            if error.code() == ConfigurationFailureCode::UnsafeCombination
                && error.source()
                    == positron_config::FailureSource::ListenerControlBindAddress
    ));

    let schema = generated_json_schema();
    assert!(schema.contains("\"minimum\": 1, \"maximum\": 3600"));
    assert!(schema.contains("\"x-positron-address-scope\": \"loopback-only\""));
    Ok(())
}

#[test]
fn accepts_each_closed_value_and_exact_numeric_and_address_boundaries()
-> Result<(), ConfigurationFailure> {
    for (value, expected) in [
        ("error", LogLevel::Error),
        ("warn", LogLevel::Warn),
        ("info", LogLevel::Info),
        ("debug", LogLevel::Debug),
    ] {
        let document = format!("schema_version = 1\n[diagnostics]\nlog_level = \"{value}\"\n");
        let effective = inputs(Some(&document), [], []).and_then(resolve)?;
        assert_eq!(effective.log_level(), expected);
        assert!(
            effective
                .redacted_reference()
                .contains(&format!("log_level = \"{value}\""))
        );
    }

    for boundary in [1, 3600] {
        let document =
            format!("schema_version = 1\n[runtime]\nshutdown_grace_seconds = {boundary}\n");
        let effective = inputs(Some(&document), [], []).and_then(resolve)?;
        assert_eq!(effective.shutdown_grace_seconds(), boundary);
    }

    for address in ["127.0.0.1:1", "[::1]:65535"] {
        let document =
            format!("schema_version = 1\n[listener]\ncontrol_bind_address = \"{address}\"\n");
        let effective = inputs(Some(&document), [], []).and_then(resolve)?;
        assert_eq!(effective.control_bind_address().to_string(), address);
    }

    let maximum_path = format!("/{}", "a".repeat(255));
    let document = format!("schema_version = 1\n[storage]\ndata_directory = \"{maximum_path}\"\n");
    let effective = inputs(Some(&document), [], []).and_then(resolve)?;
    assert!(
        effective
            .redacted_reference()
            .contains(&format!("data_directory = \"{maximum_path}\""))
    );
    Ok(())
}

#[test]
fn rejects_invalid_shapes_and_values_from_each_closed_value_domain() {
    for (document, code, source) in [
        (
            "schema_version = \"1\"\n",
            ConfigurationFailureCode::Malformed,
            FailureSource::ConfigurationDocument,
        ),
        (
            "schema_version = -1\n",
            ConfigurationFailureCode::Malformed,
            FailureSource::SchemaVersion,
        ),
        (
            "schema_version = 65536\n",
            ConfigurationFailureCode::UnsupportedValue,
            FailureSource::SchemaVersion,
        ),
        (
            "schema_version = 1\n[diagnostics]\nlog_level = \"trace\"\n",
            ConfigurationFailureCode::UnsupportedValue,
            FailureSource::DiagnosticsLogLevel,
        ),
        (
            "schema_version = 1\n[diagnostics]\nlog_level = 1\n",
            ConfigurationFailureCode::Malformed,
            FailureSource::ConfigurationDocument,
        ),
        (
            "schema_version = 1\n[runtime]\nshutdown_grace_seconds = -1\n",
            ConfigurationFailureCode::Malformed,
            FailureSource::RuntimeShutdownGraceSeconds,
        ),
        (
            "schema_version = 1\n[runtime]\nshutdown_grace_seconds = 100000\n",
            ConfigurationFailureCode::Malformed,
            FailureSource::RuntimeShutdownGraceSeconds,
        ),
        (
            "schema_version = 1\n[runtime]\nshutdown_grace_seconds = 65536\n",
            ConfigurationFailureCode::UnsupportedValue,
            FailureSource::RuntimeShutdownGraceSeconds,
        ),
        (
            "schema_version = 1\n[runtime]\nshutdown_grace_seconds = \"30\"\n",
            ConfigurationFailureCode::Malformed,
            FailureSource::ConfigurationDocument,
        ),
        (
            "schema_version = 1\n[listener]\ncontrol_bind_address = \"not-an-address\"\n",
            ConfigurationFailureCode::Malformed,
            FailureSource::ListenerControlBindAddress,
        ),
        (
            "schema_version = 1\n[listener]\ncontrol_bind_address = 4317\n",
            ConfigurationFailureCode::Malformed,
            FailureSource::ConfigurationDocument,
        ),
        (
            "schema_version = 1\n[storage]\ndata_directory = \"\"\n",
            ConfigurationFailureCode::ResourceLimit,
            FailureSource::StorageDataDirectory,
        ),
        (
            "schema_version = 1\n[storage]\nsecrets_directory = \"relative\"\n",
            ConfigurationFailureCode::UnsafeCombination,
            FailureSource::StorageSecretsDirectory,
        ),
        (
            "schema_version = 1\n[security]\nlocal_key_file = \"/keys/../root-key\"\n",
            ConfigurationFailureCode::UnsafeCombination,
            FailureSource::SecurityLocalKeyFile,
        ),
        (
            "schema_version = 1\n[storage]\ndata_directory = 1\n",
            ConfigurationFailureCode::Malformed,
            FailureSource::ConfigurationDocument,
        ),
    ] {
        let result = inputs(Some(document), [], []).and_then(resolve);
        assert!(matches!(
            result,
            Err(error) if error.code() == code && error.source() == source
        ));
    }

    let non_loopback = inputs(
        Some("schema_version = 1\n[listener]\ncontrol_bind_address = \"192.0.2.1:4317\"\n"),
        [],
        [],
    )
    .and_then(resolve);
    assert!(matches!(
        non_loopback,
        Err(error)
            if error.code() == ConfigurationFailureCode::UnsafeCombination
                && error.source() == FailureSource::ListenerControlBindAddress
    ));

    for value in ["", "01", "not-a-number"] {
        let result = inputs(
            None,
            [("POSITRON__RUNTIME__SHUTDOWN_GRACE_SECONDS", value)],
            [],
        )
        .and_then(resolve);
        assert!(matches!(
            result,
            Err(error)
                if error.code() == ConfigurationFailureCode::Malformed
                    && error.source() == FailureSource::RuntimeShutdownGraceSeconds
        ));
    }
}

#[test]
fn raw_configuration_inputs_and_failures_never_format_secret_canaries() -> Result<(), Box<dyn Error>>
{
    const CANARY: &str = "never-render-this-secret-canary";
    let environment = EnvironmentOverrides::try_from_pairs([
        ("POSITRON__SECURITY__LOCAL_KEY_FILE", CANARY),
        ("POSITRON__DIAGNOSTICS__LOG_LEVEL", "warn"),
    ])?;
    let command_line = CommandLineOverrides::try_from_pairs([
        ("security.local_key_file", CANARY),
        ("diagnostics.log_level", "debug"),
    ])?;
    let configuration_inputs = ConfigurationInputs::try_new(
        Some(
            "schema_version = 1\n\
             [security]\n\
             local_key_file = \"/var/lib/positron-secrets/never-render-this-secret-canary\"\n",
        ),
        environment.clone(),
        command_line.clone(),
    )?;

    for rendered in [
        format!("{environment:?}"),
        format!("{command_line:?}"),
        format!("{configuration_inputs:?}"),
    ] {
        assert!(!rendered.contains(CANARY));
        assert!(rendered.contains("<redacted>"));
    }

    let forbidden = match resolve(configuration_inputs) {
        Err(error) => error,
        Ok(_) => {
            return Err(std::io::Error::other("secret override was not rejected").into());
        },
    };
    for rendered in [forbidden.to_string(), format!("{forbidden:?}")] {
        assert!(!rendered.contains(CANARY));
    }

    let malformed = match inputs(
        Some(
            "schema_version = 1\n[security]\nlocal_key_file = [\"never-render-this-secret-canary\"]\n",
        ),
        [],
        [],
    )
    .and_then(resolve)
    {
        Err(error) => error,
        Ok(_) => {
            return Err(std::io::Error::other("malformed secret input was not rejected").into());
        },
    };
    for rendered in [malformed.to_string(), format!("{malformed:?}")] {
        assert!(!rendered.contains(CANARY));
    }

    let protected = inputs(
        Some(
            "schema_version = 1\n\
             [security]\n\
             local_key_file = \"/var/lib/positron-secrets/never-render-this-secret-canary\"\n",
        ),
        [],
        [],
    )
    .and_then(resolve)?;
    assert!(!format!("{protected:?}").contains(CANARY));
    assert!(!protected.redacted_reference().contains(CANARY));
    assert_eq!(
        protected.source_for("security.local_key_file"),
        Some(SettingSource::ConfigurationFile)
    );
    Ok(())
}

#[test]
fn closed_failures_expose_stable_safe_details_for_every_failure_code() -> Result<(), Box<dyn Error>>
{
    let malformed = inputs(
        Some("schema_version = 1\n[diagnostics]\nlog_level = 1\n"),
        [],
        [],
    )
    .and_then(resolve)
    .err();
    let missing = inputs(Some("[diagnostics]\nlog_level = \"warn\"\n"), [], [])
        .and_then(resolve)
        .err();
    let unknown = inputs(Some("schema_version = 1\n[unknown]\n"), [], [])
        .and_then(resolve)
        .err();
    let unsupported = inputs(
        Some("schema_version = 1\n[diagnostics]\nlog_level = \"trace\"\n"),
        [],
        [],
    )
    .and_then(resolve)
    .err();
    let unsafe_combination = inputs(
        Some(
            "schema_version = 1\n\
             [storage]\n\
             data_directory = \"/same\"\n\
             secrets_directory = \"/same\"\n",
        ),
        [],
        [],
    )
    .and_then(resolve)
    .err();
    let conflicting = EnvironmentOverrides::try_from_pairs([
        ("POSITRON__DIAGNOSTICS__LOG_LEVEL", "warn"),
        ("POSITRON__DIAGNOSTICS__LOG_LEVEL", "debug"),
    ])
    .err();
    let secret_override = inputs(None, [], [("security.local_key_file", "/secret-canary")])
        .and_then(resolve)
        .err();
    let resource_limit =
        EnvironmentOverrides::try_from_pairs([("K".repeat(65), "resource-canary")]).err();

    let current = inputs(None, [], []).and_then(resolve)?;
    let immutable_candidate = inputs(
        Some("schema_version = 1\n[storage]\nsecrets_directory = \"/different-secrets\"\n"),
        [],
        [],
    )
    .and_then(resolve)?;
    let immutable = current.plan_update(&immutable_candidate).err();

    for (error, code, source, display) in [
        (
            malformed,
            ConfigurationFailureCode::Malformed,
            FailureSource::ConfigurationDocument,
            "malformed canonical configuration",
        ),
        (
            missing,
            ConfigurationFailureCode::MissingSchemaVersion,
            FailureSource::SchemaVersion,
            "configuration schema version is required",
        ),
        (
            unknown,
            ConfigurationFailureCode::UnknownSetting,
            FailureSource::ConfigurationDocument,
            "unknown configuration setting",
        ),
        (
            unsupported,
            ConfigurationFailureCode::UnsupportedValue,
            FailureSource::DiagnosticsLogLevel,
            "unsupported configuration value",
        ),
        (
            unsafe_combination,
            ConfigurationFailureCode::UnsafeCombination,
            FailureSource::StorageDataDirectory,
            "unsafe configuration combination",
        ),
        (
            conflicting,
            ConfigurationFailureCode::ConflictingSetting,
            FailureSource::EnvironmentOverride,
            "conflicting configuration setting",
        ),
        (
            secret_override,
            ConfigurationFailureCode::SecretOverrideNotAllowed,
            FailureSource::SecurityLocalKeyFile,
            "secret configuration override is not allowed",
        ),
        (
            resource_limit,
            ConfigurationFailureCode::ResourceLimit,
            FailureSource::EnvironmentOverride,
            "configuration resource limit exceeded",
        ),
        (
            immutable,
            ConfigurationFailureCode::ImmutableSettingChanged,
            FailureSource::StorageSecretsDirectory,
            "immutable initialized configuration changed",
        ),
    ] {
        assert!(error.is_some());
        if let Some(error) = error {
            assert_eq!(error.code(), code);
            assert_eq!(error.retry_class(), RetryClass::AfterInputCorrection);
            assert_eq!(error.completion_state(), CompletionState::Rejected);
            assert_eq!(error.source(), source);
            assert_eq!(error.to_string(), display);
            assert!(Error::source(&error).is_none());
            let debug = format!("{error:?}");
            assert!(debug.contains(&format!("{code:?}")));
            assert!(debug.contains(&format!("{source:?}")));
            assert!(!debug.contains("canary"));
        }
    }
    Ok(())
}

#[test]
fn accepts_canonical_toml_comments_and_escapes_and_rejects_ambiguous_documents()
-> Result<(), ConfigurationFailure> {
    let canonical = inputs(
        Some(
            "schema_version = 1 # required document version\n\
             [diagnostics] # ordinary inline table comment\n\
             log_level = \"w\\u0061rn\" # escaped TOML string\n\
             [security]\n\
             local_key_file = \"/var/lib/positron-secrets/l\\u006fcal-root-key\"\n",
        ),
        [],
        [],
    )
    .and_then(resolve)?;
    assert_eq!(canonical.log_level(), LogLevel::Warn);
    assert_eq!(
        canonical.source_for("security.local_key_file"),
        Some(SettingSource::ConfigurationFile)
    );

    let malformed = inputs(
        Some("schema_version = 1\n[diagnostics\nlog_level = \"warn\"\n"),
        [],
        [],
    )
    .and_then(resolve);
    assert!(matches!(
        malformed,
        Err(error) if error.code() == ConfigurationFailureCode::Malformed
    ));

    let duplicate =
        inputs(Some("schema_version = 1\nschema_version = 1\n"), [], []).and_then(resolve);
    assert!(matches!(
        duplicate,
        Err(error) if error.code() == ConfigurationFailureCode::Malformed
    ));

    let unsupported_value_shape = inputs(
        Some("schema_version = 1\n[diagnostics]\nlog_level = [\"warn\"]\n"),
        [],
        [],
    )
    .and_then(resolve);
    assert!(matches!(
        unsupported_value_shape,
        Err(error) if error.code() == ConfigurationFailureCode::Malformed
    ));

    let unknown = inputs(
        Some("schema_version = 1\n[diagnostics.extra]\nvalue = \"warn\"\n"),
        [],
        [],
    )
    .and_then(resolve);
    assert!(matches!(
        unknown,
        Err(error) if error.code() == ConfigurationFailureCode::Malformed
    ));
    Ok(())
}

#[test]
fn preflight_rejects_adversarial_toml_before_unbounded_parse_allocation() {
    let oversized = "x".repeat(16 * 1024 + 1);
    let oversized_rejected = inputs(Some(Box::leak(oversized.into_boxed_str())), [], []);
    assert!(matches!(
        oversized_rejected,
        Err(error)
            if error.code() == ConfigurationFailureCode::ResourceLimit
                && error.source() == positron_config::FailureSource::ConfigurationDocument
    ));

    for document in [
        "schema_version = 1\n[diagnostics.extra]\nvalue = \"warn\"\n",
        "schema_version = 1\n[diagnostics]\nlog_level = [\"warn\"]\n",
    ] {
        let rejected = inputs(Some(document), [], []).and_then(resolve);
        assert!(matches!(
            rejected,
            Err(error) if error.code() == ConfigurationFailureCode::Malformed
        ));
    }

    let mut many_entries = String::from("schema_version = 1\n[diagnostics]\n");
    for index in 0..17 {
        many_entries.push_str(&format!("entry_{index} = \"x\"\n"));
    }
    assert_resource_limit(&many_entries);

    let long_key = format!(
        "schema_version = 1\n[diagnostics]\n{} = \"x\"\n",
        "k".repeat(65)
    );
    assert_resource_limit(&long_key);

    let long_scalar = format!(
        "schema_version = 1\n[diagnostics]\nlog_level = \"{}\"\n",
        "x".repeat(257)
    );
    assert_resource_limit(&long_scalar);
}

#[test]
fn exact_preflight_entry_ceiling_is_not_reclassified_as_a_resource_failure() {
    let mut header_is_sixteenth = String::from("schema_version = 1\n");
    for index in 0..14 {
        header_is_sixteenth.push_str(&format!("unknown_{index} = 1\n"));
    }
    header_is_sixteenth.push_str("[diagnostics]\n");
    let header_result = inputs(Some(&header_is_sixteenth), [], []).and_then(resolve);
    assert!(matches!(
        header_result,
        Err(error)
            if error.code() == ConfigurationFailureCode::UnknownSetting
                && error.source() == FailureSource::ConfigurationDocument
    ));

    let mut scalar_is_sixteenth = String::from("schema_version = 1\n[diagnostics]\n");
    for index in 0..14 {
        scalar_is_sixteenth.push_str(&format!("unknown_{index} = 1\n"));
    }
    let scalar_result = inputs(Some(&scalar_is_sixteenth), [], []).and_then(resolve);
    assert!(matches!(
        scalar_result,
        Err(error)
            if error.code() == ConfigurationFailureCode::UnknownSetting
                && error.source() == FailureSource::ConfigurationDocument
    ));

    scalar_is_sixteenth.push_str("first_excess_entry = 1\n");
    assert_resource_limit(&scalar_is_sixteenth);
}

#[test]
fn preflight_tracks_comments_strings_and_escapes_without_replacing_toml_syntax() {
    let accepted = inputs(
        Some(
            "schema_version = 1 # [not.a.table] = [\"not\", \"an\", \"array\"]\n\
             [diagnostics]\n\
             log_level = \"w\\u0061rn\" # trailing delimiters []= are comments\n\
             [security]\n\
             local_key_file = \"/var/lib/positron-secrets/key#[]=\"\n",
        ),
        [],
        [],
    )
    .and_then(resolve);
    assert!(accepted.is_ok());

    for malformed in [
        "schema_version = 1\n[diagnostics]\nlog_level = \"unterminated\n",
        "schema_version = 1\n[[diagnostics]]\nlog_level = \"warn\"\n",
    ] {
        let rejected = inputs(Some(malformed), [], []).and_then(resolve);
        assert!(matches!(
            rejected,
            Err(error) if error.code() == ConfigurationFailureCode::Malformed
        ));
    }
}

#[test]
fn comment_markers_inside_supported_string_forms_preserve_the_complete_value()
-> Result<(), ConfigurationFailure> {
    let escaped_double = inputs(
        Some(
            "schema_version = 1\n\
             [security]\n\
             local_key_file = \"/keys/root\\\"key#tail=value\"\n",
        ),
        [],
        [],
    )
    .and_then(resolve)?;
    let equivalent_single = inputs(
        Some(
            "schema_version = 1\n\
             [security]\n\
             local_key_file = '/keys/root\"key#tail=value'\n",
        ),
        [],
        [],
    )
    .and_then(resolve)?;
    assert!(escaped_double.local_key_file() == equivalent_single.local_key_file());

    let single_quoted = inputs(
        Some(
            "schema_version = 1\n\
             [security]\n\
             local_key_file = '/keys/root#tail=value'\n",
        ),
        [],
        [],
    )
    .and_then(resolve)?;
    let equivalent_double = inputs(
        Some(
            "schema_version = 1\n\
             [security]\n\
             local_key_file = \"/keys/root#tail=value\"\n",
        ),
        [],
        [],
    )
    .and_then(resolve)?;
    assert!(single_quoted.local_key_file() == equivalent_double.local_key_file());
    Ok(())
}

#[test]
fn malformed_quote_state_precedes_scalar_resource_classification() {
    let unterminated_under_limit =
        inputs(Some("schema_version = \"unterminated\n"), [], []).and_then(resolve);
    assert_document_rejection(
        unterminated_under_limit,
        ConfigurationFailureCode::Malformed,
    );

    let well_formed_over_limit = format!("schema_version = \"{}\"\n", "1".repeat(257));
    assert_document_rejection(
        inputs(Some(&well_formed_over_limit), [], []).and_then(resolve),
        ConfigurationFailureCode::ResourceLimit,
    );

    let unterminated_over_limit = format!("schema_version = \"{}\n", "1".repeat(257));
    assert_document_rejection(
        inputs(Some(&unterminated_over_limit), [], []).and_then(resolve),
        ConfigurationFailureCode::Malformed,
    );
}

#[test]
fn quoted_key_separator_scanning_preserves_syntax_and_resource_precedence() {
    for quoted_key in ["\"unknown=key\"", "'unknown=key'", "\"unknown\\\"=key\""] {
        let document = format!("schema_version = 1\n{quoted_key} = 1\n");
        assert_document_rejection(
            inputs(Some(&document), [], []).and_then(resolve),
            ConfigurationFailureCode::Malformed,
        );
    }

    let exact_key = format!("\"{}=\"", "k".repeat(61));
    assert_eq!(exact_key.len(), 64);
    let exact_document = format!("schema_version = 1\n{exact_key} = 1\n");
    assert_document_rejection(
        inputs(Some(&exact_document), [], []).and_then(resolve),
        ConfigurationFailureCode::Malformed,
    );

    let oversized_key = format!("\"{}=\"", "k".repeat(62));
    assert_eq!(oversized_key.len(), 65);
    let oversized_document = format!("schema_version = 1\n{oversized_key} = 1\n");
    assert_document_rejection(
        inputs(Some(&oversized_document), [], []).and_then(resolve),
        ConfigurationFailureCode::ResourceLimit,
    );
}

#[test]
fn basic_string_escape_state_preserves_complete_values_and_failure_precedence()
-> Result<(), ConfigurationFailure> {
    let escaped_backslash = inputs(
        Some(
            "schema_version = 1\n\
             [security]\n\
             local_key_file = \"/keys/root\\\\branch#=tail\"\n",
        ),
        [],
        [],
    )
    .and_then(resolve)?;
    let literal_backslash = inputs(
        Some(
            "schema_version = 1\n\
             [security]\n\
             local_key_file = '/keys/root\\branch#=tail'\n",
        ),
        [],
        [],
    )
    .and_then(resolve)?;
    assert!(escaped_backslash.local_key_file() == literal_backslash.local_key_file());

    let escaped_quote = inputs(
        Some(
            "schema_version = 1\n\
             [security]\n\
             local_key_file = \"/keys/root\\\"quote#=tail\"\n",
        ),
        [],
        [],
    )
    .and_then(resolve)?;
    let literal_quote = inputs(
        Some(
            "schema_version = 1\n\
             [security]\n\
             local_key_file = '/keys/root\"quote#=tail'\n",
        ),
        [],
        [],
    )
    .and_then(resolve)?;
    assert!(escaped_quote.local_key_file() == literal_quote.local_key_file());

    let oversized_after_escaped_quote = format!(
        "schema_version = 1\n[security]\nlocal_key_file = \"/keys/root\\\"#={}\"\n",
        "x".repeat(250)
    );
    assert_document_rejection(
        inputs(Some(&oversized_after_escaped_quote), [], []).and_then(resolve),
        ConfigurationFailureCode::ResourceLimit,
    );
    Ok(())
}

#[test]
fn quoted_key_quote_state_preserves_complete_token_boundaries() {
    for quoted_key in [
        "\"unknown\\\\key#=tail\"",
        "\"unknown\\\"quote#=tail\"",
        "'unknown=key#tail'",
        "''",
    ] {
        let document = format!("schema_version = 1\n{quoted_key} = 1\n");
        assert_document_rejection(
            inputs(Some(&document), [], []).and_then(resolve),
            ConfigurationFailureCode::Malformed,
        );
    }

    let exact_basic_key = format!("\"{}\\\"=#\"", "b".repeat(58));
    assert_eq!(exact_basic_key.len(), 64);
    let exact_basic_document = format!("schema_version = 1\n{exact_basic_key} = 1\n");
    assert_document_rejection(
        inputs(Some(&exact_basic_document), [], []).and_then(resolve),
        ConfigurationFailureCode::Malformed,
    );

    let oversized_basic_key = format!("\"{}\\\"=#\"", "b".repeat(59));
    assert_eq!(oversized_basic_key.len(), 65);
    let oversized_basic_document = format!("schema_version = 1\n{oversized_basic_key} = 1\n");
    assert_document_rejection(
        inputs(Some(&oversized_basic_document), [], []).and_then(resolve),
        ConfigurationFailureCode::ResourceLimit,
    );

    let exact_literal_key = format!("'{}=#'", "l".repeat(60));
    assert_eq!(exact_literal_key.len(), 64);
    let exact_literal_document = format!("schema_version = 1\n{exact_literal_key} = 1\n");
    assert_document_rejection(
        inputs(Some(&exact_literal_document), [], []).and_then(resolve),
        ConfigurationFailureCode::Malformed,
    );

    let oversized_literal_key = format!("'{}=#'", "l".repeat(61));
    assert_eq!(oversized_literal_key.len(), 65);
    let oversized_literal_document = format!("schema_version = 1\n{oversized_literal_key} = 1\n");
    assert_document_rejection(
        inputs(Some(&oversized_literal_document), [], []).and_then(resolve),
        ConfigurationFailureCode::ResourceLimit,
    );

    for unmatched in [
        "schema_version = 1\n'unterminated=# = 1\n",
        "schema_version = 1\n[security]\nlocal_key_file = '/keys/root=#tail\n",
    ] {
        assert_document_rejection(
            inputs(Some(unmatched), [], []).and_then(resolve),
            ConfigurationFailureCode::Malformed,
        );
    }
}

#[test]
fn array_table_syntax_precedes_ordinary_table_name_resource_classification() {
    let long_array_name = "a".repeat(63);
    let incomplete_long_array_name = "a".repeat(65);
    for document in [
        String::from("[[diagnostics]]\n"),
        format!("[[{long_array_name}]]\n"),
        String::from("[[diagnostics]\n"),
        String::from("[[diagnostics\n"),
        format!("[[{incomplete_long_array_name}\n"),
    ] {
        assert_document_rejection(
            inputs(Some(&document), [], []).and_then(resolve),
            ConfigurationFailureCode::Malformed,
        );
    }

    let exact_single_table = format!("schema_version = 1\n[{}]\n", "t".repeat(64));
    assert_document_rejection(
        inputs(Some(&exact_single_table), [], []).and_then(resolve),
        ConfigurationFailureCode::UnknownSetting,
    );

    let oversized_single_table = format!("schema_version = 1\n[{}]\n", "t".repeat(65));
    assert_document_rejection(
        inputs(Some(&oversized_single_table), [], []).and_then(resolve),
        ConfigurationFailureCode::ResourceLimit,
    );
}

#[test]
fn preflight_rejects_each_reachable_malformed_or_oversized_lexical_shape() {
    for document in [
        "schema_version 1\n",
        "= 1\n",
        "schema.version = 1\n",
        "schema?version = 1\n",
        "schema_version =\n",
        "schema_version = { value = 1 }\n",
        "schema_version = \"\"\"1\"\"\"\n",
        "schema_version = '''1'''\n",
        "schema_version = 'unterminated\n",
        "schema_version = \"unterminated\\\n",
        "schema_version = nope\n",
        "[]\n",
        "[diagnostics?]\n",
    ] {
        let rejected = inputs(Some(document), [], []).and_then(resolve);
        assert!(matches!(
            rejected,
            Err(error)
                if error.code() == ConfigurationFailureCode::Malformed
                    && error.source() == FailureSource::ConfigurationDocument
        ));
    }

    let oversized_header = format!("[{}]\n", "s".repeat(65));
    assert_resource_limit(&oversized_header);

    let oversized_bare_scalar = format!("schema_version = {}\n", "1".repeat(257));
    assert_resource_limit(&oversized_bare_scalar);
}

#[test]
fn preflight_name_boundaries_preserve_unknown_and_malformed_classification() {
    for document in [
        "schema_version = 1\n[unknown_section]\n",
        "schema_version = 1\n[unknown-section]\n",
    ] {
        let result = inputs(Some(document), [], []).and_then(resolve);
        assert!(matches!(
            result,
            Err(error)
                if error.code() == ConfigurationFailureCode::UnknownSetting
                    && error.source() == FailureSource::ConfigurationDocument
        ));
    }

    for document in [
        "schema_version = 1\n[\"diagnostics\"]\n",
        "\"schema_version\" = 1\n",
    ] {
        let result = inputs(Some(document), [], []).and_then(resolve);
        assert!(matches!(
            result,
            Err(error)
                if error.code() == ConfigurationFailureCode::Malformed
                    && error.source() == FailureSource::ConfigurationDocument
        ));
    }

    let exact_header = format!("schema_version = 1\n[{}]\n", "h".repeat(64));
    let exact_header_result = inputs(Some(&exact_header), [], []).and_then(resolve);
    assert!(matches!(
        exact_header_result,
        Err(error)
            if error.code() == ConfigurationFailureCode::UnknownSetting
                && error.source() == FailureSource::ConfigurationDocument
    ));
    let oversized_header = format!("schema_version = 1\n[{}]\n", "h".repeat(65));
    assert_resource_limit(&oversized_header);

    let exact_key = format!("schema_version = 1\n{} = 1\n", "k".repeat(64));
    let exact_key_result = inputs(Some(&exact_key), [], []).and_then(resolve);
    assert!(matches!(
        exact_key_result,
        Err(error)
            if error.code() == ConfigurationFailureCode::UnknownSetting
                && error.source() == FailureSource::ConfigurationDocument
    ));
    let oversized_key = format!("schema_version = 1\n{} = 1\n", "k".repeat(65));
    assert_resource_limit(&oversized_key);
}

#[test]
fn listener_byte_ceiling_precedes_address_parsing_only_after_the_ceiling() {
    let exact_value = "x".repeat(256);
    let exact_command_line = CommandLineOverrides::try_from_pairs([(
        "listener.control_bind_address",
        exact_value.as_str(),
    )]);
    assert!(exact_command_line.is_ok());
    let exact_result = exact_command_line.and_then(|command_line| {
        EnvironmentOverrides::try_from_pairs(std::iter::empty::<(&str, &str)>())
            .and_then(|environment| ConfigurationInputs::try_new(None, environment, command_line))
    });
    let exact_result = exact_result.and_then(resolve);
    assert!(matches!(
        exact_result,
        Err(error)
            if error.code() == ConfigurationFailureCode::Malformed
                && error.source() == FailureSource::ListenerControlBindAddress
    ));

    let oversized_value = "x".repeat(257);
    let oversized_result = CommandLineOverrides::try_from_pairs([(
        "listener.control_bind_address",
        oversized_value.as_str(),
    )])
    .and_then(|command_line| {
        EnvironmentOverrides::try_from_pairs(std::iter::empty::<(&str, &str)>())
            .and_then(|environment| ConfigurationInputs::try_new(None, environment, command_line))
    })
    .and_then(resolve);
    assert!(matches!(
        oversized_result,
        Err(error)
            if error.code() == ConfigurationFailureCode::ResourceLimit
                && error.source() == FailureSource::CommandLineOverride
    ));
}

#[test]
fn preflight_preserves_blank_lines_single_quoted_literals_and_escaped_quotes()
-> Result<(), ConfigurationFailure> {
    let effective = inputs(
        Some(
            "# a full-line comment containing []={}\n\
             \n\
             schema_version = 1 # inline comment\n\
             [diagnostics]\n\
             log_level = \"w\\u0061rn\"\n\
             [security]\n\
             local_key_file = '/keys/root=key#[]{}'\n",
        ),
        [],
        [],
    )
    .and_then(resolve)?;

    assert_eq!(effective.log_level(), LogLevel::Warn);
    assert_eq!(
        effective.source_for("security.local_key_file"),
        Some(SettingSource::ConfigurationFile)
    );

    let escaped_quote = inputs(
        Some(
            "schema_version = 1\n\
             [security]\n\
             local_key_file = \"/keys/root\\\"key#[]=value\"\n",
        ),
        [],
        [],
    )
    .and_then(resolve)?;
    assert_eq!(
        escaped_quote.source_for("security.local_key_file"),
        Some(SettingSource::ConfigurationFile)
    );
    Ok(())
}

fn assert_resource_limit(document: &str) {
    let rejected = inputs(
        Some(Box::leak(document.to_owned().into_boxed_str())),
        [],
        [],
    )
    .and_then(resolve);
    assert!(matches!(
        rejected,
        Err(error)
            if error.code() == ConfigurationFailureCode::ResourceLimit
                && error.source() == positron_config::FailureSource::ConfigurationDocument
    ));
}

fn assert_document_rejection<T>(
    result: Result<T, ConfigurationFailure>,
    code: ConfigurationFailureCode,
) {
    assert!(matches!(
        result,
        Err(error)
            if error.code() == code
                && error.source() == FailureSource::ConfigurationDocument
                && error.retry_class() == RetryClass::AfterInputCorrection
                && error.completion_state() == CompletionState::Rejected
    ));
}

fn inputs(
    file: Option<&str>,
    environment_pairs: impl IntoIterator<Item = (&'static str, &'static str)>,
    command_line_pairs: impl IntoIterator<Item = (&'static str, &'static str)>,
) -> Result<ConfigurationInputs, ConfigurationFailure> {
    let environment = EnvironmentOverrides::try_from_pairs(environment_pairs)?;
    let command_line = CommandLineOverrides::try_from_pairs(command_line_pairs)?;
    ConfigurationInputs::try_new(file, environment, command_line)
}
