//! Public contract tests for the M0 Configuration foundation.

use std::error::Error;

use positron_config::{
    CommandLineOverrides, ConfigurationFailure, ConfigurationFailureCode, ConfigurationInputs,
    ConfigurationPlan, EnvironmentOverrides, LogLevel, Setting, SettingSource,
    generated_json_schema, generated_reference, resolve,
};

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
fn rejects_unknown_secret_and_unsafe_configuration_without_echoing_values() {
    let unknown =
        inputs(Some("schema_version = 1\n[unknown]\nvalue = 1\n"), [], []).and_then(resolve);
    assert!(matches!(
        unknown,
        Err(error) if error.code() == ConfigurationFailureCode::UnknownSetting
    ));

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
    assert!(first_schema.contains("\"writeOnly\": true"));
    let first_reference = generated_reference();
    assert_eq!(first_reference, generated_reference());
    assert!(first_reference.contains("`listener.control_bind_address`"));
    assert!(first_reference.contains("secret-bearing (redacted)"));
    assert!(!first_reference.contains("/var/lib/positron-secrets/local-root-key"));
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
        Err(error) if error.code() == ConfigurationFailureCode::InvalidSyntax
    ));

    let duplicate =
        inputs(Some("schema_version = 1\nschema_version = 1\n"), [], []).and_then(resolve);
    assert!(matches!(
        duplicate,
        Err(error) if error.code() == ConfigurationFailureCode::InvalidSyntax
    ));

    let unsupported_value_shape = inputs(
        Some("schema_version = 1\n[diagnostics]\nlog_level = [\"warn\"]\n"),
        [],
        [],
    )
    .and_then(resolve);
    assert!(matches!(
        unsupported_value_shape,
        Err(error) if error.code() == ConfigurationFailureCode::InvalidSyntax
    ));

    let unknown = inputs(
        Some("schema_version = 1\n[diagnostics.extra]\nvalue = \"warn\"\n"),
        [],
        [],
    )
    .and_then(resolve);
    assert!(matches!(
        unknown,
        Err(error) if error.code() == ConfigurationFailureCode::UnknownSetting
    ));
    Ok(())
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
