//! Public contract tests for the M0 Configuration foundation.

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
    let unknown = inputs(Some("[unknown]\nvalue = 1\n"), [], []).and_then(resolve);
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
            "[storage]\n\
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
    let live = inputs(Some("[diagnostics]\nlog_level = \"debug\"\n"), [], []).and_then(resolve)?;
    assert!(matches!(
        current.plan_update(&live)?,
        ConfigurationPlan::PublishLive { changed } if changed == vec![Setting::DiagnosticsLogLevel]
    ));

    let drain = inputs(
        Some("[listener]\ncontrol_bind_address = \"127.0.0.1:4318\"\n"),
        [],
        [],
    )
    .and_then(resolve)?;
    assert!(matches!(
        current.plan_update(&drain)?,
        ConfigurationPlan::DrainThenPublish { changed } if changed == vec![Setting::ListenerControlBindAddress]
    ));

    let restart =
        inputs(Some("[runtime]\nshutdown_grace_seconds = 60\n"), [], []).and_then(resolve)?;
    assert!(matches!(
        current.plan_update(&restart)?,
        ConfigurationPlan::RestartRequired { changed } if changed == vec![Setting::RuntimeShutdownGraceSeconds]
    ));

    let immutable =
        inputs(Some("[storage]\ndata_directory = \"/different\"\n"), [], []).and_then(resolve)?;
    assert!(matches!(
        current.plan_update(&immutable),
        Err(error) if error.code() == ConfigurationFailureCode::ImmutableSettingChanged
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

fn inputs(
    file: Option<&str>,
    environment_pairs: impl IntoIterator<Item = (&'static str, &'static str)>,
    command_line_pairs: impl IntoIterator<Item = (&'static str, &'static str)>,
) -> Result<ConfigurationInputs, ConfigurationFailure> {
    let environment = EnvironmentOverrides::try_from_pairs(environment_pairs)?;
    let command_line = CommandLineOverrides::try_from_pairs(command_line_pairs)?;
    ConfigurationInputs::try_new(file, environment, command_line)
}
