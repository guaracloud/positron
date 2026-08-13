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
             operations_bind_address = \"[::1]:4318\"\n\
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
    assert_eq!(
        effective.operations_bind_address().to_string(),
        "[::1]:4318"
    );
    for setting in [
        Setting::SchemaVersion,
        Setting::DiagnosticsLogLevel,
        Setting::RuntimeShutdownGraceSeconds,
        Setting::ListenerOperationsBindAddress,
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
    assert!(rendered.contains("operations_bind_address = \"[::1]:4318\""));
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
        (
            "POSITRON__LISTENER__OPERATIONS_BIND_ADDRESS",
            "127.0.0.1:4319",
        ),
    ])?;
    let environment_effective = resolve(ConfigurationInputs::try_new(
        Some(
            "schema_version = 1\n\
             [diagnostics]\nlog_level = \"error\"\n\
             [runtime]\nshutdown_grace_seconds = 1\n\
             [listener]\noperations_bind_address = \"127.0.0.1:4318\"\n",
        ),
        environment.clone(),
        CommandLineOverrides::try_from_pairs([] as [(&str, &str); 0])?,
    )?)?;
    assert_eq!(environment_effective.log_level(), LogLevel::Warn);
    assert_eq!(environment_effective.shutdown_grace_seconds(), 2);
    assert_eq!(
        environment_effective.operations_bind_address().to_string(),
        "127.0.0.1:4319"
    );
    for path in [
        "diagnostics.log_level",
        "runtime.shutdown_grace_seconds",
        "listener.operations_bind_address",
    ] {
        assert_eq!(
            environment_effective.source_for(path),
            Some(SettingSource::Environment)
        );
    }

    let command_line = CommandLineOverrides::try_from_pairs([
        ("diagnostics.log_level", "debug"),
        ("runtime.shutdown_grace_seconds", "3600"),
        ("listener.operations_bind_address", "[::1]:4320"),
    ])?;
    let command_line_effective = resolve(ConfigurationInputs::try_new(
        None,
        environment,
        command_line,
    )?)?;
    assert_eq!(command_line_effective.log_level(), LogLevel::Debug);
    assert_eq!(command_line_effective.shutdown_grace_seconds(), 3600);
    assert_eq!(
        command_line_effective.operations_bind_address().to_string(),
        "[::1]:4320"
    );
    for path in [
        "diagnostics.log_level",
        "runtime.shutdown_grace_seconds",
        "listener.operations_bind_address",
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
