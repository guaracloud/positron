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
             operations_bind_address = \"127.0.0.1:4318\"\n",
        ),
        [],
        [],
    )
    .and_then(resolve)?;
    assert!(matches!(
        current.plan_update(&drain)?,
        ConfigurationPlan::DrainThenPublish { changed } if changed == vec![Setting::ListenerOperationsBindAddress]
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
             [listener]\noperations_bind_address = \"127.0.0.1:4318\"\n",
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
                Setting::ListenerOperationsBindAddress,
            ],
        }
    );

    let every_mutable_class = inputs(
        Some(
            "schema_version = 1\n\
             [diagnostics]\nlog_level = \"debug\"\n\
             [runtime]\nshutdown_grace_seconds = 60\n\
             [listener]\noperations_bind_address = \"127.0.0.1:4318\"\n",
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
                Setting::ListenerOperationsBindAddress,
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
        "listener.operations_bind_address",
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
