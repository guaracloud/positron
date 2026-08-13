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

    let listener = setting_definition(Setting::ListenerOperationsBindAddress);
    assert_eq!(listener.domain(), ValueDomain::LoopbackSocketAddress(256));
    let non_loopback = inputs(
        Some(
            "schema_version = 1\n\
             [listener]\n\
             operations_bind_address = \"0.0.0.0:4317\"\n",
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
                    == positron_config::FailureSource::ListenerOperationsBindAddress
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
            format!("schema_version = 1\n[listener]\noperations_bind_address = \"{address}\"\n");
        let effective = inputs(Some(&document), [], []).and_then(resolve)?;
        assert_eq!(effective.operations_bind_address().to_string(), address);
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
            "schema_version = 1\n[listener]\noperations_bind_address = \"not-an-address\"\n",
            ConfigurationFailureCode::Malformed,
            FailureSource::ListenerOperationsBindAddress,
        ),
        (
            "schema_version = 1\n[listener]\noperations_bind_address = 4317\n",
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
        Some("schema_version = 1\n[listener]\noperations_bind_address = \"192.0.2.1:4317\"\n"),
        [],
        [],
    )
    .and_then(resolve);
    assert!(matches!(
        non_loopback,
        Err(error)
            if error.code() == ConfigurationFailureCode::UnsafeCombination
                && error.source() == FailureSource::ListenerOperationsBindAddress
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
