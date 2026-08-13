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
        "listener.operations_bind_address",
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
                && error.source() == FailureSource::ListenerOperationsBindAddress
    ));

    let oversized_value = "x".repeat(257);
    let oversized_result = CommandLineOverrides::try_from_pairs([(
        "listener.operations_bind_address",
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
