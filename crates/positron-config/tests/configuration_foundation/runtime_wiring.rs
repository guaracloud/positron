#[test]
fn runtime_endpoints_and_key_path_are_explicit_typed_configuration() {
    let effective = inputs(
        Some(
            "schema_version = 1\n\
             [listener]\n\
             control_path = \"/tmp/positron-explicit.sock\"\n\
             operations_bind_address = \"127.0.0.1:19101\"\n\
             api_bind_address = \"127.0.0.1:19102\"\n\
             otlp_grpc_bind_address = \"127.0.0.1:19103\"\n\
             otlp_http_bind_address = \"127.0.0.1:19104\"\n\
             [storage]\n\
             data_directory = \"/srv/positron\"\n\
             secrets_directory = \"/srv/positron-secrets\"\n\
             [security]\n\
             local_key_file = \"/srv/positron-secrets/local-root-key.v1\"\n",
        ),
        [],
        [],
    )
    .and_then(resolve)
    .expect("explicit runtime wiring resolves");

    assert_eq!(effective.control_path(), "/tmp/positron-explicit.sock");
    assert_eq!(
        effective.operations_bind_address().to_string(),
        "127.0.0.1:19101"
    );
    assert_eq!(effective.api_bind_address().to_string(), "127.0.0.1:19102");
    assert_eq!(
        effective.otlp_grpc_bind_address().to_string(),
        "127.0.0.1:19103"
    );
    assert_eq!(
        effective.otlp_http_bind_address().to_string(),
        "127.0.0.1:19104"
    );
    assert_eq!(
        effective.local_key_file().as_path().to_str(),
        Some("/srv/positron-secrets/local-root-key.v1")
    );
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
