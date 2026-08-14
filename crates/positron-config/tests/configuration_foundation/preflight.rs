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
