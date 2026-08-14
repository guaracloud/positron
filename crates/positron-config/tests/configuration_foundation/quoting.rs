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
