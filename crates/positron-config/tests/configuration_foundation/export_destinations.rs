use positron_config::TenantId;

#[test]
fn resolves_only_explicitly_configured_destinations_for_their_allowed_tenants()
-> Result<(), ConfigurationFailure> {
    let tenant = TenantId::parse_canonical("11111111-1111-1111-1111-111111111111")
        .expect("canonical tenant");
    let other_tenant = TenantId::parse_canonical("22222222-2222-2222-2222-222222222222")
        .expect("canonical tenant");
    let effective = resolve(export_inputs(Some(
        "schema_version = 1\n\
         [[export.destination]]\n\
         name = \"regulated-archive\"\n\
         identity = \"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1\"\n\
         allowed_tenants = [\"11111111-1111-1111-1111-111111111111\"]\n",
    ))?)?;

    let destination = effective
        .export_destination(tenant, "regulated-archive")
        .expect("authorized configured destination");
    assert_eq!(destination.name(), "regulated-archive");
    assert_eq!(destination.identity(), [0xa1; 16]);
    assert_eq!(destination.tenant_id(), tenant);
    assert_eq!(
        effective.source_for("export.destination"),
        Some(SettingSource::ConfigurationFile)
    );
    assert!(effective
        .redacted_reference()
        .contains("[[export.destination]]"));
    assert!(effective
        .export_destination(other_tenant, "regulated-archive")
        .is_none());
    assert!(effective.export_destination(tenant, "unknown").is_none());
    Ok(())
}

#[test]
fn rejects_more_than_the_bounded_number_of_export_destinations() {
    let mut document = String::from("schema_version = 1\n");
    for index in 1_u8..=9 {
        document.push_str("[[export.destination]]\nname = \"destination-");
        document.push_str(&index.to_string());
        document.push_str("\"\nidentity = \"");
        document.push_str(&format!("{index:02x}").repeat(16));
        document.push_str("\"\nallowed_tenants = [\"11111111-1111-1111-1111-111111111111\"]\n");
    }
    let result = export_inputs(Some(&document)).and_then(resolve);
    assert!(matches!(
        result,
        Err(error)
            if error.code() == ConfigurationFailureCode::UnsupportedValue
                && error.source() == FailureSource::ExportDestinations
    ));
}

#[test]
fn absence_of_configured_destinations_disables_durable_export()
-> Result<(), ConfigurationFailure> {
    let tenant = TenantId::parse_canonical("11111111-1111-1111-1111-111111111111")
        .expect("canonical tenant");
    let effective = resolve(export_inputs(Some("schema_version = 1\n"))?)?;

    assert!(effective.export_destination(tenant, "regulated-archive").is_none());
    assert!(!effective.durable_exports_enabled());
    Ok(())
}

#[test]
fn rejects_malformed_or_ambiguous_export_destination_configuration() {
    for document in [
        "schema_version = 1\n[[export.destination]]\nname = \"bad\"\nidentity = \"not-hex\"\nallowed_tenants = [\"11111111-1111-1111-1111-111111111111\"]\n",
        "schema_version = 1\n[[export.destination]]\nname = \"duplicate\"\nidentity = \"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1\"\nallowed_tenants = [\"11111111-1111-1111-1111-111111111111\", \"11111111-1111-1111-1111-111111111111\"]\n",
        "schema_version = 1\n[[export.destination]]\nname = \"one\"\nidentity = \"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1\"\nallowed_tenants = [\"11111111-1111-1111-1111-111111111111\"]\n[[export.destination]]\nname = \"two\"\nidentity = \"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1\"\nallowed_tenants = [\"22222222-2222-2222-2222-222222222222\"]\n",
        "schema_version = 1\n[[export.destination]]\nname = \"one\"\nidentity = \"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1\"\nallowed_tenants = [\"11111111-1111-1111-1111-111111111111\"]\n[[export.destination]]\nname = \"one\"\nidentity = \"b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2\"\nallowed_tenants = [\"22222222-2222-2222-2222-222222222222\"]\n",
    ] {
        let result = export_inputs(Some(document)).and_then(resolve);
        assert!(matches!(
            result,
            Err(error)
                if error.code() == ConfigurationFailureCode::UnsupportedValue
                    && error.source() == FailureSource::ExportDestinations
        ));
    }
}

#[test]
fn keeps_export_destinations_file_only_and_immutable() -> Result<(), ConfigurationFailure> {
    let document = "schema_version = 1\n[[export.destination]]\nname = \"regulated-archive\"\nidentity = \"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1\"\nallowed_tenants = [\"11111111-1111-1111-1111-111111111111\"]\n";
    let current = resolve(export_inputs(Some(document))?)?;
    let changed = resolve(export_inputs(Some(
        "schema_version = 1\n[[export.destination]]\nname = \"regulated-archive\"\nidentity = \"b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2\"\nallowed_tenants = [\"11111111-1111-1111-1111-111111111111\"]\n",
    ))?)?;

    assert!(matches!(
        current.plan_update(&changed),
        Err(error)
            if error.code() == ConfigurationFailureCode::ImmutableSettingChanged
                && error.source() == FailureSource::ExportDestinations
    ));

    let forbidden = ConfigurationInputs::try_new(
        Some("schema_version = 1\n"),
        EnvironmentOverrides::try_from_pairs([("POSITRON__EXPORT__DESTINATION", "opaque")])?,
        CommandLineOverrides::try_from_pairs([] as [(&str, &str); 0])?,
    )
    .and_then(resolve);
    assert!(matches!(
        forbidden,
        Err(error)
            if error.code() == ConfigurationFailureCode::UnknownSetting
                && error.source() == FailureSource::ExportDestinations
    ));
    Ok(())
}

#[test]
fn canonical_export_destination_membership_order_is_not_a_change()
-> Result<(), ConfigurationFailure> {
    let current = resolve(export_inputs(Some(
        "schema_version = 1\n\
         [[export.destination]]\n\
         name = \"archive\"\n\
         identity = \"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1\"\n\
         allowed_tenants = [\"11111111-1111-1111-1111-111111111111\", \"22222222-2222-2222-2222-222222222222\"]\n\
         [[export.destination]]\n\
         name = \"warehouse\"\n\
         identity = \"b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2\"\n\
         allowed_tenants = [\"33333333-3333-3333-3333-333333333333\"]\n",
    ))?)?;
    let reordered = resolve(export_inputs(Some(
        "schema_version = 1\n\
         [[export.destination]]\n\
         name = \"warehouse\"\n\
         identity = \"b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2\"\n\
         allowed_tenants = [\"33333333-3333-3333-3333-333333333333\"]\n\
         [[export.destination]]\n\
         name = \"archive\"\n\
         identity = \"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1\"\n\
         allowed_tenants = [\"22222222-2222-2222-2222-222222222222\", \"11111111-1111-1111-1111-111111111111\"]\n",
    ))?)?;

    assert!(current.semantic_diff(&reordered).changes().is_empty());
    assert_eq!(current.plan_update(&reordered)?, ConfigurationPlan::NoChange);
    assert_eq!(current.redacted_reference(), reordered.redacted_reference());
    Ok(())
}

fn export_inputs(file: Option<&str>) -> Result<ConfigurationInputs, ConfigurationFailure> {
    ConfigurationInputs::try_new(
        file,
        EnvironmentOverrides::try_from_pairs([] as [(&str, &str); 0])?,
        CommandLineOverrides::try_from_pairs([] as [(&str, &str); 0])?,
    )
}
