#[test]
fn loki_push_listener_is_a_canonical_independent_setting() -> Result<(), Box<dyn Error>> {
    let configuration = resolve(ConfigurationInputs::try_new(
        Some(
            "schema_version = 1\n\
             [listener]\n\
             loki_push_bind_address = \"127.0.0.1:19105\"\n",
        ),
        EnvironmentOverrides::try_from_pairs(std::iter::empty::<(&str, &str)>())?,
        CommandLineOverrides::try_from_pairs(std::iter::empty::<(&str, &str)>())?,
    )?)?;

    assert_eq!(
        configuration.loki_push_bind_address().to_string(),
        "127.0.0.1:19105"
    );
    assert_eq!(
        configuration.source_for("listener.loki_push_bind_address"),
        Some(SettingSource::ConfigurationFile)
    );
    assert_eq!(
        setting_definition(Setting::ListenerLokiPushBindAddress).default_value(),
        "127.0.0.1:3100"
    );
    assert!(
        generated_reference().contains("`listener.loki_push_bind_address`")
    );
    assert!(generated_json_schema().contains("loki_push_bind_address"));
    Ok(())
}
