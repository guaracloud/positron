use std::num::NonZeroU8;

use positron_config::NetworkListenerRole;

#[test]
fn nested_proxy_trust_is_file_only_and_disabled_without_a_complete_policy()
-> Result<(), ConfigurationFailure> {
    let defaults = inputs(None, [], []).and_then(resolve)?;
    let default_profile = defaults
        .network_listener_profile(NetworkListenerRole::Operations)
        .expect("operations listener profile");
    assert!(default_profile.trusted_proxy_cidrs().is_empty());
    assert_eq!(default_profile.forwarded_hops(), None);

    let effective = inputs(
        Some(
            "schema_version = 1\n\
             [listener.operations]\n\
             trusted_proxy_cidrs = [\"198.51.100.55/24\", \"2001:db8:feed::99/64\"]\n\
             forwarded_hops = 2\n",
        ),
        [],
        [],
    )
    .and_then(resolve)?;
    let profile = effective
        .network_listener_profile(NetworkListenerRole::Operations)
        .expect("operations listener profile");

    assert_eq!(
        profile
            .trusted_proxy_cidrs()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["198.51.100.55/24", "2001:db8:feed::99/64"]
    );
    assert_eq!(profile.forwarded_hops(), NonZeroU8::new(2));
    assert_eq!(
        effective.source_for("listener.operations.trusted_proxy_cidrs"),
        Some(SettingSource::ConfigurationFile)
    );
    assert_eq!(
        effective.source_for("listener.operations.forwarded_hops"),
        Some(SettingSource::ConfigurationFile)
    );
    assert_eq!(
        setting_definition(Setting::ListenerOperationsTrustedProxyCidrs).provenance(),
        ProvenancePolicy::ConfigurationFileOnly
    );
    assert_eq!(
        setting_definition(Setting::ListenerOperationsForwardedHops).mutability(),
        MutabilityClass::DrainAndReload
    );
    assert!(
        inputs(
            Some("schema_version = 1\n"),
            [("POSITRON__LISTENER__OPERATIONS__FORWARDED_HOPS", "2")],
            [],
        )
        .and_then(resolve)
        .is_err()
    );
    Ok(())
}

#[test]
fn proxy_trust_requires_an_exact_bounded_policy_and_rejects_unknown_nested_listener_tables() {
    for document in [
        "schema_version = 1\n[listener.operations]\nforwarded_hops = 2\n",
        "schema_version = 1\n[listener.operations]\ntrusted_proxy_cidrs = [\"198.51.100.0/24\"]\n",
    ] {
        assert!(matches!(
            inputs(Some(document), [], []).and_then(resolve),
            Err(error) if error.code() == ConfigurationFailureCode::UnsafeCombination
        ));
    }
    for document in [
        "schema_version = 1\n[listener.operations]\ntrusted_proxy_cidrs = [\"198.51.100.0/33\"]\nforwarded_hops = 1\n",
        "schema_version = 1\n[listener.operations]\ntrusted_proxy_cidrs = [\"not-an-address/24\"]\nforwarded_hops = 1\n",
    ] {
        assert!(matches!(
            inputs(Some(document), [], []).and_then(resolve),
            Err(error) if error.code() == ConfigurationFailureCode::UnsupportedValue
        ));
    }
    let unknown_role = "schema_version = 1\n[listener.unknown]\ntrusted_proxy_cidrs = [\"198.51.100.0/24\"]\nforwarded_hops = 1\n";
    assert!(matches!(
        inputs(Some(unknown_role), [], []).and_then(resolve),
        Err(error) if error.code() == ConfigurationFailureCode::UnknownSetting
    ));
}
