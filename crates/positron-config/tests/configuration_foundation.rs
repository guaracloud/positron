//! Public contract tests for the Configuration foundation.

use std::{error::Error, io};

use positron_config::{
    CommandLineOverrides, CompletionState, ConfigurationFailure, ConfigurationFailureCode,
    ConfigurationInputs, ConfigurationPlan, EnvironmentOverrides, FailureSource, LogLevel,
    MutabilityClass, ProvenancePolicy, RetryClass, SecrecyClass, Setting, SettingKind,
    SettingSource, ValueDomain, generated_json_schema, generated_reference, resolve,
    setting_definition,
};

#[derive(Debug)]
struct GeneratedConfigurationFixture {
    id: String,
    class: String,
    document: String,
    expected: Option<ConfigurationFailureCode>,
}

include!("configuration_foundation/contract.rs");
include!("configuration_foundation/resolution.rs");
include!("configuration_foundation/planning.rs");
include!("configuration_foundation/bounds.rs");
include!("configuration_foundation/preflight.rs");
include!("configuration_foundation/quoting.rs");
include!("configuration_foundation/overrides.rs");
include!("configuration_foundation/runtime_wiring.rs");
include!("configuration_foundation/loki_listener.rs");
