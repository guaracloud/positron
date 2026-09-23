/// Renders a TOML basic string without allowing a value to create syntax.
#[must_use]
pub fn render_toml_basic_string(value: &str) -> String {
    let mut rendered = String::with_capacity(value.len() + 2);
    rendered.push('"');
    for character in value.chars() {
        match character {
            '\\' => rendered.push_str("\\\\"),
            '"' => rendered.push_str("\\\""),
            '\u{08}' => rendered.push_str("\\b"),
            '\t' => rendered.push_str("\\t"),
            '\n' => rendered.push_str("\\n"),
            '\u{0c}' => rendered.push_str("\\f"),
            '\r' => rendered.push_str("\\r"),
            character if character.is_control() => {
                rendered.push_str(&format!("\\u{:04x}", u32::from(character)));
            },
            character => rendered.push(character),
        }
    }
    rendered.push('"');
    rendered
}

use crate::{
    MutabilityClass, ProvenancePolicy, SecrecyClass, Setting, SettingDefinition, SettingKind,
    ValueDomain, setting_definitions,
};

/// Renders the committed JSON Schema from the Rust-owned setting table.
///
/// The schema deliberately retains custom annotations for validation rules that
/// JSON Schema cannot express alone, such as loopback-only listener binding.
#[must_use]
pub fn render_json_schema() -> String {
    let definitions = setting_definitions();
    let mut output = String::from(
        "{\n  \"$schema\": \"https://json-schema.org/draft/2020-12/schema\",\n  \"x-positron-generated-from\": \"crates/positron-config/src/contract.rs\",\n  \"title\": \"Positron Configuration Contract v1\",\n  \"type\": \"object\",\n  \"additionalProperties\": false,\n  \"properties\": {\n",
    );
    let schema_version = definitions
        .iter()
        .copied()
        .find(|definition| definition.setting() == Setting::SchemaVersion);
    if let Some(definition) = schema_version {
        output.push_str(&format!(
            "    \"schema_version\": {}",
            render_schema_value(definition)
        ));
    }

    for section in [
        "diagnostics",
        "listener",
        "runtime",
        "security",
        "export",
        "storage",
    ] {
        output.push_str(&format!(
            ",\n    \"{section}\": {{\"type\": \"object\", \"additionalProperties\": false, \"properties\": {{"
        ));
        let mut first = true;
        for definition in definitions.iter().copied().filter(|definition| {
            definition
                .path()
                .split_once('.')
                .is_some_and(|(path_section, _)| path_section == section)
        }) {
            let Some((_, field)) = definition.path().split_once('.') else {
                continue;
            };
            if !first {
                output.push_str(", ");
            }
            output.push_str(&format!("\"{field}\": {}", render_schema_value(definition)));
            first = false;
        }
        output.push_str("}}");
    }
    output.push_str("\n  },\n  \"required\": [\"schema_version\"]\n}\n");
    output
}

fn render_schema_value(definition: SettingDefinition) -> String {
    match definition.domain() {
        ValueDomain::ExactUnsignedInteger(value) => format!("{{\"const\": {value}}}"),
        ValueDomain::StringEnumeration(values) => format!(
            "{{\"type\": \"string\", \"enum\": [{}]}}",
            values
                .iter()
                .map(|value| format!("\"{value}\""))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        ValueDomain::UnsignedIntegerRange(minimum, maximum) => {
            format!("{{\"type\": \"integer\", \"minimum\": {minimum}, \"maximum\": {maximum}}}")
        },
        ValueDomain::LoopbackSocketAddress(maximum) => format!(
            "{{\"type\": \"string\", \"maxLength\": {maximum}, \"x-positron-address-scope\": \"loopback-only\"}}"
        ),
        ValueDomain::SocketAddress(maximum) => format!(
            "{{\"type\": \"string\", \"maxLength\": {maximum}, \"x-positron-address-scope\": \"tls-or-explicit-plaintext-opt-out-off-loopback\"}}"
        ),
        ValueDomain::AbsolutePath(maximum) => render_path_schema(definition, maximum, false),
        ValueDomain::ProtectedAbsolutePath(maximum) => {
            render_path_schema(definition, maximum, true)
        },
        ValueDomain::ExportDestinations(maximum, maximum_name_bytes, maximum_tenants) => format!(
            "{{\"type\": \"array\", \"maxItems\": {maximum}, \"items\": {{\"type\": \"object\", \"additionalProperties\": false, \"required\": [\"name\", \"identity\", \"allowed_tenants\"], \"properties\": {{\"name\": {{\"type\": \"string\", \"minLength\": 1, \"maxLength\": {maximum_name_bytes}, \"pattern\": \"^[a-z0-9]+(?:-[a-z0-9]+)*$\"}}, \"identity\": {{\"type\": \"string\", \"pattern\": \"^[0-9a-f]{{32}}$\", \"not\": {{\"const\": \"00000000000000000000000000000000\"}}}}, \"allowed_tenants\": {{\"type\": \"array\", \"minItems\": 1, \"maxItems\": {maximum_tenants}, \"uniqueItems\": true, \"items\": {{\"type\": \"string\", \"pattern\": \"^[0-9a-f]{{8}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{12}}$\"}}}}}}}}}}"
        ),
    }
}

fn render_path_schema(definition: SettingDefinition, maximum: usize, protected: bool) -> String {
    let mut output = format!("{{\"type\": \"string\", \"maxLength\": {maximum}");
    if definition.secrecy() == SecrecyClass::SecretBearing {
        output.push_str(", \"writeOnly\": true");
    }
    match definition.setting() {
        Setting::ListenerControlPath => output.push_str(", \"x-positron-path-kind\": \"absolute\""),
        Setting::ListenerApiTlsCertificateFile | Setting::ListenerApiTlsPrivateKeyFile => {
            output.push_str(", \"x-positron-path-kind\": \"protected-absolute\"");
        },
        Setting::SecurityLocalKeyFile if protected => output.push_str(
            ", \"x-positron-runtime-invariant\": \"storage.secrets_directory/local-root-key.v1\"",
        ),
        _ => {},
    }
    output.push('}');
    output
}

/// Renders the committed operator reference from the Rust-owned setting table.
#[must_use]
pub fn render_reference() -> String {
    let mut output = String::from(
        "<!-- Keep synchronized with `crates/positron-config/src/contract.rs`. -->\n\n# Positron Configuration Contract v1\n\nPrecedence: compiled defaults, TOML file, non-secret POSITRON__ overrides, then non-secret CLI overrides.\n\n| Setting | Type | Default | Domain | Secrecy | Provenance | Mutability |\n| --- | --- | --- | --- | --- | --- | --- |\n",
    );
    for definition in setting_definitions() {
        let default = if definition.secrecy() == SecrecyClass::SecretBearing {
            "<redacted protected-file reference>"
        } else if definition.setting() == Setting::ExportDestinations {
            "disabled"
        } else {
            definition.default_value()
        };
        let default = if definition.setting() == Setting::ExportDestinations {
            default.to_owned()
        } else {
            format!("`{default}`")
        };
        output.push_str(&format!(
            "| `{}` | {} | {} | {} | {} | {} | {} |\n",
            definition.path(),
            reference_kind(definition),
            default,
            reference_domain(definition),
            reference_secrecy(definition.secrecy()),
            reference_provenance(definition.provenance()),
            reference_mutability(definition.mutability()),
        ));
    }
    output.push_str(
        "\n## Durable export destinations\n\nDurable export is disabled unless the selected TOML file includes one or more\n`[[export.destination]]` entries. Environment and command-line overrides are\nrejected. A destination may be selected only by an authenticated tenant named\nin its `allowed_tenants`; its opaque `identity` is passed internally to the\nprotected Kernel output directory and is not supplied by an API caller.\n\n```toml\n[[export.destination]]\nname = \"regulated-archive\"\nidentity = \"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1\"\nallowed_tenants = [\"11111111-1111-1111-1111-111111111111\"]\n```\n\nDestination names and identities must be unique. The complete candidate is\nvalidated before publication; changing this immutable setting requires the\nexplicit initialization or restore workflow rather than live reload.\n\n## Operator commands\n\nThe native binary resolves this same contract without starting the database:\n\n```console\npositron config validate [--config PATH] [--set PATH=VALUE]\npositron config explain [--setting PATH]\npositron config effective --redacted [--config PATH] [--set PATH=VALUE]\npositron config diff --current PATH --candidate PATH\npositron config migrate --config PATH --output PATH\n```\n\n`validate` resolves the complete candidate and reports only its schema version\nand warning count. `explain` reports each setting's canonical type, redacted\ndefault where required, value domain, secrecy, provenance policy, and\nmutability. `effective --redacted` renders the complete redacted effective\nstate followed by the source of every setting. `diff` resolves both canonical\ndocuments without environment or command-line overrides, reports only redacted\nsemantic values and provenance, and derives one no-mutation lifecycle plan.\n\nThe current contract supports schema version 1 only. `migrate` validates its\nsource without environment or command-line overrides, then writes the validated\nsource bytes to the explicitly named output candidate. The output is created\nwith restrictive permissions and is never overwritten. This preserves protected\nfile references and avoids materializing defaults or overrides. The command\nreports the deterministic zero semantic diff for version 1; unsupported\nversions are rejected without coercion or an invented transformation.\n",
    );
    output
}

/// Renders a copyable configuration document from public canonical defaults.
///
/// Protected references remain absent so generated artifacts cannot disclose
/// secret-bearing values; their safe compiled defaults remain in effect.
#[must_use]
pub fn render_example() -> String {
    let mut output = String::from(
        "# Generated from `crates/positron-config/src/contract.rs`.\n# Protected references are intentionally omitted.\n\n",
    );
    for definition in setting_definitions() {
        if definition.setting() == Setting::SchemaVersion {
            append_example_setting(&mut output, definition);
        }
    }
    for section in ["diagnostics", "listener", "runtime", "storage"] {
        let settings = setting_definitions()
            .into_iter()
            .filter(|definition| {
                definition.secrecy() == SecrecyClass::Public
                    && definition.kind() != SettingKind::ExportDestinations
                    && definition.path().starts_with(&format!("{section}."))
            })
            .collect::<Vec<_>>();
        if settings.is_empty() {
            continue;
        }
        output.push_str(&format!("\n[{section}]\n"));
        for definition in settings {
            append_example_setting(&mut output, definition);
        }
    }
    output
}

fn append_example_setting(output: &mut String, definition: SettingDefinition) {
    let field = definition
        .path()
        .rsplit('.')
        .next()
        .unwrap_or(definition.path());
    let value = match definition.kind() {
        SettingKind::Integer => definition.default_value().to_owned(),
        SettingKind::String => render_toml_basic_string(definition.default_value()),
        SettingKind::ExportDestinations => return,
    };
    output.push_str(&format!("{field} = {value}\n"));
}

fn reference_kind(definition: SettingDefinition) -> &'static str {
    match definition.setting() {
        Setting::ExportDestinations => "array of tables",
        _ => definition.kind().as_str(),
    }
}

fn reference_domain(definition: SettingDefinition) -> String {
    match definition.setting() {
        Setting::RuntimeMaxRegisteredTenants => "`1..=1024`; maximum tenant quotas simultaneously registered in the live Resource Governor, including the default tenant and a pending non-admittable tenant-creation reservation".to_owned(),
        Setting::ListenerApiBindAddress => "socket address; at most 256 bytes; non-loopback requires TLS or the explicit plaintext opt-out".to_owned(),
        Setting::ListenerApiTransport => "`tls`, `plaintext`; plaintext emits a configuration warning, persistent ready health warning, and one redacted governance audit record".to_owned(),
        Setting::SecurityLocalKeyFile => "protected absolute path under `storage.secrets_directory`, named `local-root-key.v1`; at most 256 bytes".to_owned(),
        _ => match definition.domain() {
            ValueDomain::ExactUnsignedInteger(value) => format!("exactly `{value}`"),
            ValueDomain::StringEnumeration(values) => values.iter().map(|value| format!("`{value}`")).collect::<Vec<_>>().join(", "),
            ValueDomain::UnsignedIntegerRange(minimum, maximum) => format!("`{minimum}..={maximum}`"),
            ValueDomain::LoopbackSocketAddress(maximum) => format!("loopback socket address; at most {maximum} bytes"),
            ValueDomain::SocketAddress(maximum) => format!("socket address; at most {maximum} bytes"),
            ValueDomain::AbsolutePath(maximum) => format!("absolute path; at most {maximum} bytes"),
            ValueDomain::ProtectedAbsolutePath(maximum) => format!("protected absolute path; at most {maximum} bytes"),
            ValueDomain::ExportDestinations(maximum, name, tenants) => format!("at most {maximum} named destinations; each has a lowercase `name` of at most {name} bytes, a nonzero 16-byte lowercase hexadecimal `identity`, and one to {tenants} unique canonical `allowed_tenants`"),
        },
    }
}

fn reference_secrecy(secrecy: SecrecyClass) -> &'static str {
    match secrecy {
        SecrecyClass::Public => "public",
        SecrecyClass::SecretBearing => "secret-bearing (redacted)",
    }
}

fn reference_provenance(provenance: ProvenancePolicy) -> &'static str {
    match provenance {
        ProvenancePolicy::ConfigurationFileOnly => "compiled default, configuration file",
        ProvenancePolicy::NonSecretOverrides => {
            "compiled default, configuration file, environment, command line"
        },
        ProvenancePolicy::ProtectedConfigurationFileOnly => {
            "compiled default, protected configuration-file reference"
        },
    }
}

fn reference_mutability(mutability: MutabilityClass) -> &'static str {
    match mutability {
        MutabilityClass::LiveReloadable => "live-reloadable",
        MutabilityClass::DrainAndReload => "drain-and-reload",
        MutabilityClass::RestartRequired => "restart-required",
        MutabilityClass::ImmutableAfterInitialization => "immutable after initialization",
    }
}
