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
                && definition.path().split('.').count() == 2
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
        if section == "listener" {
            append_listener_role_schema(&mut output, &mut first, &definitions);
        }
        output.push_str("}}");
    }
    output.push_str("\n  },\n  \"required\": [\"schema_version\"]\n}\n");
    output
}

fn append_listener_role_schema(
    output: &mut String,
    first: &mut bool,
    definitions: &[SettingDefinition],
) {
    for role in ["operations", "api", "otlp_grpc", "otlp_http", "loki_push"] {
        let cidr_path = format!("listener.{role}.trusted_proxy_cidrs");
        let hop_path = format!("listener.{role}.forwarded_hops");
        let cidrs = definitions
            .iter()
            .copied()
            .find(|definition| definition.path() == cidr_path);
        let hops = definitions
            .iter()
            .copied()
            .find(|definition| definition.path() == hop_path);
        let cors = (role == "api")
            .then(|| {
                definitions
                    .iter()
                    .copied()
                    .find(|definition| definition.path() == "listener.api.cors_allowed_origins")
            })
            .flatten();
        let (Some(cidrs), Some(hops)) = (cidrs, hops) else {
            continue;
        };
        if !*first {
            output.push_str(", ");
        }
        output.push_str(&format!(
            "\"{role}\": {{\"type\": \"object\", \"additionalProperties\": false, \"properties\": {{\"trusted_proxy_cidrs\": {}, \"forwarded_hops\": {}{}}}}}",
            render_schema_value(cidrs),
            render_schema_value(hops),
            cors.map_or_else(String::new, |definition| format!(", \"cors_allowed_origins\": {}", render_schema_value(definition))),
        ));
        *first = false;
    }
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
        ValueDomain::TrustedProxyCidrs(maximum_entries, maximum_entry_bytes) => format!(
            "{{\"type\": \"array\", \"maxItems\": {maximum_entries}, \"items\": {{\"type\": \"string\", \"maxLength\": {maximum_entry_bytes}, \"x-positron-address-kind\": \"literal-ip-cidr\"}}}}"
        ),
        ValueDomain::CorsAllowedOrigins(maximum_entries, maximum_entry_bytes) => format!(
            "{{\"type\": \"array\", \"maxItems\": {maximum_entries}, \"uniqueItems\": true, \"items\": {{\"type\": \"string\", \"maxLength\": {maximum_entry_bytes}, \"x-positron-origin-kind\": \"exact-http-or-https-origin\"}}}}"
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
        Setting::ListenerOperationsTlsCertificateFile
        | Setting::ListenerOperationsTlsPrivateKeyFile
        | Setting::ListenerOperationsTlsClientCaFile
        | Setting::ListenerApiTlsCertificateFile
        | Setting::ListenerApiTlsPrivateKeyFile
        | Setting::ListenerApiTlsClientCaFile
        | Setting::ListenerOtlpGrpcTlsCertificateFile
        | Setting::ListenerOtlpGrpcTlsPrivateKeyFile
        | Setting::ListenerOtlpGrpcTlsClientCaFile
        | Setting::ListenerOtlpHttpTlsCertificateFile
        | Setting::ListenerOtlpHttpTlsPrivateKeyFile
        | Setting::ListenerOtlpHttpTlsClientCaFile
        | Setting::ListenerLokiPushTlsCertificateFile
        | Setting::ListenerLokiPushTlsPrivateKeyFile
        | Setting::ListenerLokiPushTlsClientCaFile => {
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
        } else if matches!(
            definition.setting(),
            Setting::ExportDestinations
                | Setting::ListenerOperationsTrustedProxyCidrs
                | Setting::ListenerApiTrustedProxyCidrs
                | Setting::ListenerOtlpGrpcTrustedProxyCidrs
                | Setting::ListenerOtlpHttpTrustedProxyCidrs
                | Setting::ListenerLokiPushTrustedProxyCidrs
        ) {
            "disabled"
        } else {
            definition.default_value()
        };
        let default = if matches!(
            definition.setting(),
            Setting::ExportDestinations
                | Setting::ListenerOperationsTrustedProxyCidrs
                | Setting::ListenerApiTrustedProxyCidrs
                | Setting::ListenerOtlpGrpcTrustedProxyCidrs
                | Setting::ListenerOtlpHttpTrustedProxyCidrs
                | Setting::ListenerLokiPushTrustedProxyCidrs
        ) {
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
                    && definition.path().split('.').count() == 2
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
        if section == "listener" {
            append_proxy_trust_example(&mut output);
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
        SettingKind::ExportDestinations
        | SettingKind::TrustedProxyCidrs
        | SettingKind::CorsAllowedOrigins => return,
    };
    output.push_str(&format!("{field} = {value}\n"));
}

fn append_proxy_trust_example(output: &mut String) {
    for role in ["operations", "api", "otlp_grpc", "otlp_http", "loki_push"] {
        output.push_str("\n[listener.");
        output.push_str(role);
        output.push_str("]\ntrusted_proxy_cidrs = []\nforwarded_hops = 0\n");
    }
}

fn reference_kind(definition: SettingDefinition) -> &'static str {
    match definition.setting() {
        Setting::ExportDestinations => "array of tables",
        Setting::ListenerApiCorsAllowedOrigins => "array",
        Setting::ListenerOperationsTrustedProxyCidrs
        | Setting::ListenerApiTrustedProxyCidrs
        | Setting::ListenerOtlpGrpcTrustedProxyCidrs
        | Setting::ListenerOtlpHttpTrustedProxyCidrs
        | Setting::ListenerLokiPushTrustedProxyCidrs => "array",
        _ => definition.kind().as_str(),
    }
}

fn reference_domain(definition: SettingDefinition) -> String {
    match definition.setting() {
        Setting::RuntimeMaxRegisteredTenants => "`1..=1024`; maximum tenant quotas simultaneously registered in the live Resource Governor, including the default tenant and a pending non-admittable tenant-creation reservation".to_owned(),
        Setting::ListenerApiBindAddress => "socket address; at most 256 bytes; non-loopback requires TLS or the explicit plaintext opt-out".to_owned(),
        Setting::ListenerApiTransport => "`tls`, `mtls`, `plaintext`; plaintext emits a configuration warning, persistent ready health warning, and one redacted governance audit record".to_owned(),
        Setting::ListenerAdmissionRatePerSecond => "`1..=4096`; maximum pre-authentication attempts per fixed one-second window for each listener generation. Socket admission and each HTTP/2 or gRPC request before credential parsing consume this listener-local budget; a fixed-window boundary may admit two adjacent-window bursts. The compiled default of 1024 is a selected workload allowance, not a fairness guarantee under distributed floods.".to_owned(),
        Setting::ListenerPerAddressAdmissionRatePerSecond => "`1..=4096`; maximum pre-authentication attempts from one immediate peer address per fixed one-second window; cannot exceed the shared listener attempt rate. A refused peer attempt also consumes the shared listener budget so denied traffic cannot create unbounded admission work. The compiled default of 128 is the selected eight-to-one allowance against the global default, not a fairness guarantee.".to_owned(),
        Setting::ListenerOperationsAcceptedSocketLimit
        | Setting::ListenerApiAcceptedSocketLimit
        | Setting::ListenerOtlpGrpcAcceptedSocketLimit
        | Setting::ListenerOtlpHttpAcceptedSocketLimit
        | Setting::ListenerLokiPushAcceptedSocketLimit => "`1..=4096`; maximum accepted sockets awaiting authentication for this listener role".to_owned(),
        Setting::ListenerOperationsPerAddressAcceptedSocketLimit
        | Setting::ListenerApiPerAddressAcceptedSocketLimit
        | Setting::ListenerOtlpGrpcPerAddressAcceptedSocketLimit
        | Setting::ListenerOtlpHttpPerAddressAcceptedSocketLimit
        | Setting::ListenerLokiPushPerAddressAcceptedSocketLimit => "`1..=4096`; maximum accepted sockets awaiting authentication from one immediate peer address; cannot exceed this role's accepted-socket limit".to_owned(),
        Setting::ListenerOperationsTlsHandshakeLimit
        | Setting::ListenerApiTlsHandshakeLimit
        | Setting::ListenerOtlpGrpcTlsHandshakeLimit
        | Setting::ListenerOtlpHttpTlsHandshakeLimit
        | Setting::ListenerLokiPushTlsHandshakeLimit => "`1..=128`; maximum concurrent TLS handshakes for this listener role before authentication".to_owned(),
        Setting::ListenerOperationsTlsHandshakeDeadlineSeconds
        | Setting::ListenerApiTlsHandshakeDeadlineSeconds
        | Setting::ListenerOtlpGrpcTlsHandshakeDeadlineSeconds
        | Setting::ListenerOtlpHttpTlsHandshakeDeadlineSeconds
        | Setting::ListenerLokiPushTlsHandshakeDeadlineSeconds => "`1..=300` seconds; deadline for each TLS handshake before authentication".to_owned(),
        Setting::ListenerOperationsHeaderDeadlineSeconds
        | Setting::ListenerApiHeaderDeadlineSeconds
        | Setting::ListenerOtlpGrpcHeaderDeadlineSeconds
        | Setting::ListenerOtlpHttpHeaderDeadlineSeconds
        | Setting::ListenerLokiPushHeaderDeadlineSeconds => "`1..=300` seconds; deadline for receiving one request header block".to_owned(),
        Setting::ListenerOperationsBodyDeadlineSeconds
        | Setting::ListenerApiBodyDeadlineSeconds
        | Setting::ListenerOtlpGrpcBodyDeadlineSeconds
        | Setting::ListenerOtlpHttpBodyDeadlineSeconds
        | Setting::ListenerLokiPushBodyDeadlineSeconds => "`1..=300` seconds; deadline for receiving one request body".to_owned(),
        Setting::ListenerOperationsRequestDeadlineSeconds
        | Setting::ListenerApiRequestDeadlineSeconds
        | Setting::ListenerOtlpGrpcRequestDeadlineSeconds
        | Setting::ListenerOtlpHttpRequestDeadlineSeconds
        | Setting::ListenerLokiPushRequestDeadlineSeconds => "`1..=300` seconds; deadline for handling one request".to_owned(),
        Setting::ListenerOperationsIdleDeadlineSeconds
        | Setting::ListenerApiIdleDeadlineSeconds
        | Setting::ListenerOtlpGrpcIdleDeadlineSeconds
        | Setting::ListenerOtlpHttpIdleDeadlineSeconds
        | Setting::ListenerLokiPushIdleDeadlineSeconds => "`1..=300` seconds; maximum idle connection duration".to_owned(),
        Setting::ListenerApiHttp2MaxConcurrentStreams
        | Setting::ListenerOtlpGrpcHttp2MaxConcurrentStreams => "`1..=1024`; maximum concurrent HTTP/2 request streams per accepted connection".to_owned(),
        Setting::ListenerApiHttp2InitialStreamWindowBytes
        | Setting::ListenerOtlpGrpcHttp2InitialStreamWindowBytes => "`1..=2147483647` bytes; advertised HTTP/2 flow-control window for each stream".to_owned(),
        Setting::ListenerApiHttp2InitialConnectionWindowBytes
        | Setting::ListenerOtlpGrpcHttp2InitialConnectionWindowBytes => "`1..=2147483647` bytes; advertised HTTP/2 connection flow-control window".to_owned(),
        Setting::ListenerApiHttp2MaxFrameBytes
        | Setting::ListenerOtlpGrpcHttp2MaxFrameBytes => "`16384..=16777215` bytes; maximum accepted HTTP/2 frame payload".to_owned(),
        Setting::ListenerApiHttp2MaxHeaderListBytes
        | Setting::ListenerOtlpGrpcHttp2MaxHeaderListBytes => "`1..=1048576` bytes; maximum decoded HTTP/2 header-list size".to_owned(),
        Setting::ListenerApiHttp2MinimumPingIntervalSeconds
        | Setting::ListenerOtlpGrpcHttp2MinimumPingIntervalSeconds => "`1..=300` seconds; minimum interval between non-ACK peer HTTP/2 PING frames; an earlier PING closes the connection".to_owned(),
        Setting::ListenerOtlpGrpcMaxMessageBytes => "`1..=16777216` bytes; transport gRPC message ceiling before decoding; an authenticated tenant's value profile may narrow it".to_owned(),
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
            ValueDomain::TrustedProxyCidrs(maximum, maximum_bytes) => format!("at most {maximum} literal IPv4 or IPv6 CIDRs, each at most {maximum_bytes} bytes; forwarded headers remain ignored unless this list and the matching nonzero fixed hop count are both configured"),
            ValueDomain::CorsAllowedOrigins(maximum, maximum_bytes) => format!("at most {maximum} exact `http` or `https` origins, each at most {maximum_bytes} bytes; CORS is disabled when the list is empty and never enables credential forwarding"),
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
