//! Deterministic generation for the Rust-owned Positron configuration contract.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::SocketAddr;
use std::path::Path;

use crate::error::XtaskError;

const SOURCE: &str = crate::generation::CONFIGURATION_INPUT;
const JSON_SCHEMA: &str = crate::generation::CONFIGURATION_SCHEMA;
const REFERENCE: &str = crate::generation::CONFIGURATION_REFERENCE;
const VALIDATION_FIXTURES: &str = crate::generation::CONFIGURATION_VALIDATION_FIXTURES;
const DECLARATION_START: &str =
    "pub(crate) const SETTING_DEFINITIONS: [SettingDefinition; 7] = define_settings! {";
const DECLARATION_END: &str = "};";
const MAX_SOURCE_BYTES: usize = 16_384;
const MAX_FIELD_BYTES: usize = 512;
const REQUIRED_SETTINGS: [&str; 7] = [
    "SchemaVersion",
    "DiagnosticsLogLevel",
    "RuntimeShutdownGraceSeconds",
    "ListenerControlBindAddress",
    "StorageDataDirectory",
    "StorageSecretsDirectory",
    "SecurityLocalKeyFile",
];

struct ConfigurationSpec {
    settings: Vec<SettingSpec>,
}

struct SettingSpec {
    setting: String,
    path: String,
    kind: SettingKind,
    default: String,
    secrecy: Secrecy,
    provenance: Provenance,
    mutability: Mutability,
    domain: Domain,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum SettingKind {
    Integer,
    String,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Secrecy {
    Public,
    SecretBearing,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Provenance {
    ConfigurationFileOnly,
    NonSecretOverrides,
    ProtectedConfigurationFileOnly,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Mutability {
    LiveReloadable,
    DrainAndReload,
    RestartRequired,
    ImmutableAfterInitialization,
}

enum Domain {
    ExactUnsignedInteger(u16),
    StringEnumeration(Vec<String>),
    UnsignedIntegerRange(u16, u16),
    LoopbackSocketAddress(usize),
    AbsolutePath(usize),
    ProtectedAbsolutePath(usize),
}

/// Regenerates every checked artifact owned by the Rust declaration.
pub(crate) fn generate(root: &Path) -> Result<(), XtaskError> {
    let source_path = root.join(SOURCE);
    let source = fs::read_to_string(&source_path)
        .map_err(|source| XtaskError::io(format!("read {}", source_path.display()), source))?;
    let specification = parse_source(&source_path, &source)?;
    write_generated(root, JSON_SCHEMA, &json_schema(&specification)?)?;
    write_generated(root, REFERENCE, &reference(&specification)?)?;
    write_generated(
        root,
        VALIDATION_FIXTURES,
        &validation_fixtures(&specification)?,
    )?;
    Ok(())
}

fn parse_source(path: &Path, source: &str) -> Result<ConfigurationSpec, XtaskError> {
    if source.len() > MAX_SOURCE_BYTES {
        return Err(XtaskError::invalid_path(
            path,
            "canonical Rust configuration declaration exceeds 16384 bytes",
        ));
    }
    let mut in_declarations = false;
    let mut found_end = false;
    let mut settings = Vec::with_capacity(REQUIRED_SETTINGS.len());
    for line in source.lines() {
        if !in_declarations {
            if line == DECLARATION_START {
                in_declarations = true;
            }
            continue;
        }
        if line == DECLARATION_END {
            found_end = true;
            break;
        }
        settings.push(parse_declaration(path, line)?);
    }
    if !in_declarations {
        return Err(XtaskError::invalid_path(
            path,
            "canonical Rust configuration declaration header is not exact",
        ));
    }
    if !found_end {
        return Err(XtaskError::invalid_path(
            path,
            "canonical Rust configuration declaration terminator is missing",
        ));
    }
    if settings.len() != REQUIRED_SETTINGS.len()
        || REQUIRED_SETTINGS.iter().any(|required| {
            settings
                .iter()
                .filter(|setting| setting.setting == *required)
                .count()
                != 1
        })
    {
        return Err(XtaskError::invalid_path(
            path,
            "required configuration setting is missing or ambiguous",
        ));
    }
    let paths = settings
        .iter()
        .map(|setting| setting.path.as_str())
        .collect::<BTreeSet<_>>();
    if paths.len() != settings.len() {
        return Err(XtaskError::invalid_path(
            path,
            "required configuration path is missing or ambiguous",
        ));
    }
    for setting in &settings {
        validate_semantics(path, setting)?;
    }
    Ok(ConfigurationSpec { settings })
}

fn parse_declaration(path: &Path, line: &str) -> Result<SettingSpec, XtaskError> {
    let Some(line) = line.strip_prefix("    ") else {
        return Err(XtaskError::invalid_path(
            path,
            "canonical Rust configuration declaration line is not exact",
        ));
    };
    if line.is_empty() || line.trim() != line {
        return Err(XtaskError::invalid_path(
            path,
            "canonical Rust configuration declaration line is not exact",
        ));
    }
    let declaration = line.strip_suffix(';').ok_or_else(|| {
        XtaskError::invalid_path(
            path,
            "canonical Rust configuration declaration must end with a semicolon",
        )
    })?;
    let fields = declaration.split(" | ").collect::<Vec<_>>();
    let [
        setting,
        setting_path,
        kind,
        default,
        domain,
        secrecy,
        provenance,
        mutability,
    ] = fields.as_slice()
    else {
        return Err(XtaskError::invalid_path(
            path,
            "canonical Rust configuration declaration must have exactly eight fields",
        ));
    };
    if fields.iter().any(|field| {
        field.is_empty() || field.len() > MAX_FIELD_BYTES || field.contains(['\r', '\n', '`', '\t'])
    }) {
        return Err(XtaskError::invalid_path(
            path,
            "canonical Rust configuration declaration contains an invalid or oversized field",
        ));
    }
    if !REQUIRED_SETTINGS.contains(setting) {
        return Err(XtaskError::invalid_path(
            path,
            "canonical Rust configuration setting variant is unsupported",
        ));
    }
    Ok(SettingSpec {
        setting: (*setting).to_owned(),
        path: parse_string(path, setting_path, "setting path")?,
        kind: parse_kind(path, kind)?,
        default: parse_string(path, default, "default")?,
        domain: parse_domain(path, domain)?,
        secrecy: parse_secrecy(path, secrecy)?,
        provenance: parse_provenance(path, provenance)?,
        mutability: parse_mutability(path, mutability)?,
    })
}

fn parse_string(path: &Path, value: &str, label: &str) -> Result<String, XtaskError> {
    let parsed = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .ok_or_else(|| {
            XtaskError::invalid_path(
                path,
                format!("canonical Rust configuration {label} must be an exact string literal"),
            )
        })?;
    if parsed.is_empty()
        || parsed.len() > MAX_FIELD_BYTES
        || parsed.contains(['"', '\\', '|', '\r', '\n', '\t'])
    {
        return Err(XtaskError::invalid_path(
            path,
            format!("canonical Rust configuration {label} is invalid or oversized"),
        ));
    }
    Ok(parsed.to_owned())
}

fn parse_kind(path: &Path, value: &str) -> Result<SettingKind, XtaskError> {
    match value {
        "Integer" => Ok(SettingKind::Integer),
        "String" => Ok(SettingKind::String),
        _ => Err(XtaskError::invalid_path(
            path,
            "canonical Rust configuration kind is unsupported",
        )),
    }
}

fn parse_secrecy(path: &Path, value: &str) -> Result<Secrecy, XtaskError> {
    match value {
        "Public" => Ok(Secrecy::Public),
        "SecretBearing" => Ok(Secrecy::SecretBearing),
        _ => Err(XtaskError::invalid_path(
            path,
            "canonical Rust configuration secrecy class is unsupported",
        )),
    }
}

fn parse_provenance(path: &Path, value: &str) -> Result<Provenance, XtaskError> {
    match value {
        "ConfigurationFileOnly" => Ok(Provenance::ConfigurationFileOnly),
        "NonSecretOverrides" => Ok(Provenance::NonSecretOverrides),
        "ProtectedConfigurationFileOnly" => Ok(Provenance::ProtectedConfigurationFileOnly),
        _ => Err(XtaskError::invalid_path(
            path,
            "canonical Rust configuration provenance policy is unsupported",
        )),
    }
}

fn parse_mutability(path: &Path, value: &str) -> Result<Mutability, XtaskError> {
    match value {
        "LiveReloadable" => Ok(Mutability::LiveReloadable),
        "DrainAndReload" => Ok(Mutability::DrainAndReload),
        "RestartRequired" => Ok(Mutability::RestartRequired),
        "ImmutableAfterInitialization" => Ok(Mutability::ImmutableAfterInitialization),
        _ => Err(XtaskError::invalid_path(
            path,
            "canonical Rust configuration mutability class is unsupported",
        )),
    }
}

fn parse_domain(path: &Path, value: &str) -> Result<Domain, XtaskError> {
    if let Some(arguments) = invocation(value, "ExactUnsignedInteger") {
        return parse_usize(path, arguments).and_then(|value| {
            u16::try_from(value)
                .map(Domain::ExactUnsignedInteger)
                .map_err(|_| XtaskError::invalid_path(path, "exact integer exceeds u16"))
        });
    }
    if let Some(arguments) = invocation(value, "UnsignedIntegerRange") {
        let Some((minimum, maximum)) = arguments.split_once(", ") else {
            return Err(XtaskError::invalid_path(
                path,
                "canonical Rust configuration integer range is malformed",
            ));
        };
        let minimum = u16::try_from(parse_usize(path, minimum)?)
            .map_err(|_| XtaskError::invalid_path(path, "range minimum exceeds u16"))?;
        let maximum = u16::try_from(parse_usize(path, maximum)?)
            .map_err(|_| XtaskError::invalid_path(path, "range maximum exceeds u16"))?;
        if minimum > maximum {
            return Err(XtaskError::invalid_path(
                path,
                "canonical Rust configuration integer range is inverted",
            ));
        }
        return Ok(Domain::UnsignedIntegerRange(minimum, maximum));
    }
    if let Some(arguments) = invocation(value, "StringEnumeration") {
        let list = arguments
            .strip_prefix("&[")
            .and_then(|value| value.strip_suffix(']'))
            .ok_or_else(|| {
                XtaskError::invalid_path(
                    path,
                    "canonical Rust configuration enumeration must be a borrowed string array",
                )
            })?;
        let values = list
            .split(", ")
            .map(|value| parse_string(path, value, "enumeration value"))
            .collect::<Result<Vec<_>, _>>()?;
        if values.is_empty() || values.len() > 8 {
            return Err(XtaskError::invalid_path(
                path,
                "canonical Rust configuration enumeration is empty or oversized",
            ));
        }
        return Ok(Domain::StringEnumeration(values));
    }
    for (name, constructor) in [
        (
            "LoopbackSocketAddress",
            Domain::LoopbackSocketAddress as fn(usize) -> Domain,
        ),
        ("AbsolutePath", Domain::AbsolutePath as fn(usize) -> Domain),
        (
            "ProtectedAbsolutePath",
            Domain::ProtectedAbsolutePath as fn(usize) -> Domain,
        ),
    ] {
        if let Some(arguments) = invocation(value, name) {
            return parse_usize(path, arguments).map(constructor);
        }
    }
    Err(XtaskError::invalid_path(
        path,
        "canonical Rust configuration domain is unsupported",
    ))
}

fn invocation<'a>(value: &'a str, name: &str) -> Option<&'a str> {
    value
        .strip_prefix(name)
        .and_then(|value| value.strip_prefix('('))
        .and_then(|value| value.strip_suffix(')'))
}

fn parse_usize(path: &Path, value: &str) -> Result<usize, XtaskError> {
    if value.is_empty()
        || value.len() > 5
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(XtaskError::invalid_path(
            path,
            "canonical Rust configuration integer is noncanonical",
        ));
    }
    value.parse::<usize>().map_err(|_| {
        XtaskError::invalid_path(path, "canonical Rust configuration integer is out of range")
    })
}

fn validate_semantics(path: &Path, setting: &SettingSpec) -> Result<(), XtaskError> {
    validate_path(path, &setting.path)?;
    let valid = match (&setting.kind, &setting.domain) {
        (SettingKind::Integer, Domain::ExactUnsignedInteger(expected)) => {
            setting.setting == "SchemaVersion"
                && setting.path.split('.').count() == 1
                && setting.default == expected.to_string()
                && setting.secrecy == Secrecy::Public
                && setting.provenance == Provenance::ConfigurationFileOnly
        },
        (SettingKind::Integer, Domain::UnsignedIntegerRange(minimum, maximum)) => {
            setting.setting == "RuntimeShutdownGraceSeconds"
                && parse_usize(path, &setting.default)
                    .ok()
                    .is_some_and(|default| {
                        (*minimum as usize..=*maximum as usize).contains(&default)
                    })
                && setting.secrecy == Secrecy::Public
        },
        (SettingKind::String, Domain::StringEnumeration(values)) => {
            setting.setting == "DiagnosticsLogLevel"
                && values == &["error", "warn", "info", "debug"]
                && values.contains(&setting.default)
                && setting.secrecy == Secrecy::Public
        },
        (SettingKind::String, Domain::LoopbackSocketAddress(maximum)) => {
            setting.setting == "ListenerControlBindAddress"
                && setting.default.len() <= *maximum
                && setting
                    .default
                    .parse::<SocketAddr>()
                    .ok()
                    .is_some_and(|address| address.ip().is_loopback())
                && setting.secrecy == Secrecy::Public
        },
        (SettingKind::String, Domain::AbsolutePath(maximum)) => {
            matches!(
                setting.setting.as_str(),
                "StorageDataDirectory" | "StorageSecretsDirectory"
            ) && valid_absolute_path(&setting.default, *maximum)
                && setting.secrecy == Secrecy::Public
        },
        (SettingKind::String, Domain::ProtectedAbsolutePath(maximum)) => {
            setting.setting == "SecurityLocalKeyFile"
                && valid_absolute_path(&setting.default, *maximum)
                && setting.secrecy == Secrecy::SecretBearing
                && setting.provenance == Provenance::ProtectedConfigurationFileOnly
        },
        _ => false,
    };
    if !valid {
        return Err(XtaskError::invalid_path(
            path,
            "canonical Rust configuration setting semantics are invalid or ambiguous",
        ));
    }
    if setting.provenance == Provenance::NonSecretOverrides
        && setting.secrecy == Secrecy::SecretBearing
    {
        return Err(XtaskError::invalid_path(
            path,
            "secret-bearing settings cannot permit environment or command-line provenance",
        ));
    }
    Ok(())
}

fn validate_path(source_path: &Path, setting_path: &str) -> Result<(), XtaskError> {
    let segments = setting_path.split('.').collect::<Vec<_>>();
    if segments.is_empty()
        || segments.len() > 2
        || segments.iter().any(|segment| {
            segment.is_empty()
                || segment.len() > 64
                || !segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        })
    {
        return Err(XtaskError::invalid_path(
            source_path,
            "canonical Rust configuration path is outside the bounded dotted grammar",
        ));
    }
    Ok(())
}

fn valid_absolute_path(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.starts_with('/')
        && !value.split('/').any(|component| component == "..")
}

fn json_schema(specification: &ConfigurationSpec) -> Result<String, XtaskError> {
    let schema_version = setting(specification, "SchemaVersion")?;
    let mut sections = BTreeMap::<&str, Vec<(&str, &SettingSpec)>>::new();
    for setting in &specification.settings {
        if setting.setting == "SchemaVersion" {
            continue;
        }
        let Some((section, field)) = setting.path.split_once('.') else {
            return Err(XtaskError::invalid(
                "canonical configuration model",
                "non-version settings must use one bounded section and field",
            ));
        };
        sections.entry(section).or_default().push((field, setting));
    }
    let mut properties = Vec::with_capacity(sections.len().saturating_add(1));
    properties.push(format!(
        "    \"{}\": {}",
        schema_version.path,
        json_constraint(schema_version)
    ));
    for (section, mut fields) in sections {
        fields.sort_by_key(|(field, _)| *field);
        let rendered = fields
            .into_iter()
            .map(|(field, setting)| format!("\"{field}\": {}", json_constraint(setting)))
            .collect::<Vec<_>>()
            .join(", ");
        properties.push(format!(
            "    \"{section}\": {{\"type\": \"object\", \"additionalProperties\": false, \"properties\": {{{rendered}}}}}"
        ));
    }
    Ok(format!(
        "{{\n  \"$schema\": \"https://json-schema.org/draft/2020-12/schema\",\n  \"x-positron-generated-from\": \"{SOURCE}\",\n  \"title\": \"Positron Configuration Contract v{}\",\n  \"type\": \"object\",\n  \"additionalProperties\": false,\n  \"properties\": {{\n{}\n  }},\n  \"required\": [\"{}\"]\n}}\n",
        schema_version.default,
        properties.join(",\n"),
        schema_version.path,
    ))
}

fn json_constraint(setting: &SettingSpec) -> String {
    match &setting.domain {
        Domain::ExactUnsignedInteger(value) => format!("{{\"const\": {value}}}"),
        Domain::StringEnumeration(values) => format!(
            "{{\"type\": \"string\", \"enum\": [{}]}}",
            values
                .iter()
                .map(|value| format!("\"{value}\""))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Domain::UnsignedIntegerRange(minimum, maximum) => {
            format!("{{\"type\": \"integer\", \"minimum\": {minimum}, \"maximum\": {maximum}}}")
        },
        Domain::LoopbackSocketAddress(maximum) => format!(
            "{{\"type\": \"string\", \"maxLength\": {maximum}, \"x-positron-address-scope\": \"loopback-only\"}}"
        ),
        Domain::AbsolutePath(maximum) => {
            format!("{{\"type\": \"string\", \"maxLength\": {maximum}}}")
        },
        Domain::ProtectedAbsolutePath(maximum) => {
            format!("{{\"type\": \"string\", \"maxLength\": {maximum}, \"writeOnly\": true}}")
        },
    }
}

fn reference(specification: &ConfigurationSpec) -> Result<String, XtaskError> {
    let schema_version = setting(specification, "SchemaVersion")?;
    let mut output = String::with_capacity(2_048);
    output.push_str(&format!(
        "<!-- Generated by `cargo xtask generate-config` from `{SOURCE}`; do not edit. -->\n\n"
    ));
    output.push_str(&format!(
        "# Positron Configuration Contract v{}\n\n",
        schema_version.default
    ));
    output.push_str(
        "Precedence: compiled defaults, TOML file, non-secret POSITRON__ overrides, then non-secret CLI overrides.\n\n",
    );
    output.push_str("| Setting | Type | Default | Domain | Secrecy | Provenance | Mutability |\n");
    output.push_str("| --- | --- | --- | --- | --- | --- | --- |\n");
    for required in REQUIRED_SETTINGS {
        let setting = setting(specification, required)?;
        output.push_str("| `");
        output.push_str(&setting.path);
        output.push_str("` | ");
        output.push_str(kind_label(setting.kind));
        output.push_str(" | `");
        output.push_str(if setting.secrecy == Secrecy::SecretBearing {
            "<redacted protected-file reference>"
        } else {
            &setting.default
        });
        output.push_str("` | ");
        output.push_str(&domain_label(&setting.domain));
        output.push_str(" | ");
        output.push_str(secrecy_label(setting.secrecy));
        output.push_str(" | ");
        output.push_str(provenance_label(setting.provenance));
        output.push_str(" | ");
        output.push_str(mutability_label(setting.mutability));
        output.push_str(" |\n");
    }
    Ok(output)
}

fn validation_fixtures(specification: &ConfigurationSpec) -> Result<String, XtaskError> {
    let schema_version = setting(specification, "SchemaVersion")?;
    let shutdown = setting(specification, "RuntimeShutdownGraceSeconds")?;
    let Domain::UnsignedIntegerRange(_, maximum_shutdown_seconds) = &shutdown.domain else {
        return Err(XtaskError::invalid(
            "canonical configuration model",
            "shutdown grace must retain its bounded integer domain",
        ));
    };
    let oversized_document_bytes = MAX_SOURCE_BYTES.saturating_add(1);
    Ok(format!(
        "{{\n  \"schema_version\": 1,\n  \"generated_from\": \"{SOURCE}\",\n  \"maximum_document_bytes\": {MAX_SOURCE_BYTES},\n  \"cases\": [\n    {{\"id\": \"minimal-valid-document\", \"class\": \"positive\", \"toml\": \"schema_version = {}\\n\", \"expected\": \"accepted\"}},\n    {{\"id\": \"shutdown-upper-bound\", \"class\": \"boundary\", \"toml\": \"schema_version = {}\\n[runtime]\\nshutdown_grace_seconds = {maximum_shutdown_seconds}\\n\", \"expected\": \"accepted\"}},\n    {{\"id\": \"unknown-setting\", \"class\": \"negative\", \"toml\": \"schema_version = {}\\nunknown.setting = true\\n\", \"expected\": \"unknown_setting\"}},\n    {{\"id\": \"oversized-document\", \"class\": \"adversarial\", \"recipe\": {{\"repeat\": \"#\", \"bytes\": {oversized_document_bytes}}}, \"expected\": \"resource_limit\"}}\n  ]\n}}\n",
        schema_version.default, schema_version.default, schema_version.default,
    ))
}

const fn kind_label(kind: SettingKind) -> &'static str {
    match kind {
        SettingKind::Integer => "integer",
        SettingKind::String => "string",
    }
}

fn domain_label(domain: &Domain) -> String {
    match domain {
        Domain::ExactUnsignedInteger(value) => format!("exactly `{value}`"),
        Domain::StringEnumeration(values) => values
            .iter()
            .map(|value| format!("`{value}`"))
            .collect::<Vec<_>>()
            .join(", "),
        Domain::UnsignedIntegerRange(minimum, maximum) => {
            format!("`{minimum}..={maximum}`")
        },
        Domain::LoopbackSocketAddress(maximum) => {
            format!("loopback socket address; at most {maximum} bytes")
        },
        Domain::AbsolutePath(maximum) => format!("absolute path; at most {maximum} bytes"),
        Domain::ProtectedAbsolutePath(maximum) => {
            format!("protected absolute path; at most {maximum} bytes")
        },
    }
}

const fn secrecy_label(secrecy: Secrecy) -> &'static str {
    match secrecy {
        Secrecy::Public => "public",
        Secrecy::SecretBearing => "secret-bearing (redacted)",
    }
}

const fn provenance_label(provenance: Provenance) -> &'static str {
    match provenance {
        Provenance::ConfigurationFileOnly => "compiled default, configuration file",
        Provenance::NonSecretOverrides => {
            "compiled default, configuration file, environment, command line"
        },
        Provenance::ProtectedConfigurationFileOnly => {
            "compiled default, protected configuration-file reference"
        },
    }
}

const fn mutability_label(mutability: Mutability) -> &'static str {
    match mutability {
        Mutability::LiveReloadable => "live-reloadable",
        Mutability::DrainAndReload => "drain-and-reload",
        Mutability::RestartRequired => "restart-required",
        Mutability::ImmutableAfterInitialization => "immutable after initialization",
    }
}

fn setting<'a>(
    specification: &'a ConfigurationSpec,
    name: &str,
) -> Result<&'a SettingSpec, XtaskError> {
    specification
        .settings
        .iter()
        .find(|setting| setting.setting == name)
        .ok_or_else(|| {
            XtaskError::invalid(
                "canonical configuration model",
                format!("required setting variant `{name}` is unavailable"),
            )
        })
}

fn write_generated(root: &Path, relative: &str, contents: &str) -> Result<(), XtaskError> {
    let path = root.join(relative);
    if fs::read_to_string(&path).ok().as_deref() == Some(contents) {
        return Ok(());
    }
    fs::write(&path, contents)
        .map_err(|source| XtaskError::io(format!("write {}", path.display()), source))
}
