//! Deterministic generation for the canonical Positron configuration contract.

use std::fs;
use std::path::Path;

use crate::error::XtaskError;

const SOURCE: &str = "configuration/spec.tsv";
const JSON_SCHEMA: &str = "configuration/schema.json";
const REFERENCE: &str = "configuration/reference.md";
const HEADER: &str = "path\tkind\tdefault\tsecrecy\tmutability\tconstraint";
const MAX_SOURCE_BYTES: usize = 8_192;
const MAX_FIELD_BYTES: usize = 256;
const REQUIRED_PATHS: [&str; 7] = [
    "schema_version",
    "diagnostics.log_level",
    "runtime.shutdown_grace_seconds",
    "listener.control_bind_address",
    "storage.data_directory",
    "storage.secrets_directory",
    "security.local_key_file",
];

struct ConfigurationSpec {
    settings: Vec<SettingSpec>,
}

struct SettingSpec {
    path: String,
    kind: SettingKind,
    default: String,
    secrecy: String,
    mutability: String,
    constraint: Constraint,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum SettingKind {
    Integer,
    String,
}

enum Constraint {
    Constant(u16),
    Enumeration(Vec<String>),
    Range { minimum: u16, maximum: u16 },
    MaximumLength(u16),
    MaximumLengthWriteOnly(u16),
}

/// Regenerates every checked artifact owned by the configuration specification.
pub(crate) fn generate(root: &Path) -> Result<(), XtaskError> {
    let source_path = root.join(SOURCE);
    let source = fs::read_to_string(&source_path)
        .map_err(|source| XtaskError::io(format!("read {}", source_path.display()), source))?;
    let specification = parse_source(&source_path, &source)?;
    write_generated(root, JSON_SCHEMA, &json_schema(&specification)?)?;
    write_generated(root, REFERENCE, &reference(&specification))?;
    Ok(())
}

fn parse_source(path: &Path, source: &str) -> Result<ConfigurationSpec, XtaskError> {
    if source.len() > MAX_SOURCE_BYTES {
        return Err(XtaskError::invalid_path(
            path,
            "canonical configuration specification exceeds 8192 bytes",
        ));
    }
    let mut lines = source.lines();
    if lines.next() != Some(HEADER) {
        return Err(XtaskError::invalid_path(
            path,
            "canonical configuration specification header is not exact",
        ));
    }
    let mut settings = Vec::with_capacity(REQUIRED_PATHS.len());
    for line in lines {
        if line.is_empty() {
            return Err(XtaskError::invalid_path(
                path,
                "canonical configuration specification contains an empty declaration",
            ));
        }
        let fields = line.split('\t').collect::<Vec<_>>();
        let [setting_path, kind, default, secrecy, mutability, constraint] = fields.as_slice()
        else {
            return Err(XtaskError::invalid_path(
                path,
                "canonical configuration declaration must have exactly six fields",
            ));
        };
        if fields.iter().any(|field| {
            field.is_empty()
                || field.len() > MAX_FIELD_BYTES
                || field.contains(['\r', '\n', '`', '|'])
        }) {
            return Err(XtaskError::invalid_path(
                path,
                "canonical configuration declaration contains an invalid or oversized field",
            ));
        }
        if !REQUIRED_PATHS.contains(setting_path) {
            return Err(XtaskError::invalid_path(
                path,
                "canonical configuration declaration has an unsupported setting path",
            ));
        }
        settings.push(SettingSpec {
            path: (*setting_path).to_owned(),
            kind: parse_kind(path, kind)?,
            default: (*default).to_owned(),
            secrecy: parse_secrecy(path, secrecy)?.to_owned(),
            mutability: parse_mutability(path, mutability)?.to_owned(),
            constraint: parse_constraint(path, constraint)?,
        });
    }
    if settings.len() != REQUIRED_PATHS.len()
        || REQUIRED_PATHS.iter().any(|required| {
            settings
                .iter()
                .filter(|setting| setting.path == *required)
                .count()
                != 1
        })
    {
        return Err(XtaskError::invalid_path(
            path,
            "required configuration setting is missing or ambiguous",
        ));
    }
    validate_semantics(path, &settings)?;
    Ok(ConfigurationSpec { settings })
}

fn parse_kind(path: &Path, value: &str) -> Result<SettingKind, XtaskError> {
    match value {
        "integer" => Ok(SettingKind::Integer),
        "string" => Ok(SettingKind::String),
        _ => Err(XtaskError::invalid_path(
            path,
            "canonical configuration kind is unsupported",
        )),
    }
}

fn parse_secrecy<'a>(path: &Path, value: &'a str) -> Result<&'a str, XtaskError> {
    match value {
        "public" | "secret-bearing (redacted)" => Ok(value),
        _ => Err(XtaskError::invalid_path(
            path,
            "canonical configuration secrecy class is unsupported",
        )),
    }
}

fn parse_mutability<'a>(path: &Path, value: &'a str) -> Result<&'a str, XtaskError> {
    match value {
        "live-reloadable"
        | "drain-and-reload"
        | "restart-required"
        | "immutable after initialization" => Ok(value),
        _ => Err(XtaskError::invalid_path(
            path,
            "canonical configuration mutability class is unsupported",
        )),
    }
}

fn parse_constraint(path: &Path, value: &str) -> Result<Constraint, XtaskError> {
    if let Some(value) = value.strip_prefix("const:") {
        return parse_u16(path, value).map(Constraint::Constant);
    }
    if let Some(values) = value.strip_prefix("enum:") {
        let values = values.split(',').map(str::to_owned).collect::<Vec<_>>();
        if values.is_empty()
            || values.len() > 8
            || values.iter().any(|value| {
                value.is_empty()
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
            })
        {
            return Err(XtaskError::invalid_path(
                path,
                "canonical configuration enumeration is invalid or oversized",
            ));
        }
        return Ok(Constraint::Enumeration(values));
    }
    if let Some(value) = value.strip_prefix("range:") {
        let Some((minimum, maximum)) = value.split_once(':') else {
            return Err(XtaskError::invalid_path(
                path,
                "canonical configuration range is malformed",
            ));
        };
        let minimum = parse_u16(path, minimum)?;
        let maximum = parse_u16(path, maximum)?;
        if minimum > maximum {
            return Err(XtaskError::invalid_path(
                path,
                "canonical configuration range is inverted",
            ));
        }
        return Ok(Constraint::Range { minimum, maximum });
    }
    if let Some(value) = value.strip_prefix("max-length:") {
        return parse_u16(path, value).map(Constraint::MaximumLength);
    }
    if let Some(value) = value.strip_prefix("max-length-write-only:") {
        return parse_u16(path, value).map(Constraint::MaximumLengthWriteOnly);
    }
    Err(XtaskError::invalid_path(
        path,
        "canonical configuration constraint is unsupported",
    ))
}

fn parse_u16(path: &Path, value: &str) -> Result<u16, XtaskError> {
    if value.is_empty()
        || value.len() > 5
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(XtaskError::invalid_path(
            path,
            "canonical configuration integer is noncanonical",
        ));
    }
    value.parse::<u16>().map_err(|_| {
        XtaskError::invalid_path(path, "canonical configuration integer is out of range")
    })
}

fn validate_semantics(path: &Path, settings: &[SettingSpec]) -> Result<(), XtaskError> {
    for setting in settings {
        let valid = match (&setting.kind, &setting.constraint) {
            (SettingKind::Integer, Constraint::Constant(value)) => {
                setting.path == "schema_version"
                    && setting.default == value.to_string()
                    && setting.secrecy == "public"
            },
            (SettingKind::Integer, Constraint::Range { .. }) => {
                setting.path == "runtime.shutdown_grace_seconds" && setting.secrecy == "public"
            },
            (SettingKind::String, Constraint::Enumeration(_)) => {
                setting.path == "diagnostics.log_level" && setting.secrecy == "public"
            },
            (SettingKind::String, Constraint::MaximumLength(maximum)) => {
                *maximum == 256
                    && matches!(
                        setting.path.as_str(),
                        "listener.control_bind_address"
                            | "storage.data_directory"
                            | "storage.secrets_directory"
                    )
                    && setting.secrecy == "public"
            },
            (SettingKind::String, Constraint::MaximumLengthWriteOnly(maximum)) => {
                *maximum == 256
                    && setting.path == "security.local_key_file"
                    && setting.default == "redacted protected-file reference"
                    && setting.secrecy == "secret-bearing (redacted)"
            },
            _ => false,
        };
        if !valid {
            return Err(XtaskError::invalid_path(
                path,
                "canonical configuration setting semantics are invalid or ambiguous",
            ));
        }
    }
    Ok(())
}

fn json_schema(specification: &ConfigurationSpec) -> Result<String, XtaskError> {
    let schema_version = setting(specification, "schema_version")?;
    let log_level = setting(specification, "diagnostics.log_level")?;
    let shutdown = setting(specification, "runtime.shutdown_grace_seconds")?;
    let listener = setting(specification, "listener.control_bind_address")?;
    let data = setting(specification, "storage.data_directory")?;
    let secrets = setting(specification, "storage.secrets_directory")?;
    let key = setting(specification, "security.local_key_file")?;
    Ok(format!(
        "{{\n  \"$schema\": \"https://json-schema.org/draft/2020-12/schema\",\n  \"x-positron-generated-from\": \"configuration/spec.tsv\",\n  \"title\": \"Positron Configuration Contract v1\",\n  \"type\": \"object\",\n  \"additionalProperties\": false,\n  \"properties\": {{\n    \"schema_version\": {},\n    \"diagnostics\": {{\"type\": \"object\", \"additionalProperties\": false, \"properties\": {{\"log_level\": {}}}}},\n    \"runtime\": {{\"type\": \"object\", \"additionalProperties\": false, \"properties\": {{\"shutdown_grace_seconds\": {}}}}},\n    \"listener\": {{\"type\": \"object\", \"additionalProperties\": false, \"properties\": {{\"control_bind_address\": {}}}}},\n    \"storage\": {{\"type\": \"object\", \"additionalProperties\": false, \"properties\": {{\"data_directory\": {}, \"secrets_directory\": {}}}}},\n    \"security\": {{\"type\": \"object\", \"additionalProperties\": false, \"properties\": {{\"local_key_file\": {}}}}}\n  }},\n  \"required\": [\"schema_version\"]\n}}\n",
        json_constraint(schema_version),
        json_constraint(log_level),
        json_constraint(shutdown),
        json_constraint(listener),
        json_constraint(data),
        json_constraint(secrets),
        json_constraint(key),
    ))
}

fn json_constraint(setting: &SettingSpec) -> String {
    match &setting.constraint {
        Constraint::Constant(value) => format!("{{\"const\": {value}}}"),
        Constraint::Enumeration(values) => format!(
            "{{\"enum\": [{}]}}",
            values
                .iter()
                .map(|value| format!("\"{value}\""))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Constraint::Range { minimum, maximum } => {
            format!("{{\"type\": \"integer\", \"minimum\": {minimum}, \"maximum\": {maximum}}}")
        },
        Constraint::MaximumLength(maximum) => {
            format!("{{\"type\": \"string\", \"maxLength\": {maximum}}}")
        },
        Constraint::MaximumLengthWriteOnly(maximum) => {
            format!("{{\"type\": \"string\", \"maxLength\": {maximum}, \"writeOnly\": true}}")
        },
    }
}

fn reference(specification: &ConfigurationSpec) -> String {
    let mut output = String::with_capacity(1_024);
    output.push_str(
        "<!-- Generated by `cargo xtask generate-config` from `configuration/spec.tsv`; do not edit. -->\n\n",
    );
    output.push_str("# Positron Configuration Contract v1\n\n");
    output.push_str(
        "Precedence: compiled defaults, TOML file, non-secret POSITRON__ overrides, then non-secret CLI overrides.\n\n",
    );
    output.push_str("| Setting | Default | Secrecy | Mutability |\n");
    output.push_str("| --- | --- | --- | --- |\n");
    for required in REQUIRED_PATHS {
        if let Some(setting) = specification
            .settings
            .iter()
            .find(|setting| setting.path == required)
        {
            output.push_str("| `");
            output.push_str(&setting.path);
            output.push_str("` | `");
            output.push_str(&setting.default);
            output.push_str("` | ");
            output.push_str(&setting.secrecy);
            output.push_str(" | ");
            output.push_str(&setting.mutability);
            output.push_str(" |\n");
        }
    }
    output
}

fn setting<'a>(
    specification: &'a ConfigurationSpec,
    path: &str,
) -> Result<&'a SettingSpec, XtaskError> {
    specification
        .settings
        .iter()
        .find(|setting| setting.path == path)
        .ok_or_else(|| {
            XtaskError::invalid(
                "canonical configuration model",
                format!("required setting `{path}` is unavailable"),
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
