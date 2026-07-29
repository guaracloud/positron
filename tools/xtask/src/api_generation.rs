//! Deterministic generation for the canonical Positron v1 public interface.

use std::fs;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::error::XtaskError;

const SOURCE: &str = "api/positron/v1/positron.proto";
const GENERATED_RUST: &str = "crates/positron-api/src/generated.rs";
const SCHEMA_DIGEST: &str = "api/positron/v1/schema.sha256";
const OPENAPI: &str = "api/positron/v1/openapi.json";
const HTTP_MAPPING: &str = "api/positron/v1/http.json";
const MAX_SOURCE_BYTES: usize = 65_536;
const MAX_DECLARATIONS: usize = 128;

#[derive(Debug)]
struct ApiModel {
    package: String,
    service: String,
    rpc: String,
    request: ProtoMessage,
    response: ProtoMessage,
    public_error: ProtoMessage,
    capability: ProtoEnum,
    availability: ProtoEnum,
    retry_class: ProtoEnum,
    completion_state: ProtoEnum,
    deprecation_state: ProtoEnum,
    error_code: ProtoEnum,
    failure_source: ProtoEnum,
    safe_detail: ProtoEnum,
}

#[derive(Debug)]
struct ProtoField {
    kind: String,
    name: String,
    number: u8,
    deprecated: bool,
}

#[derive(Debug)]
struct ProtoMessage {
    name: String,
    fields: Vec<ProtoField>,
}

#[derive(Debug)]
struct ProtoEnum {
    name: String,
    values: Vec<ProtoEnumValue>,
}

#[derive(Debug)]
struct ProtoEnumValue {
    name: String,
    number: u32,
    deprecated: bool,
}

/// Regenerates every checked artifact owned by the canonical API definition.
pub(crate) fn generate(root: &Path) -> Result<(), XtaskError> {
    let source_path = root.join(SOURCE);
    let source = fs::read_to_string(&source_path)
        .map_err(|source| XtaskError::io(format!("read {}", source_path.display()), source))?;
    let model = parse_source(&source_path, &source)?;
    let digest = Sha256::digest(source.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();

    write_generated(root, GENERATED_RUST, &generated_rust(&model, &digest)?)?;
    write_generated(root, SCHEMA_DIGEST, &format!("{digest}\n"))?;
    write_generated(root, OPENAPI, &openapi(&model, &digest)?)?;
    write_generated(root, HTTP_MAPPING, &http_mapping(&model, &digest)?)?;
    Ok(())
}

fn parse_source(path: &Path, source: &str) -> Result<ApiModel, XtaskError> {
    if source.len() > MAX_SOURCE_BYTES {
        return Err(XtaskError::invalid_path(
            path,
            "canonical API source exceeds 65536 bytes",
        ));
    }
    let statements = source
        .lines()
        .map(|line| line.split_once("//").map_or(line, |(code, _)| code).trim())
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    if statements.len() > MAX_DECLARATIONS {
        return Err(XtaskError::invalid_path(
            path,
            "canonical API source exceeds 128 declarations",
        ));
    }
    if statements.first().copied() != Some("syntax = \"proto3\";") {
        return Err(XtaskError::invalid_path(
            path,
            "canonical API must begin with proto3 syntax",
        ));
    }
    let package = unique_prefixed(path, &statements, "package ", ";")?;
    let service = unique_braced(path, &statements, "service ")?;
    let rpc_line = statements
        .iter()
        .filter(|line| line.starts_with("rpc "))
        .copied()
        .collect::<Vec<_>>();
    let [rpc_line] = rpc_line.as_slice() else {
        return Err(XtaskError::invalid_path(
            path,
            "canonical API requires exactly one RPC",
        ));
    };
    let rpc_body = rpc_line
        .strip_prefix("rpc ")
        .and_then(|value| value.strip_suffix(';'))
        .ok_or_else(|| XtaskError::invalid_path(path, "RPC declaration is malformed"))?;
    let (rpc, signature) = rpc_body
        .split_once('(')
        .ok_or_else(|| XtaskError::invalid_path(path, "RPC request is missing"))?;
    let (request, returns) = signature
        .split_once(") returns (")
        .ok_or_else(|| XtaskError::invalid_path(path, "RPC return is malformed"))?;
    let response = returns
        .strip_suffix(')')
        .ok_or_else(|| XtaskError::invalid_path(path, "RPC response is malformed"))?;
    for identifier in [&package, &service, rpc, request, response] {
        validate_identifier(path, identifier)?;
    }
    let declarations = statements
        .iter()
        .filter_map(|line| {
            line.strip_prefix("message ")
                .or_else(|| line.strip_prefix("enum "))
                .and_then(|value| value.strip_suffix(" {"))
                .map(str::to_owned)
        })
        .collect::<Vec<_>>();
    for required in [
        request,
        response,
        "Capability",
        "CapabilityAvailability",
        "RetryClass",
        "CompletionState",
        "DeprecationState",
        "PublicError",
        "PublicErrorCode",
        "FailureSource",
        "SafeDetail",
    ] {
        if declarations
            .iter()
            .filter(|name| name.as_str() == required)
            .count()
            != 1
        {
            return Err(XtaskError::invalid_path(
                path,
                format!("required declaration `{required}` is missing or ambiguous"),
            ));
        }
    }
    if declarations.len() != 11 {
        return Err(XtaskError::invalid_path(
            path,
            "unsupported protobuf declaration",
        ));
    }
    validate_supported_grammar(
        path,
        &statements,
        &package,
        &service,
        rpc_line,
        &declarations,
    )?;
    let request = parse_message(path, &statements, request, &["uint32", "Capability"])?;
    let response = parse_message(
        path,
        &statements,
        response,
        &[
            "uint32",
            "string",
            "CapabilityAvailability",
            "PublicError",
            "DeprecationState",
            "Capability",
        ],
    )?;
    let public_error = parse_message(
        path,
        &statements,
        "PublicError",
        &[
            "PublicErrorCode",
            "RetryClass",
            "CompletionState",
            "FailureSource",
            "SafeDetail",
        ],
    )?;
    let capability = parse_enum(
        path,
        &statements,
        "Capability",
        &[
            "CAPABILITY_UNSPECIFIED",
            "CAPABILITY_CANONICAL_PUBLIC_INTERFACE",
            "CAPABILITY_RELEASE_ONE_QUERY",
            "CAPABILITY_METRICS",
        ],
    )?;
    let availability = parse_enum(
        path,
        &statements,
        "CapabilityAvailability",
        &[
            "CAPABILITY_AVAILABILITY_UNSPECIFIED",
            "CAPABILITY_AVAILABILITY_IMPLEMENTED",
            "CAPABILITY_AVAILABILITY_UNAVAILABLE",
            "CAPABILITY_AVAILABILITY_UNSUPPORTED",
            "CAPABILITY_AVAILABILITY_VERSION_INCOMPATIBLE",
        ],
    )?;
    let retry_class = parse_enum(
        path,
        &statements,
        "RetryClass",
        &[
            "RETRY_CLASS_UNSPECIFIED",
            "RETRY_CLASS_NEVER",
            "RETRY_CLASS_AFTER_BACKOFF",
            "RETRY_CLASS_AFTER_INPUT_CORRECTION",
        ],
    )?;
    let completion_state = parse_enum(
        path,
        &statements,
        "CompletionState",
        &["COMPLETION_STATE_UNSPECIFIED", "COMPLETION_STATE_REJECTED"],
    )?;
    let deprecation_state = parse_enum(
        path,
        &statements,
        "DeprecationState",
        &[
            "DEPRECATION_STATE_UNSPECIFIED",
            "DEPRECATION_STATE_CURRENT",
            "DEPRECATION_STATE_DEPRECATED",
        ],
    )?;
    let error_code = parse_enum(
        path,
        &statements,
        "PublicErrorCode",
        &[
            "PUBLIC_ERROR_CODE_UNSPECIFIED",
            "PUBLIC_ERROR_CODE_UNSUPPORTED_API_VERSION",
            "PUBLIC_ERROR_CODE_CAPABILITY_UNAVAILABLE",
            "PUBLIC_ERROR_CODE_CAPABILITY_UNSUPPORTED",
            "PUBLIC_ERROR_CODE_MALFORMED_REQUEST",
            "PUBLIC_ERROR_CODE_REQUEST_TOO_LARGE",
            "PUBLIC_ERROR_CODE_UNKNOWN_FIELD",
        ],
    )?;
    let failure_source = parse_enum(
        path,
        &statements,
        "FailureSource",
        &[
            "FAILURE_SOURCE_UNSPECIFIED",
            "FAILURE_SOURCE_CAPABILITY_NEGOTIATION",
            "FAILURE_SOURCE_GRPC_DECODE",
            "FAILURE_SOURCE_HTTP_DECODE",
        ],
    )?;
    let safe_detail = parse_enum(
        path,
        &statements,
        "SafeDetail",
        &[
            "SAFE_DETAIL_UNSPECIFIED",
            "SAFE_DETAIL_API_MAJOR_UNSUPPORTED",
            "SAFE_DETAIL_CAPABILITY_NOT_AVAILABLE",
            "SAFE_DETAIL_CAPABILITY_NOT_SUPPORTED",
            "SAFE_DETAIL_REQUEST_MALFORMED",
            "SAFE_DETAIL_REQUEST_LIMIT_EXCEEDED",
            "SAFE_DETAIL_FIELD_NOT_RECOGNIZED",
        ],
    )?;
    Ok(ApiModel {
        package,
        service,
        rpc: rpc.to_owned(),
        request,
        response,
        public_error,
        capability,
        availability,
        retry_class,
        completion_state,
        deprecation_state,
        error_code,
        failure_source,
        safe_detail,
    })
}

fn validate_supported_grammar(
    path: &Path,
    statements: &[&str],
    package: &str,
    service: &str,
    rpc_line: &str,
    declarations: &[String],
) -> Result<(), XtaskError> {
    #[derive(Clone, Copy)]
    enum Section {
        TopLevel,
        Service,
        Message,
        Enum,
    }

    let package_declaration = format!("package {package};");
    let service_declaration = format!("service {service} {{");
    let mut section = Section::TopLevel;
    let mut syntax_seen = false;
    let mut package_seen = false;
    let mut service_seen = false;
    let mut rpc_seen = false;
    for statement in statements {
        match section {
            Section::TopLevel if *statement == "syntax = \"proto3\";" && !syntax_seen => {
                syntax_seen = true;
            },
            Section::TopLevel if *statement == package_declaration && !package_seen => {
                package_seen = true;
            },
            Section::TopLevel if *statement == service_declaration && !service_seen => {
                service_seen = true;
                section = Section::Service;
            },
            Section::TopLevel => {
                let message = statement
                    .strip_prefix("message ")
                    .and_then(|value| value.strip_suffix(" {"));
                let proto_enum = statement
                    .strip_prefix("enum ")
                    .and_then(|value| value.strip_suffix(" {"));
                if message.is_some_and(|name| declarations.iter().any(|item| item == name)) {
                    section = Section::Message;
                } else if proto_enum
                    .is_some_and(|name| declarations.iter().any(|item| item == name))
                {
                    section = Section::Enum;
                } else {
                    return Err(XtaskError::invalid_path(
                        path,
                        "unsupported protobuf statement",
                    ));
                }
            },
            Section::Service if *statement == rpc_line && !rpc_seen => {
                rpc_seen = true;
            },
            Section::Service if *statement == "}" && rpc_seen => {
                section = Section::TopLevel;
            },
            Section::Message if *statement == "}" => {
                section = Section::TopLevel;
            },
            Section::Message => {
                parse_field(path, statement)?;
            },
            Section::Enum if *statement == "}" => {
                section = Section::TopLevel;
            },
            Section::Enum => {
                parse_enum_value(path, statement)?;
            },
            Section::Service => {
                return Err(XtaskError::invalid_path(
                    path,
                    "unsupported protobuf service statement",
                ));
            },
        }
    }
    if !matches!(section, Section::TopLevel)
        || !syntax_seen
        || !package_seen
        || !service_seen
        || !rpc_seen
    {
        return Err(XtaskError::invalid_path(
            path,
            "canonical API grammar is incomplete",
        ));
    }
    Ok(())
}

fn parse_message(
    path: &Path,
    lines: &[&str],
    message: &str,
    required_kinds: &[&str],
) -> Result<ProtoMessage, XtaskError> {
    let declaration = format!("message {message} {{");
    let Some(start) = lines.iter().position(|line| *line == declaration) else {
        return Err(XtaskError::invalid_path(path, "request message is missing"));
    };
    let Some(body) = lines.get(start + 1..) else {
        return Err(XtaskError::invalid_path(
            path,
            "request message body is missing",
        ));
    };
    let end = body
        .iter()
        .position(|line| *line == "}")
        .ok_or_else(|| XtaskError::invalid_path(path, "request message is not closed"))?;
    let fields = body
        .get(..end)
        .ok_or_else(|| XtaskError::invalid_path(path, "request message body is malformed"))?
        .iter()
        .map(|line| parse_field(path, line))
        .collect::<Result<Vec<_>, _>>()?;
    if fields.len() != required_kinds.len()
        || required_kinds
            .iter()
            .any(|kind| fields.iter().filter(|field| field.kind == *kind).count() != 1)
        || has_duplicate_numbers(fields.iter().map(|field| u32::from(field.number)))
    {
        return Err(XtaskError::invalid_path(
            path,
            format!("message `{message}` fields are missing or ambiguous"),
        ));
    }
    Ok(ProtoMessage {
        name: message.to_owned(),
        fields,
    })
}

fn parse_field(path: &Path, line: &str) -> Result<ProtoField, XtaskError> {
    let declaration = line
        .strip_suffix(';')
        .ok_or_else(|| XtaskError::invalid_path(path, "request field is malformed"))?;
    let (kind, assignment) = declaration
        .split_once(' ')
        .ok_or_else(|| XtaskError::invalid_path(path, "request field type is missing"))?;
    let (name, number_and_options) = assignment
        .split_once(" = ")
        .ok_or_else(|| XtaskError::invalid_path(path, "request field number is missing"))?;
    validate_identifier(path, kind)?;
    validate_identifier(path, name)?;
    let (number, deprecated) = parse_number_and_options(path, number_and_options)?;
    let number = number
        .parse::<u8>()
        .map_err(|_| XtaskError::invalid_path(path, "request field number is invalid"))?;
    if number == 0 || number > 15 {
        return Err(XtaskError::invalid_path(
            path,
            "request field number exceeds the bounded single-byte tag range",
        ));
    }
    Ok(ProtoField {
        kind: kind.to_owned(),
        name: name.to_owned(),
        number,
        deprecated,
    })
}

fn parse_enum(
    path: &Path,
    lines: &[&str],
    name: &str,
    required_values: &[&str],
) -> Result<ProtoEnum, XtaskError> {
    let declaration = format!("enum {name} {{");
    let starts = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| **line == declaration)
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    let [start] = starts.as_slice() else {
        return Err(XtaskError::invalid_path(
            path,
            format!("enum `{name}` is missing or ambiguous"),
        ));
    };
    let Some(body) = lines.get(start + 1..) else {
        return Err(XtaskError::invalid_path(path, "enum body is missing"));
    };
    let end = body
        .iter()
        .position(|line| *line == "}")
        .ok_or_else(|| XtaskError::invalid_path(path, "enum is not closed"))?;
    let values = body
        .get(..end)
        .ok_or_else(|| XtaskError::invalid_path(path, "enum body is malformed"))?
        .iter()
        .map(|line| parse_enum_value(path, line))
        .collect::<Result<Vec<_>, _>>()?;
    if values.len() != required_values.len()
        || required_values.iter().any(|required| {
            values
                .iter()
                .filter(|value| value.name == *required)
                .count()
                != 1
        })
        || has_duplicate_numbers(values.iter().map(|value| value.number))
        || values.first().map(|value| value.number) != Some(0)
    {
        return Err(XtaskError::invalid_path(
            path,
            format!("enum `{name}` values are missing, ambiguous, or unsupported"),
        ));
    }
    Ok(ProtoEnum {
        name: name.to_owned(),
        values,
    })
}

fn parse_enum_value(path: &Path, line: &str) -> Result<ProtoEnumValue, XtaskError> {
    let declaration = line
        .strip_suffix(';')
        .ok_or_else(|| XtaskError::invalid_path(path, "enum value is malformed"))?;
    let (name, number_and_options) = declaration
        .split_once(" = ")
        .ok_or_else(|| XtaskError::invalid_path(path, "enum value number is missing"))?;
    validate_identifier(path, name)?;
    let (number, deprecated) = parse_number_and_options(path, number_and_options)?;
    let number = number
        .parse::<u32>()
        .map_err(|_| XtaskError::invalid_path(path, "enum value number is invalid"))?;
    Ok(ProtoEnumValue {
        name: name.to_owned(),
        number,
        deprecated,
    })
}

fn parse_number_and_options<'a>(
    path: &Path,
    value: &'a str,
) -> Result<(&'a str, bool), XtaskError> {
    let Some((number, options)) = value.split_once(" [") else {
        return Ok((value, false));
    };
    let options = options
        .strip_suffix(']')
        .ok_or_else(|| XtaskError::invalid_path(path, "field options are malformed"))?;
    match options {
        "deprecated = true" => Ok((number, true)),
        "deprecated = false" => Ok((number, false)),
        _ => Err(XtaskError::invalid_path(
            path,
            "unsupported protobuf field or enum option",
        )),
    }
}

fn has_duplicate_numbers(values: impl Iterator<Item = u32>) -> bool {
    let values = values.collect::<Vec<_>>();
    values
        .iter()
        .enumerate()
        .any(|(index, value)| values.iter().skip(index + 1).any(|other| other == value))
}

fn unique_prefixed(
    path: &Path,
    lines: &[&str],
    prefix: &str,
    suffix: &str,
) -> Result<String, XtaskError> {
    let values = lines
        .iter()
        .filter_map(|line| {
            line.strip_prefix(prefix)
                .and_then(|value| value.strip_suffix(suffix))
        })
        .collect::<Vec<_>>();
    let [value] = values.as_slice() else {
        return Err(XtaskError::invalid_path(
            path,
            format!("declaration `{prefix}` is missing or ambiguous"),
        ));
    };
    Ok((*value).to_owned())
}

fn unique_braced(path: &Path, lines: &[&str], prefix: &str) -> Result<String, XtaskError> {
    let values = lines
        .iter()
        .filter_map(|line| {
            line.strip_prefix(prefix)
                .and_then(|value| value.strip_suffix(" {"))
        })
        .collect::<Vec<_>>();
    let [value] = values.as_slice() else {
        return Err(XtaskError::invalid_path(
            path,
            format!("declaration `{prefix}` is missing or ambiguous"),
        ));
    };
    Ok((*value).to_owned())
}

fn validate_identifier(path: &Path, value: &str) -> Result<(), XtaskError> {
    if value.is_empty()
        || value.len() > 128
        || !value.chars().all(|character| {
            character.is_ascii_alphanumeric() || character == '_' || character == '.'
        })
    {
        return Err(XtaskError::invalid_path(
            path,
            "canonical API identifier is malformed or oversized",
        ));
    }
    Ok(())
}

fn write_generated(root: &Path, relative: &str, contents: &str) -> Result<(), XtaskError> {
    let path = root.join(relative);
    if fs::read_to_string(&path).ok().as_deref() == Some(contents) {
        return Ok(());
    }
    fs::write(&path, contents)
        .map_err(|source| XtaskError::io(format!("write {}", path.display()), source))
}

fn required_field<'a>(message: &'a ProtoMessage, kind: &str) -> Result<&'a ProtoField, XtaskError> {
    message
        .fields
        .iter()
        .find(|field| field.kind == kind)
        .ok_or_else(|| {
            XtaskError::invalid(
                "canonical API model",
                format!("message `{}` is missing `{kind}`", message.name),
            )
        })
}

fn required_variant<'a>(
    proto_enum: &'a ProtoEnum,
    name: &str,
) -> Result<&'a ProtoEnumValue, XtaskError> {
    proto_enum
        .values
        .iter()
        .find(|value| value.name == name)
        .ok_or_else(|| {
            XtaskError::invalid(
                "canonical API model",
                format!("enum `{}` is missing `{name}`", proto_enum.name),
            )
        })
}

fn rust_variant_name(proto_enum: &ProtoEnum, value: &ProtoEnumValue) -> String {
    let prefix = format!("{}_", upper_snake(&proto_enum.name));
    let semantic = match value.name.strip_prefix(&prefix) {
        Some(semantic) => semantic,
        None => &value.name,
    };
    semantic
        .split('_')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut characters = part.chars();
            match characters.next() {
                Some(first) => {
                    let mut result = first.to_ascii_uppercase().to_string();
                    result.extend(characters.map(|character| character.to_ascii_lowercase()));
                    result
                },
                None => String::new(),
            }
        })
        .collect()
}

fn upper_snake(value: &str) -> String {
    let mut result = String::new();
    for (index, character) in value.chars().enumerate() {
        if character.is_ascii_uppercase() && index != 0 {
            result.push('_');
        }
        result.push(character.to_ascii_uppercase());
    }
    result
}

fn generated_enum(proto_enum: &ProtoEnum, rust_name: &str) -> String {
    let variants = proto_enum
        .values
        .iter()
        .map(|value| {
            format!(
                "    /// Generated from `{}`.\n    {} = {},",
                value.name,
                rust_variant_name(proto_enum, value),
                value.number
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let deprecation = proto_enum
        .values
        .iter()
        .map(|value| {
            format!(
                "            Self::{} => {},",
                rust_variant_name(proto_enum, value),
                value.deprecated
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "/// Generated closed values from `{}`.\n#[derive(Clone, Copy, Debug, Eq, PartialEq)]\n#[repr(u32)]\npub enum {rust_name} {{\n{variants}\n}}\n\nimpl {rust_name} {{\n    /// Returns the protobuf deprecation option for this value.\n    #[must_use]\n    pub const fn is_deprecated(self) -> bool {{\n        match self {{\n{deprecation}\n        }}\n    }}\n}}",
        proto_enum.name
    )
}

fn required_rust_variant(proto_enum: &ProtoEnum, proto_name: &str) -> Result<String, XtaskError> {
    Ok(rust_variant_name(
        proto_enum,
        required_variant(proto_enum, proto_name)?,
    ))
}

fn rust_field_assignment(field: &ProtoField, value: &str) -> String {
    if field.name == value {
        field.name.clone()
    } else {
        format!("{}: {value}", field.name)
    }
}

fn generated_rust(model: &ApiModel, digest: &str) -> Result<String, XtaskError> {
    let api_major_field = required_field(&model.request, "uint32")?;
    let capability_field = required_field(&model.request, "Capability")?;
    let response_api_major = required_field(&model.response, "uint32")?;
    let response_digest = required_field(&model.response, "string")?;
    let response_availability = required_field(&model.response, "CapabilityAvailability")?;
    let response_refusal = required_field(&model.response, "PublicError")?;
    let response_deprecation = required_field(&model.response, "DeprecationState")?;
    let response_capability = required_field(&model.response, "Capability")?;
    let error_code_field = required_field(&model.public_error, "PublicErrorCode")?;
    let error_retry_field = required_field(&model.public_error, "RetryClass")?;
    let error_completion_field = required_field(&model.public_error, "CompletionState")?;
    let error_source_field = required_field(&model.public_error, "FailureSource")?;
    let error_detail_field = required_field(&model.public_error, "SafeDetail")?;
    let error_source_assignment = rust_field_assignment(error_source_field, "source");
    let request_api_major_assignment = rust_field_assignment(api_major_field, "api_major");
    let request_capability_assignment = rust_field_assignment(capability_field, "capability");
    let capability_unspecified =
        required_rust_variant(&model.capability, "CAPABILITY_UNSPECIFIED")?;
    let capability_canonical =
        required_rust_variant(&model.capability, "CAPABILITY_CANONICAL_PUBLIC_INTERFACE")?;
    let capability_query =
        required_rust_variant(&model.capability, "CAPABILITY_RELEASE_ONE_QUERY")?;
    let capability_metrics = required_rust_variant(&model.capability, "CAPABILITY_METRICS")?;
    let capability_from_wire = model
        .capability
        .values
        .iter()
        .map(|value| {
            let target = if value.name == "CAPABILITY_UNSPECIFIED" {
                capability_canonical.clone()
            } else {
                rust_variant_name(&model.capability, value)
            };
            format!("            {} => Ok(Self::{target}),", value.number)
        })
        .collect::<Vec<_>>()
        .join("\n");
    let capability_definition = format!(
        "{}\n\nimpl Capability {{\n    const fn wire_value(self) -> u32 {{\n        self as u32\n    }}\n\n    fn from_wire(value: u32, source: ApiFailureSource) -> Result<Self, ApiError> {{\n        match value {{\n{capability_from_wire}\n            _ => Err(ApiError::capability_unsupported(source)),\n        }}\n    }}\n}}",
        generated_enum(&model.capability, "Capability")
    );
    let availability_implemented =
        required_rust_variant(&model.availability, "CAPABILITY_AVAILABILITY_IMPLEMENTED")?;
    let availability_unavailable =
        required_rust_variant(&model.availability, "CAPABILITY_AVAILABILITY_UNAVAILABLE")?;
    let availability_unsupported =
        required_rust_variant(&model.availability, "CAPABILITY_AVAILABILITY_UNSUPPORTED")?;
    let availability_version = required_rust_variant(
        &model.availability,
        "CAPABILITY_AVAILABILITY_VERSION_INCOMPATIBLE",
    )?;
    let deprecation_current =
        required_rust_variant(&model.deprecation_state, "DEPRECATION_STATE_CURRENT")?;
    let retry_never = required_rust_variant(&model.retry_class, "RETRY_CLASS_NEVER")?;
    let retry_input =
        required_rust_variant(&model.retry_class, "RETRY_CLASS_AFTER_INPUT_CORRECTION")?;
    let completion_rejected =
        required_rust_variant(&model.completion_state, "COMPLETION_STATE_REJECTED")?;
    let code_version = required_rust_variant(
        &model.error_code,
        "PUBLIC_ERROR_CODE_UNSUPPORTED_API_VERSION",
    )?;
    let code_unavailable = required_rust_variant(
        &model.error_code,
        "PUBLIC_ERROR_CODE_CAPABILITY_UNAVAILABLE",
    )?;
    let code_unsupported = required_rust_variant(
        &model.error_code,
        "PUBLIC_ERROR_CODE_CAPABILITY_UNSUPPORTED",
    )?;
    let code_malformed =
        required_rust_variant(&model.error_code, "PUBLIC_ERROR_CODE_MALFORMED_REQUEST")?;
    let code_too_large =
        required_rust_variant(&model.error_code, "PUBLIC_ERROR_CODE_REQUEST_TOO_LARGE")?;
    let code_unknown = required_rust_variant(&model.error_code, "PUBLIC_ERROR_CODE_UNKNOWN_FIELD")?;
    let source_negotiation = required_rust_variant(
        &model.failure_source,
        "FAILURE_SOURCE_CAPABILITY_NEGOTIATION",
    )?;
    let source_grpc = required_rust_variant(&model.failure_source, "FAILURE_SOURCE_GRPC_DECODE")?;
    let source_http = required_rust_variant(&model.failure_source, "FAILURE_SOURCE_HTTP_DECODE")?;
    let detail_version =
        required_rust_variant(&model.safe_detail, "SAFE_DETAIL_API_MAJOR_UNSUPPORTED")?;
    let detail_unavailable =
        required_rust_variant(&model.safe_detail, "SAFE_DETAIL_CAPABILITY_NOT_AVAILABLE")?;
    let detail_unsupported =
        required_rust_variant(&model.safe_detail, "SAFE_DETAIL_CAPABILITY_NOT_SUPPORTED")?;
    let detail_malformed =
        required_rust_variant(&model.safe_detail, "SAFE_DETAIL_REQUEST_MALFORMED")?;
    let detail_limit =
        required_rust_variant(&model.safe_detail, "SAFE_DETAIL_REQUEST_LIMIT_EXCEEDED")?;
    let detail_unknown =
        required_rust_variant(&model.safe_detail, "SAFE_DETAIL_FIELD_NOT_RECOGNIZED")?;
    let grpc_api_major_tag = api_major_field.number << 3;
    let grpc_capability_tag = capability_field.number << 3;
    Ok(format!(
        r###"//! Generated from `{package}` service `{service}/{rpc}` using `{request}` and `{response}`; do not edit.

/// Maximum accepted or emitted capability request body.
pub const MAX_PUBLIC_REQUEST_BYTES: usize = 64;

const GRPC_API_MAJOR_TAG: u8 = {grpc_api_major_tag};
const GRPC_CAPABILITY_TAG: u8 = {grpc_capability_tag};

/// The one public API major version generated by this artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApiVersion {{
    /// Canonical Release 1 API package.
    V1,
}}

impl ApiVersion {{
    /// Returns the wire major version.
    #[must_use]
    pub const fn major(self) -> u32 {{
        match self {{
            Self::V1 => 1,
        }}
    }}
}}

{capability_definition}

/// The stable SHA-256 identity of the canonical API definition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchemaDigest(&'static str);

impl SchemaDigest {{
    /// Returns the digest embedded by deterministic generation.
    #[must_use]
    pub const fn canonical() -> Self {{
        Self("{digest}")
    }}

    /// Returns the lowercase hexadecimal digest value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {{
        self.0
    }}
}}

{availability_definition}

{deprecation_definition}

{retry_definition}

{completion_definition}

{error_code_definition}

{failure_source_definition}

{safe_detail_definition}

/// A closed typed public failure with no caller-controlled diagnostic text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApiError {{
    {error_code_name}: ApiErrorCode,
    {error_retry_name}: RetryClass,
    {error_completion_name}: CompletionState,
    {error_source_name}: ApiFailureSource,
    {error_detail_name}: SafeDetail,
}}

impl ApiError {{
    const fn unsupported_api_version() -> Self {{
        Self {{
            {error_code_name}: ApiErrorCode::{code_version},
            {error_retry_name}: RetryClass::{retry_never},
            {error_completion_name}: CompletionState::{completion_rejected},
            {error_source_name}: ApiFailureSource::{source_negotiation},
            {error_detail_name}: SafeDetail::{detail_version},
        }}
    }}

    const fn capability_unavailable() -> Self {{
        Self {{
            {error_code_name}: ApiErrorCode::{code_unavailable},
            {error_retry_name}: RetryClass::{retry_never},
            {error_completion_name}: CompletionState::{completion_rejected},
            {error_source_name}: ApiFailureSource::{source_negotiation},
            {error_detail_name}: SafeDetail::{detail_unavailable},
        }}
    }}

    const fn capability_unsupported(source: ApiFailureSource) -> Self {{
        Self {{
            {error_code_name}: ApiErrorCode::{code_unsupported},
            {error_retry_name}: RetryClass::{retry_never},
            {error_completion_name}: CompletionState::{completion_rejected},
            {error_source_assignment},
            {error_detail_name}: SafeDetail::{detail_unsupported},
        }}
    }}

    const fn malformed(source: ApiFailureSource) -> Self {{
        Self {{
            {error_code_name}: ApiErrorCode::{code_malformed},
            {error_retry_name}: RetryClass::{retry_input},
            {error_completion_name}: CompletionState::{completion_rejected},
            {error_source_assignment},
            {error_detail_name}: SafeDetail::{detail_malformed},
        }}
    }}

    const fn too_large(source: ApiFailureSource) -> Self {{
        Self {{
            {error_code_name}: ApiErrorCode::{code_too_large},
            {error_retry_name}: RetryClass::{retry_input},
            {error_completion_name}: CompletionState::{completion_rejected},
            {error_source_assignment},
            {error_detail_name}: SafeDetail::{detail_limit},
        }}
    }}

    const fn unknown_field(source: ApiFailureSource) -> Self {{
        Self {{
            {error_code_name}: ApiErrorCode::{code_unknown},
            {error_retry_name}: RetryClass::{retry_input},
            {error_completion_name}: CompletionState::{completion_rejected},
            {error_source_assignment},
            {error_detail_name}: SafeDetail::{detail_unknown},
        }}
    }}

    /// Returns the stable public code.
    #[must_use]
    pub const fn {error_code_name}(self) -> ApiErrorCode {{
        self.{error_code_name}
    }}

    /// Returns the typed retry classification.
    #[must_use]
    pub const fn {error_retry_name}(self) -> RetryClass {{
        self.{error_retry_name}
    }}

    /// Returns whether the rejected request performed any work.
    #[must_use]
    pub const fn {error_completion_name}(self) -> CompletionState {{
        self.{error_completion_name}
    }}

    /// Returns the safe semantic failure location.
    #[must_use]
    pub const fn {error_source_name}(self) -> ApiFailureSource {{
        self.{error_source_name}
    }}

    /// Returns redaction-safe detail with no caller-controlled text.
    #[must_use]
    pub const fn {error_detail_name}(self) -> SafeDetail {{
        self.{error_detail_name}
    }}
}}

/// Generated wire request for one API-major capability negotiation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct {request} {{
    {api_major_name}: u32,
    {capability_name}: Capability,
}}

impl {request} {{
    /// Creates a request for a generated API package.
    #[must_use]
    pub const fn for_version(version: ApiVersion) -> Self {{
        Self {{
            {api_major_name}: version.major(),
            {capability_name}: Capability::{capability_canonical},
        }}
    }}

    /// Creates a request for one concrete generated capability.
    #[must_use]
    pub const fn for_capability(version: ApiVersion, capability: Capability) -> Self {{
        Self {{
            {api_major_name}: version.major(),
            {request_capability_assignment},
        }}
    }}

    /// Creates a request carrying an unknown wire major for checked refusal.
    #[must_use]
    pub const fn unknown(api_major: u32, capability: Capability) -> Self {{
        Self {{
            {request_api_major_assignment},
            {request_capability_assignment},
        }}
    }}
}}

/// Generated typed response for capability negotiation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct {response} {{
    {response_availability_name}: CapabilityAvailability,
    {response_api_major_name}: ApiVersion,
    {response_digest_name}: SchemaDigest,
    {response_refusal_name}: Option<ApiError>,
    {response_deprecation_name}: DeprecationState,
    {response_capability_name}: Capability,
}}

impl {response} {{
    /// Returns the closed capability availability truth.
    #[must_use]
    pub const fn {response_availability_name}(self) -> CapabilityAvailability {{
        self.{response_availability_name}
    }}

    /// Returns the negotiated public API package.
    #[must_use]
    pub const fn {response_api_major_name}(self) -> ApiVersion {{
        self.{response_api_major_name}
    }}

    /// Returns the generated source identity.
    #[must_use]
    pub const fn {response_digest_name}(self) -> SchemaDigest {{
        self.{response_digest_name}
    }}

    /// Returns a stable refusal when negotiation did not succeed.
    #[must_use]
    pub const fn {response_refusal_name}(self) -> Option<ApiError> {{
        self.{response_refusal_name}
    }}

    /// Returns the explicit compatibility deprecation state.
    #[must_use]
    pub const fn {response_deprecation_name}(self) -> DeprecationState {{
        self.{response_deprecation_name}
    }}

    /// Returns the concrete capability described by this statement.
    #[must_use]
    pub const fn {response_capability_name}(self) -> Capability {{
        self.{response_capability_name}
    }}
}}

/// The generated public transport mappings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Transport {{
    /// Protobuf body on the generated gRPC method path.
    GrpcProtobuf,
    /// JSON body on the generated HTTP route.
    HttpJson,
}}

impl Transport {{
    const fn source(self) -> ApiFailureSource {{
        match self {{
            Self::GrpcProtobuf => ApiFailureSource::{source_grpc},
            Self::HttpJson => ApiFailureSource::{source_http},
        }}
    }}
}}

/// A bounded generated client request with no network or runtime orchestration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncodedRequest {{
    body: Vec<u8>,
    path: &'static str,
}}

impl EncodedRequest {{
    fn empty(path: &'static str) -> Self {{
        Self {{
            body: Vec::with_capacity(MAX_PUBLIC_REQUEST_BYTES),
            path,
        }}
    }}

    fn push(&mut self, byte: u8) {{
        self.body.push(byte);
    }}

    fn extend(&mut self, bytes: &[u8]) {{
        self.body.extend_from_slice(bytes);
    }}

    /// Returns the generated HTTP method.
    #[must_use]
    pub const fn method(&self) -> &'static str {{
        "POST"
    }}

    /// Returns the generated gRPC or HTTP path.
    #[must_use]
    pub const fn path(&self) -> &'static str {{
        self.path
    }}

    /// Returns the initialized bounded request body.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {{
        &self.body
    }}
}}

/// Published allocation and copy bounds for generated client encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientEncodingBounds;

impl ClientEncodingBounds {{
    /// Maximum emitted body bytes for either generated transport.
    #[must_use]
    pub const fn maximum_body_bytes(self) -> usize {{
        MAX_PUBLIC_REQUEST_BYTES
    }}

    /// One 64-byte body buffer is reserved before encoding.
    #[must_use]
    pub const fn maximum_heap_buffers(self) -> usize {{
        1
    }}

    /// Encoding creates no intermediate heap-backed body.
    #[must_use]
    pub const fn maximum_intermediate_heap_bytes(self) -> usize {{
        0
    }}

    /// Encoding never copies a completed body into another buffer.
    #[must_use]
    pub const fn maximum_full_body_copies(self) -> usize {{
        0
    }}
}}

/// Generated client encoder contract with no I/O or ambient authority.
pub struct CapabilityClient;

impl CapabilityClient {{
    /// Returns the externally reachable client encoding resource contract.
    #[must_use]
    pub const fn encoding_bounds() -> ClientEncodingBounds {{
        ClientEncodingBounds
    }}

    /// Encodes one typed request into its bounded generated transport body.
    ///
    /// The generated two-`u32` request model cannot exceed the published body
    /// bound, so typed client encoding has no input-dependent failure.
    #[must_use]
    pub fn encode(request: {request}, transport: Transport) -> EncodedRequest {{
        match transport {{
            Transport::GrpcProtobuf => encode_grpc(request),
            Transport::HttpJson => encode_http(request),
        }}
    }}
}}

/// Generated in-memory service boundary for the canonical capability contract.
pub struct {service};

impl {service} {{
    /// Negotiates one bounded, versioned public API request without ambient state.
    #[must_use]
    pub const fn negotiate(request: {request}) -> {response} {{
        if request.{api_major_name} != ApiVersion::V1.major() {{
            return {response} {{
                {response_availability_name}: CapabilityAvailability::{availability_version},
                {response_api_major_name}: ApiVersion::V1,
                {response_digest_name}: SchemaDigest::canonical(),
                {response_refusal_name}: Some(ApiError::unsupported_api_version()),
                {response_deprecation_name}: DeprecationState::{deprecation_current},
                {response_capability_name}: request.{capability_name},
            }};
        }}
        match request.{capability_name} {{
            Capability::{capability_unspecified} | Capability::{capability_canonical} => {response} {{
                {response_availability_name}: CapabilityAvailability::{availability_implemented},
                {response_api_major_name}: ApiVersion::V1,
                {response_digest_name}: SchemaDigest::canonical(),
                {response_refusal_name}: None,
                {response_deprecation_name}: DeprecationState::{deprecation_current},
                {response_capability_name}: Capability::{capability_canonical},
            }},
            Capability::{capability_query} => {response} {{
                {response_availability_name}: CapabilityAvailability::{availability_unavailable},
                {response_api_major_name}: ApiVersion::V1,
                {response_digest_name}: SchemaDigest::canonical(),
                {response_refusal_name}: Some(ApiError::capability_unavailable()),
                {response_deprecation_name}: DeprecationState::{deprecation_current},
                {response_capability_name}: request.{capability_name},
            }},
            Capability::{capability_metrics} => {response} {{
                {response_availability_name}: CapabilityAvailability::{availability_unsupported},
                {response_api_major_name}: ApiVersion::V1,
                {response_digest_name}: SchemaDigest::canonical(),
                {response_refusal_name}: Some(ApiError::capability_unsupported(
                    ApiFailureSource::{source_negotiation},
                )),
                {response_deprecation_name}: DeprecationState::{deprecation_current},
                {response_capability_name}: request.{capability_name},
            }},
        }}
    }}

    /// Decodes one bounded transport body exactly once and maps its typed outcome.
    pub fn decode_and_negotiate(
        transport: Transport,
        body: &[u8],
    ) -> Result<{response}, ApiError> {{
        if body.len() > MAX_PUBLIC_REQUEST_BYTES {{
            return Err(ApiError::too_large(transport.source()));
        }}
        let request = match transport {{
            Transport::GrpcProtobuf => decode_grpc(body)?,
            Transport::HttpJson => decode_http(body)?,
        }};
        Ok(Self::negotiate(request))
    }}
}}

fn encode_grpc(request: {request}) -> EncodedRequest {{
    let mut encoded = EncodedRequest::empty("/{package}.{service}/{rpc}");
    encoded.push(GRPC_API_MAJOR_TAG);
    encode_varint(request.{api_major_name}, &mut encoded);
    encoded.push(GRPC_CAPABILITY_TAG);
    encode_varint(request.{capability_name}.wire_value(), &mut encoded);
    encoded
}}

fn encode_http(request: {request}) -> EncodedRequest {{
    let mut encoded = EncodedRequest::empty("/v1/capabilities:{rpc_path}");
    encoded.extend(b"{{\"{api_major_name}\":");
    encode_json_u32(request.{api_major_name}, &mut encoded);
    encoded.extend(b",\"{capability_name}\":");
    encode_json_u32(request.{capability_name}.wire_value(), &mut encoded);
    encoded.extend(b"}}");
    encoded
}}

fn encode_json_u32(mut value: u32, encoded: &mut EncodedRequest) {{
    if value == 0 {{
        encoded.push(b'0');
        return;
    }}
    let mut digits = [0_u8; 10];
    let digit_count = value.ilog10() as usize + 1;
    for slot in digits.iter_mut().rev().take(digit_count) {{
        // The modulo bounds this narrowing conversion to `0..=9`.
        let digit = (value % 10) as u8;
        *slot = b'0' + digit;
        value /= 10;
    }}
    let first_digit = digits.len() - digit_count;
    for digit in digits.into_iter().skip(first_digit) {{
        encoded.push(digit);
    }}
}}

fn encode_varint(mut value: u32, encoded: &mut EncodedRequest) {{
    loop {{
        // The mask bounds this narrowing conversion to seven bits.
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {{
            encoded.push(byte);
            return;
        }}
        encoded.push(byte | 0x80);
    }}
}}

fn decode_grpc(body: &[u8]) -> Result<{request}, ApiError> {{
    let source = ApiFailureSource::{source_grpc};
    let mut cursor = 0;
    let mut api_major = None;
    let mut capability = None;
    while let Some(tag) = body.get(cursor).copied() {{
        cursor += 1;
        let (value, next) = decode_varint(body, cursor, source)?;
        cursor = next;
        match tag {{
            GRPC_API_MAJOR_TAG if api_major.is_none() => api_major = Some(value),
            GRPC_CAPABILITY_TAG if capability.is_none() => {{
                capability = Some(Capability::from_wire(value, source)?);
            }},
            GRPC_API_MAJOR_TAG | GRPC_CAPABILITY_TAG => return Err(ApiError::malformed(source)),
            _ => return Err(ApiError::unknown_field(source)),
        }}
    }}
    let Some(api_major) = api_major else {{
        return Err(ApiError::malformed(source));
    }};
    Ok({request} {{
        {request_api_major_assignment},
        {capability_name}: match capability {{
            Some(capability) => capability,
            None => Capability::{capability_canonical},
        }},
    }})
}}

fn decode_varint(
    body: &[u8],
    mut cursor: usize,
    source: ApiFailureSource,
) -> Result<(u32, usize), ApiError> {{
    let mut value = 0_u32;
    for shift in [0, 7, 14, 21, 28] {{
        let Some(byte) = body.get(cursor).copied() else {{
            return Err(ApiError::malformed(source));
        }};
        cursor += 1;
        if shift == 28 && byte & 0x7f > 0x0f {{
            return Err(ApiError::malformed(source));
        }}
        value |= u32::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {{
            return Ok((value, cursor));
        }}
    }}
    Err(ApiError::malformed(source))
}}

fn trim_json_whitespace(value: &str) -> &str {{
    value.trim_matches(&[' ', '\t', '\r', '\n'][..])
}}

fn decode_http(body: &[u8]) -> Result<{request}, ApiError> {{
    let source = ApiFailureSource::{source_http};
    let text =
        trim_json_whitespace(core::str::from_utf8(body).map_err(|_| ApiError::malformed(source))?);
    let Some(object) = text
        .strip_prefix('{{')
        .and_then(|value| value.strip_suffix('}}'))
    else {{
        return Err(ApiError::malformed(source));
    }};
    let mut api_major = None;
    let mut capability = None;
    for member in object.split(',') {{
        let Some((key, value)) = member.split_once(':') else {{
            return Err(ApiError::malformed(source));
        }};
        let key = trim_json_whitespace(key);
        match key {{
            "\"{api_major_name}\"" if api_major.is_none() => {{
                api_major = Some(parse_json_u32(value, source)?);
            }},
            "\"{capability_name}\"" if capability.is_none() => {{
                capability = Some(Capability::from_wire(
                    parse_json_u32(value, source)?,
                    source,
                )?);
            }},
            "\"{api_major_name}\"" | "\"{capability_name}\"" => {{
                return Err(ApiError::malformed(source));
            }},
            _ if key.starts_with('"') && key.ends_with('"') => {{
                return Err(ApiError::unknown_field(source));
            }},
            _ => return Err(ApiError::malformed(source)),
        }}
    }}
    let Some(api_major) = api_major else {{
        return Err(ApiError::malformed(source));
    }};
    Ok({request} {{
        {request_api_major_assignment},
        {capability_name}: match capability {{
            Some(capability) => capability,
            None => Capability::{capability_canonical},
        }},
    }})
}}

fn parse_json_u32(value: &str, source: ApiFailureSource) -> Result<u32, ApiError> {{
    let value = trim_json_whitespace(value);
    let bytes = value.as_bytes();
    let canonical = match bytes {{
        [b'0'] => true,
        [first, rest @ ..] => (b'1'..=b'9').contains(first) && rest.iter().all(u8::is_ascii_digit),
        [] => false,
    }};
    if !canonical {{
        return Err(ApiError::malformed(source));
    }}
    value
        .parse::<u32>()
        .map_err(|_| ApiError::malformed(source))
}}
"###,
        package = model.package,
        service = model.service,
        rpc = model.rpc,
        rpc_path = model.rpc.to_ascii_lowercase(),
        request = model.request.name,
        response = model.response.name,
        capability_definition = capability_definition,
        availability_definition = generated_enum(&model.availability, "CapabilityAvailability"),
        deprecation_definition = generated_enum(&model.deprecation_state, "DeprecationState"),
        retry_definition = generated_enum(&model.retry_class, "RetryClass"),
        completion_definition = generated_enum(&model.completion_state, "CompletionState"),
        error_code_definition = generated_enum(&model.error_code, "ApiErrorCode"),
        failure_source_definition = generated_enum(&model.failure_source, "ApiFailureSource"),
        safe_detail_definition = generated_enum(&model.safe_detail, "SafeDetail"),
        capability_unspecified = capability_unspecified,
        capability_canonical = capability_canonical,
        capability_query = capability_query,
        capability_metrics = capability_metrics,
        availability_implemented = availability_implemented,
        availability_unavailable = availability_unavailable,
        availability_unsupported = availability_unsupported,
        availability_version = availability_version,
        deprecation_current = deprecation_current,
        retry_never = retry_never,
        retry_input = retry_input,
        completion_rejected = completion_rejected,
        code_version = code_version,
        code_unavailable = code_unavailable,
        code_unsupported = code_unsupported,
        code_malformed = code_malformed,
        code_too_large = code_too_large,
        code_unknown = code_unknown,
        source_negotiation = source_negotiation,
        source_grpc = source_grpc,
        source_http = source_http,
        detail_version = detail_version,
        detail_unavailable = detail_unavailable,
        detail_unsupported = detail_unsupported,
        detail_malformed = detail_malformed,
        detail_limit = detail_limit,
        detail_unknown = detail_unknown,
        api_major_name = api_major_field.name,
        capability_name = capability_field.name,
        response_api_major_name = response_api_major.name,
        response_digest_name = response_digest.name,
        response_availability_name = response_availability.name,
        response_refusal_name = response_refusal.name,
        response_deprecation_name = response_deprecation.name,
        response_capability_name = response_capability.name,
        error_code_name = error_code_field.name,
        error_retry_name = error_retry_field.name,
        error_completion_name = error_completion_field.name,
        error_source_name = error_source_field.name,
        error_source_assignment = error_source_assignment,
        error_detail_name = error_detail_field.name,
        request_api_major_assignment = request_api_major_assignment,
        request_capability_assignment = request_capability_assignment,
        grpc_api_major_tag = grpc_api_major_tag,
        grpc_capability_tag = grpc_capability_tag,
    ))
}

fn semantic_proto_name(proto_enum: &ProtoEnum, value: &ProtoEnumValue) -> String {
    let prefix = format!("{}_", upper_snake(&proto_enum.name));
    match value.name.strip_prefix(&prefix) {
        Some(semantic) => semantic.to_owned(),
        None => value.name.clone(),
    }
}

fn openapi_field(field: &ProtoField) -> String {
    let schema = match field.kind.as_str() {
        "uint32" => "\"type\": \"integer\", \"minimum\": 0, \"maximum\": 4294967295".to_owned(),
        "string" => "\"type\": \"string\"".to_owned(),
        kind => format!("\"$ref\": \"#/components/schemas/{kind}\""),
    };
    format!(
        "\"{}\": {{{schema}, \"x-protobuf-field-number\": {}, \"deprecated\": {}}}",
        field.name, field.number, field.deprecated
    )
}

fn openapi_message(message: &ProtoMessage) -> String {
    let properties = message
        .fields
        .iter()
        .map(openapi_field)
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "\"{}\": {{\"type\": \"object\", \"additionalProperties\": false, \"properties\": {{{properties}}}}}",
        message.name
    )
}

fn openapi_enum(proto_enum: &ProtoEnum, rust_name: &str) -> String {
    let numbers = proto_enum
        .values
        .iter()
        .map(|value| value.number.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let names = proto_enum
        .values
        .iter()
        .map(|value| format!("\"{}\"", semantic_proto_name(proto_enum, value)))
        .collect::<Vec<_>>()
        .join(", ");
    let deprecated = proto_enum
        .values
        .iter()
        .map(|value| value.deprecated.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "\"{rust_name}\": {{\"type\": \"integer\", \"enum\": [{numbers}], \"x-enumNames\": [{names}], \"x-enumDeprecated\": [{deprecated}]}}"
    )
}

fn openapi(model: &ApiModel, digest: &str) -> Result<String, XtaskError> {
    let operation = format!("{}{}", model.rpc, model.response.name);
    let schemas = [
        openapi_message(&model.request),
        openapi_message(&model.response),
        openapi_message(&model.public_error),
        openapi_enum(&model.capability, "Capability"),
        openapi_enum(&model.availability, "CapabilityAvailability"),
        openapi_enum(&model.retry_class, "RetryClass"),
        openapi_enum(&model.completion_state, "CompletionState"),
        openapi_enum(&model.deprecation_state, "DeprecationState"),
        openapi_enum(&model.error_code, "PublicErrorCode"),
        openapi_enum(&model.failure_source, "FailureSource"),
        openapi_enum(&model.safe_detail, "SafeDetail"),
    ]
    .join(", ");
    let capability_canonical = semantic_proto_name(
        &model.capability,
        required_variant(&model.capability, "CAPABILITY_CANONICAL_PUBLIC_INTERFACE")?,
    )
    .to_ascii_lowercase();
    let capability_query = semantic_proto_name(
        &model.capability,
        required_variant(&model.capability, "CAPABILITY_RELEASE_ONE_QUERY")?,
    )
    .to_ascii_lowercase();
    let capability_metrics = semantic_proto_name(
        &model.capability,
        required_variant(&model.capability, "CAPABILITY_METRICS")?,
    )
    .to_ascii_lowercase();
    let implemented = semantic_proto_name(
        &model.availability,
        required_variant(&model.availability, "CAPABILITY_AVAILABILITY_IMPLEMENTED")?,
    );
    let unavailable = semantic_proto_name(
        &model.availability,
        required_variant(&model.availability, "CAPABILITY_AVAILABILITY_UNAVAILABLE")?,
    );
    let unsupported = semantic_proto_name(
        &model.availability,
        required_variant(&model.availability, "CAPABILITY_AVAILABILITY_UNSUPPORTED")?,
    );
    let version = semantic_proto_name(
        &model.availability,
        required_variant(
            &model.availability,
            "CAPABILITY_AVAILABILITY_VERSION_INCOMPATIBLE",
        )?,
    );
    Ok(format!(
        "{{\n  \"openapi\": \"3.1.0\",\n  \"info\": {{\"title\": \"Positron API\", \"version\": \"v1\", \"x-positron-schema-digest\": \"{digest}\"}},\n  \"paths\": {{\"/v1/capabilities:{rpc}\": {{\"post\": {{\"operationId\": \"{operation}\", \"requestBody\": {{\"required\": true, \"content\": {{\"application/json\": {{\"schema\": {{\"$ref\": \"#/components/schemas/{request}\"}}}}}}}}, \"responses\": {{\"200\": {{\"description\": \"Closed capability statement\", \"content\": {{\"application/json\": {{\"schema\": {{\"$ref\": \"#/components/schemas/{response}\"}}}}}}}}}}}}}}}},\n  \"components\": {{\"schemas\": {{{schemas}}}}},\n  \"x-positron-capability-statement\": {{\"{capability_canonical}\": \"{implemented}\", \"{capability_query}\": \"{unavailable}\", \"{capability_metrics}\": \"{unsupported}\", \"other_api_major\": \"{version}\"}},\n  \"x-positron-max-request-bytes\": 64\n}}\n",
        rpc = model.rpc.to_ascii_lowercase(),
        request = model.request.name,
        response = model.response.name,
    ))
}

fn http_fields(message: &ProtoMessage) -> String {
    message
        .fields
        .iter()
        .map(|field| {
            format!(
                "{{\"proto\": \"{}\", \"json\": \"{}\", \"type\": \"{}\", \"number\": {}, \"deprecated\": {}}}",
                field.name, field.name, field.kind, field.number, field.deprecated
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn http_enum(proto_enum: &ProtoEnum) -> String {
    let values = proto_enum
        .values
        .iter()
        .map(|value| {
            format!(
                "{{\"name\": \"{}\", \"number\": {}, \"deprecated\": {}}}",
                value.name, value.number, value.deprecated
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!("\"{}\": [{values}]", proto_enum.name)
}

fn http_mapping(model: &ApiModel, digest: &str) -> Result<String, XtaskError> {
    let enums = [
        http_enum(&model.capability),
        http_enum(&model.availability),
        http_enum(&model.retry_class),
        http_enum(&model.completion_state),
        http_enum(&model.deprecation_state),
        http_enum(&model.error_code),
        http_enum(&model.failure_source),
        http_enum(&model.safe_detail),
    ]
    .join(", ");
    Ok(format!(
        "{{\n  \"schema_digest\": \"{digest}\",\n  \"max_request_bytes\": 64,\n  \"unknown_fields\": \"reject\",\n  \"enums\": {{{enums}}},\n  \"mappings\": [{{\"rpc\": \"{package}.{service}/{rpc}\", \"method\": \"POST\", \"path\": \"/v1/capabilities:{path}\", \"request\": \"{request}\", \"response\": \"{response}\", \"request_fields\": [{request_fields}], \"response_fields\": [{response_fields}], \"public_error_fields\": [{error_fields}]}}]\n}}\n",
        package = model.package,
        service = model.service,
        rpc = model.rpc,
        path = model.rpc.to_ascii_lowercase(),
        request = model.request.name,
        response = model.response.name,
        request_fields = http_fields(&model.request),
        response_fields = http_fields(&model.response),
        error_fields = http_fields(&model.public_error),
    ))
}
