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
    request: String,
    response: String,
    api_major_field: ProtoField,
    capability_field: ProtoField,
}

#[derive(Debug)]
struct ProtoField {
    name: String,
    number: u8,
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

    write_generated(root, GENERATED_RUST, &generated_rust(&model, &digest))?;
    write_generated(root, SCHEMA_DIGEST, &format!("{digest}\n"))?;
    write_generated(root, OPENAPI, &openapi(&model, &digest))?;
    write_generated(root, HTTP_MAPPING, &http_mapping(&model, &digest))?;
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
    let request_fields = message_fields(path, &statements, request)?;
    if request_fields.len() != 2
        || request_fields
            .iter()
            .enumerate()
            .any(|(index, (_, field))| {
                request_fields
                    .iter()
                    .skip(index + 1)
                    .any(|(_, other)| other.number == field.number)
            })
    {
        return Err(XtaskError::invalid_path(
            path,
            "request fields are missing or ambiguous",
        ));
    }
    let api_major_field = unique_field(path, &request_fields, "uint32")?;
    let capability_field = unique_field(path, &request_fields, "Capability")?;
    Ok(ApiModel {
        package,
        service,
        rpc: rpc.to_owned(),
        request: request.to_owned(),
        response: response.to_owned(),
        api_major_field,
        capability_field,
    })
}

fn message_fields(
    path: &Path,
    lines: &[&str],
    message: &str,
) -> Result<Vec<(String, ProtoField)>, XtaskError> {
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
    body.get(..end)
        .ok_or_else(|| XtaskError::invalid_path(path, "request message body is malformed"))?
        .iter()
        .map(|line| parse_field(path, line))
        .collect()
}

fn parse_field(path: &Path, line: &str) -> Result<(String, ProtoField), XtaskError> {
    let declaration = line
        .strip_suffix(';')
        .ok_or_else(|| XtaskError::invalid_path(path, "request field is malformed"))?;
    let (kind, assignment) = declaration
        .split_once(' ')
        .ok_or_else(|| XtaskError::invalid_path(path, "request field type is missing"))?;
    let (name, number) = assignment
        .split_once(" = ")
        .ok_or_else(|| XtaskError::invalid_path(path, "request field number is missing"))?;
    validate_identifier(path, kind)?;
    validate_identifier(path, name)?;
    let number = number
        .parse::<u8>()
        .map_err(|_| XtaskError::invalid_path(path, "request field number is invalid"))?;
    if number == 0 || number > 15 {
        return Err(XtaskError::invalid_path(
            path,
            "request field number exceeds the bounded single-byte tag range",
        ));
    }
    Ok((
        kind.to_owned(),
        ProtoField {
            name: name.to_owned(),
            number,
        },
    ))
}

fn unique_field(
    path: &Path,
    fields: &[(String, ProtoField)],
    kind: &str,
) -> Result<ProtoField, XtaskError> {
    let matching = fields
        .iter()
        .filter(|(field_kind, _)| field_kind == kind)
        .collect::<Vec<_>>();
    let [(_, field)] = matching.as_slice() else {
        return Err(XtaskError::invalid_path(
            path,
            format!("request requires exactly one `{kind}` field"),
        ));
    };
    Ok(ProtoField {
        name: field.name.clone(),
        number: field.number,
    })
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

fn generated_rust(model: &ApiModel, digest: &str) -> String {
    let grpc_api_major_tag = model.api_major_field.number << 3;
    let grpc_capability_tag = model.capability_field.number << 3;
    format!(
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

/// The concrete behaviors described by the generated capability statement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Capability {{
    /// This canonical generated public interface.
    CanonicalPublicInterface,
    /// Release 1 query behavior, which is known but not yet available.
    ReleaseOneQuery,
    /// Metrics, which is explicitly outside Release 1 product scope.
    Metrics,
}}

impl Capability {{
    const fn wire_value(self) -> u32 {{
        match self {{
            Self::CanonicalPublicInterface => 1,
            Self::ReleaseOneQuery => 2,
            Self::Metrics => 3,
        }}
    }}

    fn from_wire(value: u32, source: ApiFailureSource) -> Result<Self, ApiError> {{
        match value {{
            0 | 1 => Ok(Self::CanonicalPublicInterface),
            2 => Ok(Self::ReleaseOneQuery),
            3 => Ok(Self::Metrics),
            _ => Err(ApiError::capability_unsupported(source)),
        }}
    }}
}}

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

/// The closed availability truth returned by capability negotiation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityAvailability {{
    /// The requested API package is implemented by this server.
    Implemented,
    /// A known capability is not available in this server state.
    Unavailable,
    /// The server does not support the requested capability.
    Unsupported,
    /// The request requires an API package this server cannot interpret.
    VersionIncompatible,
}}

/// The explicit public deprecation truth for a negotiated behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeprecationState {{
    /// The behavior is current and has no deprecation notice.
    Current,
    /// The behavior remains accepted but has a published replacement.
    Deprecated,
}}

/// The closed retry classification attached to a public failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryClass {{
    /// Retrying the same request cannot change the outcome.
    Never,
    /// The caller may retry after an owner-directed bounded backoff.
    AfterBackoff,
    /// The caller must first correct its input.
    AfterInputCorrection,
}}

/// The closed completion truth attached to a public failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionState {{
    /// The request was rejected before work began.
    Rejected,
}}

/// Stable public error codes for the generated capability foundation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApiErrorCode {{
    /// The requested API major has no compatible handler.
    UnsupportedApiVersion,
    /// The capability is known but unavailable in this server state.
    CapabilityUnavailable,
    /// The capability is outside this server's supported product scope.
    CapabilityUnsupported,
    /// The transport body cannot be decoded.
    MalformedRequest,
    /// The transport body exceeds its published bound.
    RequestTooLarge,
    /// The transport body contains a field this interface does not accept.
    UnknownField,
}}

/// A non-secret semantic location for a public failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApiFailureSource {{
    /// API package negotiation rejected the request.
    CapabilityNegotiation,
    /// The generated gRPC protobuf boundary rejected the body.
    GrpcDecode,
    /// The generated HTTP JSON boundary rejected the body.
    HttpDecode,
}}

/// Closed, redaction-safe detail for every public failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SafeDetail {{
    /// The requested API major is not supported.
    ApiMajorUnsupported,
    /// The known capability is not available.
    CapabilityNotAvailable,
    /// The requested capability is not supported.
    CapabilityNotSupported,
    /// The request body is malformed.
    RequestMalformed,
    /// The request body exceeds the declared limit.
    RequestLimitExceeded,
    /// A request field is not recognized.
    FieldNotRecognized,
}}

/// A closed typed public failure with no caller-controlled diagnostic text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApiError {{
    code: ApiErrorCode,
    retry_class: RetryClass,
    completion_state: CompletionState,
    source: ApiFailureSource,
    safe_detail: SafeDetail,
}}

impl ApiError {{
    const fn unsupported_api_version() -> Self {{
        Self {{
            code: ApiErrorCode::UnsupportedApiVersion,
            retry_class: RetryClass::Never,
            completion_state: CompletionState::Rejected,
            source: ApiFailureSource::CapabilityNegotiation,
            safe_detail: SafeDetail::ApiMajorUnsupported,
        }}
    }}

    const fn capability_unavailable() -> Self {{
        Self {{
            code: ApiErrorCode::CapabilityUnavailable,
            retry_class: RetryClass::Never,
            completion_state: CompletionState::Rejected,
            source: ApiFailureSource::CapabilityNegotiation,
            safe_detail: SafeDetail::CapabilityNotAvailable,
        }}
    }}

    const fn capability_unsupported(source: ApiFailureSource) -> Self {{
        Self {{
            code: ApiErrorCode::CapabilityUnsupported,
            retry_class: RetryClass::Never,
            completion_state: CompletionState::Rejected,
            source,
            safe_detail: SafeDetail::CapabilityNotSupported,
        }}
    }}

    const fn malformed(source: ApiFailureSource) -> Self {{
        Self {{
            code: ApiErrorCode::MalformedRequest,
            retry_class: RetryClass::AfterInputCorrection,
            completion_state: CompletionState::Rejected,
            source,
            safe_detail: SafeDetail::RequestMalformed,
        }}
    }}

    const fn too_large(source: ApiFailureSource) -> Self {{
        Self {{
            code: ApiErrorCode::RequestTooLarge,
            retry_class: RetryClass::AfterInputCorrection,
            completion_state: CompletionState::Rejected,
            source,
            safe_detail: SafeDetail::RequestLimitExceeded,
        }}
    }}

    const fn unknown_field(source: ApiFailureSource) -> Self {{
        Self {{
            code: ApiErrorCode::UnknownField,
            retry_class: RetryClass::AfterInputCorrection,
            completion_state: CompletionState::Rejected,
            source,
            safe_detail: SafeDetail::FieldNotRecognized,
        }}
    }}

    /// Returns the stable public code.
    #[must_use]
    pub const fn code(self) -> ApiErrorCode {{
        self.code
    }}

    /// Returns the typed retry classification.
    #[must_use]
    pub const fn retry_class(self) -> RetryClass {{
        self.retry_class
    }}

    /// Returns whether the rejected request performed any work.
    #[must_use]
    pub const fn completion_state(self) -> CompletionState {{
        self.completion_state
    }}

    /// Returns the safe semantic failure location.
    #[must_use]
    pub const fn source(self) -> ApiFailureSource {{
        self.source
    }}

    /// Returns redaction-safe detail with no caller-controlled text.
    #[must_use]
    pub const fn safe_detail(self) -> SafeDetail {{
        self.safe_detail
    }}
}}

/// Generated wire request for one API-major capability negotiation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct {request} {{
    api_major: u32,
    capability: Capability,
}}

impl {request} {{
    /// Creates a request for a generated API package.
    #[must_use]
    pub const fn for_version(version: ApiVersion) -> Self {{
        Self {{
            api_major: version.major(),
            capability: Capability::CanonicalPublicInterface,
        }}
    }}

    /// Creates a request for one concrete generated capability.
    #[must_use]
    pub const fn for_capability(version: ApiVersion, capability: Capability) -> Self {{
        Self {{
            api_major: version.major(),
            capability,
        }}
    }}

    /// Creates a request carrying an unknown wire major for checked refusal.
    #[must_use]
    pub const fn unknown(api_major: u32, capability: Capability) -> Self {{
        Self {{
            api_major,
            capability,
        }}
    }}
}}

/// Generated typed response for capability negotiation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct {response} {{
    availability: CapabilityAvailability,
    api_version: ApiVersion,
    schema_digest: SchemaDigest,
    refusal: Option<ApiError>,
    deprecation: DeprecationState,
    capability: Capability,
}}

impl {response} {{
    /// Returns the closed capability availability truth.
    #[must_use]
    pub const fn availability(self) -> CapabilityAvailability {{
        self.availability
    }}

    /// Returns the negotiated public API package.
    #[must_use]
    pub const fn api_version(self) -> ApiVersion {{
        self.api_version
    }}

    /// Returns the generated source identity.
    #[must_use]
    pub const fn schema_digest(self) -> SchemaDigest {{
        self.schema_digest
    }}

    /// Returns a stable refusal when negotiation did not succeed.
    #[must_use]
    pub const fn refusal(self) -> Option<ApiError> {{
        self.refusal
    }}

    /// Returns the explicit compatibility deprecation state.
    #[must_use]
    pub const fn deprecation(self) -> DeprecationState {{
        self.deprecation
    }}

    /// Returns the concrete capability described by this statement.
    #[must_use]
    pub const fn capability(self) -> Capability {{
        self.capability
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
            Self::GrpcProtobuf => ApiFailureSource::GrpcDecode,
            Self::HttpJson => ApiFailureSource::HttpDecode,
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

    fn push(&mut self, byte: u8, source: ApiFailureSource) -> Result<(), ApiError> {{
        if self.body.len() >= MAX_PUBLIC_REQUEST_BYTES {{
            return Err(ApiError::too_large(source));
        }}
        self.body.push(byte);
        Ok(())
    }}

    fn extend(&mut self, bytes: &[u8], source: ApiFailureSource) -> Result<(), ApiError> {{
        let Some(end) = self.body.len().checked_add(bytes.len()) else {{
            return Err(ApiError::too_large(source));
        }};
        if end > MAX_PUBLIC_REQUEST_BYTES {{
            return Err(ApiError::too_large(source));
        }}
        self.body.extend_from_slice(bytes);
        Ok(())
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

/// Generated client encoder contract with no I/O or ambient authority.
pub struct CapabilityClient;

impl CapabilityClient {{
    /// Encodes one typed request into its bounded generated transport body.
    pub fn encode(
        request: {request},
        transport: Transport,
    ) -> Result<EncodedRequest, ApiError> {{
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
        if request.api_major != ApiVersion::V1.major() {{
            return {response} {{
                availability: CapabilityAvailability::VersionIncompatible,
                api_version: ApiVersion::V1,
                schema_digest: SchemaDigest::canonical(),
                refusal: Some(ApiError::unsupported_api_version()),
                deprecation: DeprecationState::Current,
                capability: request.capability,
            }};
        }}
        match request.capability {{
            Capability::CanonicalPublicInterface => {response} {{
                availability: CapabilityAvailability::Implemented,
                api_version: ApiVersion::V1,
                schema_digest: SchemaDigest::canonical(),
                refusal: None,
                deprecation: DeprecationState::Current,
                capability: request.capability,
            }},
            Capability::ReleaseOneQuery => {response} {{
                availability: CapabilityAvailability::Unavailable,
                api_version: ApiVersion::V1,
                schema_digest: SchemaDigest::canonical(),
                refusal: Some(ApiError::capability_unavailable()),
                deprecation: DeprecationState::Current,
                capability: request.capability,
            }},
            Capability::Metrics => {response} {{
                availability: CapabilityAvailability::Unsupported,
                api_version: ApiVersion::V1,
                schema_digest: SchemaDigest::canonical(),
                refusal: Some(ApiError::capability_unsupported(
                    ApiFailureSource::CapabilityNegotiation,
                )),
                deprecation: DeprecationState::Current,
                capability: request.capability,
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

fn encode_grpc(request: {request}) -> Result<EncodedRequest, ApiError> {{
    let source = ApiFailureSource::GrpcDecode;
    let mut encoded = EncodedRequest::empty("/{package}.{service}/{rpc}");
    encoded.push(GRPC_API_MAJOR_TAG, source)?;
    encode_varint(request.api_major, &mut encoded, source)?;
    encoded.push(GRPC_CAPABILITY_TAG, source)?;
    encode_varint(request.capability.wire_value(), &mut encoded, source)?;
    Ok(encoded)
}}

fn encode_http(request: {request}) -> Result<EncodedRequest, ApiError> {{
    let source = ApiFailureSource::HttpDecode;
    let mut encoded = EncodedRequest::empty("/v1/capabilities:{rpc_path}");
    let body = format!(
        r#"{{{{"{api_major_name}":{{}},"{capability_name}":{{}}}}}}"#,
        request.api_major,
        request.capability.wire_value()
    );
    encoded.extend(body.as_bytes(), source)?;
    Ok(encoded)
}}

fn encode_varint(
    mut value: u32,
    encoded: &mut EncodedRequest,
    source: ApiFailureSource,
) -> Result<(), ApiError> {{
    loop {{
        let byte = u8::try_from(value & 0x7f).map_err(|_| ApiError::malformed(source))?;
        value >>= 7;
        if value == 0 {{
            encoded.push(byte, source)?;
            return Ok(());
        }}
        encoded.push(byte | 0x80, source)?;
    }}
}}

fn decode_grpc(body: &[u8]) -> Result<{request}, ApiError> {{
    let source = ApiFailureSource::GrpcDecode;
    let mut cursor = 0;
    let mut api_major = None;
    let mut capability = None;
    while cursor < body.len() {{
        let Some(tag) = body.get(cursor).copied() else {{
            return Err(ApiError::malformed(source));
        }};
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
        api_major,
        capability: match capability {{
            Some(capability) => capability,
            None => Capability::CanonicalPublicInterface,
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
        value |= u32::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {{
            return Ok((value, cursor));
        }}
    }}
    Err(ApiError::malformed(source))
}}

fn decode_http(body: &[u8]) -> Result<{request}, ApiError> {{
    let source = ApiFailureSource::HttpDecode;
    let text = core::str::from_utf8(body)
        .map_err(|_| ApiError::malformed(source))?
        .trim();
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
        match key.trim() {{
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
            _ => return Err(ApiError::unknown_field(source)),
        }}
    }}
    let Some(api_major) = api_major else {{
        return Err(ApiError::malformed(source));
    }};
    Ok({request} {{
        api_major,
        capability: match capability {{
            Some(capability) => capability,
            None => Capability::CanonicalPublicInterface,
        }},
    }})
}}

fn parse_json_u32(value: &str, source: ApiFailureSource) -> Result<u32, ApiError> {{
    value
        .trim()
        .parse::<u32>()
        .map_err(|_| ApiError::malformed(source))
}}
"###,
        package = model.package,
        service = model.service,
        rpc = model.rpc,
        rpc_path = model.rpc.to_ascii_lowercase(),
        request = model.request,
        response = model.response,
        api_major_name = model.api_major_field.name,
        capability_name = model.capability_field.name,
        grpc_api_major_tag = grpc_api_major_tag,
        grpc_capability_tag = grpc_capability_tag,
    )
}

fn openapi(model: &ApiModel, digest: &str) -> String {
    let operation = format!("{}{}", model.rpc, model.response);
    format!(
        "{{\n  \"openapi\": \"3.1.0\",\n  \"info\": {{\"title\": \"Positron API\", \"version\": \"v1\", \"x-positron-schema-digest\": \"{digest}\"}},\n  \"paths\": {{\"/v1/capabilities:{rpc}\": {{\"post\": {{\"operationId\": \"{operation}\", \"requestBody\": {{\"required\": true, \"content\": {{\"application/json\": {{\"schema\": {{\"$ref\": \"#/components/schemas/{request}\"}}}}}}}}, \"responses\": {{\"200\": {{\"description\": \"Closed capability statement\", \"content\": {{\"application/json\": {{\"schema\": {{\"$ref\": \"#/components/schemas/{response}\"}}}}}}}}}}}}}}}},\n  \"components\": {{\"schemas\": {{\"{request}\": {{\"type\": \"object\", \"additionalProperties\": false, \"required\": [\"{api_major}\"], \"properties\": {{\"{api_major}\": {{\"type\": \"integer\", \"minimum\": 0, \"maximum\": 4294967295}}, \"{capability}\": {{\"type\": \"integer\", \"enum\": [0, 1, 2, 3]}}}}}}, \"{response}\": {{\"type\": \"object\", \"properties\": {{\"availability\": {{\"enum\": [\"IMPLEMENTED\", \"UNAVAILABLE\", \"UNSUPPORTED\", \"VERSION_INCOMPATIBLE\"]}}, \"error_code\": {{\"enum\": [\"UNSUPPORTED_API_VERSION\", \"CAPABILITY_UNAVAILABLE\", \"CAPABILITY_UNSUPPORTED\", \"MALFORMED_REQUEST\", \"REQUEST_TOO_LARGE\", \"UNKNOWN_FIELD\"]}}, \"safe_detail\": {{\"enum\": [\"API_MAJOR_UNSUPPORTED\", \"CAPABILITY_NOT_AVAILABLE\", \"CAPABILITY_NOT_SUPPORTED\", \"REQUEST_MALFORMED\", \"REQUEST_LIMIT_EXCEEDED\", \"FIELD_NOT_RECOGNIZED\"]}}}}}}}}}},\n  \"x-positron-capability-statement\": {{\"canonical_public_interface\": \"IMPLEMENTED\", \"release_one_query\": \"UNAVAILABLE\", \"metrics\": \"UNSUPPORTED\", \"other_api_major\": \"VERSION_INCOMPATIBLE\"}},\n  \"x-positron-max-request-bytes\": 64\n}}\n",
        rpc = model.rpc.to_ascii_lowercase(),
        request = model.request,
        response = model.response,
        api_major = model.api_major_field.name,
        capability = model.capability_field.name,
    )
}

fn http_mapping(model: &ApiModel, digest: &str) -> String {
    format!(
        "{{\n  \"schema_digest\": \"{digest}\",\n  \"max_request_bytes\": 64,\n  \"unknown_fields\": \"reject\",\n  \"mappings\": [{{\"rpc\": \"{package}.{service}/{rpc}\", \"method\": \"POST\", \"path\": \"/v1/capabilities:{path}\", \"request\": \"{request}\", \"response\": \"{response}\", \"request_fields\": [{{\"proto\": \"{api_major}\", \"json\": \"{api_major}\", \"number\": {api_major_number}}}, {{\"proto\": \"{capability}\", \"json\": \"{capability}\", \"number\": {capability_number}}}]}}]\n}}\n",
        package = model.package,
        service = model.service,
        rpc = model.rpc,
        path = model.rpc.to_ascii_lowercase(),
        request = model.request,
        response = model.response,
        api_major = model.api_major_field.name,
        capability = model.capability_field.name,
        api_major_number = model.api_major_field.number,
        capability_number = model.capability_field.number,
    )
}
