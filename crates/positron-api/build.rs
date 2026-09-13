use sha2::{Digest, Sha256};
use std::error::Error;
use std::fmt::Write;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn Error>> {
    let schema = "../../api/positron/v1/positron.proto";
    let mapping = "../../api/positron/v1/http.json";
    println!("cargo:rerun-if-changed={schema}");
    println!("cargo:rerun-if-changed={mapping}");
    let mut digest = String::with_capacity(64);
    for byte in Sha256::digest(std::fs::read(schema)?) {
        write!(&mut digest, "{byte:02x}")?;
    }
    println!("cargo:rustc-env=POSITRON_API_SCHEMA_DIGEST={digest}");
    let mut config = prost_build::Config::new();
    config.protoc_executable(protoc_bin_vendored::protoc_bin_path()?);
    for message in [
        "ApiKeyRequest",
        "ApiKeyResponse",
        "KeyDescriptor",
        "TenantQuotaUpdateRequest",
        "TenantQuotaUpdateResponse",
    ] {
        config.type_attribute(
            format!(".positron.v1.{message}"),
            "#[derive(serde::Serialize, serde::Deserialize)] #[serde(deny_unknown_fields)]",
        );
    }
    for enumeration in ["KeyAction", "KeyScope"] {
        config.type_attribute(
            format!(".positron.v1.{enumeration}"),
            "#[derive(serde::Serialize, serde::Deserialize)] #[serde(rename_all = \"snake_case\")]",
        );
    }
    config.field_attribute(
        ".positron.v1.ApiKeyRequest.action",
        "#[serde(with = \"super::action_json\")]",
    );
    config.field_attribute(".positron.v1.ApiKeyRequest.scope", "#[serde(default, skip_serializing_if = \"Option::is_none\", with = \"super::optional_scope_json\")]");
    for field in [
        "principal",
        "expires_at_unix_seconds",
        "expected_generation",
        "idempotency_key",
        "target_tenant",
    ] {
        config.field_attribute(
            format!(".positron.v1.ApiKeyRequest.{field}"),
            "#[serde(default, skip_serializing_if = \"Option::is_none\")]",
        );
    }
    config.field_attribute(
        ".positron.v1.KeyDescriptor.scope",
        "#[serde(with = \"super::scope_json\")]",
    );
    config.skip_debug([".positron.v1.ApiKeyResponse"]);
    let descriptor = PathBuf::from(std::env::var("OUT_DIR")?).join("positron-v1.bin");
    config.file_descriptor_set_path(&descriptor);
    config.compile_protos(&[schema], &["../../api"])?;
    generate_api_key_client(&descriptor, mapping)?;
    generate_tenant_quota_client(&descriptor, mapping)?;
    generate_tenant_lifecycle_client(&descriptor, mapping)?;
    generate_tenant_retention_client(&descriptor, mapping)?;
    generate_tenant_service_client(&descriptor, mapping)?;
    generate_tenant_alias_client(&descriptor, mapping)?;
    generate_policy_preview_client(&descriptor, mapping)?;
    generate_policy_test_client(&descriptor, mapping)?;
    generate_policy_diff_client(&descriptor, mapping)?;
    generate_policy_explain_client(&descriptor, mapping)?;
    generate_policy_activate_client(&descriptor, mapping)?;
    Ok(())
}

fn generate_tenant_retention_client(
    descriptor_path: &std::path::Path,
    mapping_path: &str,
) -> Result<(), Box<dyn Error>> {
    use prost::Message;
    let descriptor =
        prost_types::FileDescriptorSet::decode(std::fs::read(descriptor_path)?.as_slice())?;
    let service = descriptor
        .file
        .iter()
        .find_map(|file| {
            (file.package.as_deref() == Some("positron.v1")).then(|| {
                file.service
                    .iter()
                    .find(|service| service.name.as_deref() == Some("TenantRetentionService"))
            })
        })
        .flatten();
    let matches_method = |name: &str, input: &str, output: &str| {
        service.is_some_and(|service| {
            service.method.iter().any(|method| {
                method.name.as_deref() == Some(name)
                    && method.input_type.as_deref() == Some(input)
                    && method.output_type.as_deref() == Some(output)
            })
        })
    };
    if !matches_method(
        "Preview",
        ".positron.v1.TenantRetentionPreviewRequest",
        ".positron.v1.TenantRetentionPreviewResponse",
    ) || !matches_method(
        "Update",
        ".positron.v1.TenantRetentionUpdateRequest",
        ".positron.v1.TenantRetentionUpdateResponse",
    ) {
        return Err("TenantRetentionService is missing required canonical protobuf methods".into());
    }
    let mapping: serde_json::Value = serde_json::from_slice(&std::fs::read(mapping_path)?)?;
    let route = |rpc: &str| -> Result<(&str, usize, usize), Box<dyn Error>> {
        let route = mapping["mappings"]
            .as_array()
            .and_then(|routes| routes.iter().find(|route| route["rpc"] == rpc))
            .ok_or_else(|| format!("{rpc} is missing from canonical HTTP mapping"))?;
        let path = route["path"]
            .as_str()
            .filter(|path| path.starts_with('/'))
            .ok_or_else(|| format!("{rpc} HTTP path is invalid"))?;
        let request_limit = route["max_request_bytes"]
            .as_u64()
            .and_then(|value| usize::try_from(value).ok())
            .ok_or_else(|| format!("{rpc} request limit is invalid"))?;
        let response_limit = route["max_response_bytes"]
            .as_u64()
            .and_then(|value| usize::try_from(value).ok())
            .ok_or_else(|| format!("{rpc} response limit is invalid"))?;
        Ok((path, request_limit, response_limit))
    };
    let (preview_path, preview_request_limit, preview_response_limit) =
        route("positron.v1.TenantRetentionService/Preview")?;
    let (update_path, update_request_limit, update_response_limit) =
        route("positron.v1.TenantRetentionService/Update")?;
    let source = format!(
        r#"// Generated by positron-api/build.rs from TenantRetentionService in the canonical protobuf descriptor and HTTP mapping. Do not edit.
use std::io::Read;
use std::time::Duration;
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TenantRetentionServiceClientFailure {{ InvalidRequest, AuthenticationRejected, TenantUnavailable, InvalidConfirmation, StaleContinuation, StaleGeneration {{ retention_generation: u64, semantic_diff: String }}, IdempotencyConflict, AdministrationUnavailable, Transport }}
impl std::fmt::Display for TenantRetentionServiceClientFailure {{ fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {{ formatter.write_str("tenant retention service request failed") }} }}
impl std::error::Error for TenantRetentionServiceClientFailure {{}}
pub struct TenantRetentionServiceClient {{ endpoint: String, client: reqwest::blocking::Client }}
impl TenantRetentionServiceClient {{
 pub fn new(transport: super::TenantRetentionTransport) -> Result<Self, TenantRetentionServiceClientFailure> {{ let (endpoint,builder)=match transport {{ super::TenantRetentionTransport::PlaintextOptOut {{ endpoint }} => (format!("http://{{endpoint}}"), reqwest::blocking::Client::builder()), super::TenantRetentionTransport::Tls {{ endpoint, server_name, trust_file }} => {{ let identity=server_name.parse::<std::net::IpAddr>(); if server_name.is_empty() || server_name.len()>253 || identity.as_ref().is_ok_and(|ip|*ip!=endpoint.ip()) {{ return Err(TenantRetentionServiceClientFailure::Transport); }} let authority=match identity {{ Ok(std::net::IpAddr::V6(_))=>format!("[{{server_name}}]"), _=>server_name.clone() }}; let trust=std::fs::read(trust_file).map_err(|_|TenantRetentionServiceClientFailure::Transport)?; let certificate=reqwest::Certificate::from_pem(&trust).map_err(|_|TenantRetentionServiceClientFailure::Transport)?; (format!("https://{{authority}}:{{}}",endpoint.port()),reqwest::blocking::Client::builder().add_root_certificate(certificate).resolve(&server_name,endpoint)) }} }}; Ok(Self {{ endpoint, client:builder.connect_timeout(Duration::from_secs(5)).timeout(Duration::from_secs(5)).no_proxy().build().map_err(|_|TenantRetentionServiceClientFailure::Transport)? }}) }}
 pub fn preview(&self,bearer:&str,request:&super::TenantRetentionPreviewRequest)->Result<super::TenantRetentionPreviewResponse,TenantRetentionServiceClientFailure>{{let bytes=self.send(bearer,{preview_path:?},request.encode().map_err(|_|TenantRetentionServiceClientFailure::InvalidRequest)?,{preview_request_limit},{preview_response_limit})?;super::TenantRetentionPreviewResponse::decode(&bytes).map_err(|_|TenantRetentionServiceClientFailure::Transport)}}
 pub fn update(&self,bearer:&str,request:&super::TenantRetentionUpdateRequest)->Result<super::TenantRetentionUpdateResponse,TenantRetentionServiceClientFailure>{{let bytes=self.send(bearer,{update_path:?},request.encode().map_err(|_|TenantRetentionServiceClientFailure::InvalidRequest)?,{update_request_limit},{update_response_limit})?;super::TenantRetentionUpdateResponse::decode(&bytes).map_err(|_|TenantRetentionServiceClientFailure::Transport)}}
 fn send(&self,bearer:&str,path:&str,body:Vec<u8>,request_limit:usize,response_limit:usize)->Result<Vec<u8>,TenantRetentionServiceClientFailure>{{if body.len()>request_limit{{Err(TenantRetentionServiceClientFailure::InvalidRequest)}}else{{let response=self.client.post(format!("{{}}{{path}}",self.endpoint)).bearer_auth(bearer).header(reqwest::header::CONTENT_TYPE,"application/json").body(body).send().map_err(|_|TenantRetentionServiceClientFailure::Transport)?;let status=response.status().as_u16();let mut bytes=Vec::with_capacity(response_limit);response.take((response_limit+1)as u64).read_to_end(&mut bytes).map_err(|_|TenantRetentionServiceClientFailure::Transport)?;if bytes.len()>response_limit{{Err(TenantRetentionServiceClientFailure::Transport)}}else if!(200..300).contains(&status){{let value=serde_json::from_slice::<serde_json::Value>(&bytes).ok();let code=value.as_ref().and_then(|value|value.get("code")?.as_str());Err(match(status,code){{(400,Some("invalid_request"))=>TenantRetentionServiceClientFailure::InvalidRequest,(401,Some("authentication_rejected"))=>TenantRetentionServiceClientFailure::AuthenticationRejected,(404,Some("tenant_unavailable"))=>TenantRetentionServiceClientFailure::TenantUnavailable,(409,Some("invalid_confirmation"))=>TenantRetentionServiceClientFailure::InvalidConfirmation,(409,Some("stale_continuation"))=>TenantRetentionServiceClientFailure::StaleContinuation,(409,Some("stale_generation"))=>stale(value.as_ref()),(409,Some("idempotency_conflict"))=>TenantRetentionServiceClientFailure::IdempotencyConflict,(503,Some("administration_unavailable"))=>TenantRetentionServiceClientFailure::AdministrationUnavailable,_=>TenantRetentionServiceClientFailure::Transport}})}}else{{Ok(bytes)}}}}}}
}}
fn stale(value:Option<&serde_json::Value>)->TenantRetentionServiceClientFailure{{let Some(value)=value else{{return TenantRetentionServiceClientFailure::Transport}};let Some(retention_generation)=value.get("retention_generation").and_then(serde_json::Value::as_u64)else{{return TenantRetentionServiceClientFailure::Transport}};let Some(semantic_diff)=value.get("semantic_diff").and_then(serde_json::Value::as_str)else{{return TenantRetentionServiceClientFailure::Transport}};if retention_generation==0||semantic_diff.is_empty()||semantic_diff.len()>1024{{return TenantRetentionServiceClientFailure::Transport}}TenantRetentionServiceClientFailure::StaleGeneration{{retention_generation,semantic_diff:semantic_diff.to_owned()}}}}
"#,
        preview_path = preview_path,
        preview_request_limit = preview_request_limit,
        preview_response_limit = preview_response_limit,
        update_path = update_path,
        update_request_limit = update_request_limit,
        update_response_limit = update_response_limit
    );
    std::fs::write(
        PathBuf::from(std::env::var("OUT_DIR")?).join("tenant_retention_service_client.rs"),
        source,
    )?;
    Ok(())
}

fn generate_tenant_service_client(
    descriptor_path: &std::path::Path,
    mapping_path: &str,
) -> Result<(), Box<dyn Error>> {
    use prost::Message;
    let descriptor =
        prost_types::FileDescriptorSet::decode(std::fs::read(descriptor_path)?.as_slice())?;
    let service = descriptor.file.iter().find_map(|file| {
        (file.package.as_deref() == Some("positron.v1"))
            .then(|| {
                file.service
                    .iter()
                    .find(|service| service.name.as_deref() == Some("TenantService"))
            })
            .flatten()
    });
    let methods = [
        (
            "Create",
            ".positron.v1.TenantCreateRequest",
            ".positron.v1.TenantCreateResponse",
        ),
        (
            "Inspect",
            ".positron.v1.TenantInspectRequest",
            ".positron.v1.TenantInspectResponse",
        ),
        (
            "List",
            ".positron.v1.TenantListRequest",
            ".positron.v1.TenantListResponse",
        ),
        (
            "UpdateDisplayName",
            ".positron.v1.TenantDisplayNameUpdateRequest",
            ".positron.v1.TenantDisplayNameUpdateResponse",
        ),
    ];
    if !methods.iter().all(|(name, input, output)| {
        service.is_some_and(|service| {
            service.method.iter().any(|method| {
                method.name.as_deref() == Some(*name)
                    && method.input_type.as_deref() == Some(*input)
                    && method.output_type.as_deref() == Some(*output)
            })
        })
    }) {
        return Err("TenantService is missing a canonical protobuf method".into());
    }
    let mapping: serde_json::Value = serde_json::from_slice(&std::fs::read(mapping_path)?)?;
    let route = |rpc: &str| -> Result<&str, Box<dyn Error>> {
        mapping["mappings"]
            .as_array()
            .and_then(|routes| routes.iter().find(|route| route["rpc"] == rpc))
            .and_then(|route| route["path"].as_str())
            .filter(|path| path.starts_with('/'))
            .ok_or_else(|| format!("{rpc} is missing from canonical HTTP mapping").into())
    };
    let create = route("positron.v1.TenantService/Create")?;
    let inspect = route("positron.v1.TenantService/Inspect")?;
    let list = route("positron.v1.TenantService/List")?;
    let update = route("positron.v1.TenantService/UpdateDisplayName")?;
    let source = format!(
        r#"// Generated by positron-api/build.rs from TenantService in the canonical HTTP mapping. Do not edit.
use std::io::Read; use std::time::Duration;
#[derive(Clone,Copy,Debug,Eq,PartialEq)] pub enum TenantServiceClientFailure {{ InvalidRequest, AuthenticationRejected, TenantUnavailable, StaleGeneration, StaleContinuation, IdempotencyConflict, AdministrationUnavailable, Transport }}
impl std::fmt::Display for TenantServiceClientFailure {{ fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{{f.write_str("tenant service request failed")}} }} impl std::error::Error for TenantServiceClientFailure {{}}
pub struct TenantServiceClient {{ endpoint:String, client:reqwest::blocking::Client }}
impl TenantServiceClient {{ pub fn new(transport:super::TenantServiceTransport)->Result<Self,TenantServiceClientFailure>{{let(endpoint,builder)=match transport{{super::TenantServiceTransport::PlaintextOptOut{{endpoint}}=>(format!("http://{{endpoint}}"),reqwest::blocking::Client::builder()),super::TenantServiceTransport::Tls{{endpoint,server_name,trust_file}}=>{{let ip=server_name.parse::<std::net::IpAddr>();if server_name.is_empty()||server_name.len()>253||ip.as_ref().is_ok_and(|ip|*ip!=endpoint.ip()){{return Err(TenantServiceClientFailure::Transport)}}let trust=std::fs::read(trust_file).map_err(|_|TenantServiceClientFailure::Transport)?;let certificate=reqwest::Certificate::from_pem(&trust).map_err(|_|TenantServiceClientFailure::Transport)?;let authority=match ip{{Ok(std::net::IpAddr::V6(_))=>format!("[{{server_name}}]"),_=>server_name.clone()}};(format!("https://{{authority}}:{{}}",endpoint.port()),reqwest::blocking::Client::builder().add_root_certificate(certificate).resolve(&server_name,endpoint))}}}};Ok(Self{{endpoint,client:builder.connect_timeout(Duration::from_secs(5)).timeout(Duration::from_secs(5)).no_proxy().build().map_err(|_|TenantServiceClientFailure::Transport)?}})}}
fn send(&self, bearer: &str, path: &str, body: Vec<u8>) -> Result<Vec<u8>, TenantServiceClientFailure> {{
    if body.len() > super::MAX_REQUEST_BYTES {{
        return Err(TenantServiceClientFailure::InvalidRequest);
    }}
    let response = self.client.post(format!("{{}}{{path}}", self.endpoint)).bearer_auth(bearer).header(reqwest::header::CONTENT_TYPE, "application/json").body(body).send().map_err(|_| TenantServiceClientFailure::Transport)?;
    let status = response.status().as_u16();
    let mut bytes = Vec::with_capacity(super::MAX_RESPONSE_BYTES);
    response.take((super::MAX_RESPONSE_BYTES + 1) as u64).read_to_end(&mut bytes).map_err(|_| TenantServiceClientFailure::Transport)?;
    if bytes.len() > super::MAX_RESPONSE_BYTES {{
        return Err(TenantServiceClientFailure::Transport);
    }}
    if !(200..300).contains(&status) {{
        let code = serde_json::from_slice::<serde_json::Value>(&bytes).ok().and_then(|value| value.get("code")?.as_str().map(str::to_owned));
        return Err(match (status, code.as_deref()) {{
            (400, Some("invalid_request")) => TenantServiceClientFailure::InvalidRequest,
            (401, Some("authentication_rejected")) => TenantServiceClientFailure::AuthenticationRejected,
            (404, Some("tenant_unavailable")) => TenantServiceClientFailure::TenantUnavailable,
            (409, Some("stale_display_generation")) => TenantServiceClientFailure::StaleGeneration,
            (409, Some("stale_continuation")) => TenantServiceClientFailure::StaleContinuation,
            (409, Some("idempotency_conflict")) => TenantServiceClientFailure::IdempotencyConflict,
            (503, Some("administration_unavailable")) => TenantServiceClientFailure::AdministrationUnavailable,
            _ => TenantServiceClientFailure::Transport,
        }});
    }}
    Ok(bytes)
}}
pub fn create(&self,b:&str,r:&super::TenantCreateRequest)->Result<super::TenantCreateResponse,TenantServiceClientFailure>{{super::TenantCreateResponse::decode(&self.send(b,{create:?},r.encode().map_err(|_|TenantServiceClientFailure::InvalidRequest)?)?).map_err(|_|TenantServiceClientFailure::Transport)}} pub fn inspect(&self,b:&str,r:&super::TenantInspectRequest)->Result<super::TenantInspectResponse,TenantServiceClientFailure>{{super::TenantInspectResponse::decode(&self.send(b,{inspect:?},r.encode().map_err(|_|TenantServiceClientFailure::InvalidRequest)?)?).map_err(|_|TenantServiceClientFailure::Transport)}} pub fn list(&self,b:&str,r:&super::TenantListRequest)->Result<super::TenantListResponse,TenantServiceClientFailure>{{super::TenantListResponse::decode(&self.send(b,{list:?},r.encode().map_err(|_|TenantServiceClientFailure::InvalidRequest)?)?).map_err(|_|TenantServiceClientFailure::Transport)}} pub fn update_display_name(&self,b:&str,r:&super::TenantDisplayNameUpdateRequest)->Result<super::TenantDisplayNameUpdateResponse,TenantServiceClientFailure>{{super::TenantDisplayNameUpdateResponse::decode(&self.send(b,{update:?},r.encode().map_err(|_|TenantServiceClientFailure::InvalidRequest)?)?).map_err(|_|TenantServiceClientFailure::Transport)}} }}
"#
    );
    std::fs::write(
        PathBuf::from(std::env::var("OUT_DIR")?).join("tenant_service_client.rs"),
        source,
    )?;
    Ok(())
}

fn generate_tenant_alias_client(
    descriptor_path: &std::path::Path,
    mapping_path: &str,
) -> Result<(), Box<dyn Error>> {
    use prost::Message;
    let descriptor =
        prost_types::FileDescriptorSet::decode(std::fs::read(descriptor_path)?.as_slice())?;
    let exists = descriptor.file.iter().any(|file| {
        file.package.as_deref() == Some("positron.v1")
            && file.service.iter().any(|service| {
                service.name.as_deref() == Some("TenantAliasService")
                    && service.method.iter().any(|method| {
                        method.name.as_deref() == Some("Bind")
                            && method.input_type.as_deref()
                                == Some(".positron.v1.TenantAliasBindRequest")
                            && method.output_type.as_deref()
                                == Some(".positron.v1.TenantAliasBindResponse")
                    })
            })
    });
    if !exists {
        return Err(
            "TenantAliasService/Bind is missing from the canonical protobuf descriptor".into(),
        );
    }
    let mapping: serde_json::Value = serde_json::from_slice(&std::fs::read(mapping_path)?)?;
    let route = mapping["mappings"]
        .as_array()
        .and_then(|routes| {
            routes
                .iter()
                .find(|route| route["rpc"] == "positron.v1.TenantAliasService/Bind")
        })
        .ok_or("TenantAliasService/Bind is missing from the canonical HTTP mapping")?;
    let path = route["path"]
        .as_str()
        .filter(|path| path.starts_with('/'))
        .ok_or("TenantAliasService/Bind HTTP path is invalid")?;
    let request_limit = route["max_request_bytes"]
        .as_u64()
        .filter(|limit| *limit <= usize::MAX as u64)
        .ok_or("TenantAliasService/Bind request limit is invalid")?;
    let response_limit = route["max_response_bytes"]
        .as_u64()
        .filter(|limit| *limit <= usize::MAX as u64)
        .ok_or("TenantAliasService/Bind response limit is invalid")?;
    let source = format!(
        r#"// Generated by positron-api/build.rs from TenantAliasService/Bind in the canonical
// protobuf descriptor and HTTP mapping. Do not edit.
use std::io::Read;
use std::time::Duration;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TenantAliasServiceClientFailure {{
    InvalidRequest,
    AuthenticationRejected,
    TenantUnavailable,
    StaleGeneration,
    IdempotencyConflict,
    AliasAlreadyBound,
    AliasConflict,
    AdministrationUnavailable,
    Transport,
}}
impl std::fmt::Display for TenantAliasServiceClientFailure {{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {{
        formatter.write_str("tenant alias service request failed")
    }}
}}
impl std::error::Error for TenantAliasServiceClientFailure {{}}

pub struct TenantAliasServiceClient {{ endpoint: String, client: reqwest::blocking::Client }}
impl TenantAliasServiceClient {{
    pub fn new(transport: super::TenantAliasTransport) -> Result<Self, TenantAliasServiceClientFailure> {{
        let (endpoint, builder) = match transport {{
            super::TenantAliasTransport::PlaintextOptOut {{ endpoint }} => (format!("http://{{endpoint}}"), reqwest::blocking::Client::builder()),
            super::TenantAliasTransport::Tls {{ endpoint, server_name, trust_file }} => {{
                let identity = server_name.parse::<std::net::IpAddr>();
                if server_name.is_empty() || server_name.len() > 253 || identity.as_ref().is_ok_and(|ip| *ip != endpoint.ip()) {{
                    return Err(TenantAliasServiceClientFailure::Transport);
                }}
                let authority = match identity {{ Ok(std::net::IpAddr::V6(_)) => format!("[{{server_name}}]"), _ => server_name.clone() }};
                let trust = std::fs::read(trust_file).map_err(|_| TenantAliasServiceClientFailure::Transport)?;
                let certificate = reqwest::Certificate::from_pem(&trust).map_err(|_| TenantAliasServiceClientFailure::Transport)?;
                (format!("https://{{authority}}:{{}}", endpoint.port()), reqwest::blocking::Client::builder().add_root_certificate(certificate).resolve(&server_name, endpoint))
            }},
        }};
        Ok(Self {{ endpoint, client: builder.connect_timeout(Duration::from_secs(5)).timeout(Duration::from_secs(5)).no_proxy().build().map_err(|_| TenantAliasServiceClientFailure::Transport)? }})
    }}
    pub fn bind(&self, bearer: &str, request: &super::TenantAliasBindRequest) -> Result<super::TenantAliasBindResponse, TenantAliasServiceClientFailure> {{
        let body = request.encode().map_err(|_| TenantAliasServiceClientFailure::InvalidRequest)?;
        if body.len() > {request_limit} {{ return Err(TenantAliasServiceClientFailure::InvalidRequest); }}
        let response = self.client.post(format!("{{}}{path}", self.endpoint)).bearer_auth(bearer).header(reqwest::header::CONTENT_TYPE, "application/json").body(body).send().map_err(|_| TenantAliasServiceClientFailure::Transport)?;
        let status = response.status().as_u16();
        let mut bytes = Vec::with_capacity({response_limit});
        response.take(({response_limit} + 1) as u64).read_to_end(&mut bytes).map_err(|_| TenantAliasServiceClientFailure::Transport)?;
        if bytes.len() > {response_limit} {{ return Err(TenantAliasServiceClientFailure::Transport); }}
        else if !(200..300).contains(&status) {{
            let value = serde_json::from_slice::<serde_json::Value>(&bytes).ok();
            let code = value.as_ref().and_then(|value| value.get("code")?.as_str());
            return Err(match (status, code) {{
                (400, Some("invalid_request")) => TenantAliasServiceClientFailure::InvalidRequest,
                (401, Some("authentication_rejected")) => TenantAliasServiceClientFailure::AuthenticationRejected,
                (404, Some("tenant_unavailable")) => TenantAliasServiceClientFailure::TenantUnavailable,
                (409, Some("stale_generation")) => TenantAliasServiceClientFailure::StaleGeneration,
                (409, Some("idempotency_conflict")) => TenantAliasServiceClientFailure::IdempotencyConflict,
                (409, Some("alias_already_bound")) => TenantAliasServiceClientFailure::AliasAlreadyBound,
                (409, Some("alias_conflict")) => TenantAliasServiceClientFailure::AliasConflict,
                (503, Some("administration_unavailable")) => TenantAliasServiceClientFailure::AdministrationUnavailable,
                _ => TenantAliasServiceClientFailure::Transport,
            }});
        }}
        super::TenantAliasBindResponse::decode(&bytes).map_err(|_| TenantAliasServiceClientFailure::Transport)
    }}
}}
"#,
        path = path,
        request_limit = request_limit,
        response_limit = response_limit,
    );
    std::fs::write(
        PathBuf::from(std::env::var("OUT_DIR")?).join("tenant_alias_service_client.rs"),
        source,
    )?;
    Ok(())
}

fn generate_policy_preview_client(
    descriptor_path: &std::path::Path,
    mapping_path: &str,
) -> Result<(), Box<dyn Error>> {
    use prost::Message;
    let descriptor =
        prost_types::FileDescriptorSet::decode(std::fs::read(descriptor_path)?.as_slice())?;
    let exists = descriptor.file.iter().any(|file| {
        file.package.as_deref() == Some("positron.v1")
            && file.service.iter().any(|service| {
                service.name.as_deref() == Some("PolicyService")
                    && service.method.iter().any(|method| {
                        method.name.as_deref() == Some("Validate")
                            && method.input_type.as_deref()
                                == Some(".positron.v1.PolicyPreviewRequest")
                            && method.output_type.as_deref()
                                == Some(".positron.v1.PolicyValidateResponse")
                    })
            })
    });
    if !exists {
        return Err(
            "PolicyService/Validate is missing from the canonical protobuf descriptor".into(),
        );
    }
    let mapping: serde_json::Value = serde_json::from_slice(&std::fs::read(mapping_path)?)?;
    let route = mapping["mappings"]
        .as_array()
        .and_then(|routes| {
            routes
                .iter()
                .find(|route| route["rpc"] == "positron.v1.PolicyService/Validate")
        })
        .ok_or("PolicyService/Validate is missing from the canonical HTTP mapping")?;
    let path = route["path"]
        .as_str()
        .filter(|path| path.starts_with('/'))
        .ok_or("PolicyService/Validate HTTP path is invalid")?;
    let request_limit = route["max_request_bytes"]
        .as_u64()
        .filter(|limit| *limit <= usize::MAX as u64)
        .ok_or("PolicyService/Validate request limit is invalid")?;
    let response_limit = route["max_response_bytes"]
        .as_u64()
        .filter(|limit| *limit <= usize::MAX as u64)
        .ok_or("PolicyService/Validate response limit is invalid")?;
    let source = format!(
        r#"// Generated by positron-api/build.rs from PolicyService/Validate in the canonical
// protobuf descriptor and HTTP mapping. Do not edit.
use std::io::Read;
use std::time::Duration;

pub const MAX_REQUEST_BYTES: usize = {request_limit};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyPreviewServiceClientFailure {{
    InvalidRequest,
    AuthenticationRejected,
    AdministrationUnavailable,
    Transport,
}}
impl std::fmt::Display for PolicyPreviewServiceClientFailure {{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {{
        formatter.write_str("policy preview service request failed")
    }}
}}
impl std::error::Error for PolicyPreviewServiceClientFailure {{}}

pub struct PolicyPreviewServiceClient {{
    endpoint: String,
    client: reqwest::blocking::Client,
}}
impl PolicyPreviewServiceClient {{
    pub fn new(transport: super::PolicyPreviewTransport) -> Result<Self, PolicyPreviewServiceClientFailure> {{
        let (endpoint, builder) = match transport {{
            super::PolicyPreviewTransport::PlaintextOptOut {{ endpoint }} => (format!("http://{{endpoint}}"), reqwest::blocking::Client::builder()),
            super::PolicyPreviewTransport::Tls {{ endpoint, server_name, trust_file }} => {{
                let identity = server_name.parse::<std::net::IpAddr>();
                if server_name.is_empty() || server_name.len() > 253 || identity.as_ref().is_ok_and(|ip| *ip != endpoint.ip()) {{
                    return Err(PolicyPreviewServiceClientFailure::Transport);
                }}
                let authority = match identity {{ Ok(std::net::IpAddr::V6(_)) => format!("[{{server_name}}]"), _ => server_name.clone() }};
                let trust = std::fs::read(trust_file).map_err(|_| PolicyPreviewServiceClientFailure::Transport)?;
                let certificate = reqwest::Certificate::from_pem(&trust).map_err(|_| PolicyPreviewServiceClientFailure::Transport)?;
                (format!("https://{{authority}}:{{}}", endpoint.port()), reqwest::blocking::Client::builder().add_root_certificate(certificate).resolve(&server_name, endpoint))
            }},
        }};
        Ok(Self {{ endpoint, client: builder.connect_timeout(Duration::from_secs(5)).timeout(Duration::from_secs(5)).no_proxy().build().map_err(|_| PolicyPreviewServiceClientFailure::Transport)? }})
    }}
    pub fn validate(&self, bearer: &str, request: &super::PolicyPreviewRequest) -> Result<super::PolicyValidateResponse, PolicyPreviewServiceClientFailure> {{
        let body = request.encode().map_err(|_| PolicyPreviewServiceClientFailure::InvalidRequest)?;
        if body.len() > MAX_REQUEST_BYTES {{ return Err(PolicyPreviewServiceClientFailure::InvalidRequest); }}
        let response = self.client.post(format!("{{}}{path}", self.endpoint)).bearer_auth(bearer).header(reqwest::header::CONTENT_TYPE, "application/json").body(body).send().map_err(|_| PolicyPreviewServiceClientFailure::Transport)?;
        let status = response.status().as_u16();
        let mut bytes = Vec::with_capacity({response_limit});
        response.take(({response_limit} + 1) as u64).read_to_end(&mut bytes).map_err(|_| PolicyPreviewServiceClientFailure::Transport)?;
        if bytes.len() > {response_limit} {{ return Err(PolicyPreviewServiceClientFailure::Transport); }}
        if !(200..300).contains(&status) {{
            let code = serde_json::from_slice::<serde_json::Value>(&bytes).ok().and_then(|value| value.get("code")?.as_str().map(str::to_owned));
            return Err(match (status, code.as_deref()) {{
                (400, Some("invalid_request")) => PolicyPreviewServiceClientFailure::InvalidRequest,
                (401, Some("authentication_rejected")) => PolicyPreviewServiceClientFailure::AuthenticationRejected,
                (503, Some("administration_unavailable")) => PolicyPreviewServiceClientFailure::AdministrationUnavailable,
                _ => PolicyPreviewServiceClientFailure::Transport,
            }});
        }}
        super::PolicyValidateResponse::decode(&bytes).map_err(|_| PolicyPreviewServiceClientFailure::Transport)
    }}
}}
"#,
        path = path,
        request_limit = request_limit,
        response_limit = response_limit,
    );
    std::fs::write(
        PathBuf::from(std::env::var("OUT_DIR")?).join("policy_preview_service_client.rs"),
        source,
    )?;
    Ok(())
}

fn generate_policy_test_client(
    descriptor_path: &std::path::Path,
    mapping_path: &str,
) -> Result<(), Box<dyn Error>> {
    use prost::Message;
    let descriptor =
        prost_types::FileDescriptorSet::decode(std::fs::read(descriptor_path)?.as_slice())?;
    let found = descriptor.file.iter().any(|file| {
        file.package.as_deref() == Some("positron.v1")
            && file.service.iter().any(|service| {
                service.name.as_deref() == Some("PolicyService")
                    && service
                        .method
                        .iter()
                        .any(|method| method.name.as_deref() == Some("Test"))
            })
    });
    if !found {
        return Err("PolicyService/Test is missing from the canonical protobuf descriptor".into());
    }
    let mapping: serde_json::Value = serde_json::from_slice(&std::fs::read(mapping_path)?)?;
    let route = mapping["mappings"]
        .as_array()
        .and_then(|routes| {
            routes
                .iter()
                .find(|route| route["rpc"] == "positron.v1.PolicyService/Test")
        })
        .ok_or("PolicyService/Test is missing from the canonical HTTP mapping")?;
    let path = route["path"]
        .as_str()
        .filter(|path| path.starts_with('/'))
        .ok_or("PolicyService/Test HTTP path is invalid")?;
    let request_limit = route["max_request_bytes"]
        .as_u64()
        .filter(|limit| *limit <= usize::MAX as u64)
        .ok_or("PolicyService/Test request limit is invalid")?;
    let response_limit = route["max_response_bytes"]
        .as_u64()
        .filter(|limit| *limit <= usize::MAX as u64)
        .ok_or("PolicyService/Test response limit is invalid")?;
    let source = format!(
        r#"// Generated by positron-api/build.rs from PolicyService/Test in the canonical
// protobuf descriptor and HTTP mapping. Do not edit.
use std::io::Read;
use std::time::Duration;
pub const MAX_TEST_REQUEST_BYTES: usize = {request_limit};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyTestServiceClientFailure {{
    InvalidRequest,
    AuthenticationRejected,
    AdministrationUnavailable,
    Transport,
}}
impl std::fmt::Display for PolicyTestServiceClientFailure {{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {{
        formatter.write_str("policy test service request failed")
    }}
}}
impl std::error::Error for PolicyTestServiceClientFailure {{}}

pub struct PolicyTestServiceClient {{
    endpoint: String,
    client: reqwest::blocking::Client,
}}
impl PolicyTestServiceClient {{
    pub fn new(transport: super::PolicyPreviewTransport) -> Result<Self, PolicyTestServiceClientFailure> {{
        let (endpoint, builder) = match transport {{
            super::PolicyPreviewTransport::PlaintextOptOut {{ endpoint }} => (format!("http://{{endpoint}}"), reqwest::blocking::Client::builder()),
            super::PolicyPreviewTransport::Tls {{ endpoint, server_name, trust_file }} => {{
                let identity = server_name.parse::<std::net::IpAddr>();
                if server_name.is_empty() || server_name.len() > 253 || identity.as_ref().is_ok_and(|ip| *ip != endpoint.ip()) {{
                    return Err(PolicyTestServiceClientFailure::Transport);
                }}
                let authority = match identity {{
                    Ok(std::net::IpAddr::V6(_)) => format!("[{{server_name}}]"),
                    _ => server_name.clone(),
                }};
                let trust = std::fs::read(trust_file).map_err(|_| PolicyTestServiceClientFailure::Transport)?;
                let certificate = reqwest::Certificate::from_pem(&trust).map_err(|_| PolicyTestServiceClientFailure::Transport)?;
                (format!("https://{{authority}}:{{}}", endpoint.port()), reqwest::blocking::Client::builder().add_root_certificate(certificate).resolve(&server_name, endpoint))
            }},
        }};
        Ok(Self {{
            endpoint,
            client: builder.connect_timeout(Duration::from_secs(5)).timeout(Duration::from_secs(5)).no_proxy().build().map_err(|_| PolicyTestServiceClientFailure::Transport)?,
        }})
    }}
    pub fn test(&self, bearer: &str, request: &super::PolicyTestRequest) -> Result<super::PolicyTestResponse, PolicyTestServiceClientFailure> {{
        let body = request.encode()?;
        if body.len() > MAX_TEST_REQUEST_BYTES {{
            return Err(PolicyTestServiceClientFailure::InvalidRequest);
        }}
        let response = self.client.post(format!("{{}}{path}", self.endpoint)).bearer_auth(bearer).header(reqwest::header::CONTENT_TYPE, "application/json").body(body).send().map_err(|_| PolicyTestServiceClientFailure::Transport)?;
        let status = response.status().as_u16();
        let mut bytes = Vec::with_capacity({response_limit});
        response.take(({response_limit} + 1) as u64).read_to_end(&mut bytes).map_err(|_| PolicyTestServiceClientFailure::Transport)?;
        if bytes.len() > {response_limit} {{
            return Err(PolicyTestServiceClientFailure::Transport);
        }}
        if !(200..300).contains(&status) {{
            let code = serde_json::from_slice::<serde_json::Value>(&bytes).ok().and_then(|value| value.get("code")?.as_str().map(str::to_owned));
            return Err(match (status, code.as_deref()) {{
                (400, Some("invalid_request")) => PolicyTestServiceClientFailure::InvalidRequest,
                (401, Some("authentication_rejected")) => PolicyTestServiceClientFailure::AuthenticationRejected,
                (503, Some("administration_unavailable")) => PolicyTestServiceClientFailure::AdministrationUnavailable,
                _ => PolicyTestServiceClientFailure::Transport,
            }});
        }}
        super::PolicyTestResponse::decode(&bytes)
    }}
}}
"#,
        path = path,
        request_limit = request_limit,
        response_limit = response_limit,
    );
    std::fs::write(
        PathBuf::from(std::env::var("OUT_DIR")?).join("policy_test_service_client.rs"),
        source,
    )?;
    Ok(())
}

fn generate_policy_diff_client(
    descriptor_path: &std::path::Path,
    mapping_path: &str,
) -> Result<(), Box<dyn Error>> {
    use prost::Message;
    let descriptor =
        prost_types::FileDescriptorSet::decode(std::fs::read(descriptor_path)?.as_slice())?;
    let found = descriptor.file.iter().any(|file| {
        file.package.as_deref() == Some("positron.v1")
            && file.service.iter().any(|service| {
                service.name.as_deref() == Some("PolicyService")
                    && service.method.iter().any(|method| {
                        method.name.as_deref() == Some("Diff")
                            && method.input_type.as_deref()
                                == Some(".positron.v1.PolicyDiffRequest")
                            && method.output_type.as_deref()
                                == Some(".positron.v1.PolicyDiffResponse")
                    })
            })
    });
    if !found {
        return Err("PolicyService/Diff is missing from the canonical protobuf descriptor".into());
    }
    let mapping: serde_json::Value = serde_json::from_slice(&std::fs::read(mapping_path)?)?;
    let route = mapping["mappings"]
        .as_array()
        .and_then(|routes| {
            routes
                .iter()
                .find(|route| route["rpc"] == "positron.v1.PolicyService/Diff")
        })
        .ok_or("PolicyService/Diff is missing from the canonical HTTP mapping")?;
    let path = route["path"]
        .as_str()
        .filter(|path| path.starts_with('/'))
        .ok_or("PolicyService/Diff HTTP path is invalid")?;
    let request_limit = route["max_request_bytes"]
        .as_u64()
        .filter(|limit| *limit <= usize::MAX as u64)
        .ok_or("PolicyService/Diff request limit is invalid")?;
    let response_limit = route["max_response_bytes"]
        .as_u64()
        .filter(|limit| *limit <= usize::MAX as u64)
        .ok_or("PolicyService/Diff response limit is invalid")?;
    let source = format!(
        r#"// Generated by positron-api/build.rs from PolicyService/Diff in the canonical
// protobuf descriptor and HTTP mapping. Do not edit.
use std::io::Read;
use std::time::Duration;
pub const MAX_DIFF_REQUEST_BYTES: usize = {request_limit};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyDiffServiceClientFailure {{
    InvalidRequest,
    AuthenticationRejected,
    AdministrationUnavailable,
    Transport,
}}
impl std::fmt::Display for PolicyDiffServiceClientFailure {{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {{ formatter.write_str("policy diff service request failed") }}
}}
impl std::error::Error for PolicyDiffServiceClientFailure {{}}
pub struct PolicyDiffServiceClient {{ endpoint: String, client: reqwest::blocking::Client }}
impl PolicyDiffServiceClient {{
    pub fn new(transport: super::PolicyPreviewTransport) -> Result<Self, PolicyDiffServiceClientFailure> {{
        let (endpoint, builder) = match transport {{
            super::PolicyPreviewTransport::PlaintextOptOut {{ endpoint }} => (format!("http://{{endpoint}}"), reqwest::blocking::Client::builder()),
            super::PolicyPreviewTransport::Tls {{ endpoint, server_name, trust_file }} => {{
                let identity = server_name.parse::<std::net::IpAddr>();
                if server_name.is_empty() || server_name.len() > 253 || identity.as_ref().is_ok_and(|ip| *ip != endpoint.ip()) {{ return Err(PolicyDiffServiceClientFailure::Transport); }}
                let authority = match identity {{ Ok(std::net::IpAddr::V6(_)) => format!("[{{server_name}}]"), _ => server_name.clone() }};
                let trust = std::fs::read(trust_file).map_err(|_| PolicyDiffServiceClientFailure::Transport)?;
                let certificate = reqwest::Certificate::from_pem(&trust).map_err(|_| PolicyDiffServiceClientFailure::Transport)?;
                (format!("https://{{authority}}:{{}}", endpoint.port()), reqwest::blocking::Client::builder().add_root_certificate(certificate).resolve(&server_name, endpoint))
            }},
        }};
        Ok(Self {{ endpoint, client: builder.connect_timeout(Duration::from_secs(5)).timeout(Duration::from_secs(5)).no_proxy().build().map_err(|_| PolicyDiffServiceClientFailure::Transport)? }})
    }}
    pub fn diff(&self, bearer: &str, request: &super::PolicyDiffRequest) -> Result<super::PolicyDiffResponse, PolicyDiffServiceClientFailure> {{
        let body = request.encode()?;
        if body.len() > MAX_DIFF_REQUEST_BYTES {{ return Err(PolicyDiffServiceClientFailure::InvalidRequest); }}
        let response = self.client.post(format!("{{}}{path}", self.endpoint)).bearer_auth(bearer).header(reqwest::header::CONTENT_TYPE, "application/json").body(body).send().map_err(|_| PolicyDiffServiceClientFailure::Transport)?;
        let status = response.status().as_u16();
        let mut bytes = Vec::with_capacity({response_limit});
        response.take(({response_limit} + 1) as u64).read_to_end(&mut bytes).map_err(|_| PolicyDiffServiceClientFailure::Transport)?;
        if bytes.len() > {response_limit} {{ return Err(PolicyDiffServiceClientFailure::Transport); }}
        if !(200..300).contains(&status) {{
            let code = serde_json::from_slice::<serde_json::Value>(&bytes).ok().and_then(|value| value.get("code")?.as_str().map(str::to_owned));
            return Err(match (status, code.as_deref()) {{
                (400, Some("invalid_request")) => PolicyDiffServiceClientFailure::InvalidRequest,
                (401, Some("authentication_rejected")) => PolicyDiffServiceClientFailure::AuthenticationRejected,
                (503, Some("administration_unavailable")) => PolicyDiffServiceClientFailure::AdministrationUnavailable,
                _ => PolicyDiffServiceClientFailure::Transport,
            }});
        }}
        super::PolicyDiffResponse::decode(&bytes)
    }}
}}
"#,
        path = path,
        request_limit = request_limit,
        response_limit = response_limit,
    );
    std::fs::write(
        PathBuf::from(std::env::var("OUT_DIR")?).join("policy_diff_service_client.rs"),
        source,
    )?;
    Ok(())
}

fn generate_policy_explain_client(
    descriptor_path: &std::path::Path,
    mapping_path: &str,
) -> Result<(), Box<dyn Error>> {
    use prost::Message;
    let descriptor =
        prost_types::FileDescriptorSet::decode(std::fs::read(descriptor_path)?.as_slice())?;
    let found = descriptor.file.iter().any(|file| {
        file.package.as_deref() == Some("positron.v1")
            && file.service.iter().any(|service| {
                service.name.as_deref() == Some("PolicyService")
                    && service.method.iter().any(|method| {
                        method.name.as_deref() == Some("Explain")
                            && method.input_type.as_deref()
                                == Some(".positron.v1.PolicyExplainRequest")
                            && method.output_type.as_deref()
                                == Some(".positron.v1.PolicyExplainResponse")
                    })
            })
    });
    if !found {
        return Err(
            "PolicyService/Explain is missing from the canonical protobuf descriptor".into(),
        );
    }
    let mapping: serde_json::Value = serde_json::from_slice(&std::fs::read(mapping_path)?)?;
    let route = mapping["mappings"]
        .as_array()
        .and_then(|routes| {
            routes
                .iter()
                .find(|route| route["rpc"] == "positron.v1.PolicyService/Explain")
        })
        .ok_or("PolicyService/Explain is missing from the canonical HTTP mapping")?;
    let path = route["path"]
        .as_str()
        .filter(|path| path.starts_with('/'))
        .ok_or("PolicyService/Explain HTTP path is invalid")?;
    let request_limit = route["max_request_bytes"]
        .as_u64()
        .filter(|limit| *limit <= usize::MAX as u64)
        .ok_or("PolicyService/Explain request limit is invalid")?;
    let response_limit = route["max_response_bytes"]
        .as_u64()
        .filter(|limit| *limit <= usize::MAX as u64)
        .ok_or("PolicyService/Explain response limit is invalid")?;
    let source = format!(
        r#"// Generated by positron-api/build.rs from PolicyService/Explain in the canonical
// protobuf descriptor and HTTP mapping. Do not edit.
use std::io::Read;
use std::time::Duration;
pub const MAX_EXPLAIN_REQUEST_BYTES: usize = {request_limit};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyExplainServiceClientFailure {{
    InvalidRequest,
    AuthenticationRejected,
    AdministrationUnavailable,
    Transport,
}}
impl std::fmt::Display for PolicyExplainServiceClientFailure {{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {{ formatter.write_str("policy explain service request failed") }}
}}
impl std::error::Error for PolicyExplainServiceClientFailure {{}}
pub struct PolicyExplainServiceClient {{ endpoint: String, client: reqwest::blocking::Client }}
impl PolicyExplainServiceClient {{
    pub fn new(transport: super::PolicyPreviewTransport) -> Result<Self, PolicyExplainServiceClientFailure> {{
        let (endpoint, builder) = match transport {{
            super::PolicyPreviewTransport::PlaintextOptOut {{ endpoint }} => (format!("http://{{endpoint}}"), reqwest::blocking::Client::builder()),
            super::PolicyPreviewTransport::Tls {{ endpoint, server_name, trust_file }} => {{
                let identity = server_name.parse::<std::net::IpAddr>();
                if server_name.is_empty() || server_name.len() > 253 || identity.as_ref().is_ok_and(|ip| *ip != endpoint.ip()) {{ return Err(PolicyExplainServiceClientFailure::Transport); }}
                let authority = match identity {{ Ok(std::net::IpAddr::V6(_)) => format!("[{{server_name}}]"), _ => server_name.clone() }};
                let trust = std::fs::read(trust_file).map_err(|_| PolicyExplainServiceClientFailure::Transport)?;
                let certificate = reqwest::Certificate::from_pem(&trust).map_err(|_| PolicyExplainServiceClientFailure::Transport)?;
                (format!("https://{{authority}}:{{}}", endpoint.port()), reqwest::blocking::Client::builder().add_root_certificate(certificate).resolve(&server_name, endpoint))
            }},
        }};
        Ok(Self {{ endpoint, client: builder.connect_timeout(Duration::from_secs(5)).timeout(Duration::from_secs(5)).no_proxy().build().map_err(|_| PolicyExplainServiceClientFailure::Transport)? }})
    }}
    pub fn explain(&self, bearer: &str, request: &super::PolicyExplainRequest) -> Result<super::PolicyExplainResponse, PolicyExplainServiceClientFailure> {{
        let body = request.encode().map_err(|_| PolicyExplainServiceClientFailure::InvalidRequest)?;
        if body.len() > MAX_EXPLAIN_REQUEST_BYTES {{ return Err(PolicyExplainServiceClientFailure::InvalidRequest); }}
        let response = self.client.post(format!("{{}}{path}", self.endpoint)).bearer_auth(bearer).header(reqwest::header::CONTENT_TYPE, "application/json").body(body).send().map_err(|_| PolicyExplainServiceClientFailure::Transport)?;
        let status = response.status().as_u16();
        let mut bytes = Vec::with_capacity({response_limit});
        response.take(({response_limit} + 1) as u64).read_to_end(&mut bytes).map_err(|_| PolicyExplainServiceClientFailure::Transport)?;
        if bytes.len() > {response_limit} {{ return Err(PolicyExplainServiceClientFailure::Transport); }}
        if !(200..300).contains(&status) {{
            let code = serde_json::from_slice::<serde_json::Value>(&bytes).ok().and_then(|value| value.get("code")?.as_str().map(str::to_owned));
            return Err(match (status, code.as_deref()) {{
                (400, Some("invalid_request")) => PolicyExplainServiceClientFailure::InvalidRequest,
                (401, Some("authentication_rejected")) => PolicyExplainServiceClientFailure::AuthenticationRejected,
                (503, Some("administration_unavailable")) => PolicyExplainServiceClientFailure::AdministrationUnavailable,
                _ => PolicyExplainServiceClientFailure::Transport,
            }});
        }}
        super::PolicyExplainResponse::decode(&bytes).map_err(|_| PolicyExplainServiceClientFailure::Transport)
    }}
}}
"#,
        path = path,
        request_limit = request_limit,
        response_limit = response_limit,
    );
    std::fs::write(
        PathBuf::from(std::env::var("OUT_DIR")?).join("policy_explain_service_client.rs"),
        source,
    )?;
    Ok(())
}

fn generate_policy_activate_client(
    descriptor_path: &std::path::Path,
    mapping_path: &str,
) -> Result<(), Box<dyn Error>> {
    use prost::Message;
    let descriptor =
        prost_types::FileDescriptorSet::decode(std::fs::read(descriptor_path)?.as_slice())?;
    let found = descriptor.file.iter().any(|file| {
        file.package.as_deref() == Some("positron.v1")
            && file.service.iter().any(|service| {
                service.name.as_deref() == Some("PolicyService")
                    && service.method.iter().any(|method| {
                        method.name.as_deref() == Some("Activate")
                            && method.input_type.as_deref()
                                == Some(".positron.v1.PolicyActivateRequest")
                            && method.output_type.as_deref()
                                == Some(".positron.v1.PolicyActivateResponse")
                    })
            })
    });
    if !found {
        return Err(
            "PolicyService/Activate is missing from the canonical protobuf descriptor".into(),
        );
    }
    let mapping: serde_json::Value = serde_json::from_slice(&std::fs::read(mapping_path)?)?;
    let route = mapping["mappings"]
        .as_array()
        .and_then(|routes| {
            routes
                .iter()
                .find(|route| route["rpc"] == "positron.v1.PolicyService/Activate")
        })
        .ok_or("PolicyService/Activate is missing from the canonical HTTP mapping")?;
    let path = route["path"]
        .as_str()
        .filter(|path| path.starts_with('/'))
        .ok_or("PolicyService/Activate HTTP path is invalid")?;
    let request_limit = route["max_request_bytes"]
        .as_u64()
        .filter(|limit| *limit <= usize::MAX as u64)
        .ok_or("PolicyService/Activate request limit is invalid")?;
    let response_limit = route["max_response_bytes"]
        .as_u64()
        .filter(|limit| *limit <= usize::MAX as u64)
        .ok_or("PolicyService/Activate response limit is invalid")?;
    let source = format!(
        r#"// Generated by positron-api/build.rs from PolicyService/Activate in the canonical
// protobuf descriptor and HTTP mapping. Do not edit.
use std::io::Read;
use std::time::Duration;
pub const MAX_ACTIVATE_REQUEST_BYTES: usize = {request_limit};
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyActivateServiceClientFailure {{
    InvalidRequest,
    AuthenticationRejected,
    StaleGeneration {{ resource_generation: u64, semantic_diff: String }},
    IdempotencyConflict,
    AdministrationUnavailable,
    Transport,
}}
impl std::fmt::Display for PolicyActivateServiceClientFailure {{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {{ formatter.write_str("policy activate service request failed") }}
}}
impl std::error::Error for PolicyActivateServiceClientFailure {{}}
pub struct PolicyActivateServiceClient {{ endpoint: String, client: reqwest::blocking::Client }}
impl PolicyActivateServiceClient {{
    pub fn new(transport: super::PolicyPreviewTransport) -> Result<Self, PolicyActivateServiceClientFailure> {{
        let (endpoint, builder) = match transport {{
            super::PolicyPreviewTransport::PlaintextOptOut {{ endpoint }} => (format!("http://{{endpoint}}"), reqwest::blocking::Client::builder()),
            super::PolicyPreviewTransport::Tls {{ endpoint, server_name, trust_file }} => {{
                let identity = server_name.parse::<std::net::IpAddr>();
                if server_name.is_empty() || server_name.len() > 253 || identity.as_ref().is_ok_and(|ip| *ip != endpoint.ip()) {{ return Err(PolicyActivateServiceClientFailure::Transport); }}
                let authority = match identity {{ Ok(std::net::IpAddr::V6(_)) => format!("[{{server_name}}]"), _ => server_name.clone() }};
                let trust = std::fs::read(trust_file).map_err(|_| PolicyActivateServiceClientFailure::Transport)?;
                let certificate = reqwest::Certificate::from_pem(&trust).map_err(|_| PolicyActivateServiceClientFailure::Transport)?;
                (format!("https://{{authority}}:{{}}", endpoint.port()), reqwest::blocking::Client::builder().add_root_certificate(certificate).resolve(&server_name, endpoint))
            }},
        }};
        Ok(Self {{ endpoint, client: builder.connect_timeout(Duration::from_secs(5)).timeout(Duration::from_secs(5)).no_proxy().build().map_err(|_| PolicyActivateServiceClientFailure::Transport)? }})
    }}
    pub fn activate(&self, bearer: &str, request: &super::PolicyActivateRequest) -> Result<super::PolicyActivateResponse, PolicyActivateServiceClientFailure> {{
        let body = request.encode()?;
        if body.len() > MAX_ACTIVATE_REQUEST_BYTES {{ return Err(PolicyActivateServiceClientFailure::InvalidRequest); }}
        let response = self.client.post(format!("{{}}{path}", self.endpoint)).bearer_auth(bearer).header(reqwest::header::CONTENT_TYPE, "application/json").body(body).send().map_err(|_| PolicyActivateServiceClientFailure::Transport)?;
        let status = response.status().as_u16();
        let mut bytes = Vec::with_capacity({response_limit});
        response.take(({response_limit} + 1) as u64).read_to_end(&mut bytes).map_err(|_| PolicyActivateServiceClientFailure::Transport)?;
        if bytes.len() > {response_limit} {{ return Err(PolicyActivateServiceClientFailure::Transport); }}
        if !(200..300).contains(&status) {{
            let value = serde_json::from_slice::<serde_json::Value>(&bytes).ok();
            let code = value.as_ref().and_then(|value| value.get("code")?.as_str());
            return Err(match (status, code) {{
                (400, Some("invalid_request")) => PolicyActivateServiceClientFailure::InvalidRequest,
                (401, Some("authentication_rejected")) => PolicyActivateServiceClientFailure::AuthenticationRejected,
                (409, Some("stale_generation")) => {{
                    let generation = value.as_ref().and_then(|value| value.get("resource_generation")?.as_u64());
                    let semantic_diff = value.as_ref().and_then(|value| value.get("semantic_diff")?.as_str()).filter(|value| !value.is_empty() && value.len() <= 1024);
                    match (generation, semantic_diff) {{
                        (Some(resource_generation), Some(semantic_diff)) if resource_generation != 0 => PolicyActivateServiceClientFailure::StaleGeneration {{ resource_generation, semantic_diff: semantic_diff.to_owned() }},
                        _ => PolicyActivateServiceClientFailure::Transport,
                    }}
                }},
                (409, Some("idempotency_conflict")) => PolicyActivateServiceClientFailure::IdempotencyConflict,
                (503, Some("administration_unavailable")) => PolicyActivateServiceClientFailure::AdministrationUnavailable,
                _ => PolicyActivateServiceClientFailure::Transport,
            }});
        }}
        super::PolicyActivateResponse::decode(&bytes)
    }}
}}
"#,
        path = path,
        request_limit = request_limit,
        response_limit = response_limit,
    );
    std::fs::write(
        PathBuf::from(std::env::var("OUT_DIR")?).join("policy_activate_service_client.rs"),
        source,
    )?;
    Ok(())
}

fn generate_tenant_quota_client(
    descriptor_path: &std::path::Path,
    mapping_path: &str,
) -> Result<(), Box<dyn Error>> {
    use prost::Message;
    let descriptor =
        prost_types::FileDescriptorSet::decode(std::fs::read(descriptor_path)?.as_slice())?;
    let exists = descriptor.file.iter().any(|file| {
        file.package.as_deref() == Some("positron.v1")
            && file.service.iter().any(|service| {
                service.name.as_deref() == Some("TenantQuotaService")
                    && service.method.iter().any(|method| {
                        method.name.as_deref() == Some("Update")
                            && method.input_type.as_deref()
                                == Some(".positron.v1.TenantQuotaUpdateRequest")
                            && method.output_type.as_deref()
                                == Some(".positron.v1.TenantQuotaUpdateResponse")
                    })
            })
    });
    if !exists {
        return Err(
            "TenantQuotaService/Update is missing from the canonical protobuf descriptor".into(),
        );
    }
    let mapping: serde_json::Value = serde_json::from_slice(&std::fs::read(mapping_path)?)?;
    let route = mapping["mappings"]
        .as_array()
        .and_then(|routes| {
            routes
                .iter()
                .find(|route| route["rpc"] == "positron.v1.TenantQuotaService/Update")
        })
        .ok_or("TenantQuotaService/Update is missing from the canonical HTTP mapping")?;
    let path = route["path"]
        .as_str()
        .filter(|path| path.starts_with('/'))
        .ok_or("TenantQuotaService/Update HTTP path is invalid")?;
    let request_limit = route["max_request_bytes"]
        .as_u64()
        .filter(|limit| *limit <= usize::MAX as u64)
        .ok_or("TenantQuotaService/Update request limit is invalid")?;
    let response_limit = route["max_response_bytes"]
        .as_u64()
        .filter(|limit| *limit <= usize::MAX as u64)
        .ok_or("TenantQuotaService/Update response limit is invalid")?;
    let source = format!(
        r#"// Generated by positron-api/build.rs from TenantQuotaService/Update in the canonical
// protobuf descriptor and HTTP mapping. Do not edit.
use std::io::Read;
use std::time::Duration;

pub const MAX_REQUEST_BYTES: usize = {request_limit};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TenantQuotaServiceClientFailure {{
    InvalidRequest,
    AuthenticationRejected,
    StaleGeneration {{ resource_generation: u64, semantic_diff: String }},
    IdempotencyConflict,
    AdministrationUnavailable,
    Transport,
}}
impl std::fmt::Display for TenantQuotaServiceClientFailure {{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {{
        formatter.write_str("tenant quota service request failed")
    }}
}}
impl std::error::Error for TenantQuotaServiceClientFailure {{}}

pub struct TenantQuotaServiceClient {{
    endpoint: String,
    client: reqwest::blocking::Client,
}}
impl TenantQuotaServiceClient {{
    pub fn new(transport: super::TenantQuotaTransport) -> Result<Self, TenantQuotaServiceClientFailure> {{
        let (endpoint, builder) = match transport {{
            super::TenantQuotaTransport::PlaintextOptOut {{ endpoint }} => (format!("http://{{endpoint}}"), reqwest::blocking::Client::builder()),
            super::TenantQuotaTransport::Tls {{ endpoint, server_name, trust_file }} => {{
                let identity = server_name.parse::<std::net::IpAddr>();
                if server_name.is_empty() || server_name.len() > 253 || identity.as_ref().is_ok_and(|ip| *ip != endpoint.ip()) {{
                    return Err(TenantQuotaServiceClientFailure::Transport);
                }}
                let authority = match identity {{ Ok(std::net::IpAddr::V6(_)) => format!("[{{server_name}}]"), _ => server_name.clone() }};
                let trust = std::fs::read(trust_file).map_err(|_| TenantQuotaServiceClientFailure::Transport)?;
                let certificate = reqwest::Certificate::from_pem(&trust).map_err(|_| TenantQuotaServiceClientFailure::Transport)?;
                (format!("https://{{authority}}:{{}}", endpoint.port()), reqwest::blocking::Client::builder().add_root_certificate(certificate).resolve(&server_name, endpoint))
            }},
        }};
        Ok(Self {{ endpoint, client: builder.connect_timeout(Duration::from_secs(5)).timeout(Duration::from_secs(5)).no_proxy().build().map_err(|_| TenantQuotaServiceClientFailure::Transport)? }})
    }}
    pub fn update(&self, bearer: &str, request: &super::TenantQuotaUpdateRequest) -> Result<super::TenantQuotaUpdateResponse, TenantQuotaServiceClientFailure> {{
        let body = request.encode().map_err(|_| TenantQuotaServiceClientFailure::InvalidRequest)?;
        if body.len() > MAX_REQUEST_BYTES {{ return Err(TenantQuotaServiceClientFailure::Transport); }}
        let response = self.client.post(format!("{{}}{path}", self.endpoint)).bearer_auth(bearer).header(reqwest::header::CONTENT_TYPE, "application/json").body(body).send().map_err(|_| TenantQuotaServiceClientFailure::Transport)?;
        let status = response.status().as_u16();
        let mut bytes = Vec::with_capacity({response_limit});
        response.take(({response_limit} + 1) as u64).read_to_end(&mut bytes).map_err(|_| TenantQuotaServiceClientFailure::Transport)?;
        if bytes.len() > {response_limit} {{ return Err(TenantQuotaServiceClientFailure::Transport); }}
        if !(200..300).contains(&status) {{
            let value = serde_json::from_slice::<serde_json::Value>(&bytes).ok();
            let code = value.as_ref().and_then(|value| value.get("code")?.as_str());
            return Err(match (status, code) {{
                (400, Some("invalid_request")) => TenantQuotaServiceClientFailure::InvalidRequest,
                (401, Some("authentication_rejected")) => TenantQuotaServiceClientFailure::AuthenticationRejected,
                (409, Some("stale_generation")) => stale_generation(value.as_ref()),
                (409, Some("idempotency_conflict")) => TenantQuotaServiceClientFailure::IdempotencyConflict,
                (503, Some("administration_unavailable")) => TenantQuotaServiceClientFailure::AdministrationUnavailable,
                _ => TenantQuotaServiceClientFailure::Transport,
            }});
        }}
        serde_json::from_slice(&bytes).map_err(|_| TenantQuotaServiceClientFailure::Transport)
    }}
}}
fn stale_generation(value: Option<&serde_json::Value>) -> TenantQuotaServiceClientFailure {{
    let Some(value) = value else {{ return TenantQuotaServiceClientFailure::Transport; }};
    let Some(resource_generation) = value.get("resource_generation").and_then(serde_json::Value::as_u64) else {{ return TenantQuotaServiceClientFailure::Transport; }};
    let Some(semantic_diff) = value.get("semantic_diff").and_then(serde_json::Value::as_str) else {{ return TenantQuotaServiceClientFailure::Transport; }};
    if resource_generation == 0 || semantic_diff.is_empty() || semantic_diff.len() > 1024 {{ return TenantQuotaServiceClientFailure::Transport; }}
    TenantQuotaServiceClientFailure::StaleGeneration {{ resource_generation, semantic_diff: semantic_diff.to_owned() }}
}}
"#,
        path = path,
        request_limit = request_limit,
        response_limit = response_limit,
    );
    std::fs::write(
        PathBuf::from(std::env::var("OUT_DIR")?).join("tenant_quota_service_client.rs"),
        source,
    )?;
    Ok(())
}

fn generate_api_key_client(
    descriptor_path: &std::path::Path,
    mapping_path: &str,
) -> Result<(), Box<dyn Error>> {
    use prost::Message;
    let descriptor =
        prost_types::FileDescriptorSet::decode(std::fs::read(descriptor_path)?.as_slice())?;
    let service_exists = descriptor.file.iter().any(|file| {
        file.package.as_deref() == Some("positron.v1")
            && file.service.iter().any(|service| {
                service.name.as_deref() == Some("ApiKeyService")
                    && service.method.iter().any(|method| {
                        method.name.as_deref() == Some("Manage")
                            && method.input_type.as_deref() == Some(".positron.v1.ApiKeyRequest")
                            && method.output_type.as_deref() == Some(".positron.v1.ApiKeyResponse")
                    })
            })
    });
    if !service_exists {
        return Err(
            "ApiKeyService/Manage is missing from the canonical protobuf descriptor".into(),
        );
    }
    let mapping: serde_json::Value = serde_json::from_slice(&std::fs::read(mapping_path)?)?;
    let route = mapping["mappings"]
        .as_array()
        .and_then(|routes| {
            routes
                .iter()
                .find(|route| route["rpc"] == "positron.v1.ApiKeyService/Manage")
        })
        .ok_or("ApiKeyService/Manage is missing from the canonical HTTP mapping")?;
    let path = route["path"]
        .as_str()
        .filter(|path| path.starts_with('/'))
        .ok_or("ApiKeyService/Manage HTTP path is invalid")?;
    let request_limit = route["max_request_bytes"]
        .as_u64()
        .filter(|limit| *limit <= usize::MAX as u64)
        .ok_or("ApiKeyService/Manage request limit is invalid")?;
    let response_limit = route["max_response_bytes"]
        .as_u64()
        .filter(|limit| *limit <= usize::MAX as u64)
        .ok_or("ApiKeyService/Manage response limit is invalid")?;
    let source = format!(
        r#"// Generated by positron-api/build.rs from ApiKeyService/Manage in the canonical
// protobuf descriptor and HTTP mapping. Do not edit.
use std::io::Read;
use std::fs;
use std::net::IpAddr;
use std::time::Duration;

pub struct ApiKeyServiceClient {{
    endpoint: String,
    client: reqwest::blocking::Client,
}}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApiKeyServiceClientFailure {{
    InvalidRequest,
    AuthenticationRejected,
    StaleGeneration,
    IdempotencyConflict,
    KeyUnavailable,
    AdministrationUnavailable,
    Transport,
}}

impl std::fmt::Display for ApiKeyServiceClientFailure {{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {{
        formatter.write_str("API-key service request failed")
    }}
}}
impl std::error::Error for ApiKeyServiceClientFailure {{}}

impl ApiKeyServiceClient {{
    pub fn new(transport: super::ApiKeyTransport) -> Result<Self, ApiKeyServiceClientFailure> {{
        let (endpoint, builder) = match transport {{
            super::ApiKeyTransport::Tls {{ endpoint, server_name, trust_file }} => {{
                if server_name.is_empty() || server_name.len() > 253 || !server_name.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':')) {{
                    return Err(ApiKeyServiceClientFailure::Transport);
                }}
                let expected_identity = server_name.parse::<IpAddr>();
                if expected_identity.as_ref().is_ok_and(|identity| *identity != endpoint.ip()) {{
                    return Err(ApiKeyServiceClientFailure::Transport);
                }}
                let authority = match expected_identity {{
                    Ok(IpAddr::V6(_)) => format!("[{{server_name}}]"),
                    Ok(IpAddr::V4(_)) | Err(_) => server_name.clone(),
                }};
                let trust = fs::read(trust_file).map_err(|_| ApiKeyServiceClientFailure::Transport)?;
                let certificate = reqwest::Certificate::from_pem(&trust)
                    .map_err(|_| ApiKeyServiceClientFailure::Transport)?;
                (format!("https://{{authority}}:{{}}", endpoint.port()), reqwest::blocking::Client::builder().add_root_certificate(certificate).resolve(&server_name, endpoint))
            }},
            super::ApiKeyTransport::PlaintextOptOut {{ endpoint }} => {{
                (format!("http://{{endpoint}}"), reqwest::blocking::Client::builder())
            }},
        }};
        let client = builder
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(5))
            .no_proxy()
            .build()
            .map_err(|_| ApiKeyServiceClientFailure::Transport)?;
        Ok(Self {{ endpoint, client }})
    }}

    pub fn manage(
        &self,
        bearer: &str,
        request: &super::ApiKeyRequest,
    ) -> Result<super::ApiKeyResponse, ApiKeyServiceClientFailure> {{
        let body = request.encode().map_err(|_| ApiKeyServiceClientFailure::Transport)?;
        if body.len() > {request_limit} {{
            return Err(ApiKeyServiceClientFailure::Transport);
        }}
        let url = format!("{{}}{{}}", self.endpoint, {path:?});
        let response = self.client.post(url)
            .bearer_auth(bearer)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .map_err(|_| ApiKeyServiceClientFailure::Transport)?;
        let status = response.status().as_u16();
        let mut bytes = zeroize::Zeroizing::new(Vec::with_capacity({response_limit}));
        response.take(({response_limit} + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| ApiKeyServiceClientFailure::Transport)?;
        if bytes.len() > {response_limit} {{
            return Err(ApiKeyServiceClientFailure::Transport);
        }}
        if !(200..300).contains(&status) {{
            let code = serde_json::from_slice::<serde_json::Value>(&bytes).ok()
                .and_then(|value| value.get("code")?.as_str().map(str::to_owned));
            return Err(match (status, code.as_deref()) {{
                (400, Some("invalid_request")) => ApiKeyServiceClientFailure::InvalidRequest,
                (401, Some("authentication_rejected")) => ApiKeyServiceClientFailure::AuthenticationRejected,
                (404, Some("key_unavailable")) => ApiKeyServiceClientFailure::KeyUnavailable,
                (409, Some("stale_generation")) => ApiKeyServiceClientFailure::StaleGeneration,
                (409, Some("idempotency_conflict")) => ApiKeyServiceClientFailure::IdempotencyConflict,
                (503, Some("administration_unavailable")) => ApiKeyServiceClientFailure::AdministrationUnavailable,
                _ => ApiKeyServiceClientFailure::Transport,
            }});
        }}
        super::ApiKeyResponse::decode(&bytes).map_err(|_| ApiKeyServiceClientFailure::Transport)
    }}
}}
"#
    );
    std::fs::write(
        PathBuf::from(std::env::var("OUT_DIR")?).join("api_key_service_client.rs"),
        source,
    )?;
    Ok(())
}

fn generate_tenant_lifecycle_client(
    descriptor_path: &std::path::Path,
    mapping_path: &str,
) -> Result<(), Box<dyn Error>> {
    use prost::Message;
    let descriptor =
        prost_types::FileDescriptorSet::decode(std::fs::read(descriptor_path)?.as_slice())?;
    let exists = descriptor.file.iter().any(|file| {
        file.package.as_deref() == Some("positron.v1")
            && file.service.iter().any(|service| {
                service.name.as_deref() == Some("TenantLifecycleService")
                    && service.method.iter().any(|method| {
                        method.name.as_deref() == Some("Transition")
                            && method.input_type.as_deref()
                                == Some(".positron.v1.TenantLifecycleTransitionRequest")
                            && method.output_type.as_deref()
                                == Some(".positron.v1.TenantLifecycleTransitionResponse")
                    })
            })
    });
    if !exists {
        return Err(
            "TenantLifecycleService/Transition is missing from the canonical protobuf descriptor"
                .into(),
        );
    }
    let mapping: serde_json::Value = serde_json::from_slice(&std::fs::read(mapping_path)?)?;
    let route = mapping["mappings"]
        .as_array()
        .and_then(|routes| {
            routes
                .iter()
                .find(|route| route["rpc"] == "positron.v1.TenantLifecycleService/Transition")
        })
        .ok_or("TenantLifecycleService/Transition is missing from the canonical HTTP mapping")?;
    let path = route["path"]
        .as_str()
        .filter(|path| path.starts_with('/'))
        .ok_or("TenantLifecycleService/Transition HTTP path is invalid")?;
    let request_limit = route["max_request_bytes"]
        .as_u64()
        .filter(|limit| *limit <= usize::MAX as u64)
        .ok_or("TenantLifecycleService/Transition request limit is invalid")?;
    let response_limit = route["max_response_bytes"]
        .as_u64()
        .filter(|limit| *limit <= usize::MAX as u64)
        .ok_or("TenantLifecycleService/Transition response limit is invalid")?;
    let source = format!(
        r#"// Generated by positron-api/build.rs from TenantLifecycleService/Transition in the canonical protobuf descriptor and HTTP mapping. Do not edit.
use std::io::Read;
use std::time::Duration;
pub const MAX_REQUEST_BYTES: usize = {request_limit};
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TenantLifecycleServiceClientFailure {{ InvalidRequest, AuthenticationRejected, TenantUnavailable, StaleGeneration {{ lifecycle_generation: u64, semantic_diff: String }}, IdempotencyConflict, InvalidTransition, PurgeCompletionUnavailable, AdministrationUnavailable, Transport }}
impl std::fmt::Display for TenantLifecycleServiceClientFailure {{ fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {{ f.write_str("tenant lifecycle service request failed") }} }}
impl std::error::Error for TenantLifecycleServiceClientFailure {{}}
pub struct TenantLifecycleServiceClient {{ endpoint: String, client: reqwest::blocking::Client }}
impl TenantLifecycleServiceClient {{
 pub fn new(transport: super::TenantLifecycleTransport) -> Result<Self, TenantLifecycleServiceClientFailure> {{ let (endpoint,builder)=match transport {{ super::TenantLifecycleTransport::PlaintextOptOut {{ endpoint }} => (format!("http://{{endpoint}}"),reqwest::blocking::Client::builder()), super::TenantLifecycleTransport::Tls {{ endpoint,server_name,trust_file }} => {{ let identity=server_name.parse::<std::net::IpAddr>(); if server_name.is_empty() || server_name.len()>253 || identity.as_ref().is_ok_and(|ip| *ip != endpoint.ip()) {{ return Err(TenantLifecycleServiceClientFailure::Transport); }} let authority=match identity {{ Ok(std::net::IpAddr::V6(_))=>format!("[{{server_name}}]"), _=>server_name.clone() }}; let trust=std::fs::read(trust_file).map_err(|_|TenantLifecycleServiceClientFailure::Transport)?; let certificate=reqwest::Certificate::from_pem(&trust).map_err(|_|TenantLifecycleServiceClientFailure::Transport)?; (format!("https://{{authority}}:{{}}",endpoint.port()),reqwest::blocking::Client::builder().add_root_certificate(certificate).resolve(&server_name,endpoint)) }} }}; Ok(Self {{ endpoint,client:builder.connect_timeout(Duration::from_secs(5)).timeout(Duration::from_secs(5)).no_proxy().build().map_err(|_|TenantLifecycleServiceClientFailure::Transport)? }}) }}
 pub fn transition(&self,bearer:&str,request:&super::TenantLifecycleTransitionRequest)->Result<super::TenantLifecycleTransitionResponse,TenantLifecycleServiceClientFailure> {{ let body=request.encode().map_err(|_|TenantLifecycleServiceClientFailure::InvalidRequest)?; if body.len()>MAX_REQUEST_BYTES {{ return Err(TenantLifecycleServiceClientFailure::InvalidRequest); }} let response=self.client.post(format!("{{}}{path}",self.endpoint)).bearer_auth(bearer).header(reqwest::header::CONTENT_TYPE,"application/json").body(body).send().map_err(|_|TenantLifecycleServiceClientFailure::Transport)?; let status=response.status().as_u16(); let mut bytes=Vec::with_capacity({response_limit}); response.take(({response_limit}+1) as u64).read_to_end(&mut bytes).map_err(|_|TenantLifecycleServiceClientFailure::Transport)?; if bytes.len()>{response_limit} {{ return Err(TenantLifecycleServiceClientFailure::Transport); }} else if !(200..300).contains(&status) {{ let value=serde_json::from_slice::<serde_json::Value>(&bytes).ok(); let code=value.as_ref().and_then(|v|v.get("code")?.as_str()); return Err(match (status,code) {{ (400,Some("invalid_request"))=>TenantLifecycleServiceClientFailure::InvalidRequest,(401,Some("authentication_rejected"))=>TenantLifecycleServiceClientFailure::AuthenticationRejected,(404,Some("tenant_unavailable"))=>TenantLifecycleServiceClientFailure::TenantUnavailable,(409,Some("stale_generation"))=>stale(value.as_ref()),(409,Some("idempotency_conflict"))=>TenantLifecycleServiceClientFailure::IdempotencyConflict,(409,Some("invalid_transition"))=>TenantLifecycleServiceClientFailure::InvalidTransition,(409,Some("purge_completion_unavailable"))=>TenantLifecycleServiceClientFailure::PurgeCompletionUnavailable,(503,Some("administration_unavailable"))=>TenantLifecycleServiceClientFailure::AdministrationUnavailable,_=>TenantLifecycleServiceClientFailure::Transport }}); }} super::TenantLifecycleTransitionResponse::decode(&bytes).map_err(|_|TenantLifecycleServiceClientFailure::Transport) }}
}}
fn stale(value: Option<&serde_json::Value>) -> TenantLifecycleServiceClientFailure {{ let Some(value)=value else {{ return TenantLifecycleServiceClientFailure::Transport; }}; let Some(lifecycle_generation)=value.get("lifecycle_generation").and_then(serde_json::Value::as_u64) else {{ return TenantLifecycleServiceClientFailure::Transport; }}; let Some(semantic_diff)=value.get("semantic_diff").and_then(serde_json::Value::as_str) else {{ return TenantLifecycleServiceClientFailure::Transport; }}; if lifecycle_generation==0 || semantic_diff.is_empty() || semantic_diff.len()>1024 {{ return TenantLifecycleServiceClientFailure::Transport; }} TenantLifecycleServiceClientFailure::StaleGeneration {{ lifecycle_generation,semantic_diff:semantic_diff.to_owned() }} }}
"#,
        path = path,
        request_limit = request_limit,
        response_limit = response_limit
    );
    std::fs::write(
        PathBuf::from(std::env::var("OUT_DIR")?).join("tenant_lifecycle_service_client.rs"),
        source,
    )?;
    Ok(())
}
