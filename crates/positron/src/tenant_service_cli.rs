use std::collections::BTreeMap;
use std::io::{IsTerminal, Read};
use std::net::SocketAddr;
use std::process::ExitCode;

use positron_api::tenant_service::{
    TenantCreateRequest, TenantDisplayNameUpdateRequest, TenantInspectRequest, TenantListRequest,
    TenantServiceClient, TenantServiceClientFailure, TenantServiceTransport,
};
use zeroize::Zeroizing;

pub(super) fn run(arguments: impl Iterator<Item = String>) -> ExitCode {
    match execute(arguments) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("positron: {message}");
            ExitCode::from(2)
        },
    }
}

fn execute(arguments: impl Iterator<Item = String>) -> Result<(), &'static str> {
    let (transport, command) = parse(arguments)?;
    let credential = credential()?;
    let bearer = credential.trim_end_matches(['\r', '\n']);
    let client = TenantServiceClient::new(transport).map_err(|_| "API endpoint unavailable")?;
    match command {
        Command::Create(request) => {
            let response = client.create(bearer, &request).map_err(client_failure)?;
            println!(
                "tenant={} resource_generation={} audit_position={}",
                response.tenant, response.resource_generation, response.audit_position
            );
        },
        Command::Inspect(request) => {
            let response = client.inspect(bearer, &request).map_err(client_failure)?;
            print_descriptor(&response.tenant);
        },
        Command::List(mut request) => loop {
            let response = client.list(bearer, &request).map_err(client_failure)?;
            for descriptor in response.tenants {
                print_descriptor(&descriptor);
            }
            match response.continuation {
                Some(continuation) => request = TenantListRequest::with_continuation(continuation),
                None => break,
            }
        },
        Command::UpdateDisplayName(request) => {
            let response = client
                .update_display_name(bearer, &request)
                .map_err(client_failure)?;
            println!(
                "tenant={} display_generation={} audit_position={}",
                response.tenant, response.display_generation, response.audit_position
            );
        },
    }
    Ok(())
}

fn print_descriptor(descriptor: &positron_api::tenant_service::TenantDescriptor) {
    println!(
        "tenant={} slug={} display_name={} retention_seconds={} display_generation={} retention_generation={} lifecycle={:?}",
        descriptor.tenant,
        descriptor.slug,
        descriptor.display_name,
        descriptor.retention_seconds,
        descriptor.display_generation,
        descriptor.retention_generation,
        descriptor.lifecycle
    );
}

fn credential() -> Result<Zeroizing<String>, &'static str> {
    let input = std::io::stdin();
    if input.is_terminal() {
        return Err("credential input must be a pipe; terminal input is refused to prevent echo");
    }
    let mut credential = Zeroizing::new(String::new());
    input
        .take(1025)
        .read_to_string(&mut credential)
        .map_err(|_| "credential input unavailable")?;
    let bearer = credential.trim_end_matches(['\r', '\n']);
    if credential.len() > 1024
        || bearer.is_empty()
        || bearer.len() > 1024
        || !bearer
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err("invalid credential input");
    }
    Ok(credential)
}

fn client_failure(failure: TenantServiceClientFailure) -> &'static str {
    match failure {
        TenantServiceClientFailure::InvalidRequest => {
            "invalid tenant request; correct the request before retrying"
        },
        TenantServiceClientFailure::AuthenticationRejected => "authentication rejected",
        TenantServiceClientFailure::TenantUnavailable => "tenant unavailable",
        TenantServiceClientFailure::StaleGeneration => {
            "stale display generation; inspect current state before retrying"
        },
        TenantServiceClientFailure::StaleContinuation => {
            "tenant list changed; restart enumeration without a continuation"
        },
        TenantServiceClientFailure::IdempotencyConflict => {
            "idempotency conflict; inspect current state before retrying"
        },
        TenantServiceClientFailure::AdministrationUnavailable => {
            "administration unavailable; retry with the same idempotency key"
        },
        TenantServiceClientFailure::Transport => {
            "API transport unavailable; inspect state before retrying"
        },
    }
}

enum Command {
    Create(TenantCreateRequest),
    Inspect(TenantInspectRequest),
    List(TenantListRequest),
    UpdateDisplayName(TenantDisplayNameUpdateRequest),
}

fn parse(
    mut arguments: impl Iterator<Item = String>,
) -> Result<(TenantServiceTransport, Command), &'static str> {
    let command = arguments.next().ok_or(USAGE)?;
    if !matches!(
        command.as_str(),
        "create" | "inspect" | "list" | "update-display-name"
    ) {
        return Err(USAGE);
    }
    let mut options = BTreeMap::new();
    let mut credential_stdin = false;
    let mut allow_plaintext = false;
    while let Some(option) = arguments.next() {
        if option == "--credential-stdin" {
            if credential_stdin {
                return Err("duplicate tenant option");
            }
            credential_stdin = true;
        } else if option == "--allow-plaintext" {
            if allow_plaintext {
                return Err("duplicate tenant option");
            }
            allow_plaintext = true;
        } else {
            if !matches!(
                option.as_str(),
                "--endpoint"
                    | "--server-name"
                    | "--trust-file"
                    | "--tenant"
                    | "--slug"
                    | "--display-name"
                    | "--retention-seconds"
                    | "--weight"
                    | "--memory-bytes"
                    | "--queue-slots"
                    | "--task-slots"
                    | "--buffer-cache-bytes"
                    | "--batch-items"
                    | "--lease-slots"
                    | "--retry-slots"
                    | "--io-permits"
                    | "--cpu-work-units"
                    | "--file-descriptors"
                    | "--disk-headroom-bytes"
                    | "--idempotency-key"
                    | "--expected-display-generation"
                    | "--continuation"
            ) {
                return Err("unknown tenant option");
            }
            let value = arguments.next().ok_or("missing tenant option value")?;
            if options.insert(option, value).is_some() {
                return Err("duplicate tenant option");
            }
        }
    }
    if !credential_stdin {
        return Err(
            "--credential-stdin is required; secrets are never accepted as arguments or environment variables",
        );
    }
    let transport = transport(&mut options, allow_plaintext)?;
    let command = match command.as_str() {
        "create" => Command::Create(TenantCreateRequest::new(
            required(&mut options, "--tenant")?,
            required(&mut options, "--slug")?,
            required(&mut options, "--display-name")?,
            number(&mut options, "--retention-seconds")?,
            number(&mut options, "--weight")?,
            [
                number(&mut options, "--memory-bytes")?,
                number(&mut options, "--queue-slots")?,
                number(&mut options, "--task-slots")?,
                number(&mut options, "--buffer-cache-bytes")?,
                number(&mut options, "--batch-items")?,
                number(&mut options, "--lease-slots")?,
                number(&mut options, "--retry-slots")?,
                number(&mut options, "--io-permits")?,
                number(&mut options, "--cpu-work-units")?,
                number(&mut options, "--file-descriptors")?,
                number(&mut options, "--disk-headroom-bytes")?,
            ],
            required(&mut options, "--idempotency-key")?,
        )),
        "inspect" => Command::Inspect(TenantInspectRequest::new(required(
            &mut options,
            "--tenant",
        )?)),
        "list" => match options.remove("--continuation") {
            Some(continuation) => Command::List(TenantListRequest::with_continuation(continuation)),
            None => Command::List(TenantListRequest::new()),
        },
        "update-display-name" => Command::UpdateDisplayName(TenantDisplayNameUpdateRequest::new(
            required(&mut options, "--tenant")?,
            number(&mut options, "--expected-display-generation")?,
            required(&mut options, "--display-name")?,
            required(&mut options, "--idempotency-key")?,
        )),
        _ => return Err(USAGE),
    };
    if !options.is_empty() {
        return Err("option does not apply to tenant command");
    }
    match &command {
        Command::Create(request) => request
            .validate()
            .map_err(|_| "invalid tenant create request")?,
        Command::Inspect(request) => request
            .validate()
            .map_err(|_| "invalid tenant inspect request")?,
        Command::List(_) => {},
        Command::UpdateDisplayName(request) => request
            .validate()
            .map_err(|_| "invalid display-name update request")?,
    }
    Ok((transport, command))
}

fn transport(
    options: &mut BTreeMap<String, String>,
    allow_plaintext: bool,
) -> Result<TenantServiceTransport, &'static str> {
    let endpoint: SocketAddr = required(options, "--endpoint")?
        .parse()
        .map_err(|_| "invalid API endpoint")?;
    if endpoint.port() == 0 {
        return Err("invalid API endpoint");
    }
    if allow_plaintext {
        if options.contains_key("--server-name") || options.contains_key("--trust-file") {
            return Err("TLS options do not apply to plaintext opt-out");
        }
        Ok(TenantServiceTransport::PlaintextOptOut { endpoint })
    } else {
        Ok(TenantServiceTransport::Tls {
            endpoint,
            server_name: required(options, "--server-name")?,
            trust_file: required(options, "--trust-file")?.into(),
        })
    }
}

fn required(options: &mut BTreeMap<String, String>, name: &str) -> Result<String, &'static str> {
    options.remove(name).ok_or("required tenant option absent")
}
fn number<T: std::str::FromStr>(
    options: &mut BTreeMap<String, String>,
    name: &str,
) -> Result<T, &'static str> {
    required(options, name)?
        .parse()
        .map_err(|_| "invalid tenant numeric value")
}

const USAGE: &str = "usage: positron tenant create|inspect|list [--continuation OPAQUE_TOKEN]|update-display-name --endpoint IP:PORT --credential-stdin [named request options] [--server-name NAME --trust-file PATH | --allow-plaintext]";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_commands_default_to_tls_and_require_explicit_plaintext() {
        let tls = parse(valid("inspect --tenant 22222222-2222-2222-2222-222222222222 --server-name tenant.example --trust-file ca.pem").split_whitespace().map(ToOwned::to_owned)).expect("TLS parse");
        assert!(matches!(tls.0, TenantServiceTransport::Tls { .. }));
        let plaintext = parse(
            valid("list --allow-plaintext")
                .split_whitespace()
                .map(ToOwned::to_owned),
        )
        .expect("plaintext parse");
        assert!(matches!(
            plaintext.0,
            TenantServiceTransport::PlaintextOptOut { .. }
        ));
    }

    #[test]
    fn tenant_commands_reject_secret_arguments_and_inapplicable_fields() {
        for command in [
            "list --allow-plaintext --tenant 22222222-2222-2222-2222-222222222222",
            "inspect --allow-plaintext --credential secret --tenant 22222222-2222-2222-2222-222222222222",
            "inspect --allow-plaintext --server-name ignored --tenant 22222222-2222-2222-2222-222222222222",
        ] {
            assert!(
                parse(valid(command).split_whitespace().map(ToOwned::to_owned)).is_err(),
                "{command}"
            );
        }
    }

    #[test]
    fn generated_tenant_and_alias_clients_use_trusted_tls_for_all_operations()
    -> Result<(), Box<dyn std::error::Error>> {
        use positron_api::tenant_aliases::{
            TenantAliasBindRequest, TenantAliasServiceClient, TenantAliasServiceClientFailure,
            TenantAliasTransport,
        };
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
        use rustls::{ServerConfig, ServerConnection, StreamOwned};
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::Arc;
        use std::thread;

        let certificate = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../positron-runtime/tests/native_transport/fixtures/api-test-cert.pem"
        );
        let private_key = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../positron-runtime/tests/native_transport/fixtures/api-test-key.pem"
        );
        let certificates =
            CertificateDer::pem_file_iter(certificate)?.collect::<Result<Vec<_>, _>>()?;
        let private_key = PrivateKeyDer::from_pem_slice(&std::fs::read(private_key)?)?;
        let configuration = Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certificates, private_key)?,
        );
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let endpoint = listener.local_addr()?;
        let server = thread::spawn(move || -> Result<(), std::io::Error> {
            let responses = [
                (
                    "/v1/tenants:create",
                    200,
                    r#"{"tenant":"22222222-2222-2222-2222-222222222222","resource_generation":1,"audit_position":2}"#,
                ),
                (
                    "/v1/tenants:inspect",
                    200,
                    r#"{"tenant":{"tenant":"22222222-2222-2222-2222-222222222222","slug":"acme-observability","display_name":"Acme Observability","retention_seconds":2592000,"display_generation":1,"retention_generation":1,"lifecycle":"active"}}"#,
                ),
                (
                    "/v1/tenants:list",
                    200,
                    r#"{"tenants":[{"tenant":"22222222-2222-2222-2222-222222222222","slug":"acme-observability","display_name":"Acme Observability","retention_seconds":2592000,"display_generation":1,"retention_generation":1,"lifecycle":"active"}],"continuation":null}"#,
                ),
                (
                    "/v1/tenants:update-display-name",
                    409,
                    r#"{"code":"stale_display_generation","display_generation":2,"semantic_diff":"display name changed"}"#,
                ),
                (
                    "/v1/tenant-aliases:bind",
                    409,
                    r#"{"code":"idempotency_conflict"}"#,
                ),
                (
                    "/v1/tenant-aliases:bind",
                    401,
                    r#"{"code":"authentication_rejected"}"#,
                ),
            ];
            for (path, status, body) in responses {
                let (stream, _) = listener.accept()?;
                let connection = ServerConnection::new(Arc::clone(&configuration))
                    .map_err(std::io::Error::other)?;
                let mut stream = StreamOwned::new(connection, stream);
                let mut bytes = [0_u8; 8192];
                let read = stream.read(&mut bytes)?;
                let request = String::from_utf8_lossy(&bytes[..read]);
                assert!(request.starts_with(&format!("POST {path} HTTP/1.1\r\n")));
                assert!(
                    request
                        .to_ascii_lowercase()
                        .contains("authorization: bearer credential-material\r\n")
                );
                stream.write_all(
                    format!(
                        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )?;
            }
            Ok(())
        });

        let service = TenantServiceClient::new(TenantServiceTransport::Tls {
            endpoint,
            server_name: "localhost".to_owned(),
            trust_file: certificate.into(),
        })?;
        let create = TenantCreateRequest::new(
            "22222222-2222-2222-2222-222222222222".to_owned(),
            "acme-observability".to_owned(),
            "Acme Observability".to_owned(),
            2_592_000,
            1,
            [1; 11],
            "01010101-0101-0101-0101-010101010101".to_owned(),
        );
        assert_eq!(
            service
                .create("credential-material", &create)?
                .resource_generation,
            1
        );
        assert_eq!(
            service
                .inspect(
                    "credential-material",
                    &TenantInspectRequest::new("22222222-2222-2222-2222-222222222222".to_owned())
                )?
                .tenant
                .slug,
            "acme-observability"
        );
        assert_eq!(
            service
                .list("credential-material", &TenantListRequest::new())?
                .tenants
                .len(),
            1
        );
        assert_eq!(
            service
                .update_display_name(
                    "credential-material",
                    &TenantDisplayNameUpdateRequest::new(
                        "22222222-2222-2222-2222-222222222222".to_owned(),
                        1,
                        "Acme Production".to_owned(),
                        "01010101-0101-0101-0101-010101010101".to_owned(),
                    ),
                )
                .expect_err("stale display generation"),
            TenantServiceClientFailure::StaleGeneration
        );
        let alias = TenantAliasServiceClient::new(TenantAliasTransport::Tls {
            endpoint,
            server_name: "localhost".to_owned(),
            trust_file: certificate.into(),
        })?;
        let alias_request = TenantAliasBindRequest::new(
            "22222222-2222-2222-2222-222222222222".to_owned(),
            "loki.acme_42".to_owned(),
            1,
            "01010101-0101-0101-0101-010101010101".to_owned(),
        );
        assert_eq!(
            alias
                .bind("credential-material", &alias_request)
                .expect_err("idempotency replay"),
            TenantAliasServiceClientFailure::IdempotencyConflict
        );
        assert_eq!(
            alias
                .bind("credential-material", &alias_request)
                .expect_err("authentication failure"),
            TenantAliasServiceClientFailure::AuthenticationRejected
        );
        server
            .join()
            .map_err(|_| "TLS loopback server panicked")??;
        Ok(())
    }

    fn valid(command: &str) -> String {
        format!("{command} --endpoint 127.0.0.1:8080 --credential-stdin")
    }
}
