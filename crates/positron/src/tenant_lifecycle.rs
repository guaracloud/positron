use std::io::{IsTerminal, Read};
use std::net::SocketAddr;
use std::process::ExitCode;

use positron_api::tenant_lifecycle::{
    TenantLifecycleServiceClient, TenantLifecycleServiceClientFailure, TenantLifecycleState,
    TenantLifecycleTransitionRequest, TenantLifecycleTransport,
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
    let (transport, request) = parse(arguments)?;
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
    let client =
        TenantLifecycleServiceClient::new(transport).map_err(|_| "API endpoint unavailable")?;
    let response = client
        .transition(bearer, &request)
        .map_err(client_failure)?;
    println!(
        "tenant={} from={:?} to={:?} lifecycle_generation={} audit_position={} audit_ingest_time_unix_seconds={}",
        response.tenant,
        response.from,
        response.to,
        response.lifecycle_generation,
        response.audit_position,
        response.audit_ingest_time_unix_seconds
    );
    Ok(())
}

fn client_failure(failure: TenantLifecycleServiceClientFailure) -> &'static str {
    match failure {
        TenantLifecycleServiceClientFailure::InvalidRequest => {
            "invalid tenant lifecycle request; correct the request before retrying"
        },
        TenantLifecycleServiceClientFailure::AuthenticationRejected => "authentication rejected",
        TenantLifecycleServiceClientFailure::TenantUnavailable => "tenant unavailable",
        TenantLifecycleServiceClientFailure::StaleGeneration { .. } => {
            "stale lifecycle generation; inspect current state before retrying"
        },
        TenantLifecycleServiceClientFailure::IdempotencyConflict => {
            "idempotency conflict; inspect current state before retrying"
        },
        TenantLifecycleServiceClientFailure::InvalidTransition => {
            "invalid lifecycle transition; inspect current state before retrying"
        },
        TenantLifecycleServiceClientFailure::PurgeCompletionUnavailable => {
            "purge completion unavailable; retry only after cryptographic purge completion"
        },
        TenantLifecycleServiceClientFailure::AdministrationUnavailable => {
            "administration unavailable; retry with the same idempotency key"
        },
        TenantLifecycleServiceClientFailure::Transport => {
            "API transport unavailable; inspect state before retrying"
        },
    }
}

fn parse(
    mut arguments: impl Iterator<Item = String>,
) -> Result<(TenantLifecycleTransport, TenantLifecycleTransitionRequest), &'static str> {
    if arguments.next().as_deref() != Some("transition") {
        return Err(
            "usage: positron tenant lifecycle transition --endpoint IP:PORT --credential-stdin --tenant ID --target active|read-only|suspended|purging|purged --expected-generation N --idempotency-key UUID [--server-name NAME --trust-file PATH | --allow-plaintext]",
        );
    }
    let mut options = std::collections::BTreeMap::new();
    let mut credential_stdin = false;
    let mut allow_plaintext = false;
    while let Some(argument) = arguments.next() {
        if argument == "--credential-stdin" {
            if credential_stdin {
                return Err("duplicate lifecycle option");
            }
            credential_stdin = true;
            continue;
        }
        if argument == "--allow-plaintext" {
            if allow_plaintext {
                return Err("duplicate lifecycle option");
            }
            allow_plaintext = true;
            continue;
        }
        if !matches!(
            argument.as_str(),
            "--endpoint"
                | "--tenant"
                | "--target"
                | "--expected-generation"
                | "--idempotency-key"
                | "--server-name"
                | "--trust-file"
        ) {
            return Err("unknown lifecycle option");
        }
        let value = arguments.next().ok_or("missing lifecycle option value")?;
        if options.insert(argument, value).is_some() {
            return Err("duplicate lifecycle option");
        }
    }
    if !credential_stdin {
        return Err(
            "--credential-stdin is required; secrets are never accepted as arguments or environment variables",
        );
    }
    let endpoint: SocketAddr = options
        .remove("--endpoint")
        .ok_or("--endpoint is required")?
        .parse()
        .map_err(|_| "invalid API endpoint")?;
    if endpoint.port() == 0 {
        return Err("invalid API endpoint");
    }
    let transport = if allow_plaintext {
        if options.contains_key("--trust-file") || options.contains_key("--server-name") {
            return Err("TLS options do not apply to plaintext opt-out");
        }
        TenantLifecycleTransport::PlaintextOptOut { endpoint }
    } else {
        TenantLifecycleTransport::Tls {
            endpoint,
            server_name: options
                .remove("--server-name")
                .ok_or("--server-name is required for TLS")?,
            trust_file: options
                .remove("--trust-file")
                .ok_or("--trust-file is required unless --allow-plaintext is explicit")?
                .into(),
        }
    };
    let target = match options.remove("--target").as_deref() {
        Some("active") => TenantLifecycleState::Active,
        Some("read-only") => TenantLifecycleState::ReadOnly,
        Some("suspended") => TenantLifecycleState::Suspended,
        Some("purging") => TenantLifecycleState::Purging,
        Some("purged") => TenantLifecycleState::Purged,
        _ => return Err("target must be active, read-only, suspended, purging, or purged"),
    };
    let request = TenantLifecycleTransitionRequest::new(
        options.remove("--tenant").ok_or("--tenant is required")?,
        target,
        options
            .remove("--expected-generation")
            .ok_or("--expected-generation is required")?
            .parse()
            .map_err(|_| "invalid lifecycle generation")?,
        options
            .remove("--idempotency-key")
            .ok_or("--idempotency-key is required")?,
    );
    if !options.is_empty() {
        return Err("option does not apply to tenant lifecycle transition");
    }
    request
        .validate()
        .map_err(|_| "invalid tenant lifecycle request")?;
    Ok((transport, request))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_transition_defaults_to_tls_and_requires_explicit_plaintext_opt_out() {
        let tls = parse(
            valid_command("--server-name lifecycle.example --trust-file lifecycle-ca.pem")
                .split_whitespace()
                .map(ToOwned::to_owned),
        )
        .expect("TLS request parses");
        assert!(matches!(tls.0, TenantLifecycleTransport::Tls { .. }));
        let plaintext = parse(
            valid_command("--allow-plaintext")
                .split_whitespace()
                .map(ToOwned::to_owned),
        )
        .expect("explicit plaintext request parses");
        assert!(matches!(
            plaintext.0,
            TenantLifecycleTransport::PlaintextOptOut { .. }
        ));
    }

    #[test]
    fn lifecycle_transition_rejects_invalid_target_and_ambiguous_transport() {
        for command in [
            valid_command(""),
            valid_command("--allow-plaintext --target unavailable"),
            valid_command("--allow-plaintext --expected-generation 0"),
            valid_command("--allow-plaintext --server-name ignored"),
            valid_command("--allow-plaintext --unknown value"),
        ] {
            assert!(
                parse(command.split_whitespace().map(ToOwned::to_owned)).is_err(),
                "{command}"
            );
        }
    }

    #[test]
    fn lifecycle_transition_client_sends_the_canonical_request_and_decodes_success()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let endpoint = listener.local_addr()?;
        let command = valid_command("--allow-plaintext").replacen(
            "--endpoint 127.0.0.1:8080",
            &format!("--endpoint {endpoint}"),
            1,
        );
        let (transport, request) = parse(command.split_whitespace().map(ToOwned::to_owned))?;
        let server = thread::spawn(move || -> Result<(), std::io::Error> {
            let (mut stream, _) = listener.accept()?;
            let mut bytes = [0_u8; 4096];
            let read = stream.read(&mut bytes)?;
            let request = String::from_utf8_lossy(&bytes[..read]);
            assert!(request.starts_with("POST /v1/tenant-lifecycle:transition HTTP/1.1\r\n"));
            assert!(request.contains("\"tenant\":\"22222222-2222-2222-2222-222222222222\""));
            assert!(request.contains("\"target\":\"read_only\""));
            let body = r#"{"tenant":"22222222-2222-2222-2222-222222222222","from":"active","to":"read_only","lifecycle_generation":2,"audit_position":7,"audit_ingest_time_unix_seconds":9}"#;
            stream.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )?;
            Ok(())
        });
        let client = TenantLifecycleServiceClient::new(transport)?;
        let response = client.transition("key-material", &request)?;
        assert_eq!(response.to, TenantLifecycleState::ReadOnly);
        assert_eq!(response.lifecycle_generation, 2);
        server.join().map_err(|_| "server panicked")??;
        Ok(())
    }

    fn valid_command(transport: &str) -> String {
        format!(
            "transition --endpoint 127.0.0.1:8080 --credential-stdin --tenant 22222222-2222-2222-2222-222222222222 --target read-only --expected-generation 1 --idempotency-key 01010101-0101-0101-0101-010101010101 {transport}"
        )
    }
}
