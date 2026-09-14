use std::collections::BTreeMap;
use std::io::{IsTerminal, Read};
use std::net::SocketAddr;
use std::process::ExitCode;

use positron_api::tenant_aliases::{
    TenantAliasBindRequest, TenantAliasServiceClient, TenantAliasServiceClientFailure,
    TenantAliasTransport,
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
        TenantAliasServiceClient::new(transport).map_err(|_| "API endpoint unavailable")?;
    let response = client.bind(bearer, &request).map_err(client_failure)?;
    println!(
        "tenant={} alias_generation={} audit_position={} audit_ingest_time_unix_seconds={}",
        response.tenant,
        response.alias_generation,
        response.audit_position,
        response.audit_ingest_time_unix_seconds
    );
    Ok(())
}

fn client_failure(failure: TenantAliasServiceClientFailure) -> &'static str {
    match failure {
        TenantAliasServiceClientFailure::InvalidRequest => {
            "invalid tenant alias request; correct the request before retrying"
        },
        TenantAliasServiceClientFailure::AuthenticationRejected => "authentication rejected",
        TenantAliasServiceClientFailure::TenantUnavailable => "tenant unavailable",
        TenantAliasServiceClientFailure::StaleGeneration => {
            "stale alias generation; inspect current state before retrying"
        },
        TenantAliasServiceClientFailure::IdempotencyConflict => {
            "idempotency conflict; inspect current state before retrying"
        },
        TenantAliasServiceClientFailure::AliasAlreadyBound => {
            "alias already bound; inspect current state before retrying"
        },
        TenantAliasServiceClientFailure::AliasConflict => {
            "alias conflict; inspect current state before retrying"
        },
        TenantAliasServiceClientFailure::AdministrationUnavailable => {
            "administration unavailable; retry with the same idempotency key"
        },
        TenantAliasServiceClientFailure::Transport => {
            "API transport unavailable; inspect state before retrying"
        },
    }
}

fn parse(
    mut arguments: impl Iterator<Item = String>,
) -> Result<(TenantAliasTransport, TenantAliasBindRequest), &'static str> {
    if arguments.next().as_deref() != Some("bind") {
        return Err(USAGE);
    }
    let mut options = BTreeMap::new();
    let mut credential_stdin = false;
    let mut allow_plaintext = false;
    while let Some(option) = arguments.next() {
        if option == "--credential-stdin" {
            if credential_stdin {
                return Err("duplicate tenant alias option");
            }
            credential_stdin = true;
        } else if option == "--allow-plaintext" {
            if allow_plaintext {
                return Err("duplicate tenant alias option");
            }
            allow_plaintext = true;
        } else {
            if !matches!(
                option.as_str(),
                "--endpoint"
                    | "--server-name"
                    | "--trust-file"
                    | "--tenant"
                    | "--external-alias"
                    | "--expected-generation"
                    | "--idempotency-key"
            ) {
                return Err("unknown tenant alias option");
            }
            let value = arguments
                .next()
                .ok_or("missing tenant alias option value")?;
            if options.insert(option, value).is_some() {
                return Err("duplicate tenant alias option");
            }
        }
    }
    if !credential_stdin {
        return Err(
            "--credential-stdin is required; secrets are never accepted as arguments or environment variables",
        );
    }
    let endpoint: SocketAddr = take(&mut options, "--endpoint")?
        .parse()
        .map_err(|_| "invalid API endpoint")?;
    if endpoint.port() == 0 {
        return Err("invalid API endpoint");
    }
    let transport = if allow_plaintext {
        if options.contains_key("--server-name") || options.contains_key("--trust-file") {
            return Err("TLS options do not apply to plaintext opt-out");
        }
        TenantAliasTransport::PlaintextOptOut { endpoint }
    } else {
        TenantAliasTransport::Tls {
            endpoint,
            server_name: take(&mut options, "--server-name")?,
            trust_file: take(&mut options, "--trust-file")?.into(),
        }
    };
    let request = TenantAliasBindRequest::new(
        take(&mut options, "--tenant")?,
        take(&mut options, "--external-alias")?,
        take(&mut options, "--expected-generation")?
            .parse()
            .map_err(|_| "invalid alias generation")?,
        take(&mut options, "--idempotency-key")?,
    );
    if !options.is_empty() {
        return Err("option does not apply to tenant alias bind");
    }
    request
        .validate()
        .map_err(|_| "invalid tenant alias request")?;
    Ok((transport, request))
}

fn take(options: &mut BTreeMap<String, String>, name: &str) -> Result<String, &'static str> {
    options
        .remove(name)
        .ok_or("required tenant alias option absent")
}

const USAGE: &str = "usage: positron tenant alias bind --endpoint IP:PORT --credential-stdin --tenant ID --external-alias ALIAS --expected-generation N --idempotency-key UUID [--server-name NAME --trust-file PATH | --allow-plaintext]";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alias_bind_defaults_to_tls_and_requires_explicit_plaintext() {
        let tls = parse(
            valid("--server-name alias.example --trust-file ca.pem")
                .split_whitespace()
                .map(ToOwned::to_owned),
        )
        .expect("TLS parse");
        assert!(matches!(tls.0, TenantAliasTransport::Tls { .. }));
        let plaintext = parse(
            valid("--allow-plaintext")
                .split_whitespace()
                .map(ToOwned::to_owned),
        )
        .expect("plaintext parse");
        assert!(matches!(
            plaintext.0,
            TenantAliasTransport::PlaintextOptOut { .. }
        ));
    }

    #[test]
    fn alias_bind_rejects_secret_arguments_and_ambiguous_transport() {
        for suffix in [
            "--credential secret",
            "--allow-plaintext --server-name ignored",
            "--external-alias invalid alias",
        ] {
            assert!(
                parse(
                    valid(&format!("--allow-plaintext {suffix}"))
                        .split_whitespace()
                        .map(ToOwned::to_owned)
                )
                .is_err()
            );
        }
    }

    fn valid(suffix: &str) -> String {
        format!(
            "bind --endpoint 127.0.0.1:8080 --credential-stdin --tenant 22222222-2222-2222-2222-222222222222 --external-alias loki.acme_42 --expected-generation 1 --idempotency-key 01010101-0101-0101-0101-010101010101 {suffix}"
        )
    }
}
