use std::io::{IsTerminal, Read, Write};
use std::net::SocketAddr;
use std::process::ExitCode;

use positron_api::api_keys::{ApiKeyRequest, ApiKeyServiceClient, KeyAction, KeyScope};
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
    let (endpoint, request) = parse(arguments)?;
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
    let client = ApiKeyServiceClient::new(endpoint).map_err(|_| "API endpoint unavailable")?;
    let mut response = client
        .manage(bearer, &request)
        .map_err(|_| "API-key request rejected; inspect state before retrying")?;
    let mut output = std::io::stdout().lock();
    for key in std::mem::take(&mut response.keys) {
        writeln!(
            output,
            "{} {:?} active={} generation={} expiry={}",
            key.principal,
            key.scope(),
            key.active,
            key.generation,
            key.expires_at_unix_seconds
                .map_or_else(|| "none".to_owned(), |value| value.to_string())
        )
        .map_err(|_| "output unavailable")?;
    }
    if let Some(principal) = response.principal.take() {
        writeln!(output, "principal={principal}").map_err(|_| "output unavailable")?;
        if let Some(secret) = response.secret.take() {
            let secret = Zeroizing::new(secret);
            writeln!(output, "secret={}", secret.as_str()).map_err(|_| "output unavailable")?;
        } else {
            writeln!(output, "completed; secret unavailable (never redisplayed)")
                .map_err(|_| "output unavailable")?;
        }
    }
    Ok(())
}

fn parse(
    mut arguments: impl Iterator<Item = String>,
) -> Result<(SocketAddr, ApiKeyRequest), &'static str> {
    let action = match arguments.next().as_deref() {
        Some("create") => KeyAction::Create,
        Some("list") => KeyAction::List,
        Some("rotate") => KeyAction::Rotate,
        Some("revoke") => KeyAction::Revoke,
        Some("scope-inspect") => KeyAction::ScopeInspect,
        _ => {
            return Err(
                "usage: positron key create|list|rotate|revoke|scope-inspect --endpoint IP:PORT --credential-stdin [--scope SCOPE] [--principal ID] [--expected-generation N --idempotency-key ID] [--expires-at N]",
            );
        },
    };
    let mut options = std::collections::BTreeMap::new();
    let mut credential_stdin = false;
    while let Some(argument) = arguments.next() {
        if argument == "--credential-stdin" && !credential_stdin {
            credential_stdin = true;
            continue;
        }
        if !matches!(
            argument.as_str(),
            "--endpoint"
                | "--scope"
                | "--principal"
                | "--expected-generation"
                | "--idempotency-key"
                | "--expires-at"
        ) {
            return Err("unknown key option");
        }
        let value = arguments.next().ok_or("missing key option value")?;
        if options.insert(argument, value).is_some() {
            return Err("duplicate key option");
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
    if !endpoint.ip().is_loopback() || endpoint.port() == 0 {
        return Err("the native API endpoint must be a loopback address");
    }
    let request = match action {
        KeyAction::Unspecified => return Err("invalid key command"),
        KeyAction::List => ApiKeyRequest::list(),
        KeyAction::ScopeInspect => ApiKeyRequest::inspect(
            options
                .remove("--principal")
                .ok_or("--principal is required")?,
        ),
        KeyAction::Create | KeyAction::Rotate | KeyAction::Revoke => {
            let expected = options
                .remove("--expected-generation")
                .ok_or("--expected-generation is required")?
                .parse()
                .map_err(|_| "invalid generation")?;
            let idempotency = options
                .remove("--idempotency-key")
                .ok_or("--idempotency-key is required")?;
            if action == KeyAction::Create {
                let scope = match options.remove("--scope").as_deref() {
                    Some("ingest") => KeyScope::Ingest,
                    Some("query") => KeyScope::Query,
                    Some("tenant-administration") => KeyScope::TenantAdministration,
                    _ => return Err("scope must be ingest, query, or tenant-administration"),
                };
                let expiry = options
                    .remove("--expires-at")
                    .map(|value| value.parse())
                    .transpose()
                    .map_err(|_| "invalid expiry")?;
                ApiKeyRequest::create(scope, expiry, expected, idempotency)
            } else {
                ApiKeyRequest::mutation(
                    action,
                    options
                        .remove("--principal")
                        .ok_or("--principal is required")?,
                    expected,
                    idempotency,
                )
                .map_err(|_| "invalid mutation")?
            }
        },
    };
    if !options.is_empty() {
        return Err("option does not apply to this key command");
    }
    request.encode().map_err(|_| "invalid key request")?;
    Ok((endpoint, request))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn key_arguments_reject_secret_options_and_unrelated_mutation_flags() {
        for command in [
            "list --endpoint 127.0.0.1:8080 --credential-stdin --secret sensitive",
            "list --endpoint 127.0.0.1:8080 --credential-stdin --scope query",
            "list --endpoint 192.0.2.1:8080 --credential-stdin",
            "list --endpoint 127.0.0.1:8080",
        ] {
            assert!(parse(command.split_whitespace().map(ToOwned::to_owned)).is_err());
        }
        assert!(
            parse(
                "list --endpoint 127.0.0.1:8080 --credential-stdin"
                    .split_whitespace()
                    .map(ToOwned::to_owned)
            )
            .is_ok()
        );
    }
}
