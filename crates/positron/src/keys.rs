use std::io::{IsTerminal, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::ExitCode;
use std::time::Duration;

use positron_api::api_keys::{
    ApiKeyRequest, ApiKeyResponse, HTTP_PATH, KeyAction, KeyScope, MAX_RESPONSE_BYTES,
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
    let mut response = send(endpoint, bearer, &request)?;
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

fn send(
    endpoint: SocketAddr,
    bearer: &str,
    request: &ApiKeyRequest,
) -> Result<ApiKeyResponse, &'static str> {
    let body = request.encode().map_err(|_| "invalid key request")?;
    let mut stream = TcpStream::connect_timeout(&endpoint, Duration::from_secs(5))
        .map_err(|_| "API endpoint unavailable")?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| "API transport unavailable")?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| "API transport unavailable")?;
    let header = Zeroizing::new(format!(
        "POST {HTTP_PATH} HTTP/1.1\r\nHost: {endpoint}\r\nAuthorization: Bearer {bearer}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    ));
    stream
        .write_all(header.as_bytes())
        .and_then(|()| stream.write_all(&body))
        .map_err(|_| "API request transmission failed; inspect state before retrying")?;
    let mut bytes = Zeroizing::new(Vec::new());
    stream
        .take((MAX_RESPONSE_BYTES + 8193) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "API response unavailable; retry with the same idempotency key")?;
    if bytes.len() > MAX_RESPONSE_BYTES + 8192 {
        return Err("API response too large");
    }
    let split = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or("invalid API response")?;
    let head = std::str::from_utf8(bytes.get(..split).ok_or("invalid API response")?)
        .map_err(|_| "invalid API response")?;
    if !head.starts_with("HTTP/1.1 200 ") {
        return Err(if head.starts_with("HTTP/1.1 401 ") {
            "authentication rejected"
        } else if head.starts_with("HTTP/1.1 409 ") {
            "generation or idempotency conflict; inspect current state"
        } else {
            "API-key request rejected"
        });
    }
    ApiKeyResponse::decode(bytes.get(split + 4..).ok_or("invalid API response")?)
        .map_err(|_| "invalid API response")
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
