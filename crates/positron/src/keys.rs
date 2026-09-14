use std::io::{IsTerminal, Read, Write};
use std::net::SocketAddr;
use std::process::ExitCode;

use positron_api::api_keys::{
    ApiKeyRequest, ApiKeyServiceClient, ApiKeyServiceClientFailure, ApiKeyTransport, KeyAction,
    KeyScope,
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
    let client = ApiKeyServiceClient::new(transport).map_err(|_| "API endpoint unavailable")?;
    let mut response = client.manage(bearer, &request).map_err(client_failure)?;
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

fn client_failure(failure: ApiKeyServiceClientFailure) -> &'static str {
    match failure {
        ApiKeyServiceClientFailure::InvalidRequest => {
            "invalid key request; correct the request before retrying"
        },
        ApiKeyServiceClientFailure::AuthenticationRejected => "authentication rejected",
        ApiKeyServiceClientFailure::StaleGeneration => {
            "stale generation; inspect current state before retrying"
        },
        ApiKeyServiceClientFailure::IdempotencyConflict => {
            "idempotency conflict; inspect current state before retrying"
        },
        ApiKeyServiceClientFailure::KeyUnavailable => "key unavailable; inspect current state",
        ApiKeyServiceClientFailure::AdministrationUnavailable => {
            "administration unavailable; retry with the same idempotency key"
        },
        ApiKeyServiceClientFailure::Transport => {
            "API transport unavailable; inspect state before retrying"
        },
    }
}

fn parse(
    mut arguments: impl Iterator<Item = String>,
) -> Result<(ApiKeyTransport, ApiKeyRequest), &'static str> {
    let action = match arguments.next().as_deref() {
        Some("create") => KeyAction::Create,
        Some("list") => KeyAction::List,
        Some("rotate") => KeyAction::Rotate,
        Some("revoke") => KeyAction::Revoke,
        Some("scope-inspect") => KeyAction::ScopeInspect,
        _ => {
            return Err(
                "usage: positron key create|list|rotate|revoke|scope-inspect --endpoint IP:PORT --credential-stdin [--scope SCOPE] [--target-tenant ID] [--principal ID] [--expected-generation N --idempotency-key ID] [--expires-at N]",
            );
        },
    };
    let mut options = std::collections::BTreeMap::new();
    let mut credential_stdin = false;
    let mut allow_plaintext = false;
    while let Some(argument) = arguments.next() {
        if argument == "--credential-stdin" && !credential_stdin {
            credential_stdin = true;
            continue;
        }
        if argument == "--allow-plaintext" && !allow_plaintext {
            allow_plaintext = true;
            continue;
        }
        if !matches!(
            argument.as_str(),
            "--endpoint"
                | "--scope"
                | "--target-tenant"
                | "--principal"
                | "--expected-generation"
                | "--idempotency-key"
                | "--expires-at"
                | "--trust-file"
                | "--server-name"
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
    if endpoint.port() == 0 {
        return Err("invalid API endpoint");
    }
    let transport = if allow_plaintext {
        if options.contains_key("--trust-file") {
            return Err("--trust-file does not apply to plaintext opt-out");
        }
        ApiKeyTransport::PlaintextOptOut { endpoint }
    } else {
        ApiKeyTransport::Tls {
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
    let target_tenant = options.remove("--target-tenant");
    let request = match action {
        KeyAction::Unspecified => return Err("invalid key command"),
        KeyAction::List => match target_tenant {
            Some(tenant) => ApiKeyRequest::list_for_tenant(tenant),
            None => ApiKeyRequest::list(),
        },
        KeyAction::ScopeInspect => {
            let principal = options
                .remove("--principal")
                .ok_or("--principal is required")?;
            match target_tenant {
                Some(tenant) => ApiKeyRequest::inspect_for_tenant(principal, tenant),
                None => ApiKeyRequest::inspect(principal),
            }
        },
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
                if let Some(target_tenant) = target_tenant {
                    ApiKeyRequest::create_for_tenant(
                        scope,
                        target_tenant,
                        expiry,
                        expected,
                        idempotency,
                    )
                } else {
                    ApiKeyRequest::create(scope, expiry, expected, idempotency)
                }
            } else {
                let principal = options
                    .remove("--principal")
                    .ok_or("--principal is required")?;
                match target_tenant {
                    Some(tenant) => ApiKeyRequest::mutation_for_tenant(
                        action,
                        principal,
                        tenant,
                        expected,
                        idempotency,
                    ),
                    None => ApiKeyRequest::mutation(action, principal, expected, idempotency),
                }
                .map_err(|_| "invalid mutation")?
            }
        },
    };
    if !options.is_empty() {
        return Err("option does not apply to this key command");
    }
    request.encode().map_err(|_| "invalid key request")?;
    Ok((transport, request))
}

#[cfg(test)]
mod tests {
    use super::*;
    use positron_api::api_keys::ApiKeyServiceClientFailure;

    #[test]
    fn typed_api_failures_preserve_safe_retry_guidance() {
        assert_eq!(
            client_failure(ApiKeyServiceClientFailure::IdempotencyConflict),
            "idempotency conflict; inspect current state before retrying"
        );
        assert_eq!(
            client_failure(ApiKeyServiceClientFailure::AuthenticationRejected),
            "authentication rejected"
        );
        assert_eq!(
            client_failure(ApiKeyServiceClientFailure::InvalidRequest),
            "invalid key request; correct the request before retrying"
        );
    }
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
                "list --endpoint 127.0.0.1:8080 --credential-stdin --allow-plaintext"
                    .split_whitespace()
                    .map(ToOwned::to_owned)
            )
            .is_ok()
        );
        assert!(
            parse(
                "list --endpoint 192.0.2.1:8080 --credential-stdin --allow-plaintext"
                    .split_whitespace()
                    .map(ToOwned::to_owned)
            )
            .is_ok()
        );
        assert!(
            parse(
                "list --endpoint 127.0.0.1:8080 --credential-stdin --trust-file ca.pem"
                    .split_whitespace()
                    .map(ToOwned::to_owned)
            )
            .is_err()
        );
    }

    #[test]
    fn key_create_parses_an_explicit_administrative_target_tenant() {
        let (_, request) = parse(
            "create --endpoint 127.0.0.1:8080 --credential-stdin --allow-plaintext --scope query --target-tenant 22222222-2222-2222-2222-222222222222 --expected-generation 1 --idempotency-key 01010101-0101-0101-0101-010101010101"
                .split_whitespace()
                .map(ToOwned::to_owned),
        )
        .expect("target tenant create parses");

        assert_eq!(
            request.target_tenant(),
            Some("22222222-2222-2222-2222-222222222222")
        );
    }

    #[test]
    fn key_lifecycle_parses_an_explicit_administrative_target_tenant() {
        let (_, list) = parse(
            "list --endpoint 127.0.0.1:8080 --credential-stdin --allow-plaintext --target-tenant 22222222-2222-2222-2222-222222222222"
                .split_whitespace()
                .map(ToOwned::to_owned),
        )
        .expect("target tenant list parses");
        assert_eq!(
            list.target_tenant(),
            Some("22222222-2222-2222-2222-222222222222")
        );
        let (_, rotate) = parse(
            "rotate --endpoint 127.0.0.1:8080 --credential-stdin --allow-plaintext --target-tenant 22222222-2222-2222-2222-222222222222 --principal 33333333-3333-3333-3333-333333333333 --expected-generation 2 --idempotency-key 01010101-0101-0101-0101-010101010101"
                .split_whitespace()
                .map(ToOwned::to_owned),
        )
        .expect("target tenant rotation parses");
        assert_eq!(
            rotate.target_tenant(),
            Some("22222222-2222-2222-2222-222222222222")
        );
    }
}
