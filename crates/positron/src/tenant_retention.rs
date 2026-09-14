use std::collections::BTreeMap;
use std::io::{IsTerminal, Read};
use std::net::SocketAddr;
use std::process::ExitCode;

use positron_api::tenant_retention::{
    TenantRetentionPreviewRequest, TenantRetentionServiceClient,
    TenantRetentionServiceClientFailure, TenantRetentionTransport, TenantRetentionUpdateRequest,
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
        TenantRetentionServiceClient::new(transport).map_err(|_| "API endpoint unavailable")?;
    match request {
        Request::Preview(mut request) => {
            let mut complete = None;
            let mut scopes = 0_usize;
            loop {
                let preview = client.preview(bearer, &request).map_err(client_failure)?;
                let current = (
                    preview.tenant.clone(),
                    preview.retention_generation,
                    preview.proposed_retention_seconds,
                    preview.catalog_identity.clone(),
                    preview.catalog_generation,
                    preview.confirmation_digest.clone(),
                    preview.confirmation_evaluated_at_unix_nanos,
                );
                if let Some(expected) = &complete {
                    if expected != &current {
                        return Err("retention preview changed; request a new complete preview");
                    }
                } else {
                    complete = Some(current);
                }
                scopes = scopes
                    .checked_add(preview.scopes.len())
                    .ok_or("retention preview has too many scopes")?;
                match preview.continuation {
                    Some(continuation) => {
                        request = TenantRetentionPreviewRequest::new(
                            request.tenant().to_owned(),
                            request.proposed_retention_seconds(),
                        )
                        .with_continuation(continuation);
                    },
                    None => break,
                }
            }
            let (tenant, generation, proposed, identity, catalog_generation, digest, evaluation) =
                complete.ok_or("retention preview response was empty")?;
            println!(
                "tenant={tenant} retention_generation={generation} proposed_retention_seconds={proposed} catalog_identity={identity} catalog_generation={catalog_generation} confirmation_digest={digest} confirmation_evaluated_at_unix_nanos={evaluation} scopes={scopes}"
            );
        },
        Request::Update(request) => {
            let update = client.update(bearer, &request).map_err(client_failure)?;
            println!(
                "tenant={} retention_generation={} audit_position={} audit_ingest_time_unix_seconds={}",
                update.tenant,
                update.retention_generation,
                update.audit_position,
                update.audit_ingest_time_unix_seconds
            );
        },
    }
    Ok(())
}

fn client_failure(failure: TenantRetentionServiceClientFailure) -> &'static str {
    match failure {
        TenantRetentionServiceClientFailure::InvalidRequest => {
            "invalid tenant retention request; correct the request before retrying"
        },
        TenantRetentionServiceClientFailure::AuthenticationRejected => "authentication rejected",
        TenantRetentionServiceClientFailure::TenantUnavailable => "tenant unavailable",
        TenantRetentionServiceClientFailure::InvalidConfirmation => {
            "retention confirmation is invalid; request a current preview before retrying"
        },
        TenantRetentionServiceClientFailure::StaleContinuation => {
            "stale retention preview; request a current preview before retrying"
        },
        TenantRetentionServiceClientFailure::StaleGeneration { .. } => {
            "stale retention generation; request a current preview before retrying"
        },
        TenantRetentionServiceClientFailure::IdempotencyConflict => {
            "idempotency conflict; inspect current state before retrying"
        },
        TenantRetentionServiceClientFailure::AdministrationUnavailable => {
            "administration unavailable; retry with the same idempotency key"
        },
        TenantRetentionServiceClientFailure::Transport => {
            "API transport unavailable; inspect state before retrying"
        },
    }
}

enum Request {
    Preview(TenantRetentionPreviewRequest),
    Update(TenantRetentionUpdateRequest),
}

fn parse(
    mut arguments: impl Iterator<Item = String>,
) -> Result<(TenantRetentionTransport, Request), &'static str> {
    let operation = arguments.next().ok_or(usage())?;
    if !matches!(operation.as_str(), "preview" | "update") {
        return Err(usage());
    }
    let mut options = BTreeMap::new();
    let mut credential_stdin = false;
    let mut allow_plaintext = false;
    while let Some(argument) = arguments.next() {
        if argument == "--credential-stdin" {
            if credential_stdin {
                return Err("duplicate retention option");
            }
            credential_stdin = true;
            continue;
        }
        if argument == "--allow-plaintext" {
            if allow_plaintext {
                return Err("duplicate retention option");
            }
            allow_plaintext = true;
            continue;
        }
        if !matches!(
            argument.as_str(),
            "--endpoint"
                | "--tenant"
                | "--proposed-retention-seconds"
                | "--expected-generation"
                | "--confirmation-digest"
                | "--confirmation-evaluated-at-unix-nanos"
                | "--idempotency-key"
                | "--server-name"
                | "--trust-file"
                | "--continuation"
        ) {
            return Err("unknown retention option");
        }
        let value = arguments.next().ok_or("missing retention option value")?;
        if options.insert(argument, value).is_some() {
            return Err("duplicate retention option");
        }
    }
    if !credential_stdin {
        return Err(
            "--credential-stdin is required; secrets are never accepted as arguments or environment variables",
        );
    }
    let transport = transport(&mut options, allow_plaintext)?;
    let tenant = options.remove("--tenant").ok_or("--tenant is required")?;
    let proposed_retention_seconds = positive_u64(
        options.remove("--proposed-retention-seconds"),
        "--proposed-retention-seconds is required",
    )?;
    let request = match operation.as_str() {
        "preview" => {
            let request = TenantRetentionPreviewRequest::new(tenant, proposed_retention_seconds);
            Request::Preview(match options.remove("--continuation") {
                Some(continuation) => request.with_continuation(continuation),
                None => request,
            })
        },
        "update" => {
            let digest = options.remove("--confirmation-digest");
            let mut request = TenantRetentionUpdateRequest::new(
                tenant,
                proposed_retention_seconds,
                positive_u64(
                    options.remove("--expected-generation"),
                    "--expected-generation is required",
                )?,
                digest.clone(),
                options
                    .remove("--idempotency-key")
                    .ok_or("--idempotency-key is required")?,
            );
            if digest.is_some() {
                request = request.with_confirmation_evaluated_at_unix_nanos(positive_i64(
                    options.remove("--confirmation-evaluated-at-unix-nanos"),
                    "--confirmation-evaluated-at-unix-nanos is required with confirmation",
                )?);
            }
            Request::Update(request)
        },
        _ => return Err(usage()),
    };
    if !options.is_empty() {
        return Err("option does not apply to retention operation");
    }
    match &request {
        Request::Preview(request) => request
            .validate()
            .map_err(|_| "invalid retention preview request")?,
        Request::Update(request) => request
            .validate()
            .map_err(|_| "invalid retention update request")?,
    }
    Ok((transport, request))
}

fn transport(
    options: &mut BTreeMap<String, String>,
    allow_plaintext: bool,
) -> Result<TenantRetentionTransport, &'static str> {
    let endpoint: SocketAddr = options
        .remove("--endpoint")
        .ok_or("--endpoint is required")?
        .parse()
        .map_err(|_| "invalid API endpoint")?;
    if endpoint.port() == 0 {
        return Err("invalid API endpoint");
    }
    if allow_plaintext {
        if options.contains_key("--trust-file") || options.contains_key("--server-name") {
            return Err("TLS options do not apply to plaintext opt-out");
        }
        Ok(TenantRetentionTransport::PlaintextOptOut { endpoint })
    } else {
        Ok(TenantRetentionTransport::Tls {
            endpoint,
            server_name: options
                .remove("--server-name")
                .ok_or("--server-name is required for TLS")?,
            trust_file: options
                .remove("--trust-file")
                .ok_or("--trust-file is required unless --allow-plaintext is explicit")?
                .into(),
        })
    }
}

fn positive_u64(value: Option<String>, absent: &'static str) -> Result<u64, &'static str> {
    value
        .ok_or(absent)?
        .parse::<u64>()
        .map_err(|_| "invalid retention value")
        .and_then(|value| {
            (value != 0)
                .then_some(value)
                .ok_or("invalid retention value")
        })
}

fn positive_i64(value: Option<String>, absent: &'static str) -> Result<i64, &'static str> {
    value
        .ok_or(absent)?
        .parse::<i64>()
        .map_err(|_| "invalid retention evaluation time")
        .and_then(|value| {
            (value > 0)
                .then_some(value)
                .ok_or("invalid retention evaluation time")
        })
}

const fn usage() -> &'static str {
    "usage: positron tenant retention preview --endpoint IP:PORT --credential-stdin --tenant UUID --proposed-retention-seconds N [--continuation OPAQUE_TOKEN] [--server-name NAME --trust-file PATH | --allow-plaintext]\n       positron tenant retention update --endpoint IP:PORT --credential-stdin --tenant UUID --proposed-retention-seconds N --expected-generation N --idempotency-key UUID [--confirmation-digest HEX --confirmation-evaluated-at-unix-nanos N] [--server-name NAME --trust-file PATH | --allow-plaintext]"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retention_preview_and_update_default_to_tls_with_explicit_plaintext_opt_out() {
        let tls = parse(
            preview("--server-name retention.example --trust-file retention-ca.pem")
                .split_whitespace()
                .map(ToOwned::to_owned),
        )
        .expect("TLS preview parses");
        assert!(matches!(tls.0, TenantRetentionTransport::Tls { .. }));
        let plaintext = parse(
            update("--allow-plaintext")
                .split_whitespace()
                .map(ToOwned::to_owned),
        )
        .expect("plaintext update parses");
        assert!(matches!(
            plaintext.0,
            TenantRetentionTransport::PlaintextOptOut { .. }
        ));
    }

    #[test]
    fn retention_parser_rejects_invalid_confirmation_and_ambiguous_transport() {
        for command in [
            preview("--allow-plaintext --tenant invalid"),
            preview("--allow-plaintext --proposed-retention-seconds 0"),
            update("--allow-plaintext --expected-generation 0"),
            update("--allow-plaintext --confirmation-digest invalid"),
            update("--allow-plaintext --trust-file ignored.pem"),
            update("--allow-plaintext --unknown value"),
        ] {
            assert!(
                parse(command.split_whitespace().map(ToOwned::to_owned)).is_err(),
                "{command}"
            );
        }
    }

    fn preview(transport: &str) -> String {
        format!(
            "preview --endpoint 127.0.0.1:8080 --credential-stdin --tenant 22222222-2222-2222-2222-222222222222 --proposed-retention-seconds 86400 {transport}"
        )
    }

    fn update(transport: &str) -> String {
        format!(
            "update --endpoint 127.0.0.1:8080 --credential-stdin --tenant 22222222-2222-2222-2222-222222222222 --proposed-retention-seconds 86400 --expected-generation 1 --confirmation-digest abababababababababababababababababababababababababababababababab --confirmation-evaluated-at-unix-nanos 123 --idempotency-key 01010101-0101-0101-0101-010101010101 {transport}"
        )
    }
}
