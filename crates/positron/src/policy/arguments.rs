use std::io::Read;
use std::net::SocketAddr;

use positron_api::policy::{
    MAX_ACTIVATE_REQUEST_BYTES, MAX_DIFF_REQUEST_BYTES, MAX_EXPLAIN_REQUEST_BYTES,
    MAX_REQUEST_BYTES, MAX_TEST_REQUEST_BYTES, PolicyActivateRequest, PolicyDiffRequest,
    PolicyExplainRequest, PolicyPreviewRequest, PolicyPreviewTransport, PolicyTestRequest,
};

pub(super) enum PolicyCommand {
    Validate(PolicyPreviewRequest),
    Test(PolicyTestRequest),
    Diff(PolicyDiffRequest),
    Explain(PolicyExplainRequest),
    Activate(PolicyActivateRequest),
}
pub(super) fn parse(
    mut arguments: impl Iterator<Item = String>,
) -> Result<(PolicyPreviewTransport, PolicyCommand), &'static str> {
    let command = arguments.next().ok_or(policy_usage())?;
    if !matches!(
        command.as_str(),
        "validate" | "test" | "diff" | "explain" | "activate"
    ) {
        return Err(policy_usage());
    }
    let mut options = std::collections::BTreeMap::new();
    let mut credential_stdin = false;
    let mut allow_plaintext = false;
    while let Some(argument) = arguments.next() {
        if argument == "--credential-stdin" {
            if credential_stdin {
                return Err("duplicate policy option");
            }
            credential_stdin = true;
            continue;
        }
        if argument == "--allow-plaintext" {
            if allow_plaintext {
                return Err("duplicate policy option");
            }
            allow_plaintext = true;
            continue;
        }
        if !matches!(
            argument.as_str(),
            "--endpoint"
                | "--policy-file"
                | "--candidate-file"
                | "--before-policy-file"
                | "--after-policy-file"
                | "--expected-generation"
                | "--idempotency-key"
                | "--server-name"
                | "--trust-file"
        ) {
            return Err("unknown policy option");
        }
        let value = arguments.next().ok_or("missing policy option value")?;
        if options.insert(argument, value).is_some() {
            return Err("duplicate policy option");
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
        PolicyPreviewTransport::PlaintextOptOut { endpoint }
    } else {
        PolicyPreviewTransport::Tls {
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
    let request = match command.as_str() {
        "validate" => {
            let request = PolicyPreviewRequest::new(read_file(
                &mut options,
                "--policy-file",
                MAX_REQUEST_BYTES,
                "policy file unavailable",
            )?);
            request.validate().map_err(|_| "invalid policy candidate")?;
            PolicyCommand::Validate(request)
        },
        "test" => {
            let request = PolicyTestRequest::new(
                read_file(
                    &mut options,
                    "--policy-file",
                    MAX_TEST_REQUEST_BYTES,
                    "policy file unavailable",
                )?,
                read_file(
                    &mut options,
                    "--candidate-file",
                    MAX_TEST_REQUEST_BYTES,
                    "candidate file unavailable",
                )?,
            );
            request
                .validate()
                .map_err(|_| "invalid policy or candidate input")?;
            PolicyCommand::Test(request)
        },
        "diff" => {
            let request = PolicyDiffRequest::new(
                read_file(
                    &mut options,
                    "--before-policy-file",
                    MAX_DIFF_REQUEST_BYTES,
                    "before policy file unavailable",
                )?,
                read_file(
                    &mut options,
                    "--after-policy-file",
                    MAX_DIFF_REQUEST_BYTES,
                    "after policy file unavailable",
                )?,
            );
            request.validate().map_err(|_| "invalid policy input")?;
            PolicyCommand::Diff(request)
        },
        "explain" => {
            let request = PolicyExplainRequest::new(
                read_file(
                    &mut options,
                    "--policy-file",
                    MAX_EXPLAIN_REQUEST_BYTES,
                    "policy file unavailable",
                )?,
                read_file(
                    &mut options,
                    "--candidate-file",
                    MAX_EXPLAIN_REQUEST_BYTES,
                    "candidate file unavailable",
                )?,
            );
            request
                .validate()
                .map_err(|_| "invalid policy or candidate input")?;
            PolicyCommand::Explain(request)
        },
        "activate" => {
            let request = PolicyActivateRequest::new(
                read_file(
                    &mut options,
                    "--policy-file",
                    MAX_ACTIVATE_REQUEST_BYTES,
                    "policy file unavailable",
                )?,
                options
                    .remove("--expected-generation")
                    .ok_or("--expected-generation is required")?
                    .parse()
                    .map_err(|_| "invalid policy generation")?,
                options
                    .remove("--idempotency-key")
                    .ok_or("--idempotency-key is required")?,
            );
            request
                .validate()
                .map_err(|_| "invalid policy activation request")?;
            PolicyCommand::Activate(request)
        },
        _ => return Err(policy_usage()),
    };
    if !options.is_empty() {
        return Err("option does not apply to policy command");
    }
    Ok((transport, request))
}

fn policy_usage() -> &'static str {
    "usage: positron policy validate --endpoint IP:PORT --credential-stdin --policy-file PATH [--server-name NAME --trust-file PATH | --allow-plaintext]\n       positron policy test --endpoint IP:PORT --credential-stdin --policy-file PATH --candidate-file PATH [--server-name NAME --trust-file PATH | --allow-plaintext]\n       positron policy diff --endpoint IP:PORT --credential-stdin --before-policy-file PATH --after-policy-file PATH [--server-name NAME --trust-file PATH | --allow-plaintext]\n       positron policy explain --endpoint IP:PORT --credential-stdin --policy-file PATH --candidate-file PATH [--server-name NAME --trust-file PATH | --allow-plaintext]\n       positron policy activate --endpoint IP:PORT --credential-stdin --policy-file PATH --expected-generation N --idempotency-key UUID [--server-name NAME --trust-file PATH | --allow-plaintext]"
}

fn read_file(
    options: &mut std::collections::BTreeMap<String, String>,
    flag: &str,
    maximum_bytes: usize,
    unavailable: &'static str,
) -> Result<String, &'static str> {
    let path = options.remove(flag).ok_or(match flag {
        "--candidate-file" => "--candidate-file is required",
        "--before-policy-file" => "--before-policy-file is required",
        "--after-policy-file" => "--after-policy-file is required",
        _ => "--policy-file is required",
    })?;
    let limit = maximum_bytes.checked_add(1).ok_or(unavailable)?;
    let mut contents = String::new();
    std::fs::File::open(path)
        .map_err(|_| unavailable)?
        .take(u64::try_from(limit).map_err(|_| unavailable)?)
        .read_to_string(&mut contents)
        .map_err(|_| unavailable)?;
    if contents.len() == limit {
        return Err("policy or candidate file exceeds its public bound");
    }
    Ok(contents)
}
