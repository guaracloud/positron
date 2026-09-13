use std::io::{IsTerminal, Read};
use std::process::ExitCode;

use positron_api::policy::{
    PolicyActivateServiceClient, PolicyActivateServiceClientFailure, PolicyDiffServiceClient,
    PolicyDiffServiceClientFailure, PolicyExplainServiceClient, PolicyExplainServiceClientFailure,
    PolicyPreviewServiceClient, PolicyPreviewServiceClientFailure, PolicyTestServiceClient,
    PolicyTestServiceClientFailure,
};
use zeroize::Zeroizing;

mod arguments;
use arguments::{PolicyCommand, parse};

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
    let mut input = std::io::stdin();
    if input.is_terminal() {
        return Err("credential input must be a pipe; terminal input is refused to prevent echo");
    }
    execute_with_input(arguments, &mut input)
}

fn execute_with_input(
    arguments: impl Iterator<Item = String>,
    input: &mut impl Read,
) -> Result<(), &'static str> {
    let (transport, request) = parse(arguments)?;
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
    match request {
        PolicyCommand::Validate(request) => {
            let client = PolicyPreviewServiceClient::new(transport)
                .map_err(|_| "API endpoint unavailable")?;
            let response = client.validate(bearer, &request).map_err(preview_failure)?;
            println!(
                "policy_generation={} policy_digest={} rule_count={}",
                response.policy_generation, response.policy_digest, response.rule_count
            );
        },
        PolicyCommand::Test(request) => {
            let client =
                PolicyTestServiceClient::new(transport).map_err(|_| "API endpoint unavailable")?;
            let response = client.test(bearer, &request).map_err(test_failure)?;
            println!(
                "policy_generation={} policy_digest={} accepted={} applied_rule_count={}",
                response.policy_generation,
                response.policy_digest,
                response.accepted,
                response.applied_rule_count
            );
        },
        PolicyCommand::Diff(request) => {
            let client =
                PolicyDiffServiceClient::new(transport).map_err(|_| "API endpoint unavailable")?;
            let response = client.diff(bearer, &request).map_err(diff_failure)?;
            println!(
                "before_policy_generation={} before_policy_digest={} after_policy_generation={} after_policy_digest={} semantic_changes={}",
                response.before_policy_generation,
                response.before_policy_digest,
                response.after_policy_generation,
                response.after_policy_digest,
                response.semantic_changes.join(",")
            );
        },
        PolicyCommand::Explain(request) => {
            let client = PolicyExplainServiceClient::new(transport)
                .map_err(|_| "API endpoint unavailable")?;
            let response = client.explain(bearer, &request).map_err(explain_failure)?;
            println!(
                "policy_generation={} policy_digest={} outcome={} explanation={}",
                response.policy_generation,
                response.policy_digest,
                response.outcome,
                response.explanation
            );
        },
        PolicyCommand::Activate(request) => {
            let client = PolicyActivateServiceClient::new(transport)
                .map_err(|_| "API endpoint unavailable")?;
            let response = client
                .activate(bearer, &request)
                .map_err(activate_failure)?;
            println!(
                "resource_generation={} policy_digest={} audit_position={}",
                response.resource_generation, response.policy_digest, response.audit_position
            );
        },
    }
    Ok(())
}

fn preview_failure(failure: PolicyPreviewServiceClientFailure) -> &'static str {
    match failure {
        PolicyPreviewServiceClientFailure::InvalidRequest => {
            "invalid policy candidate; correct the request before retrying"
        },
        PolicyPreviewServiceClientFailure::AuthenticationRejected => "authentication rejected",
        PolicyPreviewServiceClientFailure::AdministrationUnavailable => {
            "policy validation unavailable; retry after the service recovers"
        },
        PolicyPreviewServiceClientFailure::Transport => {
            "API transport unavailable; inspect state before retrying"
        },
    }
}

fn test_failure(failure: PolicyTestServiceClientFailure) -> &'static str {
    match failure {
        PolicyTestServiceClientFailure::InvalidRequest => "invalid policy or candidate input",
        PolicyTestServiceClientFailure::AuthenticationRejected => "authentication rejected",
        PolicyTestServiceClientFailure::AdministrationUnavailable => {
            "policy test unavailable; retry after the service recovers"
        },
        PolicyTestServiceClientFailure::Transport => {
            "API transport unavailable; inspect state before retrying"
        },
    }
}

fn diff_failure(failure: PolicyDiffServiceClientFailure) -> &'static str {
    match failure {
        PolicyDiffServiceClientFailure::InvalidRequest => "invalid policy input",
        PolicyDiffServiceClientFailure::AuthenticationRejected => "authentication rejected",
        PolicyDiffServiceClientFailure::AdministrationUnavailable => {
            "policy diff unavailable; retry after the service recovers"
        },
        PolicyDiffServiceClientFailure::Transport => {
            "API transport unavailable; inspect state before retrying"
        },
    }
}

fn explain_failure(failure: PolicyExplainServiceClientFailure) -> &'static str {
    match failure {
        PolicyExplainServiceClientFailure::InvalidRequest => "invalid policy or candidate input",
        PolicyExplainServiceClientFailure::AuthenticationRejected => "authentication rejected",
        PolicyExplainServiceClientFailure::AdministrationUnavailable => {
            "policy explanation unavailable; retry after the service recovers"
        },
        PolicyExplainServiceClientFailure::Transport => {
            "API transport unavailable; inspect state before retrying"
        },
    }
}

fn activate_failure(failure: PolicyActivateServiceClientFailure) -> &'static str {
    match failure {
        PolicyActivateServiceClientFailure::InvalidRequest => "invalid policy activation request",
        PolicyActivateServiceClientFailure::AuthenticationRejected => "authentication rejected",
        PolicyActivateServiceClientFailure::StaleGeneration { .. } => {
            "stale policy generation; inspect current state before retrying"
        },
        PolicyActivateServiceClientFailure::IdempotencyConflict => {
            "idempotency conflict; inspect current state before retrying"
        },
        PolicyActivateServiceClientFailure::AdministrationUnavailable => {
            "policy activation unavailable; retry with the same idempotency key"
        },
        PolicyActivateServiceClientFailure::Transport => {
            "API transport unavailable; inspect state before retrying"
        },
    }
}

#[cfg(test)]
mod tests;
