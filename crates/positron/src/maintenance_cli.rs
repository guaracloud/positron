use std::collections::BTreeMap;
use std::io::{IsTerminal, Read};
use std::net::SocketAddr;
use std::process::ExitCode;

use positron_api::maintenance::{
    MaintenanceControlResponse, MaintenanceExplainRequest, MaintenancePauseRequest,
    MaintenanceResumeRequest, MaintenanceRunRequest, MaintenanceServiceClient,
    MaintenanceServiceClientFailure, MaintenanceStatusRequest, MaintenanceTaskStatus,
    MaintenanceTransport,
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
        MaintenanceServiceClient::new(transport).map_err(|_| "API endpoint unavailable")?;
    match command {
        Command::Status => {
            let status = client
                .status(bearer, &MaintenanceStatusRequest {})
                .map_err(client_failure)?;
            println!(
                "queued={} running={} deferred={} terminal={} tasks={}",
                status.queued,
                status.running,
                status.deferred,
                status.terminal,
                status.tasks.len()
            );
            for task in &status.tasks {
                print_task(task);
            }
        },
        Command::Explain(request) => {
            let response = client.explain(bearer, &request).map_err(client_failure)?;
            print_task(&response.task);
        },
        Command::Run(request) => {
            let response = client.run(bearer, &request).map_err(client_failure)?;
            print_task(&response.task);
        },
        Command::Pause(request) => {
            let response = client.pause(bearer, &request).map_err(client_failure)?;
            print_control(&response);
        },
        Command::Resume(request) => {
            let response = client.resume(bearer, &request).map_err(client_failure)?;
            print_control(&response);
        },
    }
    Ok(())
}

fn print_control(response: &MaintenanceControlResponse) {
    print_task(&response.task);
    println!("audit_position={}", response.audit_position);
}

fn print_task(task: &MaintenanceTaskStatus) {
    println!(
        "identity={} class={} scope={} phase={} submitted_at_unix_seconds={} checkpoint_sequence={} pause_until_unix_seconds={} cancellation_requested={}",
        task.identity,
        task.class,
        task.scope,
        task.phase,
        task.submitted_at_unix_seconds,
        task.checkpoint_sequence
            .map_or_else(|| "none".to_owned(), |value| value.to_string()),
        task.pause_until_unix_seconds
            .map_or_else(|| "none".to_owned(), |value| value.to_string()),
        task.cancellation_requested,
    );
}

fn client_failure(failure: MaintenanceServiceClientFailure) -> &'static str {
    match failure {
        MaintenanceServiceClientFailure::InvalidRequest => "invalid maintenance request",
        MaintenanceServiceClientFailure::AuthenticationRejected => "authentication rejected",
        MaintenanceServiceClientFailure::SourceUnavailable => {
            "maintenance source unavailable; inspect current state before retrying"
        },
        MaintenanceServiceClientFailure::TaskUnavailable => {
            "maintenance task unavailable; inspect current state before retrying"
        },
        MaintenanceServiceClientFailure::PreconditionFailed => {
            "maintenance precondition failed; inspect current state before retrying"
        },
        MaintenanceServiceClientFailure::IdempotencyConflict => {
            "maintenance idempotency conflict; inspect current state before retrying"
        },
        MaintenanceServiceClientFailure::AdministrationUnavailable => {
            "maintenance administration unavailable; retry with the same idempotency key"
        },
        MaintenanceServiceClientFailure::Transport => "maintenance API transport failed",
    }
}

enum Command {
    Status,
    Explain(MaintenanceExplainRequest),
    Run(MaintenanceRunRequest),
    Pause(MaintenancePauseRequest),
    Resume(MaintenanceResumeRequest),
}

fn parse(
    mut arguments: impl Iterator<Item = String>,
) -> Result<(MaintenanceTransport, Command), &'static str> {
    let operation = arguments.next().ok_or(USAGE)?;
    if !matches!(
        operation.as_str(),
        "status" | "explain" | "run" | "pause" | "resume"
    ) {
        return Err(USAGE);
    }
    let mut options = BTreeMap::new();
    let mut credential_stdin = false;
    let mut allow_plaintext = false;
    while let Some(option) = arguments.next() {
        if option == "--credential-stdin" {
            if credential_stdin {
                return Err("duplicate maintenance option");
            }
            credential_stdin = true;
            continue;
        }
        if option == "--allow-plaintext" {
            if allow_plaintext {
                return Err("duplicate maintenance option");
            }
            allow_plaintext = true;
            continue;
        }
        if !matches!(
            option.as_str(),
            "--endpoint"
                | "--task-id"
                | "--tenant"
                | "--signal"
                | "--shard"
                | "--resource-generation"
                | "--duration-seconds"
                | "--idempotency-key"
        ) {
            return Err("unknown maintenance option");
        }
        let value = arguments.next().ok_or("missing maintenance option value")?;
        if options.insert(option, value).is_some() {
            return Err("duplicate maintenance option");
        }
    }
    if !credential_stdin {
        return Err(
            "--credential-stdin is required; secrets are never accepted as arguments or environment variables",
        );
    }
    if !allow_plaintext {
        return Err("--allow-plaintext is required for this maintenance endpoint");
    }
    let endpoint: SocketAddr = take(&mut options, "--endpoint")?
        .parse()
        .map_err(|_| "invalid API endpoint")?;
    if endpoint.port() == 0 {
        return Err("invalid API endpoint");
    }
    let command = match operation.as_str() {
        "status" => Command::Status,
        "explain" => Command::Explain(MaintenanceExplainRequest {
            identity: take(&mut options, "--task-id")?,
        }),
        "run" => Command::Run(MaintenanceRunRequest::new(
            "compaction".to_owned(),
            take(&mut options, "--tenant")?,
            take(&mut options, "--signal")?,
            take(&mut options, "--shard")?
                .parse()
                .map_err(|_| "invalid maintenance shard")?,
            take(&mut options, "--idempotency-key")?,
        )),
        "pause" => Command::Pause(MaintenancePauseRequest::new(
            take(&mut options, "--task-id")?,
            take(&mut options, "--resource-generation")?
                .parse()
                .map_err(|_| "invalid resource generation")?,
            take(&mut options, "--duration-seconds")?
                .parse()
                .map_err(|_| "invalid maintenance pause duration")?,
            take(&mut options, "--idempotency-key")?,
        )),
        "resume" => Command::Resume(MaintenanceResumeRequest::new(
            take(&mut options, "--task-id")?,
            take(&mut options, "--idempotency-key")?,
        )),
        _ => return Err(USAGE),
    };
    if !options.is_empty() {
        return Err("option does not apply to maintenance operation");
    }
    match &command {
        Command::Status | Command::Explain(_) => {},
        Command::Run(request) => request
            .validate()
            .map_err(|_| "invalid maintenance run request")?,
        Command::Pause(request) => request
            .validate()
            .map_err(|_| "invalid maintenance pause request")?,
        Command::Resume(request) => request
            .validate()
            .map_err(|_| "invalid maintenance resume request")?,
    }
    Ok((MaintenanceTransport::PlaintextOptOut { endpoint }, command))
}

fn take(options: &mut BTreeMap<String, String>, name: &str) -> Result<String, &'static str> {
    options
        .remove(name)
        .ok_or("required maintenance option absent")
}

const USAGE: &str = "usage: positron maintenance status|explain|run|pause|resume --endpoint IP:PORT --credential-stdin [operation options] --allow-plaintext";
