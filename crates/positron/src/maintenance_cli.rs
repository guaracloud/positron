use std::io::{IsTerminal, Read};
use std::process::ExitCode;

use positron_api::maintenance::{
    MaintenanceServiceClient, MaintenanceServiceClientFailure, MaintenanceStatusRequest,
    MaintenanceTransport,
};
use zeroize::Zeroizing;

pub(super) fn run(mut arguments: impl Iterator<Item = String>) -> ExitCode {
    match arguments.next().as_deref() {
        Some("status") => match parse_status(arguments) {
            Ok(transport) => status(transport),
            Err(()) => {
                eprintln!(
                    "positron: usage: positron maintenance status --endpoint HOST:PORT --allow-plaintext --credential-stdin"
                );
                ExitCode::from(2)
            },
        },
        _ => {
            eprintln!(
                "positron: usage: positron maintenance status --endpoint HOST:PORT --allow-plaintext --credential-stdin"
            );
            ExitCode::from(2)
        },
    }
}

fn parse_status(arguments: impl Iterator<Item = String>) -> Result<MaintenanceTransport, ()> {
    let mut endpoint = None;
    let mut plaintext = false;
    let mut credential_stdin = false;
    let mut arguments = arguments;
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--endpoint" => endpoint = Some(arguments.next().ok_or(())?.parse().map_err(|_| ())?),
            "--allow-plaintext" => plaintext = true,
            "--credential-stdin" => credential_stdin = true,
            _ => return Err(()),
        }
    }
    if !plaintext || !credential_stdin {
        return Err(());
    }
    Ok(MaintenanceTransport::PlaintextOptOut {
        endpoint: endpoint.ok_or(())?,
    })
}

fn status(transport: MaintenanceTransport) -> ExitCode {
    match execute(transport) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("positron: {message}");
            ExitCode::from(2)
        },
    }
}

fn execute(transport: MaintenanceTransport) -> Result<(), &'static str> {
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
    if credential.len() > 1024 || bearer.is_empty() {
        return Err("invalid credential input");
    }
    let client =
        MaintenanceServiceClient::new(transport).map_err(|_| "API endpoint unavailable")?;
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
    for task in status.tasks {
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
    Ok(())
}

const fn client_failure(failure: MaintenanceServiceClientFailure) -> &'static str {
    match failure {
        MaintenanceServiceClientFailure::InvalidRequest => "invalid maintenance request",
        MaintenanceServiceClientFailure::AuthenticationRejected => "authentication rejected",
        MaintenanceServiceClientFailure::AdministrationUnavailable => {
            "maintenance administration unavailable"
        },
        MaintenanceServiceClientFailure::Transport => "maintenance API transport failed",
    }
}
