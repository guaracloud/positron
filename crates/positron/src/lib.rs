//! Thin native process composition.

#![forbid(unsafe_code)]

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use positron_config::{CommandLineOverrides, ConfigurationInputs, EnvironmentOverrides, resolve};
use positron_kernel::MountQualification;
use positron_runtime::{
    ApplicationRuntime, BootstrapPaths, ExitOutcome, HostInputs, InitializationMode,
    NativeBindings, NativeHost, ServeConfiguration, ShutdownTrigger,
};
use signal_hook::consts::signal::{SIGINT, SIGTERM};
use signal_hook::iterator::Signals;

const EXIT_OK: u8 = 0;
const EXIT_CONFIGURATION: u8 = 2;
const EXIT_STARTUP: u8 = 3;
const EXIT_FORCED: u8 = 4;

pub fn run_native(
    arguments: impl IntoIterator<Item = String>,
    environment: impl IntoIterator<Item = (String, String)>,
) -> ExitCode {
    match run(arguments, environment) {
        Ok(outcome) => exit_code(outcome),
        Err(failure) => {
            eprintln!("positron: {}", failure.message());
            ExitCode::from(failure.code())
        },
    }
}

fn run(
    arguments: impl IntoIterator<Item = String>,
    environment: impl IntoIterator<Item = (String, String)>,
) -> Result<ExitOutcome, LaunchFailure> {
    let arguments = Arguments::parse(arguments)?;
    let document = arguments
        .config
        .as_deref()
        .map(std::fs::read_to_string)
        .transpose()
        .map_err(|_| LaunchFailure::Configuration)?;
    let environment = EnvironmentOverrides::try_from_pairs(
        environment
            .into_iter()
            .filter(|(key, _)| key.starts_with("POSITRON__")),
    )
    .map_err(|_| LaunchFailure::Configuration)?;
    let command_line = CommandLineOverrides::try_from_pairs(arguments.overrides)
        .map_err(|_| LaunchFailure::Configuration)?;
    let inputs = ConfigurationInputs::try_new(document.as_deref(), environment, command_line)
        .map_err(|_| LaunchFailure::Configuration)?;
    let effective = resolve(inputs).map_err(|_| LaunchFailure::Configuration)?;
    let paths = BootstrapPaths::new(
        Path::new(effective.data_directory()),
        Path::new(effective.secrets_directory()),
        MountQualification::LocalHost,
    )
    .map_err(|_| LaunchFailure::Configuration)?;
    let base = effective.control_bind_address();
    let bindings = NativeBindings::new(
        std::env::temp_dir().join(format!("positron-{}.sock", std::process::id())),
        base,
        next_address(base, 1)?,
        next_address(base, 2)?,
    )
    .map_err(|_| LaunchFailure::Configuration)?;
    let host = NativeHost::new(bindings);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, arguments.initialization),
        HostInputs::new(&host, &host),
    )
    .map_err(LaunchFailure::Startup)?;
    if process.health().phase() == positron_runtime::ProcessPhase::Fenced {
        return Ok(ExitOutcome::Fenced);
    }
    let signals = Signals::new([SIGINT, SIGTERM]).map_err(|_| LaunchFailure::Signal)?;
    let deadline = Duration::from_secs(u64::from(effective.shutdown_grace_seconds()));
    wait_for_shutdown(process, signals, deadline)
}

fn wait_for_shutdown(
    process: positron_runtime::RunningProcess,
    mut signals: Signals,
    deadline: Duration,
) -> Result<ExitOutcome, LaunchFailure> {
    let Some(_) = signals.forever().next() else {
        return Err(LaunchFailure::Signal);
    };
    let handle = signals.handle();
    let second = std::thread::Builder::new()
        .name("positron-second-signal".into())
        .spawn(move || {
            let signalled = signals.forever().next().is_some();
            handle.close();
            signalled
        })
        .map_err(|_| LaunchFailure::Signal)?;
    let started = Instant::now();
    let outcome = process.shutdown(ShutdownTrigger::FirstSignal);
    if second.is_finished() {
        let _ = second.join();
        return Ok(ExitOutcome::Forced);
    }
    if started.elapsed() > deadline {
        return Ok(ExitOutcome::Forced);
    }
    Ok(outcome)
}

fn next_address(base: SocketAddr, increment: u16) -> Result<SocketAddr, LaunchFailure> {
    let port = base
        .port()
        .checked_add(increment)
        .ok_or(LaunchFailure::Configuration)?;
    if !base.ip().is_loopback() {
        return Err(LaunchFailure::Configuration);
    }
    Ok(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)))
}

#[derive(Debug)]
struct Arguments {
    config: Option<PathBuf>,
    overrides: Vec<(String, String)>,
    initialization: InitializationMode,
}

impl Arguments {
    fn parse(arguments: impl IntoIterator<Item = String>) -> Result<Self, LaunchFailure> {
        let mut arguments = arguments.into_iter();
        let mut config = None;
        let mut overrides = Vec::new();
        let mut initialization = InitializationMode::ExistingOnly;
        while let Some(argument) = arguments.next() {
            match argument.as_str() {
                "serve" => {},
                "--init-if-empty" => initialization = InitializationMode::InitializeIfEmpty,
                "--config" if config.is_none() => {
                    config = Some(PathBuf::from(arguments.next().ok_or(LaunchFailure::Usage)?));
                },
                "--set" => {
                    let value = arguments.next().ok_or(LaunchFailure::Usage)?;
                    let (key, value) = value.split_once('=').ok_or(LaunchFailure::Usage)?;
                    overrides.push((key.to_owned(), value.to_owned()));
                },
                _ => return Err(LaunchFailure::Usage),
            }
        }
        Ok(Self {
            config,
            overrides,
            initialization,
        })
    }
}

#[derive(Clone, Copy, Debug)]
enum LaunchFailure {
    Usage,
    Configuration,
    Startup(ExitOutcome),
    Signal,
}

impl LaunchFailure {
    const fn code(self) -> u8 {
        match self {
            Self::Usage | Self::Configuration => EXIT_CONFIGURATION,
            Self::Startup(outcome) => match outcome {
                ExitOutcome::InvalidConfiguration => EXIT_CONFIGURATION,
                ExitOutcome::Forced => EXIT_FORCED,
                ExitOutcome::Graceful
                | ExitOutcome::StartupUnavailable(_)
                | ExitOutcome::ListenerUnavailable(_)
                | ExitOutcome::TaskUnavailable(_)
                | ExitOutcome::Fenced => EXIT_STARTUP,
            },
            Self::Signal => EXIT_STARTUP,
        }
    }

    const fn message(self) -> &'static str {
        match self {
            Self::Usage => "invalid command line",
            Self::Configuration => "configuration rejected",
            Self::Startup(_) => "startup failed",
            Self::Signal => "signal handling unavailable",
        }
    }
}

fn exit_code(outcome: ExitOutcome) -> ExitCode {
    match outcome {
        ExitOutcome::Graceful => ExitCode::from(EXIT_OK),
        ExitOutcome::Forced => ExitCode::from(EXIT_FORCED),
        ExitOutcome::InvalidConfiguration => ExitCode::from(EXIT_CONFIGURATION),
        ExitOutcome::StartupUnavailable(_)
        | ExitOutcome::ListenerUnavailable(_)
        | ExitOutcome::TaskUnavailable(_)
        | ExitOutcome::Fenced => ExitCode::from(EXIT_STARTUP),
    }
}

#[cfg(test)]
mod tests {
    use super::{ExitOutcome, LaunchFailure, exit_code};
    use positron_runtime::{BootstrapFailureCode, ListenerRole, TaskRole};

    #[test]
    fn every_typed_runtime_outcome_has_a_stable_native_exit() {
        for outcome in [
            ExitOutcome::Graceful,
            ExitOutcome::Forced,
            ExitOutcome::InvalidConfiguration,
            ExitOutcome::StartupUnavailable(BootstrapFailureCode::StorageUnavailable),
            ExitOutcome::ListenerUnavailable(ListenerRole::Api),
            ExitOutcome::TaskUnavailable(TaskRole::Api),
            ExitOutcome::Fenced,
        ] {
            let code = exit_code(outcome);
            let launch = LaunchFailure::Startup(outcome);
            assert_eq!(launch.message(), "startup failed");
            assert!(launch.code() > 0);
            if outcome == ExitOutcome::Graceful {
                assert_eq!(code, std::process::ExitCode::SUCCESS);
            }
        }
        assert_eq!(LaunchFailure::Signal.code(), 3);
        assert_eq!(
            LaunchFailure::Signal.message(),
            "signal handling unavailable"
        );
    }
}
