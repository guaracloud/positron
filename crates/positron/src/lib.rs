//! Thin native process composition.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use positron_config::{CommandLineOverrides, ConfigurationInputs, EnvironmentOverrides, resolve};
use positron_kernel::MountQualification;
use positron_runtime::{
    ApplicationRuntime, BootstrapPaths, ExitOutcome, HostInputs, InitializationMode,
    NativeBindings, NativeHost, RecoveryAttempt, RecoveryAttemptHost, RecoveryDecision,
    ServeConfiguration, ShutdownTrigger,
};
use signal_hook::consts::signal::{SIGINT, SIGTERM};
use signal_hook::iterator::Signals;

const EXIT_OK: u8 = 0;
const EXIT_CONFIGURATION: u8 = 2;
const EXIT_STARTUP: u8 = 3;
const EXIT_FORCED: u8 = 4;
const STARTUP_RECOVERY_DEADLINE: Duration = Duration::from_secs(3);

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
    let paths = BootstrapPaths::with_local_key(
        Path::new(effective.data_directory()),
        Path::new(effective.secrets_directory()),
        effective.local_key_file().as_path(),
        MountQualification::LocalHost,
    )
    .map_err(|_| LaunchFailure::Configuration)?;
    let bindings = NativeBindings::new(
        PathBuf::from(effective.control_path()),
        effective.operations_bind_address(),
        effective.api_bind_address(),
        effective.otlp_grpc_bind_address(),
        effective.otlp_http_bind_address(),
    )
    .map_err(|_| LaunchFailure::Configuration)?;
    let host = NativeHost::new(bindings);
    let recovery =
        NativeRecovery::new(Signals::new([SIGINT, SIGTERM]).map_err(|_| LaunchFailure::Signal)?);
    let process = match ApplicationRuntime::start(
        ServeConfiguration::new(paths, arguments.initialization),
        HostInputs::with_recovery(&host, &host, &recovery),
    ) {
        Ok(process) => process,
        Err(outcome @ (ExitOutcome::Graceful | ExitOutcome::Forced)) => return Ok(outcome),
        Err(outcome) => return Err(LaunchFailure::Startup(outcome)),
    };
    let signals = recovery.into_signals()?;
    let deadline = Duration::from_secs(u64::from(effective.shutdown_grace_seconds()));
    wait_for_shutdown(process, signals, deadline)
}

struct NativeRecovery {
    started: Instant,
    signals: std::sync::Mutex<Option<Signals>>,
}

impl NativeRecovery {
    fn new(signals: Signals) -> Self {
        Self {
            started: Instant::now(),
            signals: std::sync::Mutex::new(Some(signals)),
        }
    }

    fn into_signals(self) -> Result<Signals, LaunchFailure> {
        self.signals
            .into_inner()
            .map_err(|_| LaunchFailure::Signal)?
            .ok_or(LaunchFailure::Signal)
    }

    fn pending_trigger(signals: &mut Signals) -> Option<ShutdownTrigger> {
        let count = signals.pending().take(2).count();
        match count {
            0 => None,
            1 => Some(ShutdownTrigger::FirstSignal),
            _ => Some(ShutdownTrigger::SecondSignal),
        }
    }
}

impl RecoveryAttemptHost for NativeRecovery {
    fn after_failure(&self, attempt: RecoveryAttempt) -> RecoveryDecision {
        if attempt.number() >= 32 || self.started.elapsed() >= STARTUP_RECOVERY_DEADLINE {
            return RecoveryDecision::Exhausted;
        }
        let delay =
            Duration::from_millis(10_u64.saturating_mul(u64::from(attempt.number())).min(100));
        let wait_until = Instant::now() + delay;
        while Instant::now() < wait_until && self.started.elapsed() < STARTUP_RECOVERY_DEADLINE {
            let trigger = self
                .signals
                .lock()
                .ok()
                .and_then(|mut signals| signals.as_mut().and_then(Self::pending_trigger));
            if let Some(trigger) = trigger {
                return RecoveryDecision::Terminate(trigger);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        if self.started.elapsed() >= STARTUP_RECOVERY_DEADLINE {
            RecoveryDecision::Exhausted
        } else {
            RecoveryDecision::Retry
        }
    }
}

fn wait_for_shutdown(
    process: positron_runtime::RunningProcess,
    mut signals: Signals,
    deadline: Duration,
) -> Result<ExitOutcome, LaunchFailure> {
    let Some(_) = signals.forever().next() else {
        return Err(LaunchFailure::Signal);
    };
    let mut draining = process.begin_shutdown();
    let deadline_at = Instant::now() + deadline;
    loop {
        if signals.pending().next().is_some() {
            return Ok(draining.finish(ShutdownTrigger::SecondSignal));
        }
        if Instant::now() >= deadline_at {
            return Ok(draining.finish(ShutdownTrigger::DeadlineExpired));
        }
        match draining.poll() {
            Ok(true) => return Ok(draining.finish(ShutdownTrigger::FirstSignal)),
            Ok(false) => std::thread::yield_now(),
            Err(_) => return Ok(draining.finish(ShutdownTrigger::DeadlineExpired)),
        }
    }
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
                | ExitOutcome::InternalCleanupFailure(_)
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
        | ExitOutcome::InternalCleanupFailure(_)
        | ExitOutcome::Fenced => ExitCode::from(EXIT_STARTUP),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ExitOutcome, LaunchFailure, NativeRecovery, RecoveryAttemptHost, RecoveryDecision,
        ShutdownTrigger, exit_code,
    };
    use positron_runtime::{BootstrapFailureCode, ListenerRole, RecoveryAttempt, TaskRole};
    use signal_hook::iterator::Signals;

    #[test]
    fn every_typed_runtime_outcome_has_a_stable_native_exit() {
        for outcome in [
            ExitOutcome::Graceful,
            ExitOutcome::Forced,
            ExitOutcome::InvalidConfiguration,
            ExitOutcome::StartupUnavailable(BootstrapFailureCode::StorageUnavailable),
            ExitOutcome::ListenerUnavailable(ListenerRole::Api),
            ExitOutcome::TaskUnavailable(TaskRole::Api),
            ExitOutcome::InternalCleanupFailure(positron_runtime::CleanupFailure::none()),
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

    #[test]
    fn native_recovery_retries_then_exhausts_at_the_attempt_bound()
    -> Result<(), Box<dyn std::error::Error>> {
        let recovery = NativeRecovery::new(Signals::new(std::iter::empty::<i32>())?);

        assert_eq!(
            recovery.after_failure(RecoveryAttempt::for_test(1)),
            RecoveryDecision::Retry
        );
        assert_eq!(
            recovery.after_failure(RecoveryAttempt::for_test(32)),
            RecoveryDecision::Exhausted
        );
        assert!(recovery.into_signals().is_ok());
        Ok(())
    }

    #[test]
    fn native_recovery_preserves_typed_attempt_metadata() -> Result<(), Box<dyn std::error::Error>>
    {
        let recovery = NativeRecovery::new(Signals::new(std::iter::empty::<i32>())?);
        let attempt = RecoveryAttempt::for_test(2);
        assert_eq!(attempt.failure(), BootstrapFailureCode::StorageUnavailable);
        assert!(!attempt.ownership_held());
        assert_eq!(recovery.after_failure(attempt), RecoveryDecision::Retry);
        Ok(())
    }

    #[test]
    fn pending_native_signal_interrupts_recovery_backoff() -> Result<(), Box<dyn std::error::Error>>
    {
        let recovery = NativeRecovery::new(Signals::new([signal_hook::consts::signal::SIGUSR1])?);
        signal_hook::low_level::raise(signal_hook::consts::signal::SIGUSR1)?;

        assert_eq!(
            recovery.after_failure(RecoveryAttempt::for_test(1)),
            RecoveryDecision::Terminate(ShutdownTrigger::FirstSignal)
        );
        Ok(())
    }
}
