//! Controlled, bounded execution for external quality-harness invocations.
//!
//! This module is the sole semantic owner for child launch, process-group
//! ownership, descriptor capture, bounded waiting, termination, reaping, and
//! final execution verdicts used by `xtask` tooling. A reconciled verdict
//! proves that the direct child has exited, its process group has no remaining
//! members, and every owned capture or input broker has been reaped.

use std::ffi::{OsStr, OsString};
#[cfg(unix)]
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, ExitStatus, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

pub(crate) const DEFAULT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(3);
const TERMINATION_GRACE: Duration = Duration::from_millis(10);
const POLL_INTERVAL: Duration = Duration::from_millis(5);

/// The explicit inputs for one controlled external invocation.
#[derive(Debug)]
pub(crate) struct InvocationSpec {
    /// The executable to launch.
    pub(crate) program: OsString,
    /// The exact argument vector supplied to the executable.
    pub(crate) arguments: Vec<OsString>,
    /// The workspace-relative invocation directory.
    pub(crate) current_dir: PathBuf,
    /// The complete explicit environment visible to the child.
    pub(crate) environment: Vec<(OsString, OsString)>,
    /// The absolute, caller-resolved tools used by the lifecycle owner itself.
    pub(crate) tools: ExecutionTools,
    /// The owned standard input contract.
    pub(crate) input: InvocationInput,
    /// The owned output-descriptor contract.
    pub(crate) output: OutputMode,
    /// The caller-owned cancellation signal for this invocation only.
    pub(crate) cancellation: Arc<AtomicBool>,
    /// The registered deadline for ordinary direct execution.
    pub(crate) deadline: Instant,
    /// The separately registered bound for termination and process reaping.
    pub(crate) shutdown_timeout: Duration,
    /// An optional create-new marker that requests controlled termination.
    pub(crate) cancellation_marker: Option<PathBuf>,
}

/// Resolved helper executables that are outside the target child's environment.
#[derive(Clone, Debug)]
pub(crate) struct ExecutionTools {
    /// The absolute process-group probe and signal executable.
    pub(crate) process_control: PathBuf,
    /// The absolute bounded stream-capture executable.
    pub(crate) capture_broker: PathBuf,
}

#[cfg(unix)]
impl ExecutionTools {
    fn validate(&self, command: &str) -> Result<(), ExecutionFailure> {
        for (purpose, path) in [
            ("process control", &self.process_control),
            ("capture broker", &self.capture_broker),
        ] {
            if !path.is_absolute() || !path.is_file() {
                return Err(ExecutionFailure::new(
                    command.to_owned(),
                    FailurePhase::Descriptor,
                    format!(
                        "resolved {purpose} tool is not an absolute file: {}",
                        path.display()
                    ),
                ));
            }
        }
        Ok(())
    }
}

/// The bounded standard-input forms supported by the controlled owner.
#[derive(Debug)]
pub(crate) enum InvocationInput {
    /// Close standard input before the child starts executing.
    Null,
    /// Write this finite payload and close standard input.
    Bytes(Vec<u8>),
}

/// The externally visible output ownership mode.
#[derive(Debug)]
pub(crate) enum OutputMode {
    /// Close both child output streams without capture workers.
    Discard,
    /// Capture independently bounded standard output and standard error.
    Capture { maximum_bytes_per_stream: usize },
    /// Stream stdout into one create-new bounded artifact while capturing stderr.
    CaptureWithStdoutArtifact {
        artifact: ArtifactOutput,
        maximum_artifact_bytes: usize,
        maximum_stderr_bytes: usize,
    },
}

#[derive(Debug)]
pub(crate) struct ArtifactOutput {
    file: std::fs::File,
    parent: std::fs::File,
    name: String,
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl ArtifactOutput {
    pub(crate) fn new(
        file: std::fs::File,
        parent: std::fs::File,
        name: String,
        path: PathBuf,
        device: u64,
        inode: u64,
    ) -> Self {
        Self {
            file,
            parent,
            name,
            path,
            device,
            inode,
        }
    }
}

/// A fully reconciled execution result.
#[derive(Debug)]
pub(crate) struct ExecutionVerdict {
    /// The direct process exit verdict after complete reconciliation.
    pub(crate) status: ExitStatus,
    /// Independently captured output, when capture was requested.
    pub(crate) output: CapturedOutput,
}

/// The independently owned captured output streams.
#[derive(Debug)]
pub(crate) struct CapturedOutput {
    /// The exact captured standard output.
    pub(crate) stdout: String,
    /// The exact captured standard error.
    pub(crate) stderr: String,
}

/// The closed result of one controlled invocation.
#[derive(Debug)]
pub(crate) enum ExecutionOutcome {
    /// The child and all owned resources were reconciled.
    Reconciled(ExecutionVerdict),
    /// Launch, execution, descriptor, descendant, or cleanup reconciliation failed.
    Failed(ExecutionFailure),
}

impl ExecutionOutcome {
    /// Converts the closed outcome into the caller's ordinary result flow.
    pub(crate) fn into_result(self) -> Result<ExecutionVerdict, ExecutionFailure> {
        match self {
            Self::Reconciled(verdict) => Ok(verdict),
            Self::Failed(failure) => Err(failure),
        }
    }
}

/// A typed failure phase for controlled external execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FailurePhase {
    /// The requested program could not start.
    Launch,
    /// An owned standard descriptor was unavailable.
    Descriptor,
    /// An owned input worker could not complete.
    Input,
    /// The direct child could not be observed or reaped.
    DirectProcess,
    /// The direct child exceeded its declared deadline.
    Deadline,
    /// The caller cancelled the controlled invocation.
    Cancellation,
    /// A direct child exited while a controlled descendant remained alive.
    Descendant,
    /// A captured stream could not be read or decoded.
    Capture,
    /// Controlled termination or cleanup could not complete.
    Cleanup,
    /// This host cannot establish the required process-ownership boundary.
    #[cfg(not(unix))]
    UnsupportedPlatform,
}

impl FailurePhase {
    /// The stable diagnostic label for this failure class.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Launch => "launch",
            Self::Descriptor => "descriptor",
            Self::Input => "input",
            Self::DirectProcess => "direct-process",
            Self::Deadline => "deadline",
            Self::Cancellation => "cancellation",
            Self::Descendant => "descendant",
            Self::Capture => "capture",
            Self::Cleanup => "cleanup",
            #[cfg(not(unix))]
            Self::UnsupportedPlatform => "unsupported-platform",
        }
    }
}

/// A safe, typed failed verdict with command and phase context.
#[derive(Debug)]
pub(crate) struct ExecutionFailure {
    /// The safe display form of the requested invocation.
    pub(crate) command: String,
    /// The lifecycle phase that could not complete.
    pub(crate) phase: FailurePhase,
    /// Bounded diagnostic context for the failed phase.
    pub(crate) detail: String,
    /// Honest reconciliation observations when a launched process was shut down.
    pub(crate) shutdown: Option<Box<ShutdownEvidence>>,
}

impl ExecutionFailure {
    fn new(command: String, phase: FailurePhase, detail: impl Into<String>) -> Self {
        Self {
            command,
            phase,
            detail: detail.into(),
            shutdown: None,
        }
    }
}

/// Observed shutdown behavior for a failed controlled invocation.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ShutdownEvidence {
    pub(crate) termination_requested: bool,
    pub(crate) process_reaped: bool,
    pub(crate) live: usize,
    pub(crate) bound: Duration,
    pub(crate) process_elapsed: Duration,
    pub(crate) resource_elapsed: Duration,
    pub(crate) elapsed: Duration,
}

fn cancellation_requested(cancellation: &AtomicBool) -> bool {
    cancellation.load(Ordering::Acquire)
}

fn cancellation_failure(command: &str) -> ExecutionFailure {
    ExecutionFailure::new(
        command.to_owned(),
        FailurePhase::Cancellation,
        "the caller requested cancellation before reconciliation completed",
    )
}

/// Executes one explicit invocation and returns a closed reconciliation outcome.
pub(crate) fn execute(specification: InvocationSpec) -> ExecutionOutcome {
    let command = command_display(&specification.program, &specification.arguments);
    if cancellation_requested(specification.cancellation.as_ref()) {
        return ExecutionOutcome::Failed(cancellation_failure(&command));
    }

    #[cfg(unix)]
    {
        execute_unix(specification)
    }

    #[cfg(not(unix))]
    {
        ExecutionOutcome::Failed(ExecutionFailure::new(
            command,
            FailurePhase::UnsupportedPlatform,
            "controlled descendant reconciliation requires a Unix process-group boundary",
        ))
    }
}

#[cfg(unix)]
fn execute_unix(specification: InvocationSpec) -> ExecutionOutcome {
    let command_display = command_display(&specification.program, &specification.arguments);
    if Instant::now() >= specification.deadline {
        return ExecutionOutcome::Failed(ExecutionFailure::new(
            command_display,
            FailurePhase::Deadline,
            "the invocation deadline had already elapsed before launch",
        ));
    }
    if let Err(failure) = specification.tools.validate(&command_display) {
        return ExecutionOutcome::Failed(failure);
    }

    let mut command = std::process::Command::new(&specification.program);
    command
        .env_clear()
        .current_dir(&specification.current_dir)
        .args(&specification.arguments)
        .envs(
            specification
                .environment
                .iter()
                .map(|(name, value)| (name, value)),
        );
    configure_standard_descriptors(&mut command, &specification.output, &specification.input);
    configure_isolated_process_group(&mut command);

    // positron-concurrency-spawn: execute_unix\tcontrolled-command-v1
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(source) => {
            return ExecutionOutcome::Failed(ExecutionFailure::new(
                command_display,
                FailurePhase::Launch,
                source.to_string(),
            ));
        },
    };
    let group = ProcessGroup::new(child.id(), specification.tools.process_control.clone());
    let mut workers = match OwnedWorkers::start(
        &mut child,
        OwnedWorkersRequest {
            command: &command_display,
            output: specification.output,
            input: specification.input,
            current_dir: &specification.current_dir,
            tools: &specification.tools,
            deadline: specification.deadline,
        },
    ) {
        Ok(workers) => workers,
        Err(failure) => {
            return finish_after_setup_failure(
                &mut child,
                &group,
                failure,
                specification.shutdown_timeout,
            );
        },
    };

    let status = match wait_for_direct_child(
        &mut child,
        &command_display,
        specification.deadline,
        Some(specification.cancellation.as_ref()),
        specification.cancellation_marker.as_deref(),
    ) {
        Ok(status) => status,
        Err(failure) => {
            return finish_after_execution_failure(
                &mut child,
                &group,
                &mut workers,
                failure,
                specification.shutdown_timeout,
            );
        },
    };

    if cancellation_requested(specification.cancellation.as_ref()) {
        return finish_after_execution_failure(
            &mut child,
            &group,
            &mut workers,
            cancellation_failure(&command_display),
            specification.shutdown_timeout,
        );
    }

    match group.exists(&command_display, specification.deadline) {
        Ok(true) => {
            let failure = ExecutionFailure::new(
                command_display,
                FailurePhase::Descendant,
                "the direct child exited while its controlled process group still owned descendants or inherited descriptors",
            );
            finish_after_execution_failure(
                &mut child,
                &group,
                &mut workers,
                failure,
                specification.shutdown_timeout,
            )
        },
        Ok(false) => {
            if cancellation_requested(specification.cancellation.as_ref()) {
                return finish_after_execution_failure(
                    &mut child,
                    &group,
                    &mut workers,
                    cancellation_failure(&command_display),
                    specification.shutdown_timeout,
                );
            }
            match workers.join_until(
                &command_display,
                specification.deadline,
                specification.cancellation.as_ref(),
            ) {
                Ok(output) => ExecutionOutcome::Reconciled(ExecutionVerdict { status, output }),
                Err(failure) => ExecutionOutcome::Failed(failure),
            }
        },
        Err(failure) => finish_after_execution_failure(
            &mut child,
            &group,
            &mut workers,
            failure,
            specification.shutdown_timeout,
        ),
    }
}

#[cfg(unix)]
fn configure_isolated_process_group(command: &mut std::process::Command) {
    use std::os::unix::process::CommandExt as _;

    command.process_group(0);
}

#[cfg(unix)]
fn configure_standard_descriptors(
    command: &mut std::process::Command,
    output: &OutputMode,
    input: &InvocationInput,
) {
    match input {
        InvocationInput::Null => {
            command.stdin(Stdio::null());
        },
        InvocationInput::Bytes(_) => {
            command.stdin(Stdio::piped());
        },
    }
    match output {
        OutputMode::Discard => {
            command.stdout(Stdio::null()).stderr(Stdio::null());
        },
        OutputMode::Capture { .. } | OutputMode::CaptureWithStdoutArtifact { .. } => {
            command.stdout(Stdio::piped()).stderr(Stdio::piped());
        },
    }
}

#[cfg(unix)]
fn finish_after_setup_failure(
    child: &mut Child,
    group: &ProcessGroup,
    mut failure: ExecutionFailure,
    shutdown_timeout: Duration,
) -> ExecutionOutcome {
    let shutdown_started = Instant::now();
    let Some(shutdown_deadline) = shutdown_started.checked_add(shutdown_timeout) else {
        return ExecutionOutcome::Failed(ExecutionFailure::new(
            failure.command,
            FailurePhase::Cleanup,
            "the setup-failure shutdown deadline cannot be represented",
        ));
    };
    let cleanup = terminate_and_reap(child, group, &failure.command, shutdown_deadline);
    let process_elapsed = shutdown_started.elapsed();
    let process_reaped = cleanup.is_ok();
    let evidence = ShutdownEvidence {
        termination_requested: true,
        process_reaped,
        live: usize::from(!process_reaped),
        bound: shutdown_timeout,
        process_elapsed,
        resource_elapsed: Duration::ZERO,
        elapsed: process_elapsed,
    };
    if process_elapsed > shutdown_timeout {
        let mut cleanup = ExecutionFailure::new(
            failure.command,
            FailurePhase::Cleanup,
            "controlled setup reconciliation exceeded the registered shutdown deadline",
        );
        cleanup.shutdown = Some(Box::new(evidence));
        return ExecutionOutcome::Failed(cleanup);
    }
    match cleanup {
        Ok(()) => {
            failure.shutdown = Some(Box::new(evidence));
            ExecutionOutcome::Failed(failure)
        },
        Err(mut cleanup) => {
            cleanup.shutdown = Some(Box::new(evidence));
            ExecutionOutcome::Failed(cleanup)
        },
    }
}

#[cfg(unix)]
fn finish_after_execution_failure(
    child: &mut Child,
    group: &ProcessGroup,
    workers: &mut OwnedWorkers,
    mut failure: ExecutionFailure,
    shutdown_timeout: Duration,
) -> ExecutionOutcome {
    let shutdown_started = Instant::now();
    let shutdown_deadline = match shutdown_started.checked_add(shutdown_timeout) {
        Some(deadline) => deadline,
        None => {
            return ExecutionOutcome::Failed(ExecutionFailure::new(
                failure.command,
                FailurePhase::Cleanup,
                "the registered shutdown deadline cannot be represented",
            ));
        },
    };
    let cleanup = terminate_and_reap(child, group, &failure.command, shutdown_deadline);
    let process_elapsed = shutdown_started.elapsed();
    let resource_started = Instant::now();
    let workers_result = workers.abort(&failure.command, shutdown_deadline);
    let resource_elapsed = resource_started.elapsed();
    let process_reaped = cleanup.is_ok();
    let elapsed = shutdown_started.elapsed();
    let evidence = ShutdownEvidence {
        termination_requested: true,
        process_reaped,
        live: usize::from(!process_reaped),
        bound: shutdown_timeout,
        process_elapsed,
        resource_elapsed,
        elapsed,
    };
    if elapsed > shutdown_timeout {
        let mut cleanup = ExecutionFailure::new(
            failure.command,
            FailurePhase::Cleanup,
            "controlled reconciliation exceeded the registered shutdown deadline",
        );
        cleanup.shutdown = Some(Box::new(evidence));
        return ExecutionOutcome::Failed(cleanup);
    }
    match (cleanup, workers_result) {
        (Ok(()), Ok(())) => {
            failure.shutdown = Some(Box::new(evidence));
            ExecutionOutcome::Failed(failure)
        },
        (Err(mut cleanup), _) => {
            cleanup.shutdown = Some(Box::new(evidence));
            ExecutionOutcome::Failed(cleanup)
        },
        (Ok(()), Err(mut worker)) => {
            worker.shutdown = Some(Box::new(evidence));
            ExecutionOutcome::Failed(worker)
        },
    }
}

#[cfg(unix)]
fn wait_for_direct_child(
    child: &mut Child,
    command: &str,
    deadline: Instant,
    cancellation: Option<&AtomicBool>,
    cancellation_marker: Option<&std::path::Path>,
) -> Result<ExitStatus, ExecutionFailure> {
    loop {
        if let Some(cancellation) = cancellation
            && cancellation_requested(cancellation)
        {
            return Err(cancellation_failure(command));
        }
        if let Some(marker) = cancellation_marker {
            match marker.try_exists() {
                Ok(true) => return Err(cancellation_failure(command)),
                Ok(false) => {},
                Err(source) => {
                    return Err(ExecutionFailure::new(
                        command.to_owned(),
                        FailurePhase::Descriptor,
                        format!(
                            "inspect controlled cancellation marker {}: {source}",
                            marker.display()
                        ),
                    ));
                },
            }
        }
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    return Err(ExecutionFailure::new(
                        command.to_owned(),
                        FailurePhase::Deadline,
                        "the direct child exceeded its declared execution deadline",
                    ));
                }
                wait_for_progress(deadline);
            },
            Err(source) => {
                return Err(ExecutionFailure::new(
                    command.to_owned(),
                    FailurePhase::DirectProcess,
                    source.to_string(),
                ));
            },
        }
    }
}

#[cfg(unix)]
fn terminate_and_reap(
    child: &mut Child,
    group: &ProcessGroup,
    command: &str,
    shutdown_deadline: Instant,
) -> Result<(), ExecutionFailure> {
    group.signal(Signal::Terminate, command, shutdown_deadline)?;
    let grace_deadline = Instant::now()
        .checked_add(TERMINATION_GRACE)
        .unwrap_or(shutdown_deadline)
        .min(shutdown_deadline);
    if !wait_for_group_while_reaping_direct(
        child,
        group,
        command,
        grace_deadline,
        shutdown_deadline,
    )? {
        group.signal(Signal::Kill, command, shutdown_deadline)?;
        if !wait_for_group_while_reaping_direct(
            child,
            group,
            command,
            shutdown_deadline,
            shutdown_deadline,
        )? {
            return Err(group.not_empty_failure(command));
        }
    }
    wait_for_direct_child(child, command, shutdown_deadline, None, None).map(|_| ())
}

#[cfg(unix)]
fn wait_for_group_while_reaping_direct(
    child: &mut Child,
    group: &ProcessGroup,
    command: &str,
    progress_deadline: Instant,
    shutdown_deadline: Instant,
) -> Result<bool, ExecutionFailure> {
    loop {
        child.try_wait().map_err(|source| {
            ExecutionFailure::new(
                command.to_owned(),
                FailurePhase::DirectProcess,
                source.to_string(),
            )
        })?;
        if !group.exists(command, shutdown_deadline)? {
            return Ok(true);
        }
        if Instant::now() >= progress_deadline {
            return Ok(false);
        }
        wait_for_progress(progress_deadline);
    }
}

#[cfg(unix)]
fn wait_for_progress(deadline: Instant) {
    let remaining = deadline.saturating_duration_since(Instant::now());
    thread::park_timeout(remaining.min(POLL_INTERVAL));
}

#[cfg(unix)]
struct ProcessGroup {
    identifier: u32,
    process_control: PathBuf,
}

#[cfg(unix)]
impl ProcessGroup {
    fn new(identifier: u32, process_control: PathBuf) -> Self {
        Self {
            identifier,
            process_control,
        }
    }

    fn exists(&self, command: &str, deadline: Instant) -> Result<bool, ExecutionFailure> {
        let target = format!("-{}", self.identifier);
        let status = run_platform_kill(
            &[
                OsString::from("-0"),
                OsString::from("--"),
                OsString::from(target),
            ],
            command,
            &self.process_control,
            deadline,
        )?;
        Ok(status.success())
    }

    fn signal(
        &self,
        signal: Signal,
        command: &str,
        deadline: Instant,
    ) -> Result<(), ExecutionFailure> {
        if !self.exists(command, deadline)? {
            return Ok(());
        }
        let target = format!("-{}", self.identifier);
        let status = run_platform_kill(
            &[
                OsString::from(signal.flag()),
                OsString::from("--"),
                OsString::from(target),
            ],
            command,
            &self.process_control,
            deadline,
        )?;
        if status.success() || !self.exists(command, deadline)? {
            return Ok(());
        }
        Err(ExecutionFailure::new(
            command.to_owned(),
            FailurePhase::Cleanup,
            format!(
                "{} did not terminate controlled process group {}",
                signal.name(),
                self.identifier
            ),
        ))
    }

    fn not_empty_failure(&self, command: &str) -> ExecutionFailure {
        ExecutionFailure::new(
            command.to_owned(),
            FailurePhase::Cleanup,
            format!(
                "controlled process group {} remained alive after forced termination",
                self.identifier
            ),
        )
    }
}

#[cfg(unix)]
#[derive(Clone, Copy)]
enum Signal {
    Terminate,
    Kill,
}

#[cfg(unix)]
impl Signal {
    fn flag(self) -> &'static str {
        match self {
            Self::Terminate => "-TERM",
            Self::Kill => "-KILL",
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Terminate => "termination signal",
            Self::Kill => "forced termination signal",
        }
    }
}

#[cfg(unix)]
fn run_platform_kill(
    arguments: &[OsString],
    command: &str,
    process_control: &std::path::Path,
    deadline: Instant,
) -> Result<ExitStatus, ExecutionFailure> {
    require_shutdown_time(command, deadline, "platform process-control launch")?;
    let mut child = std::process::Command::new(process_control)
        .env_clear()
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        // positron-concurrency-spawn: run_platform_kill\tcontrolled-platform-kill-v1
        .spawn()
        .map_err(|source| {
            ExecutionFailure::new(
                command.to_owned(),
                FailurePhase::Cleanup,
                source.to_string(),
            )
        })?;
    match wait_for_direct_child(&mut child, command, deadline, None, None) {
        Ok(status) => Ok(status),
        Err(failure) if failure.phase == FailurePhase::Deadline => {
            child.kill().map_err(|source| {
                ExecutionFailure::new(
                    command.to_owned(),
                    FailurePhase::Cleanup,
                    source.to_string(),
                )
            })?;
            if let Err(reap) = wait_for_direct_child(&mut child, command, deadline, None, None) {
                return Err(ExecutionFailure::new(
                    command.to_owned(),
                    FailurePhase::Cleanup,
                    format!(
                        "platform process-control command could not be reaped before the registered shutdown deadline: {}",
                        reap.detail
                    ),
                ));
            }
            Err(ExecutionFailure::new(
                command.to_owned(),
                FailurePhase::Cleanup,
                "platform process-control command exceeded its bounded deadline",
            ))
        },
        Err(failure) => Err(failure),
    }
}

#[cfg(unix)]
fn require_shutdown_time(
    command: &str,
    deadline: Instant,
    operation: &str,
) -> Result<Duration, ExecutionFailure> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(ExecutionFailure::new(
            command.to_owned(),
            FailurePhase::Cleanup,
            format!("{operation} reached the registered shutdown deadline"),
        ));
    }
    Ok(remaining)
}

#[cfg(unix)]
struct OwnedWorkers {
    capture: Option<CaptureBroker>,
    input: Option<InputBroker>,
}

#[cfg(unix)]
struct OwnedWorkersRequest<'a> {
    command: &'a str,
    output: OutputMode,
    input: InvocationInput,
    current_dir: &'a std::path::Path,
    tools: &'a ExecutionTools,
    deadline: Instant,
}

#[cfg(unix)]
impl OwnedWorkers {
    fn start(
        child: &mut Child,
        request: OwnedWorkersRequest<'_>,
    ) -> Result<Self, ExecutionFailure> {
        let OwnedWorkersRequest {
            command,
            output,
            input,
            current_dir,
            tools,
            deadline,
        } = request;
        let input_pipe = match input {
            InvocationInput::Null => None,
            InvocationInput::Bytes(bytes) => {
                let stdin = child.stdin.take().ok_or_else(|| {
                    ExecutionFailure::new(
                        command.to_owned(),
                        FailurePhase::Descriptor,
                        "owned standard input pipe was unavailable",
                    )
                })?;
                Some((stdin, bytes))
            },
        };
        if matches!(output, OutputMode::Discard) {
            if input_pipe.is_some() {
                return Err(ExecutionFailure::new(
                    command.to_owned(),
                    FailurePhase::Descriptor,
                    "discarded output mode requires closed standard input",
                ));
            }
            return Ok(Self {
                capture: None,
                input: None,
            });
        }
        let stdout = child.stdout.take().ok_or_else(|| {
            ExecutionFailure::new(
                command.to_owned(),
                FailurePhase::Descriptor,
                "owned stdout capture pipe was unavailable",
            )
        })?;
        let stderr = child.stderr.take().ok_or_else(|| {
            ExecutionFailure::new(
                command.to_owned(),
                FailurePhase::Descriptor,
                "owned stderr capture pipe was unavailable",
            )
        })?;
        let request = match output {
            OutputMode::Discard => {
                return Err(ExecutionFailure::new(
                    command.to_owned(),
                    FailurePhase::Descriptor,
                    "discarded output mode reached capture setup",
                ));
            },
            OutputMode::Capture {
                maximum_bytes_per_stream,
            } => CaptureBrokerRequest {
                stdout: StdoutTarget::Capture {
                    maximum_bytes: maximum_bytes_per_stream,
                },
                maximum_stderr_bytes: maximum_bytes_per_stream,
                current_dir,
                invocation_id: child.id(),
                command,
                capture_broker: &tools.capture_broker,
            },
            OutputMode::CaptureWithStdoutArtifact {
                artifact,
                maximum_artifact_bytes,
                maximum_stderr_bytes,
            } => CaptureBrokerRequest {
                stdout: StdoutTarget::Artifact {
                    artifact,
                    maximum_bytes: maximum_artifact_bytes,
                },
                maximum_stderr_bytes,
                current_dir,
                invocation_id: child.id(),
                command,
                capture_broker: &tools.capture_broker,
            },
        };
        let mut capture = Some(CaptureBroker::start(stdout, stderr, request, deadline)?);
        let input = match input_pipe {
            Some((stdin, bytes)) => match InputBroker::start(
                stdin,
                bytes,
                current_dir,
                child.id(),
                command,
                &tools.capture_broker,
            ) {
                Ok(input) => Some(input),
                Err(failure) => {
                    let cleanup = match capture.take() {
                        Some(capture) => capture.abort(command, deadline),
                        None => Ok(()),
                    };
                    return match cleanup {
                        Ok(()) => Err(failure),
                        Err(cleanup) => Err(cleanup),
                    };
                },
            },
            None => None,
        };
        Ok(Self { capture, input })
    }

    fn join_until(
        &mut self,
        command: &str,
        deadline: Instant,
        cancellation: &AtomicBool,
    ) -> Result<CapturedOutput, ExecutionFailure> {
        if let Some(input) = self.input.take()
            && let Err(failure) = input.join_until(command, deadline, cancellation)
        {
            let cleanup = match self.capture.take() {
                Some(capture) => capture.abort(command, deadline),
                None => Ok(()),
            };
            return match cleanup {
                Ok(()) => Err(failure),
                Err(cleanup) => Err(cleanup),
            };
        }
        match self.capture.take() {
            Some(capture) => capture.join_until(command, deadline, cancellation),
            None => Ok(CapturedOutput {
                stdout: String::new(),
                stderr: String::new(),
            }),
        }
    }

    fn abort(&mut self, command: &str, deadline: Instant) -> Result<(), ExecutionFailure> {
        let capture = match self.capture.take() {
            Some(capture) => capture.abort(command, deadline),
            None => Ok(()),
        };
        let input = match self.input.take() {
            Some(input) => input.abort(command, deadline),
            None => Ok(()),
        };
        match (capture, input) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(failure), _) | (Ok(()), Err(failure)) => Err(failure),
        }
    }
}

#[cfg(unix)]
struct InputBroker {
    child: Option<Child>,
    status: Option<ExitStatus>,
    directory: PathBuf,
    payload: PathBuf,
}

#[cfg(unix)]
impl InputBroker {
    fn start(
        input: std::process::ChildStdin,
        bytes: Vec<u8>,
        current_dir: &std::path::Path,
        invocation_id: u32,
        command: &str,
        broker: &std::path::Path,
    ) -> Result<Self, ExecutionFailure> {
        let base = current_dir.join("target/quality/input");
        fs::create_dir_all(&base).map_err(|source| {
            ExecutionFailure::new(
                command.to_owned(),
                FailurePhase::Input,
                format!("create input broker directory: {source}"),
            )
        })?;
        let directory = base.join(format!("invocation-{invocation_id}"));
        fs::create_dir(&directory).map_err(|source| {
            ExecutionFailure::new(
                command.to_owned(),
                FailurePhase::Input,
                format!("create invocation input directory: {source}"),
            )
        })?;
        let payload = directory.join("payload");
        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&payload)
        {
            Ok(file) => file,
            Err(source) => {
                return match fs::remove_dir(&directory) {
                    Ok(()) => Err(ExecutionFailure::new(
                        command.to_owned(),
                        FailurePhase::Input,
                        format!("create input broker payload: {source}"),
                    )),
                    Err(cleanup) => Err(ExecutionFailure::new(
                        command.to_owned(),
                        FailurePhase::Cleanup,
                        format!("remove incomplete input directory: {cleanup}"),
                    )),
                };
            },
        };
        if let Err(source) = file.write_all(&bytes) {
            drop(file);
            return match remove_input_paths(&directory, &payload) {
                Ok(()) => Err(ExecutionFailure::new(
                    command.to_owned(),
                    FailurePhase::Input,
                    format!("write input broker payload: {source}"),
                )),
                Err(cleanup) => Err(cleanup),
            };
        }
        drop(file);
        let source = match File::open(&payload) {
            Ok(source) => source,
            Err(error) => {
                return match remove_input_paths(&directory, &payload) {
                    Ok(()) => Err(ExecutionFailure::new(
                        command.to_owned(),
                        FailurePhase::Input,
                        format!("open input broker payload: {error}"),
                    )),
                    Err(cleanup) => Err(cleanup),
                };
            },
        };
        let child = match std::process::Command::new(broker)
            .env_clear()
            .args(["-c", &bytes.len().to_string()])
            .stdin(Stdio::from(source))
            .stdout(Stdio::from(input))
            .stderr(Stdio::null())
            // positron-concurrency-spawn: InputBroker::start\tcontrolled-input-broker-v1
            .spawn()
        {
            Ok(child) => child,
            Err(source) => {
                return match remove_input_paths(&directory, &payload) {
                    Ok(()) => Err(ExecutionFailure::new(
                        command.to_owned(),
                        FailurePhase::Input,
                        format!("start input broker: {source}"),
                    )),
                    Err(cleanup) => Err(cleanup),
                };
            },
        };
        Ok(Self {
            child: Some(child),
            status: None,
            directory,
            payload,
        })
    }

    fn join_until(
        mut self,
        command: &str,
        deadline: Instant,
        cancellation: &AtomicBool,
    ) -> Result<(), ExecutionFailure> {
        loop {
            if cancellation_requested(cancellation) {
                let failure = cancellation_failure(command);
                return match self.abort(command, deadline) {
                    Ok(()) => Err(failure),
                    Err(cleanup) => Err(cleanup),
                };
            }
            match self.poll(command) {
                Ok(Some(status)) => return self.finish(command, status),
                Ok(None) => {},
                Err(failure) => {
                    return match self.abort(command, deadline) {
                        Ok(()) => Err(failure),
                        Err(cleanup) => Err(cleanup),
                    };
                },
            }
            if Instant::now() >= deadline {
                let failure = ExecutionFailure::new(
                    command.to_owned(),
                    FailurePhase::Deadline,
                    "input broker remained blocked after the invocation deadline",
                );
                return match self.abort(command, deadline) {
                    Ok(()) => Err(failure),
                    Err(cleanup) => Err(cleanup),
                };
            }
            wait_for_progress(deadline);
        }
    }

    fn poll(&mut self, command: &str) -> Result<Option<ExitStatus>, ExecutionFailure> {
        if let Some(status) = self.status {
            return Ok(Some(status));
        }
        let child = self.child.as_mut().ok_or_else(|| {
            ExecutionFailure::new(
                command.to_owned(),
                FailurePhase::Input,
                "input broker lost its process handle",
            )
        })?;
        match child.try_wait() {
            Ok(Some(status)) => {
                self.status = Some(status);
                Ok(Some(status))
            },
            Ok(None) => Ok(None),
            Err(source) => Err(ExecutionFailure::new(
                command.to_owned(),
                FailurePhase::Input,
                format!("observe input broker: {source}"),
            )),
        }
    }

    fn finish(self, command: &str, status: ExitStatus) -> Result<(), ExecutionFailure> {
        let cleanup = remove_input_paths(&self.directory, &self.payload);
        if !status.success() {
            return match cleanup {
                Ok(()) => Err(ExecutionFailure::new(
                    command.to_owned(),
                    FailurePhase::Input,
                    format!("input broker exited with {status}"),
                )),
                Err(cleanup) => Err(cleanup),
            };
        }
        cleanup
    }

    fn abort(mut self, command: &str, deadline: Instant) -> Result<(), ExecutionFailure> {
        let process = match self.child.take() {
            Some(mut child) => match child.try_wait() {
                Ok(Some(status)) => {
                    self.status = Some(status);
                    Ok(())
                },
                Ok(None) => {
                    if let Err(source) = child.kill() {
                        match child.try_wait() {
                            Ok(Some(status)) => {
                                self.status = Some(status);
                                Ok(())
                            },
                            Ok(None) | Err(_) => Err(ExecutionFailure::new(
                                command.to_owned(),
                                FailurePhase::Cleanup,
                                format!("kill input broker: {source}"),
                            )),
                        }
                    } else {
                        wait_for_direct_child(&mut child, command, deadline, None, None).map(
                            |status| {
                                self.status = Some(status);
                            },
                        )
                    }
                },
                Err(source) => Err(ExecutionFailure::new(
                    command.to_owned(),
                    FailurePhase::Cleanup,
                    format!("observe input broker during cleanup: {source}"),
                )),
            },
            None => Ok(()),
        };
        let cleanup = remove_input_paths(&self.directory, &self.payload);
        match (process, cleanup) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(failure), _) | (Ok(()), Err(failure)) => Err(failure),
        }
    }
}

#[cfg(unix)]
fn remove_input_paths(
    directory: &std::path::Path,
    payload: &std::path::Path,
) -> Result<(), ExecutionFailure> {
    let mut failures = Vec::new();
    if let Err(source) = fs::remove_file(payload) {
        failures.push(format!(
            "remove input broker payload {}: {source}",
            payload.display()
        ));
    }
    if let Err(source) = fs::remove_dir(directory) {
        failures.push(format!("remove input broker directory: {source}"));
    }
    if failures.is_empty() {
        return Ok(());
    }
    Err(ExecutionFailure::new(
        directory.display().to_string(),
        FailurePhase::Cleanup,
        failures.join("; "),
    ))
}

#[cfg(unix)]
struct CaptureBroker {
    stdout: CaptureReader,
    stderr: CaptureReader,
    directory: PathBuf,
    artifact_cleanup: Option<ArtifactCleanup>,
}

#[cfg(unix)]
struct CaptureBrokerRequest<'a> {
    stdout: StdoutTarget,
    maximum_stderr_bytes: usize,
    current_dir: &'a std::path::Path,
    invocation_id: u32,
    command: &'a str,
    capture_broker: &'a std::path::Path,
}

#[cfg(unix)]
enum StdoutTarget {
    Capture {
        maximum_bytes: usize,
    },
    Artifact {
        artifact: ArtifactOutput,
        maximum_bytes: usize,
    },
}

#[cfg(unix)]
struct ArtifactCleanup {
    parent: File,
    name: String,
    path: PathBuf,
    device: u64,
    inode: u64,
}

#[cfg(unix)]
fn normalized_device_identity<T>(device: T) -> Result<u64, T::Error>
where
    T: TryInto<u64>,
{
    device.try_into()
}

#[cfg(unix)]
impl ArtifactCleanup {
    fn remove_if_owned(self, command: &str) -> Result<(), ExecutionFailure> {
        let metadata = rustix::fs::statat(
            &self.parent,
            &self.name,
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        );
        let metadata = match metadata {
            Ok(metadata) => metadata,
            Err(rustix::io::Errno::NOENT) => return Ok(()),
            Err(source) => {
                return Err(ExecutionFailure::new(
                    command.to_owned(),
                    FailurePhase::Cleanup,
                    format!(
                        "inspect stdout artifact {} during cleanup: {}",
                        self.path.display(),
                        std::io::Error::from_raw_os_error(source.raw_os_error())
                    ),
                ));
            },
        };
        let device = normalized_device_identity(metadata.st_dev).map_err(|_| {
            ExecutionFailure::new(
                command.to_owned(),
                FailurePhase::Cleanup,
                format!(
                    "stdout artifact device identity is invalid during cleanup: {}",
                    self.path.display()
                ),
            )
        })?;
        let inode = metadata.st_ino;
        if device != self.device || inode != self.inode {
            return Err(ExecutionFailure::new(
                command.to_owned(),
                FailurePhase::Cleanup,
                format!(
                    "stdout artifact canonical name was replaced during cleanup: {}",
                    self.path.display()
                ),
            ));
        }
        rustix::fs::unlinkat(&self.parent, &self.name, rustix::fs::AtFlags::empty()).map_err(
            |source| {
                ExecutionFailure::new(
                    command.to_owned(),
                    FailurePhase::Cleanup,
                    format!(
                        "remove owned stdout artifact {}: {}",
                        self.path.display(),
                        std::io::Error::from_raw_os_error(source.raw_os_error())
                    ),
                )
            },
        )?;
        self.parent.sync_all().map_err(|source| {
            ExecutionFailure::new(
                command.to_owned(),
                FailurePhase::Cleanup,
                format!(
                    "synchronize stdout artifact parent {}: {source}",
                    self.path.display()
                ),
            )
        })
    }
}

#[cfg(unix)]
impl CaptureBroker {
    fn start(
        stdout: std::process::ChildStdout,
        stderr: std::process::ChildStderr,
        request: CaptureBrokerRequest<'_>,
        deadline: Instant,
    ) -> Result<Self, ExecutionFailure> {
        let CaptureBrokerRequest {
            stdout: stdout_target,
            maximum_stderr_bytes,
            current_dir,
            invocation_id,
            command,
            capture_broker,
        } = request;
        let stderr_broker_limit = maximum_stderr_bytes.checked_add(1).ok_or_else(|| {
            ExecutionFailure::new(
                command.to_owned(),
                FailurePhase::Capture,
                "captured output limit cannot reserve an overflow-detection byte",
            )
        })?;
        let base = current_dir.join("target/quality/capture");
        fs::create_dir_all(&base).map_err(|source| {
            ExecutionFailure::new(
                command.to_owned(),
                FailurePhase::Descriptor,
                format!("create capture broker directory: {source}"),
            )
        })?;
        let directory = base.join(format!("invocation-{invocation_id}"));
        fs::create_dir(&directory).map_err(|source| {
            ExecutionFailure::new(
                command.to_owned(),
                FailurePhase::Descriptor,
                format!("create invocation capture directory: {source}"),
            )
        })?;
        let (stdout_path, stdout_file, maximum_stdout_bytes, mut artifact_cleanup) =
            match stdout_target {
                StdoutTarget::Capture { maximum_bytes } => {
                    let path = directory.join("stdout");
                    let file = match create_capture_file(&path, command) {
                        Ok(file) => file,
                        Err(failure) => {
                            return match remove_capture_paths(&directory, &[]) {
                                Ok(()) => Err(failure),
                                Err(cleanup) => Err(cleanup),
                            };
                        },
                    };
                    (path, file, maximum_bytes, None)
                },
                StdoutTarget::Artifact {
                    artifact:
                        ArtifactOutput {
                            file,
                            parent,
                            name,
                            path,
                            device,
                            inode,
                        },
                    maximum_bytes,
                } => {
                    let cleanup = ArtifactCleanup {
                        parent,
                        name,
                        path: path.clone(),
                        device,
                        inode,
                    };
                    (path, file, maximum_bytes, Some(cleanup))
                },
            };
        let stdout_broker_limit = match maximum_stdout_bytes.checked_add(1) {
            Some(limit) => limit,
            None => {
                let failure = ExecutionFailure::new(
                    command.to_owned(),
                    FailurePhase::Capture,
                    "stdout artifact limit cannot reserve an overflow-detection byte",
                );
                let cleanup =
                    cleanup_capture_start(&directory, &[], artifact_cleanup.take(), command);
                return match cleanup {
                    Ok(()) => Err(failure),
                    Err(cleanup) => Err(cleanup),
                };
            },
        };
        let stderr_path = directory.join("stderr");
        let stderr_file = match create_capture_file(&stderr_path, command) {
            Ok(file) => file,
            Err(failure) => {
                let cleanup_paths = if artifact_cleanup.is_some() {
                    Vec::new()
                } else {
                    vec![stdout_path.as_path()]
                };
                return match cleanup_capture_start(
                    &directory,
                    &cleanup_paths,
                    artifact_cleanup.take(),
                    command,
                ) {
                    Ok(()) => Err(failure),
                    Err(cleanup) => Err(cleanup),
                };
            },
        };
        let stdout = match CaptureReader::start(
            stdout,
            stdout_file,
            CaptureReaderRequest {
                path: stdout_path.clone(),
                stream: "stdout",
                maximum_bytes: maximum_stdout_bytes,
                broker_limit: stdout_broker_limit,
                command,
                capture_broker,
            },
        ) {
            Ok(reader) => reader,
            Err(failure) => {
                let cleanup_paths = if artifact_cleanup.is_some() {
                    vec![stderr_path.as_path()]
                } else {
                    vec![stdout_path.as_path(), stderr_path.as_path()]
                };
                return match cleanup_capture_start(
                    &directory,
                    &cleanup_paths,
                    artifact_cleanup.take(),
                    command,
                ) {
                    Ok(()) => Err(failure),
                    Err(cleanup) => Err(cleanup),
                };
            },
        };
        let stderr = match CaptureReader::start(
            stderr,
            stderr_file,
            CaptureReaderRequest {
                path: stderr_path.clone(),
                stream: "stderr",
                maximum_bytes: maximum_stderr_bytes,
                broker_limit: stderr_broker_limit,
                command,
                capture_broker,
            },
        ) {
            Ok(reader) => reader,
            Err(failure) => {
                let broker_cleanup = stdout.abort(command, deadline);
                let cleanup_paths = if artifact_cleanup.is_some() {
                    vec![stderr_path.as_path()]
                } else {
                    vec![stdout_path.as_path(), stderr_path.as_path()]
                };
                let file_cleanup = cleanup_capture_start(
                    &directory,
                    &cleanup_paths,
                    artifact_cleanup.take(),
                    command,
                );
                return match (broker_cleanup, file_cleanup) {
                    (_, Err(cleanup)) | (Err(cleanup), Ok(())) => Err(cleanup),
                    (Ok(()), Ok(())) => Err(failure),
                };
            },
        };
        Ok(Self {
            stdout,
            stderr,
            directory,
            artifact_cleanup,
        })
    }

    fn join_until(
        mut self,
        command: &str,
        deadline: Instant,
        cancellation: &AtomicBool,
    ) -> Result<CapturedOutput, ExecutionFailure> {
        loop {
            if cancellation_requested(cancellation) {
                let failure = cancellation_failure(command);
                return match self.abort(command, deadline) {
                    Ok(()) => Err(failure),
                    Err(cleanup) => Err(cleanup),
                };
            }
            let stdout_complete = match self.stdout.poll(command) {
                Ok(complete) => complete,
                Err(failure) => {
                    return match self.abort(command, deadline) {
                        Ok(()) => Err(failure),
                        Err(cleanup) => Err(cleanup),
                    };
                },
            };
            let stderr_complete = match self.stderr.poll(command) {
                Ok(complete) => complete,
                Err(failure) => {
                    return match self.abort(command, deadline) {
                        Ok(()) => Err(failure),
                        Err(cleanup) => Err(cleanup),
                    };
                },
            };
            if stdout_complete && stderr_complete {
                return self.finish(command);
            }
            if Instant::now() >= deadline {
                let failure = ExecutionFailure::new(
                    command.to_owned(),
                    FailurePhase::Deadline,
                    "capture descriptors remained open after the invocation deadline",
                );
                return match self.abort(command, deadline) {
                    Ok(()) => Err(failure),
                    Err(cleanup) => Err(cleanup),
                };
            }
            wait_for_progress(deadline);
        }
    }

    fn finish(mut self, command: &str) -> Result<CapturedOutput, ExecutionFailure> {
        let retains_stdout_artifact = self.artifact_cleanup.is_some();
        let stdout = if retains_stdout_artifact {
            self.stdout.finish_artifact(command).map(|()| String::new())
        } else {
            self.stdout.finish(command)
        };
        let stderr = self.stderr.finish(command);
        let cleanup_paths = if retains_stdout_artifact {
            vec![self.stderr.path.as_path()]
        } else {
            vec![self.stdout.path.as_path(), self.stderr.path.as_path()]
        };
        let cleanup = remove_capture_paths(&self.directory, &cleanup_paths);
        let artifact_cleanup = if stdout.is_ok() && stderr.is_ok() && cleanup.is_ok() {
            self.artifact_cleanup.take();
            Ok(())
        } else {
            match self.artifact_cleanup.take() {
                Some(artifact) => artifact.remove_if_owned(command),
                None => Ok(()),
            }
        };
        match (stdout, stderr, cleanup, artifact_cleanup) {
            (_, _, _, Err(cleanup)) => Err(cleanup),
            (Ok(stdout), Ok(stderr), Ok(()), Ok(())) => Ok(CapturedOutput { stdout, stderr }),
            (Err(failure), _, _, Ok(())) | (Ok(_), Err(failure), _, Ok(())) => Err(failure),
            (Ok(_), Ok(_), Err(cleanup), Ok(())) => Err(cleanup),
        }
    }

    fn abort(mut self, command: &str, deadline: Instant) -> Result<(), ExecutionFailure> {
        let stdout_path = self.stdout.path.clone();
        let stderr_path = self.stderr.path.clone();
        let stdout = self.stdout.abort(command, deadline);
        let stderr = self.stderr.abort(command, deadline);
        let cleanup_paths = if self.artifact_cleanup.is_some() {
            vec![stderr_path.as_path()]
        } else {
            vec![stdout_path.as_path(), stderr_path.as_path()]
        };
        let cleanup = remove_capture_paths(&self.directory, &cleanup_paths);
        let artifact_cleanup = match self.artifact_cleanup.take() {
            Some(artifact) => artifact.remove_if_owned(command),
            None => Ok(()),
        };
        match (stdout, stderr, cleanup, artifact_cleanup) {
            (_, _, _, Err(cleanup)) => Err(cleanup),
            (Ok(()), Ok(()), Ok(()), Ok(())) => Ok(()),
            (Err(failure), _, _, Ok(())) | (Ok(()), Err(failure), _, Ok(())) => Err(failure),
            (Ok(()), Ok(()), Err(cleanup), Ok(())) => Err(cleanup),
        }
    }
}

#[cfg(unix)]
fn cleanup_capture_start(
    directory: &std::path::Path,
    paths: &[&std::path::Path],
    artifact: Option<ArtifactCleanup>,
    command: &str,
) -> Result<(), ExecutionFailure> {
    let capture_cleanup = remove_capture_paths(directory, paths);
    let artifact_cleanup = match artifact {
        Some(artifact) => artifact.remove_if_owned(command),
        None => Ok(()),
    };
    match (capture_cleanup, artifact_cleanup) {
        (_, Err(cleanup)) | (Err(cleanup), Ok(())) => Err(cleanup),
        (Ok(()), Ok(())) => Ok(()),
    }
}

#[cfg(unix)]
struct CaptureReader {
    child: Option<Child>,
    status: Option<ExitStatus>,
    path: PathBuf,
    stream: &'static str,
    maximum_bytes: usize,
}

#[cfg(unix)]
struct CaptureReaderRequest<'a> {
    path: PathBuf,
    stream: &'static str,
    maximum_bytes: usize,
    broker_limit: usize,
    command: &'a str,
    capture_broker: &'a std::path::Path,
}

#[cfg(unix)]
impl CaptureReader {
    fn start(
        input: impl Into<Stdio>,
        output: File,
        request: CaptureReaderRequest<'_>,
    ) -> Result<Self, ExecutionFailure> {
        let CaptureReaderRequest {
            path,
            stream,
            maximum_bytes,
            broker_limit,
            command,
            capture_broker,
        } = request;
        let child = std::process::Command::new(capture_broker)
            .env_clear()
            .args(["-c", &broker_limit.to_string()])
            .stdin(input)
            .stdout(Stdio::from(output))
            .stderr(Stdio::null())
            // positron-concurrency-spawn: CaptureReader::start\tcontrolled-capture-broker-v1
            .spawn()
            .map_err(|source| {
                ExecutionFailure::new(
                    command.to_owned(),
                    FailurePhase::Descriptor,
                    format!("start {stream} capture broker: {source}"),
                )
            })?;
        Ok(Self {
            child: Some(child),
            status: None,
            path,
            stream,
            maximum_bytes,
        })
    }

    fn poll(&mut self, command: &str) -> Result<bool, ExecutionFailure> {
        if self.status.is_some() {
            return Ok(true);
        }
        let child = self.child.as_mut().ok_or_else(|| {
            ExecutionFailure::new(
                command.to_owned(),
                FailurePhase::Capture,
                format!("{} capture broker lost its process handle", self.stream),
            )
        })?;
        match child.try_wait() {
            Ok(Some(status)) => {
                self.status = Some(status);
                Ok(true)
            },
            Ok(None) => Ok(false),
            Err(source) => Err(ExecutionFailure::new(
                command.to_owned(),
                FailurePhase::Capture,
                format!("observe {} capture broker: {source}", self.stream),
            )),
        }
    }

    fn finish(&mut self, command: &str) -> Result<String, ExecutionFailure> {
        self.validate_terminal_status(command)?;
        let output = File::open(&self.path).map_err(|source| {
            ExecutionFailure::new(
                command.to_owned(),
                FailurePhase::Capture,
                format!("open {} capture: {source}", self.stream),
            )
        })?;
        read_limited_output(output, self.maximum_bytes).map_err(|failure| {
            ExecutionFailure::new(
                command.to_owned(),
                FailurePhase::Capture,
                format!("{} capture failed: {}", self.stream, failure.detail),
            )
        })
    }

    fn finish_artifact(&mut self, command: &str) -> Result<(), ExecutionFailure> {
        self.validate_terminal_status(command)?;
        let artifact = File::open(&self.path).map_err(|source| {
            ExecutionFailure::new(
                command.to_owned(),
                FailurePhase::Capture,
                format!("open streamed stdout artifact: {source}"),
            )
        })?;
        let bytes = artifact
            .metadata()
            .map_err(|source| {
                ExecutionFailure::new(
                    command.to_owned(),
                    FailurePhase::Capture,
                    format!("inspect streamed stdout artifact: {source}"),
                )
            })?
            .len();
        if bytes > self.maximum_bytes as u64 {
            return Err(ExecutionFailure::new(
                command.to_owned(),
                FailurePhase::Capture,
                format!(
                    "streamed stdout artifact exceeded the {}-byte limit",
                    self.maximum_bytes
                ),
            ));
        }
        artifact.sync_all().map_err(|source| {
            ExecutionFailure::new(
                command.to_owned(),
                FailurePhase::Capture,
                format!("sync streamed stdout artifact: {source}"),
            )
        })
    }

    fn validate_terminal_status(&self, command: &str) -> Result<(), ExecutionFailure> {
        let status = self.status.ok_or_else(|| {
            ExecutionFailure::new(
                command.to_owned(),
                FailurePhase::Capture,
                format!("{} capture broker has no terminal status", self.stream),
            )
        })?;
        if !status.success() {
            return Err(ExecutionFailure::new(
                command.to_owned(),
                FailurePhase::Capture,
                format!("{} capture broker exited with {status}", self.stream),
            ));
        }
        Ok(())
    }

    fn abort(mut self, command: &str, deadline: Instant) -> Result<(), ExecutionFailure> {
        let Some(mut child) = self.child.take() else {
            return Ok(());
        };
        match child.try_wait() {
            Ok(Some(status)) => {
                self.status = Some(status);
                Ok(())
            },
            Ok(None) => {
                if let Err(source) = child.kill() {
                    return match child.try_wait() {
                        Ok(Some(status)) => {
                            self.status = Some(status);
                            Ok(())
                        },
                        Ok(None) | Err(_) => Err(ExecutionFailure::new(
                            command.to_owned(),
                            FailurePhase::Cleanup,
                            format!("kill {} capture broker: {source}", self.stream),
                        )),
                    };
                }
                wait_for_direct_child(&mut child, command, deadline, None, None).map(|status| {
                    self.status = Some(status);
                })
            },
            Err(source) => Err(ExecutionFailure::new(
                command.to_owned(),
                FailurePhase::Cleanup,
                format!(
                    "observe {} capture broker during cleanup: {source}",
                    self.stream
                ),
            )),
        }
    }
}

#[cfg(unix)]
fn create_capture_file(path: &std::path::Path, command: &str) -> Result<File, ExecutionFailure> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| {
            ExecutionFailure::new(
                command.to_owned(),
                FailurePhase::Descriptor,
                format!("create capture broker file {}: {source}", path.display()),
            )
        })
}

#[cfg(unix)]
fn remove_capture_paths(
    directory: &std::path::Path,
    paths: &[&std::path::Path],
) -> Result<(), ExecutionFailure> {
    let mut failures = Vec::new();
    for path in paths {
        if let Err(source) = fs::remove_file(path) {
            failures.push(format!(
                "remove capture broker file {}: {source}",
                path.display()
            ));
        }
    }
    if let Err(source) = fs::remove_dir(directory) {
        failures.push(format!("remove capture broker directory: {source}"));
    }
    if failures.is_empty() {
        return Ok(());
    }
    Err(ExecutionFailure::new(
        directory.display().to_string(),
        FailurePhase::Cleanup,
        failures.join("; "),
    ))
}

#[cfg(unix)]
struct OutputReadFailure {
    detail: String,
}

#[cfg(unix)]
fn read_limited_output(
    output: impl Read,
    maximum_bytes: usize,
) -> Result<String, OutputReadFailure> {
    let mut output = output;
    let mut bytes = Vec::with_capacity(maximum_bytes.min(8_192));
    let mut buffer = [0_u8; 8_192];
    let mut exceeded = false;

    // The broker caps its regular output file at one byte past the retained
    // limit. Reading that file is non-blocking with respect to escaped writers.
    loop {
        let read = output
            .read(&mut buffer)
            .map_err(|source| OutputReadFailure {
                detail: source.to_string(),
            })?;
        if read == 0 {
            break;
        }
        let retained = maximum_bytes.saturating_sub(bytes.len()).min(read);
        let retained_bytes = buffer.get(..retained).ok_or_else(|| OutputReadFailure {
            detail: "captured output retention exceeded the fixed read buffer".to_owned(),
        })?;
        bytes.extend_from_slice(retained_bytes);
        if retained != read {
            exceeded = true;
        }
    }

    if exceeded {
        return Err(OutputReadFailure {
            detail: format!("captured output exceeded the {maximum_bytes}-byte limit"),
        });
    }
    String::from_utf8(bytes).map_err(|source| OutputReadFailure {
        detail: source.to_string(),
    })
}

fn command_display(program: &OsStr, arguments: &[OsString]) -> String {
    let mut parts = Vec::with_capacity(arguments.len() + 1);
    parts.push(program.to_string_lossy().into_owned());
    parts.extend(
        arguments
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned()),
    );
    parts.join(" ")
}

#[cfg(all(test, unix))]
mod tests {
    use super::{
        ArtifactOutput, CapturedOutput, DEFAULT_SHUTDOWN_TIMEOUT, ExecutionFailure,
        ExecutionOutcome, ExecutionTools, ExecutionVerdict, FailurePhase, InvocationInput,
        InvocationSpec, OutputMode, execute,
    };
    use std::error::Error;
    use std::ffi::{OsStr, OsString};
    use std::fs::{self, File, OpenOptions};
    use std::io;
    use std::io::Write as _;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::PathBuf;
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::mpsc;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;
    static CANCELLATION_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn reconciles_a_successful_child_with_independent_captured_streams() -> TestResult {
        let verdict = reconciled(execute(captured_shell(
            "printf '%s' normal-stdout; printf '%s' normal-stderr >&2",
            Duration::from_secs(1),
        )?))?;

        if !verdict.status.success() {
            return Err(io::Error::other(format!(
                "successful controlled child returned {}",
                verdict.status
            ))
            .into());
        }
        assert_output(
            verdict.output,
            "normal-stdout",
            "normal-stderr",
            "successful controlled child",
        )
    }

    #[test]
    fn reconciles_an_immediate_child_after_its_process_group_disappears() -> TestResult {
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(1))
            .ok_or_else(|| io::Error::other("test group deadline cannot be represented"))?;
        let verdict = reconciled(execute(InvocationSpec {
            program: OsString::from("/usr/bin/true"),
            arguments: Vec::new(),
            current_dir: std::env::current_dir()?,
            environment: Vec::new(),
            tools: test_execution_tools()?,
            input: InvocationInput::Null,
            output: OutputMode::Capture {
                maximum_bytes_per_stream: 1_024,
            },
            cancellation: Arc::new(AtomicBool::new(false)),
            deadline,
            shutdown_timeout: DEFAULT_SHUTDOWN_TIMEOUT,
            cancellation_marker: None,
        }))?;

        if !verdict.status.success() {
            return Err(io::Error::other(format!(
                "immediate controlled child returned {}",
                verdict.status
            ))
            .into());
        }
        assert_output(
            verdict.output,
            "",
            "",
            "immediate controlled child with an empty process group",
        )
    }

    #[test]
    fn reconciles_a_nonzero_child_with_independent_captured_streams() -> TestResult {
        let verdict = reconciled(execute(captured_shell(
            "printf '%s' nonzero-stdout; printf '%s' nonzero-stderr >&2; exit 23",
            Duration::from_secs(1),
        )?))?;

        if verdict.status.code() != Some(23) {
            return Err(io::Error::other(format!(
                "nonzero controlled child returned {} instead of exit status 23",
                verdict.status
            ))
            .into());
        }
        assert_output(
            verdict.output,
            "nonzero-stdout",
            "nonzero-stderr",
            "nonzero controlled child",
        )
    }

    #[test]
    fn exposes_only_the_invocation_environment_to_the_controlled_child() -> TestResult {
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(1))
            .ok_or_else(|| io::Error::other("test environment deadline cannot be represented"))?;
        let verdict = reconciled(execute(InvocationSpec {
            program: OsString::from("/usr/bin/env"),
            arguments: Vec::new(),
            current_dir: std::env::current_dir()?,
            environment: vec![(
                OsString::from("POSITRON_CONTROLLED_MARKER"),
                OsString::from("isolated"),
            )],
            tools: test_execution_tools()?,
            input: InvocationInput::Null,
            output: OutputMode::Capture {
                maximum_bytes_per_stream: 1_024,
            },
            cancellation: Arc::new(AtomicBool::new(false)),
            deadline,
            shutdown_timeout: DEFAULT_SHUTDOWN_TIMEOUT,
            cancellation_marker: None,
        }))?;

        if !verdict.status.success() {
            return Err(io::Error::other(format!(
                "environment-controlled child returned {}",
                verdict.status
            ))
            .into());
        }
        assert_output(
            verdict.output,
            "POSITRON_CONTROLLED_MARKER=isolated\n",
            "",
            "environment-controlled child",
        )
    }

    #[test]
    fn returns_a_typed_launch_failure_for_an_unstartable_program() -> TestResult {
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(1))
            .ok_or_else(|| io::Error::other("test launch deadline cannot be represented"))?;
        let outcome = execute(InvocationSpec {
            program: OsString::from("/dev/null/positron-controlled-launch-failure"),
            arguments: Vec::new(),
            current_dir: std::env::current_dir()?,
            environment: Vec::new(),
            tools: test_execution_tools()?,
            input: InvocationInput::Null,
            output: OutputMode::Capture {
                maximum_bytes_per_stream: 1_024,
            },
            cancellation: Arc::new(AtomicBool::new(false)),
            deadline,
            shutdown_timeout: DEFAULT_SHUTDOWN_TIMEOUT,
            cancellation_marker: None,
        });

        match outcome {
            ExecutionOutcome::Failed(failure) if failure.phase == FailurePhase::Launch => Ok(()),
            ExecutionOutcome::Failed(failure) => Err(io::Error::other(format!(
                "unstartable program returned {} instead of launch: {}",
                failure.phase.as_str(),
                failure.detail
            ))
            .into()),
            ExecutionOutcome::Reconciled(verdict) => Err(io::Error::other(format!(
                "unstartable program reconciled with {}",
                verdict.status
            ))
            .into()),
        }
    }

    #[test]
    fn returns_a_closed_deadline_failure_after_terminating_the_direct_child() -> TestResult {
        let outcome = execute(captured_shell(
            "exec /bin/sleep 60",
            Duration::from_millis(50),
        )?);

        match outcome {
            ExecutionOutcome::Failed(failure) if failure.phase == FailurePhase::Deadline => Ok(()),
            ExecutionOutcome::Failed(failure) => Err(io::Error::other(format!(
                "controlled deadline returned {} instead of deadline: {}",
                failure.phase.as_str(),
                failure.detail
            ))
            .into()),
            ExecutionOutcome::Reconciled(verdict) => Err(io::Error::other(format!(
                "deadline-exceeded controlled child reconciled with {}",
                verdict.status
            ))
            .into()),
        }
    }

    #[test]
    fn returns_a_closed_cancellation_failure_after_terminating_the_direct_child() -> TestResult {
        let protocol = CancellationProtocol::create()?;
        let cancellation = Arc::new(AtomicBool::new(false));
        let worker_cancellation = Arc::clone(&cancellation);
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(2))
            .ok_or_else(|| io::Error::other("test cancellation deadline cannot be represented"))?;
        let specification = InvocationSpec {
            program: OsString::from("/bin/sh"),
            arguments: vec![
                OsString::from("-c"),
                OsString::from(
                    ": > \"$POSITRON_CONTROLLED_READY\"; read -r _ < \"$POSITRON_CONTROLLED_RELEASE\"",
                ),
            ],
            current_dir: std::env::current_dir()?,
            environment: protocol.environment(),
            tools: test_execution_tools()?,
            input: InvocationInput::Null,
            output: OutputMode::Capture {
                maximum_bytes_per_stream: 1_024,
            },
            cancellation: worker_cancellation,
            deadline,
            shutdown_timeout: DEFAULT_SHUTDOWN_TIMEOUT,
            cancellation_marker: None,
        };
        let worker = thread::spawn(move || execute(specification));

        let ready = protocol.wait_until_ready(Duration::from_secs(1));
        cancellation.store(true, Ordering::Release);
        let outcome = joined_outcome(worker, "cancellation");
        let cleanup = protocol.remove();
        cleanup?;
        ready?;
        let outcome = outcome?;

        match outcome {
            ExecutionOutcome::Failed(failure) if failure.phase == FailurePhase::Cancellation => {
                Ok(())
            },
            ExecutionOutcome::Failed(failure) => Err(io::Error::other(format!(
                "controlled cancellation returned {} instead of cancellation: {}",
                failure.phase.as_str(),
                failure.detail
            ))
            .into()),
            ExecutionOutcome::Reconciled(verdict) => Err(io::Error::other(format!(
                "cancelled controlled child reconciled with {}",
                verdict.status
            ))
            .into()),
        }
    }

    #[test]
    fn one_shutdown_deadline_bounds_slow_process_control_without_starting_capture_brokers()
    -> TestResult {
        let protocol = CancellationProtocol::create()?;
        let helpers = SlowExecutionTools::create(Duration::from_millis(40))?;
        let cancellation = Arc::new(AtomicBool::new(false));
        let worker_cancellation = Arc::clone(&cancellation);
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(2))
            .ok_or_else(|| io::Error::other("slow-helper execution deadline overflowed"))?;
        let specification = InvocationSpec {
            program: OsString::from("/bin/sh"),
            arguments: vec![
                OsString::from("-c"),
                OsString::from(": > \"$POSITRON_CONTROLLED_READY\"; exec /bin/sleep 60"),
            ],
            current_dir: std::env::current_dir()?,
            environment: protocol.environment(),
            tools: helpers.tools(),
            input: InvocationInput::Null,
            output: OutputMode::Discard,
            cancellation: worker_cancellation,
            deadline,
            shutdown_timeout: Duration::from_millis(100),
            cancellation_marker: None,
        };
        let worker = thread::spawn(move || execute(specification));

        protocol.wait_until_ready(Duration::from_secs(1))?;
        cancellation.store(true, Ordering::Release);
        let outcome = joined_outcome(worker, "slow process-control cancellation")?;
        let capture_started = helpers.capture_started();
        let helper_cleanup = helpers.remove();
        let protocol_cleanup = protocol.remove();
        helper_cleanup?;
        protocol_cleanup?;
        if capture_started? {
            return Err(io::Error::other(
                "discard output mode started a capture broker during bounded shutdown",
            )
            .into());
        }
        let ExecutionOutcome::Failed(failure) = outcome else {
            return Err(io::Error::other(
                "slow process-control cancellation unexpectedly reconciled",
            )
            .into());
        };
        let observed = failure.shutdown.ok_or_else(|| {
            io::Error::other("slow process-control failure omitted shutdown evidence")
        })?;
        if observed.bound != Duration::from_millis(100)
            || observed.elapsed >= Duration::from_millis(150)
            || failure.phase != FailurePhase::Cleanup
        {
            return Err(io::Error::other(format!(
                "slow process-control helper escaped one shutdown deadline: phase={}, bound={}ms, elapsed={}ms",
                failure.phase.as_str(),
                observed.bound.as_millis(),
                observed.elapsed.as_millis(),
            ))
            .into());
        }
        Ok(())
    }

    #[test]
    fn returns_a_closed_descendant_failure_after_killing_a_term_ignoring_group() -> TestResult {
        let protocol = TermIgnoringProtocol::create()?;
        let mut specification = captured_shell(
            r#"
(
  trap '' TERM
  : > "$POSITRON_CONTROLLED_READY"
  while :; do
    /bin/sleep 60
  done
) &
printf '%s\n' "$!" > "$POSITRON_CONTROLLED_PID"
while [ ! -f "$POSITRON_CONTROLLED_READY" ]; do
  :
done
"#,
            Duration::from_secs(3),
        )?;
        specification.environment = protocol.environment();

        let outcome = execute(specification);
        let descendant_running = protocol.descendant_is_running();
        let cleanup = protocol.remove();
        cleanup?;
        if descendant_running? {
            return Err(io::Error::other(
                format!(
                    "controlled owner returned before killing the TERM-ignoring process group: {outcome:?}"
                ),
            )
            .into());
        }

        match outcome {
            ExecutionOutcome::Failed(failure) if failure.phase == FailurePhase::Descendant => {
                Ok(())
            },
            ExecutionOutcome::Failed(failure) => Err(io::Error::other(format!(
                "TERM-ignoring controlled group returned {} instead of descendant: {}",
                failure.phase.as_str(),
                failure.detail
            ))
            .into()),
            ExecutionOutcome::Reconciled(verdict) => Err(io::Error::other(format!(
                "TERM-ignoring controlled group reconciled with {}",
                verdict.status
            ))
            .into()),
        }
    }

    #[test]
    fn returns_a_bounded_deadline_failure_when_an_escaped_descendant_retains_capture_descriptors()
    -> TestResult {
        let outcome = execute_escaped_descriptor_fixture_with_deadline(Duration::from_millis(100))?;
        match outcome {
            ExecutionOutcome::Failed(failure) if failure.phase == FailurePhase::Deadline => Ok(()),
            ExecutionOutcome::Failed(failure) => Err(io::Error::other(format!(
                "escaped capture descriptors returned {} instead of deadline: {}",
                failure.phase.as_str(),
                failure.detail
            ))
            .into()),
            ExecutionOutcome::Reconciled(verdict) => Err(io::Error::other(format!(
                "escaped capture descriptors reconciled with {}",
                verdict.status
            ))
            .into()),
        }
    }

    #[test]
    fn returns_a_bounded_cancellation_failure_when_an_escaped_descendant_retains_descriptors_and_unread_input()
    -> TestResult {
        let outcome = execute_escaped_descriptor_fixture_with_cancellation_and_unread_input()?;
        match outcome {
            ExecutionOutcome::Failed(failure) if failure.phase == FailurePhase::Cancellation => {
                Ok(())
            },
            ExecutionOutcome::Failed(failure) => Err(io::Error::other(format!(
                "cancelled escaped capture descriptors returned {} instead of cancellation: {}",
                failure.phase.as_str(),
                failure.detail
            ))
            .into()),
            ExecutionOutcome::Reconciled(verdict) => Err(io::Error::other(format!(
                "cancelled escaped capture descriptors reconciled with {}",
                verdict.status
            ))
            .into()),
        }
    }

    #[test]
    fn returns_a_bounded_deadline_failure_when_an_escaped_descendant_retains_unread_input()
    -> TestResult {
        let outcome = execute_escaped_descriptor_fixture_with_deadline_and_unread_input(
            Duration::from_secs(1),
        )?;
        match outcome {
            ExecutionOutcome::Failed(failure) if failure.phase == FailurePhase::Deadline => Ok(()),
            ExecutionOutcome::Failed(failure) => Err(io::Error::other(format!(
                "escaped unread input returned {} instead of deadline: {}",
                failure.phase.as_str(),
                failure.detail
            ))
            .into()),
            ExecutionOutcome::Reconciled(verdict) => Err(io::Error::other(format!(
                "escaped unread input reconciled with {}",
                verdict.status
            ))
            .into()),
        }
    }

    #[test]
    fn reconciles_parallel_invocations_when_the_shorter_one_is_observed_first() -> TestResult {
        let start = Arc::new(Barrier::new(2));
        let first_start = Arc::clone(&start);
        let mut first_specification = captured_shell(
            "printf 'first:%s' \"$POSITRON_CONTROLLED_MARKER\"; /bin/sleep 1; printf '%s' first-after; printf '%s' first-stderr >&2",
            Duration::from_secs(2),
        )?;
        first_specification.environment = vec![(
            OsString::from("POSITRON_CONTROLLED_MARKER"),
            OsString::from("alpha"),
        )];
        let second_start = Arc::clone(&start);
        let mut second_specification = captured_shell(
            "printf 'second:%s' \"$POSITRON_CONTROLLED_MARKER\"; printf '%s' second-stderr >&2",
            Duration::from_secs(2),
        )?;
        second_specification.environment = vec![(
            OsString::from("POSITRON_CONTROLLED_MARKER"),
            OsString::from("beta"),
        )];

        let first = thread::spawn(move || {
            first_start.wait();
            execute(first_specification)
        });
        let second = thread::spawn(move || {
            second_start.wait();
            execute(second_specification)
        });

        let second_outcome = joined_outcome(second, "second")?;
        let first_outcome = joined_outcome(first, "first")?;
        let second = reconciled(second_outcome)?;
        let first = reconciled(first_outcome)?;

        if !first.status.success() || !second.status.success() {
            return Err(io::Error::other(format!(
                "parallel controlled children returned first={}; second={}",
                first.status, second.status
            ))
            .into());
        }
        assert_output(
            first.output,
            "first:alphafirst-after",
            "first-stderr",
            "first parallel controlled child",
        )?;
        assert_output(
            second.output,
            "second:beta",
            "second-stderr",
            "second parallel controlled child",
        )
    }

    #[test]
    fn reports_capture_failure_without_waiting_for_the_execution_deadline() -> TestResult {
        let started = Instant::now();
        let outcome = execute(captured_shell_with_limit(
            "exec /bin/dd if=/dev/zero bs=65536 count=32 2>/dev/null",
            Duration::from_secs(2),
            16,
        )?);
        let elapsed = started.elapsed();

        if elapsed >= Duration::from_secs(1) {
            return Err(io::Error::other(format!(
                "over-limit capture returned after {elapsed:?}, indicating a descriptor stall"
            ))
            .into());
        }
        match outcome {
            ExecutionOutcome::Failed(failure) if failure.phase == FailurePhase::Capture => Ok(()),
            ExecutionOutcome::Failed(failure) => Err(io::Error::other(format!(
                "over-limit capture returned {} instead of capture: {}",
                failure.phase.as_str(),
                failure.detail
            ))
            .into()),
            ExecutionOutcome::Reconciled(verdict) => Err(io::Error::other(format!(
                "over-limit capture reconciled with {}",
                verdict.status
            ))
            .into()),
        }
    }

    #[test]
    fn streams_stdout_above_the_capture_ceiling_without_retaining_it_in_memory() -> TestResult {
        let directory = artifact_test_directory("above-capture-ceiling")?;
        let artifact = directory.join("metadata.json");
        let outcome = execute(artifact_output_specification(
            &directory, &artifact, 196_608, 262_144,
        )?);
        let result = (|| {
            let verdict = reconciled(outcome)?;
            if !verdict.status.success() {
                return Err(io::Error::other(format!(
                    "streamed artifact child returned {}",
                    verdict.status
                ))
                .into());
            }
            if !verdict.output.stdout.is_empty() {
                return Err(
                    io::Error::other("streamed artifact was also retained in memory").into(),
                );
            }
            if fs::metadata(&artifact)?.len() != 196_608 {
                return Err(io::Error::other(
                    "streamed artifact did not retain the exact stdout length",
                )
                .into());
            }
            Ok(())
        })();
        let cleanup = fs::remove_dir_all(&directory);
        cleanup?;
        result
    }

    #[test]
    fn rejects_and_removes_a_streamed_stdout_artifact_above_eight_mibibytes() -> TestResult {
        let directory = artifact_test_directory("above-artifact-limit")?;
        let artifact = directory.join("metadata.json");
        let outcome = execute(artifact_output_specification(
            &directory, &artifact, 9_437_184, 8_388_608,
        )?);
        let result = match outcome {
            ExecutionOutcome::Failed(failure)
                if failure.phase == FailurePhase::Capture
                    && failure
                        .detail
                        .contains("streamed stdout artifact exceeded the 8388608-byte limit") =>
            {
                if artifact.try_exists()? {
                    Err(
                        io::Error::other("over-limit streamed stdout artifact was not removed")
                            .into(),
                    )
                } else {
                    Ok(())
                }
            },
            ExecutionOutcome::Failed(failure) => Err(io::Error::other(format!(
                "over-limit streamed artifact returned {} instead of capture: {}",
                failure.phase.as_str(),
                failure.detail
            ))
            .into()),
            ExecutionOutcome::Reconciled(verdict) => Err(io::Error::other(format!(
                "over-limit streamed artifact reconciled with {}",
                verdict.status
            ))
            .into()),
        };
        let cleanup = fs::remove_dir_all(&directory);
        cleanup?;
        result
    }

    fn captured_shell(script: &str, timeout: Duration) -> TestResult<InvocationSpec> {
        captured_shell_with_limit(script, timeout, 1_024)
    }

    fn artifact_test_directory(subject: &str) -> TestResult<PathBuf> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let sequence = CANCELLATION_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "positron-controlled-{subject}-{}-{timestamp}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&directory)?;
        Ok(directory)
    }

    fn artifact_output_specification(
        current_dir: &std::path::Path,
        artifact_path: &std::path::Path,
        output_bytes: usize,
        maximum_artifact_bytes: usize,
    ) -> TestResult<InvocationSpec> {
        if !output_bytes.is_multiple_of(1_024) {
            return Err(io::Error::other("artifact test size must be a multiple of 1024").into());
        }
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(3))
            .ok_or_else(|| io::Error::other("artifact test deadline cannot be represented"))?;
        let artifact_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(artifact_path)?;
        let artifact_metadata = artifact_file.metadata()?;
        let artifact_parent_path = artifact_path
            .parent()
            .ok_or_else(|| io::Error::other("artifact test path has no parent"))?;
        let artifact_parent = File::open(artifact_parent_path)?;
        let artifact_name = artifact_path
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or_else(|| io::Error::other("artifact test name is not UTF-8"))?
            .to_owned();
        Ok(InvocationSpec {
            program: OsString::from("/bin/dd"),
            arguments: vec![
                OsString::from("if=/dev/zero"),
                OsString::from("bs=1024"),
                OsString::from(format!("count={}", output_bytes / 1_024)),
            ],
            current_dir: current_dir.to_path_buf(),
            environment: Vec::new(),
            tools: test_execution_tools()?,
            input: InvocationInput::Null,
            output: OutputMode::CaptureWithStdoutArtifact {
                artifact: ArtifactOutput::new(
                    artifact_file,
                    artifact_parent,
                    artifact_name,
                    artifact_path.to_path_buf(),
                    artifact_metadata.dev(),
                    artifact_metadata.ino(),
                ),
                maximum_artifact_bytes,
                maximum_stderr_bytes: 131_072,
            },
            cancellation: Arc::new(AtomicBool::new(false)),
            deadline,
            shutdown_timeout: DEFAULT_SHUTDOWN_TIMEOUT,
            cancellation_marker: None,
        })
    }

    fn escaped_descriptor_spec(
        protocol: &EscapedDescriptorProtocol,
        cancellation: Arc<AtomicBool>,
        timeout: Duration,
    ) -> TestResult<InvocationSpec> {
        let python = python3_path()?;
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| io::Error::other("test escape deadline cannot be represented"))?;
        Ok(InvocationSpec {
            program: python.into_os_string(),
            arguments: vec![
                OsString::from("-c"),
                OsString::from(
                    r#"
import os
import sys
import time

synchronization_read, synchronization_write = os.pipe()
with open(sys.argv[3], "w", encoding="utf-8") as direct_identity:
    direct_identity.write(str(os.getpid()))
child = os.fork()
if child == 0:
    os.close(synchronization_read)
    os.setsid()
    release = os.open(sys.argv[2], os.O_RDONLY | os.O_NONBLOCK)
    with open(sys.argv[1], "w", encoding="utf-8") as identity:
        identity.write(str(os.getpid()))
    os.write(synchronization_write, b"1")
    os.close(synchronization_write)
    while True:
        try:
            if os.read(release, 1):
                break
        except BlockingIOError:
            time.sleep(0.005)
    os.close(release)
    os._exit(0)

os.close(synchronization_write)
if os.read(synchronization_read, 1) != b"1":
    os._exit(1)
os.close(synchronization_read)
os._exit(0)
"#,
                ),
                protocol.pid.as_os_str().to_owned(),
                protocol.release.as_os_str().to_owned(),
                protocol.direct_pid.as_os_str().to_owned(),
            ],
            current_dir: std::env::current_dir()?,
            environment: Vec::new(),
            tools: test_execution_tools()?,
            input: InvocationInput::Null,
            output: OutputMode::Capture {
                maximum_bytes_per_stream: 1_024,
            },
            cancellation,
            deadline,
            shutdown_timeout: DEFAULT_SHUTDOWN_TIMEOUT,
            cancellation_marker: None,
        })
    }

    fn execute_escaped_descriptor_fixture_with_deadline(
        timeout: Duration,
    ) -> TestResult<ExecutionOutcome> {
        let protocol = EscapedDescriptorProtocol::create()?;
        let specification =
            escaped_descriptor_spec(&protocol, Arc::new(AtomicBool::new(false)), timeout)?;
        let outcome = execute(specification);
        let cleanup = protocol.remove();
        cleanup?;
        Ok(outcome)
    }

    fn execute_escaped_descriptor_fixture_with_cancellation_and_unread_input()
    -> TestResult<ExecutionOutcome> {
        let protocol = EscapedDescriptorProtocol::create()?;
        let cancellation = Arc::new(AtomicBool::new(false));
        let mut specification =
            escaped_descriptor_spec(&protocol, Arc::clone(&cancellation), Duration::from_secs(2))?;
        specification.input = InvocationInput::Bytes(vec![b'x'; 2_097_152]);
        let (sender, receiver) = mpsc::channel();
        let worker = thread::spawn(move || sender.send(execute(specification)));

        let result = (|| {
            protocol.wait_until_direct_child_stops(Duration::from_secs(1))?;
            cancellation.store(true, Ordering::Release);
            let outcome = match receiver.recv_timeout(Duration::from_secs(1)) {
                Ok(outcome) => outcome,
                Err(source) => {
                    protocol.release()?;
                    let published = receiver.recv_timeout(Duration::from_secs(2)).map_err(
                        |release_source| {
                            io::Error::other(format!(
                                "controlled owner remained blocked after cancellation test release: {release_source}"
                            ))
                        },
                    )?;
                    let send = worker.join().map_err(|_| {
                        io::Error::other("escaped-descriptor execution worker panicked")
                    })?;
                    send.map_err(|_| {
                        io::Error::other(
                            "escaped-descriptor execution worker could not publish its outcome",
                        )
                    })?;
                    let _published_after_release = published;
                    return Err(io::Error::other(format!(
                        "controlled owner did not reconcile escaped capture descriptors after cancellation: {source}"
                    ))
                    .into());
                },
            };
            protocol.release()?;
            let send = worker
                .join()
                .map_err(|_| io::Error::other("escaped-descriptor execution worker panicked"))?;
            send.map_err(|_| {
                io::Error::other(
                    "escaped-descriptor execution worker could not publish its outcome",
                )
            })?;
            Ok(outcome)
        })();
        let cleanup = protocol.remove();
        cleanup?;
        result
    }

    fn execute_escaped_descriptor_fixture_with_deadline_and_unread_input(
        timeout: Duration,
    ) -> TestResult<ExecutionOutcome> {
        let protocol = EscapedDescriptorProtocol::create()?;
        let mut specification =
            escaped_descriptor_spec(&protocol, Arc::new(AtomicBool::new(false)), timeout)?;
        specification.input = InvocationInput::Bytes(vec![b'x'; 2_097_152]);
        let outcome = execute(specification);
        let cleanup = protocol.remove();
        cleanup?;
        Ok(outcome)
    }

    fn captured_shell_with_limit(
        script: &str,
        timeout: Duration,
        maximum_bytes_per_stream: usize,
    ) -> TestResult<InvocationSpec> {
        let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
            io::Error::other("test controlled-execution deadline cannot be represented")
        })?;
        Ok(InvocationSpec {
            program: OsString::from("/bin/sh"),
            arguments: vec![OsString::from("-c"), OsString::from(script)],
            current_dir: std::env::current_dir()?,
            environment: Vec::new(),
            tools: test_execution_tools()?,
            input: InvocationInput::Null,
            output: OutputMode::Capture {
                maximum_bytes_per_stream,
            },
            cancellation: Arc::new(AtomicBool::new(false)),
            deadline,
            shutdown_timeout: DEFAULT_SHUTDOWN_TIMEOUT,
            cancellation_marker: None,
        })
    }

    fn reconciled(outcome: ExecutionOutcome) -> TestResult<ExecutionVerdict> {
        match outcome {
            ExecutionOutcome::Reconciled(verdict) => Ok(verdict),
            ExecutionOutcome::Failed(failure) => Err(failure_error(failure).into()),
        }
    }

    fn joined_outcome(
        worker: thread::JoinHandle<ExecutionOutcome>,
        subject: &str,
    ) -> TestResult<ExecutionOutcome> {
        worker
            .join()
            .map_err(|_| {
                io::Error::other(format!("{subject} controlled-invocation worker panicked"))
            })
            .map_err(Into::into)
    }

    fn assert_output(
        output: CapturedOutput,
        expected_stdout: &str,
        expected_stderr: &str,
        subject: &str,
    ) -> TestResult {
        if output.stdout != expected_stdout || output.stderr != expected_stderr {
            return Err(io::Error::other(format!(
                "{subject} returned stdout={:?}; stderr={:?}",
                output.stdout, output.stderr
            ))
            .into());
        }
        Ok(())
    }

    fn failure_error(failure: ExecutionFailure) -> io::Error {
        io::Error::other(format!(
            "controlled owner failed during {} for `{}`: {}",
            failure.phase.as_str(),
            failure.command,
            failure.detail
        ))
    }

    struct SlowExecutionTools {
        directory: PathBuf,
        process_control: PathBuf,
        capture_broker: PathBuf,
        capture_marker: PathBuf,
    }

    impl SlowExecutionTools {
        fn create(delay: Duration) -> TestResult<Self> {
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
            let sequence = CANCELLATION_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let directory = std::env::temp_dir().join(format!(
                "positron-controlled-slow-tools-{}-{timestamp}-{sequence}",
                std::process::id()
            ));
            fs::create_dir_all(&directory)?;
            let process_control = directory.join("process-control");
            let capture_broker = directory.join("capture-broker");
            let capture_marker = directory.join("capture-started");
            let delay_seconds = format!("{:.3}", delay.as_secs_f64());
            fs::write(
                &process_control,
                format!("#!/bin/sh\n/bin/sleep {delay_seconds}\nexec /bin/kill \"$@\"\n"),
            )?;
            fs::write(
                &capture_broker,
                format!(
                    "#!/bin/sh\n: > '{}'\nexec /usr/bin/head \"$@\"\n",
                    capture_marker.display()
                ),
            )?;
            for path in [&process_control, &capture_broker] {
                let mut permissions = fs::metadata(path)?.permissions();
                permissions.set_mode(0o755);
                fs::set_permissions(path, permissions)?;
            }
            Ok(Self {
                directory,
                process_control,
                capture_broker,
                capture_marker,
            })
        }

        fn tools(&self) -> ExecutionTools {
            ExecutionTools {
                process_control: self.process_control.clone(),
                capture_broker: self.capture_broker.clone(),
            }
        }

        fn capture_started(&self) -> TestResult<bool> {
            Ok(self.capture_marker.try_exists()?)
        }

        fn remove(self) -> TestResult {
            fs::remove_dir_all(self.directory)?;
            Ok(())
        }
    }

    struct CancellationProtocol {
        directory: PathBuf,
        ready: PathBuf,
        release: PathBuf,
    }

    impl CancellationProtocol {
        fn create() -> TestResult<Self> {
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
            let sequence = CANCELLATION_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let directory = std::env::temp_dir().join(format!(
                "positron-controlled-cancellation-{}-{timestamp}-{sequence}",
                std::process::id()
            ));
            fs::create_dir_all(&directory)?;
            let release = directory.join("release");
            let status = Command::new("mkfifo").arg(&release).status()?;
            if !status.success() {
                return Err(io::Error::other(format!(
                    "create controlled cancellation FIFO failed with {status}"
                ))
                .into());
            }
            Ok(Self {
                ready: directory.join("ready"),
                directory,
                release,
            })
        }

        fn environment(&self) -> Vec<(OsString, OsString)> {
            vec![
                (
                    OsString::from("POSITRON_CONTROLLED_READY"),
                    self.ready.as_os_str().to_owned(),
                ),
                (
                    OsString::from("POSITRON_CONTROLLED_RELEASE"),
                    self.release.as_os_str().to_owned(),
                ),
            ]
        }

        fn wait_until_ready(&self, timeout: Duration) -> TestResult {
            let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
                io::Error::other("test cancellation readiness deadline cannot be represented")
            })?;
            while !self.ready.is_file() {
                if Instant::now() >= deadline {
                    return Err(io::Error::other(
                        "controlled cancellation child did not complete its readiness handshake",
                    )
                    .into());
                }
                thread::yield_now();
            }
            Ok(())
        }

        fn remove(self) -> TestResult {
            fs::remove_dir_all(self.directory)?;
            Ok(())
        }
    }

    struct TermIgnoringProtocol {
        directory: PathBuf,
        ready: PathBuf,
        pid: PathBuf,
    }

    impl TermIgnoringProtocol {
        fn create() -> TestResult<Self> {
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
            let sequence = CANCELLATION_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let directory = std::env::temp_dir().join(format!(
                "positron-controlled-term-ignore-{}-{timestamp}-{sequence}",
                std::process::id()
            ));
            fs::create_dir_all(&directory)?;
            Ok(Self {
                ready: directory.join("ready"),
                pid: directory.join("descendant.pid"),
                directory,
            })
        }

        fn environment(&self) -> Vec<(OsString, OsString)> {
            vec![
                (
                    OsString::from("POSITRON_CONTROLLED_READY"),
                    self.ready.as_os_str().to_owned(),
                ),
                (
                    OsString::from("POSITRON_CONTROLLED_PID"),
                    self.pid.as_os_str().to_owned(),
                ),
            ]
        }

        fn descendant_is_running(&self) -> TestResult<bool> {
            let pid = fs::read_to_string(&self.pid)?.trim().to_owned();
            let status = Command::new("/bin/kill")
                .args(["-0", &pid])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()?;
            Ok(status.success())
        }

        fn remove(self) -> TestResult {
            if self.pid.is_file() && self.descendant_is_running()? {
                let pid = fs::read_to_string(&self.pid)?.trim().to_owned();
                let status = Command::new("/bin/kill")
                    .args(["-KILL", &pid])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()?;
                if !status.success() {
                    return Err(io::Error::other(format!(
                        "test cleanup could not kill TERM-ignoring descendant: {status}"
                    ))
                    .into());
                }
            }
            fs::remove_dir_all(self.directory)?;
            Ok(())
        }
    }

    struct EscapedDescriptorProtocol {
        directory: PathBuf,
        release: PathBuf,
        pid: PathBuf,
        direct_pid: PathBuf,
        released: AtomicBool,
    }

    impl EscapedDescriptorProtocol {
        fn create() -> TestResult<Self> {
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
            let sequence = CANCELLATION_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let directory = PathBuf::from("/tmp")
                .join(format!("pce-{}-{timestamp}-{sequence}", std::process::id()));
            fs::create_dir_all(&directory)?;
            let release = directory.join("release");
            let status = Command::new("/usr/bin/mkfifo").arg(&release).status()?;
            if !status.success() {
                return Err(io::Error::other(format!(
                    "create escaped-descriptor release FIFO failed with {status}"
                ))
                .into());
            }
            Ok(Self {
                pid: directory.join("descendant.pid"),
                direct_pid: directory.join("direct.pid"),
                directory,
                release,
                released: AtomicBool::new(false),
            })
        }

        fn wait_until_direct_child_stops(&self, timeout: Duration) -> TestResult {
            let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
                io::Error::other("test direct-child deadline cannot be represented")
            })?;
            while process_identity_is_running(&self.direct_pid)? {
                if Instant::now() >= deadline {
                    return Err(io::Error::other(
                        "escaped-descriptor direct child remained alive before cancellation",
                    )
                    .into());
                }
                thread::yield_now();
            }
            Ok(())
        }

        fn descendant_is_running(&self) -> TestResult<bool> {
            process_identity_is_running(&self.pid)
        }

        fn release(&self) -> TestResult {
            if self.released.load(Ordering::Acquire) {
                return Ok(());
            }
            if !self.descendant_is_running()? {
                return Ok(());
            }
            let mut release = OpenOptions::new().write(true).open(&self.release)?;
            release.write_all(b"1")?;
            self.released.store(true, Ordering::Release);
            Ok(())
        }

        fn remove(self) -> TestResult {
            self.release()?;
            let deadline = Instant::now()
                .checked_add(Duration::from_secs(2))
                .ok_or_else(|| io::Error::other("test cleanup deadline cannot be represented"))?;
            while self.descendant_is_running()? {
                if Instant::now() >= deadline {
                    let pid = fs::read_to_string(&self.pid)?.trim().to_owned();
                    let status = Command::new("/bin/kill").args(["-KILL", &pid]).status()?;
                    if !status.success() {
                        return Err(io::Error::other(format!(
                            "test cleanup could not kill escaped descendant: {status}"
                        ))
                        .into());
                    }
                    break;
                }
                thread::yield_now();
            }
            fs::remove_dir_all(self.directory)?;
            Ok(())
        }
    }

    fn process_identity_is_running(identity: &std::path::Path) -> TestResult<bool> {
        if !identity.is_file() {
            return Ok(false);
        }
        let pid = fs::read_to_string(identity)?.trim().to_owned();
        let status = Command::new("/bin/kill")
            .args(["-0", &pid])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        Ok(status.success())
    }

    fn test_execution_tools() -> TestResult<ExecutionTools> {
        Ok(ExecutionTools {
            process_control: fs::canonicalize("/bin/kill")?,
            capture_broker: fs::canonicalize("/usr/bin/head")?,
        })
    }

    fn python3_path() -> TestResult<PathBuf> {
        for candidate in ["/usr/bin/python3", "/opt/homebrew/bin/python3"] {
            let path = PathBuf::from(candidate);
            if path.is_file() {
                return Ok(path);
            }
        }
        Err(io::Error::other(
            "escaped-descriptor regression requires an absolute Python 3 interpreter",
        )
        .into())
    }
}
