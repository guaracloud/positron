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

const PLATFORM_CONTROL_BUDGET: Duration = Duration::from_secs(1);
const TERMINATION_GRACE: Duration = Duration::from_secs(1);
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
    /// The complete deadline for direct execution and reconciliation.
    pub(crate) deadline: Instant,
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OutputMode {
    /// Forward output to the invoking terminal without buffering it.
    Inherit,
    /// Capture independently bounded standard output and standard error.
    Capture { maximum_bytes_per_stream: usize },
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
}

impl ExecutionFailure {
    fn new(command: String, phase: FailurePhase, detail: impl Into<String>) -> Self {
        Self {
            command,
            phase,
            detail: detail.into(),
        }
    }
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
    configure_standard_descriptors(&mut command, specification.output, &specification.input);
    configure_isolated_process_group(&mut command);

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
        &command_display,
        specification.output,
        specification.input,
        &specification.current_dir,
        &specification.tools,
    ) {
        Ok(workers) => workers,
        Err(failure) => {
            return finish_after_setup_failure(&mut child, &group, failure);
        },
    };

    let status = match wait_for_direct_child(
        &mut child,
        &command_display,
        specification.deadline,
        Some(specification.cancellation.as_ref()),
    ) {
        Ok(status) => status,
        Err(failure) => {
            return finish_after_execution_failure(&mut child, &group, &mut workers, failure);
        },
    };

    if cancellation_requested(specification.cancellation.as_ref()) {
        return finish_after_execution_failure(
            &mut child,
            &group,
            &mut workers,
            cancellation_failure(&command_display),
        );
    }

    match group.exists(&command_display) {
        Ok(true) => {
            let failure = ExecutionFailure::new(
                command_display,
                FailurePhase::Descendant,
                "the direct child exited while its controlled process group still owned descendants or inherited descriptors",
            );
            finish_after_execution_failure(&mut child, &group, &mut workers, failure)
        },
        Ok(false) => {
            if cancellation_requested(specification.cancellation.as_ref()) {
                return finish_after_execution_failure(
                    &mut child,
                    &group,
                    &mut workers,
                    cancellation_failure(&command_display),
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
        Err(failure) => finish_after_execution_failure(&mut child, &group, &mut workers, failure),
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
    output: OutputMode,
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
        OutputMode::Inherit => {
            command.stdout(Stdio::inherit()).stderr(Stdio::inherit());
        },
        OutputMode::Capture { .. } => {
            command.stdout(Stdio::piped()).stderr(Stdio::piped());
        },
    }
}

#[cfg(unix)]
fn finish_after_setup_failure(
    child: &mut Child,
    group: &ProcessGroup,
    failure: ExecutionFailure,
) -> ExecutionOutcome {
    match terminate_and_reap(child, group, &failure.command) {
        Ok(()) => ExecutionOutcome::Failed(failure),
        Err(cleanup) => ExecutionOutcome::Failed(cleanup),
    }
}

#[cfg(unix)]
fn finish_after_execution_failure(
    child: &mut Child,
    group: &ProcessGroup,
    workers: &mut OwnedWorkers,
    failure: ExecutionFailure,
) -> ExecutionOutcome {
    let cleanup = terminate_and_reap(child, group, &failure.command);
    let workers_result = workers.abort(&failure.command);
    match (cleanup, workers_result) {
        (Ok(()), Ok(())) => ExecutionOutcome::Failed(failure),
        (Err(cleanup), _) => ExecutionOutcome::Failed(cleanup),
        (Ok(()), Err(worker)) => ExecutionOutcome::Failed(worker),
    }
}

#[cfg(unix)]
fn wait_for_direct_child(
    child: &mut Child,
    command: &str,
    deadline: Instant,
    cancellation: Option<&AtomicBool>,
) -> Result<ExitStatus, ExecutionFailure> {
    loop {
        if let Some(cancellation) = cancellation
            && cancellation_requested(cancellation)
        {
            return Err(cancellation_failure(command));
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
) -> Result<(), ExecutionFailure> {
    group.signal(Signal::Terminate, command)?;
    let grace_deadline = Instant::now() + TERMINATION_GRACE;
    if !wait_for_group_while_reaping_direct(child, group, command, grace_deadline)? {
        group.signal(Signal::Kill, command)?;
        let kill_deadline = Instant::now() + TERMINATION_GRACE;
        if !wait_for_group_while_reaping_direct(child, group, command, kill_deadline)? {
            return Err(group.not_empty_failure(command));
        }
    }
    let reap_deadline = Instant::now() + TERMINATION_GRACE;
    wait_for_direct_child(child, command, reap_deadline, None).map(|_| ())
}

#[cfg(unix)]
fn wait_for_group_while_reaping_direct(
    child: &mut Child,
    group: &ProcessGroup,
    command: &str,
    deadline: Instant,
) -> Result<bool, ExecutionFailure> {
    loop {
        child.try_wait().map_err(|source| {
            ExecutionFailure::new(
                command.to_owned(),
                FailurePhase::DirectProcess,
                source.to_string(),
            )
        })?;
        if !group.exists(command)? {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        wait_for_progress(deadline);
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

    fn exists(&self, command: &str) -> Result<bool, ExecutionFailure> {
        let target = format!("-{}", self.identifier);
        let status = run_platform_kill(
            &[
                OsString::from("-0"),
                OsString::from("--"),
                OsString::from(target),
            ],
            command,
            &self.process_control,
        )?;
        Ok(status.success())
    }

    fn signal(&self, signal: Signal, command: &str) -> Result<(), ExecutionFailure> {
        if !self.exists(command)? {
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
        )?;
        if status.success() || !self.exists(command)? {
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
) -> Result<ExitStatus, ExecutionFailure> {
    let mut child = std::process::Command::new(process_control)
        .env_clear()
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|source| {
            ExecutionFailure::new(
                command.to_owned(),
                FailurePhase::Cleanup,
                source.to_string(),
            )
        })?;
    let deadline = Instant::now() + PLATFORM_CONTROL_BUDGET;
    match wait_for_direct_child(&mut child, command, deadline, None) {
        Ok(status) => Ok(status),
        Err(failure) if failure.phase == FailurePhase::Deadline => {
            child.kill().map_err(|source| {
                ExecutionFailure::new(
                    command.to_owned(),
                    FailurePhase::Cleanup,
                    source.to_string(),
                )
            })?;
            let reap_deadline = Instant::now() + PLATFORM_CONTROL_BUDGET;
            wait_for_direct_child(&mut child, command, reap_deadline, None).map(|_| ())?;
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
struct OwnedWorkers {
    capture: Option<CaptureBroker>,
    input: Option<InputBroker>,
}

#[cfg(unix)]
impl OwnedWorkers {
    fn start(
        child: &mut Child,
        command: &str,
        output: OutputMode,
        input: InvocationInput,
        current_dir: &std::path::Path,
        tools: &ExecutionTools,
    ) -> Result<Self, ExecutionFailure> {
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
        let capture_pipes = match output {
            OutputMode::Inherit => None,
            OutputMode::Capture {
                maximum_bytes_per_stream,
            } => {
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
                Some((stdout, stderr, maximum_bytes_per_stream))
            },
        };
        let mut capture = match capture_pipes {
            Some((stdout, stderr, maximum_bytes_per_stream)) => Some(CaptureBroker::start(
                stdout,
                stderr,
                CaptureBrokerRequest {
                    maximum_bytes: maximum_bytes_per_stream,
                    current_dir,
                    invocation_id: child.id(),
                    command,
                    capture_broker: &tools.capture_broker,
                },
            )?),
            None => None,
        };
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
                        Some(capture) => capture.abort(command),
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
                Some(capture) => capture.abort(command),
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

    fn abort(&mut self, command: &str) -> Result<(), ExecutionFailure> {
        let capture = match self.capture.take() {
            Some(capture) => capture.abort(command),
            None => Ok(()),
        };
        let input = match self.input.take() {
            Some(input) => input.abort(command),
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
                return match self.abort(command) {
                    Ok(()) => Err(failure),
                    Err(cleanup) => Err(cleanup),
                };
            }
            match self.poll(command) {
                Ok(Some(status)) => return self.finish(command, status),
                Ok(None) => {},
                Err(failure) => {
                    return match self.abort(command) {
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
                return match self.abort(command) {
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

    fn abort(mut self, command: &str) -> Result<(), ExecutionFailure> {
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
                        let deadline = Instant::now() + PLATFORM_CONTROL_BUDGET;
                        wait_for_direct_child(&mut child, command, deadline, None).map(|status| {
                            self.status = Some(status);
                        })
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
}

#[cfg(unix)]
struct CaptureBrokerRequest<'a> {
    maximum_bytes: usize,
    current_dir: &'a std::path::Path,
    invocation_id: u32,
    command: &'a str,
    capture_broker: &'a std::path::Path,
}

#[cfg(unix)]
impl CaptureBroker {
    fn start(
        stdout: std::process::ChildStdout,
        stderr: std::process::ChildStderr,
        request: CaptureBrokerRequest<'_>,
    ) -> Result<Self, ExecutionFailure> {
        let CaptureBrokerRequest {
            maximum_bytes,
            current_dir,
            invocation_id,
            command,
            capture_broker,
        } = request;
        let broker_limit = maximum_bytes.checked_add(1).ok_or_else(|| {
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
        let stdout_path = directory.join("stdout");
        let stderr_path = directory.join("stderr");
        let stdout_file = match create_capture_file(&stdout_path, command) {
            Ok(file) => file,
            Err(failure) => {
                return match fs::remove_dir(&directory) {
                    Ok(()) => Err(failure),
                    Err(source) => Err(ExecutionFailure::new(
                        command.to_owned(),
                        FailurePhase::Cleanup,
                        format!("remove incomplete capture directory: {source}"),
                    )),
                };
            },
        };
        let stderr_file = match create_capture_file(&stderr_path, command) {
            Ok(file) => file,
            Err(failure) => {
                return match remove_capture_paths(&directory, &[&stdout_path]) {
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
                maximum_bytes,
                broker_limit,
                command,
                capture_broker,
            },
        ) {
            Ok(reader) => reader,
            Err(failure) => {
                return match remove_capture_paths(&directory, &[&stdout_path, &stderr_path]) {
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
                maximum_bytes,
                broker_limit,
                command,
                capture_broker,
            },
        ) {
            Ok(reader) => reader,
            Err(failure) => {
                let broker_cleanup = stdout.abort(command);
                let file_cleanup = remove_capture_paths(&directory, &[&stdout_path, &stderr_path]);
                return match (broker_cleanup, file_cleanup) {
                    (Ok(()), Ok(())) => Err(failure),
                    (Err(cleanup), _) | (Ok(()), Err(cleanup)) => Err(cleanup),
                };
            },
        };
        Ok(Self {
            stdout,
            stderr,
            directory,
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
                return match self.abort(command) {
                    Ok(()) => Err(failure),
                    Err(cleanup) => Err(cleanup),
                };
            }
            let stdout_complete = match self.stdout.poll(command) {
                Ok(complete) => complete,
                Err(failure) => {
                    return match self.abort(command) {
                        Ok(()) => Err(failure),
                        Err(cleanup) => Err(cleanup),
                    };
                },
            };
            let stderr_complete = match self.stderr.poll(command) {
                Ok(complete) => complete,
                Err(failure) => {
                    return match self.abort(command) {
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
                return match self.abort(command) {
                    Ok(()) => Err(failure),
                    Err(cleanup) => Err(cleanup),
                };
            }
            wait_for_progress(deadline);
        }
    }

    fn finish(mut self, command: &str) -> Result<CapturedOutput, ExecutionFailure> {
        let stdout = self.stdout.finish(command);
        let stderr = self.stderr.finish(command);
        let cleanup =
            remove_capture_paths(&self.directory, &[&self.stdout.path, &self.stderr.path]);
        match (stdout, stderr, cleanup) {
            (Ok(stdout), Ok(stderr), Ok(())) => Ok(CapturedOutput { stdout, stderr }),
            (Err(failure), _, _) | (Ok(_), Err(failure), _) => Err(failure),
            (Ok(_), Ok(_), Err(cleanup)) => Err(cleanup),
        }
    }

    fn abort(self, command: &str) -> Result<(), ExecutionFailure> {
        let stdout_path = self.stdout.path.clone();
        let stderr_path = self.stderr.path.clone();
        let stdout = self.stdout.abort(command);
        let stderr = self.stderr.abort(command);
        let cleanup = remove_capture_paths(&self.directory, &[&stdout_path, &stderr_path]);
        match (stdout, stderr, cleanup) {
            (Ok(()), Ok(()), Ok(())) => Ok(()),
            (Err(failure), _, _) | (Ok(()), Err(failure), _) => Err(failure),
            (Ok(()), Ok(()), Err(cleanup)) => Err(cleanup),
        }
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

    fn abort(mut self, command: &str) -> Result<(), ExecutionFailure> {
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
                let deadline = Instant::now() + PLATFORM_CONTROL_BUDGET;
                wait_for_direct_child(&mut child, command, deadline, None).map(|status| {
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
        CapturedOutput, ExecutionFailure, ExecutionOutcome, ExecutionTools, ExecutionVerdict,
        FailurePhase, InvocationInput, InvocationSpec, OutputMode, execute,
    };
    use std::error::Error;
    use std::ffi::OsString;
    use std::fs::{self, OpenOptions};
    use std::io;
    use std::io::Write as _;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::mpsc::{self, RecvTimeoutError};
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
                "controlled owner returned before killing the TERM-ignoring process group",
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
        let protocol = EscapedDescriptorProtocol::create()?;
        let specification = escaped_descriptor_spec(
            &protocol,
            Arc::new(AtomicBool::new(false)),
            Duration::from_millis(100),
        )?;
        let (sender, receiver) = mpsc::channel();
        let worker = thread::spawn(move || sender.send(execute(specification)));

        let result = (|| {
            protocol.wait_until_ready(Duration::from_secs(1))?;
            let outcome = match receiver.recv_timeout(Duration::from_secs(1)) {
                Ok(outcome) => outcome,
                Err(RecvTimeoutError::Timeout) => {
                    protocol.release()?;
                    let released = receiver.recv_timeout(Duration::from_secs(2)).map_err(
                        |source| {
                            io::Error::other(format!(
                                "controlled owner remained blocked after test descriptor release: {source}"
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
                    let _released_outcome = released;
                    return Err(io::Error::other(
                        "controlled owner did not reconcile escaped capture descriptors before its deadline",
                    )
                    .into());
                },
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(io::Error::other(
                        "escaped-descriptor execution worker disconnected without an outcome",
                    )
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

            match outcome {
                ExecutionOutcome::Failed(failure) if failure.phase == FailurePhase::Deadline => {
                    Ok(())
                },
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
        })();
        let cleanup = protocol.remove();
        cleanup?;
        result
    }

    #[test]
    fn returns_a_bounded_cancellation_failure_when_an_escaped_descendant_retains_descriptors_and_unread_input()
    -> TestResult {
        let protocol = EscapedDescriptorProtocol::create()?;
        let cancellation = Arc::new(AtomicBool::new(false));
        let mut specification =
            escaped_descriptor_spec(&protocol, Arc::clone(&cancellation), Duration::from_secs(2))?;
        specification.input = InvocationInput::Bytes(vec![b'x'; 2_097_152]);
        let (sender, receiver) = mpsc::channel();
        let worker = thread::spawn(move || sender.send(execute(specification)));

        let result = (|| {
            protocol.wait_until_ready(Duration::from_secs(1))?;
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

            match outcome {
                ExecutionOutcome::Failed(failure)
                    if failure.phase == FailurePhase::Cancellation =>
                {
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
        })();
        let cleanup = protocol.remove();
        cleanup?;
        result
    }

    #[test]
    fn returns_a_bounded_deadline_failure_when_an_escaped_descendant_retains_unread_input()
    -> TestResult {
        let protocol = EscapedDescriptorProtocol::create()?;
        let mut specification = escaped_descriptor_spec(
            &protocol,
            Arc::new(AtomicBool::new(false)),
            Duration::from_secs(1),
        )?;
        specification.input = InvocationInput::Bytes(vec![b'x'; 2_097_152]);
        let (sender, receiver) = mpsc::channel();
        let worker = thread::spawn(move || sender.send(execute(specification)));

        let result = (|| {
            protocol.wait_until_ready(Duration::from_secs(1))?;
            let outcome = match receiver.recv_timeout(Duration::from_secs(2)) {
                Ok(outcome) => outcome,
                Err(RecvTimeoutError::Timeout) => {
                    protocol.release()?;
                    let released =
                        receiver
                            .recv_timeout(Duration::from_secs(2))
                            .map_err(|source| {
                                io::Error::other(format!(
                                    "controlled owner remained blocked after test input release: {source}"
                                ))
                            })?;
                    let send = worker
                        .join()
                        .map_err(|_| io::Error::other("escaped-input execution worker panicked"))?;
                    send.map_err(|_| {
                        io::Error::other(
                            "escaped-input execution worker could not publish its outcome",
                        )
                    })?;
                    let _released_outcome = released;
                    return Err(io::Error::other(
                        "controlled owner did not reconcile escaped unread input before its deadline",
                    )
                    .into());
                },
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(io::Error::other(
                        "escaped-input execution worker disconnected without an outcome",
                    )
                    .into());
                },
            };
            protocol.release()?;
            let send = worker
                .join()
                .map_err(|_| io::Error::other("escaped-input execution worker panicked"))?;
            send.map_err(|_| {
                io::Error::other("escaped-input execution worker could not publish its outcome")
            })?;

            match outcome {
                ExecutionOutcome::Failed(failure) if failure.phase == FailurePhase::Deadline => {
                    Ok(())
                },
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
        })();
        let cleanup = protocol.remove();
        cleanup?;
        result
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

    fn captured_shell(script: &str, timeout: Duration) -> TestResult<InvocationSpec> {
        captured_shell_with_limit(script, timeout, 1_024)
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
import socket
import sys
import time

synchronization_read, synchronization_write = os.pipe()
with open(sys.argv[4], "w", encoding="utf-8") as direct_identity:
    direct_identity.write(str(os.getpid()))
child = os.fork()
if child == 0:
    os.close(synchronization_read)
    os.setsid()
    release = os.open(sys.argv[3], os.O_RDONLY | os.O_NONBLOCK)
    with open(sys.argv[2], "w", encoding="utf-8") as identity:
        identity.write(str(os.getpid()))
    readiness = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    readiness.sendto(b"ready", sys.argv[1])
    readiness.close()
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
                protocol.readiness_socket_path().as_os_str().to_owned(),
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
        })
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
        readiness_socket: std::os::unix::net::UnixDatagram,
        readiness_socket_path: PathBuf,
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
            let readiness_socket_path = directory.join("ready.sock");
            let readiness_socket = std::os::unix::net::UnixDatagram::bind(&readiness_socket_path)?;
            let release = directory.join("release");
            let status = Command::new("/usr/bin/mkfifo").arg(&release).status()?;
            if !status.success() {
                return Err(io::Error::other(format!(
                    "create escaped-descriptor release FIFO failed with {status}"
                ))
                .into());
            }
            Ok(Self {
                readiness_socket,
                readiness_socket_path,
                pid: directory.join("descendant.pid"),
                direct_pid: directory.join("direct.pid"),
                directory,
                release,
                released: AtomicBool::new(false),
            })
        }

        fn readiness_socket_path(&self) -> &std::path::Path {
            &self.readiness_socket_path
        }

        fn wait_until_ready(&self, timeout: Duration) -> TestResult {
            self.readiness_socket.set_read_timeout(Some(timeout))?;
            let mut signal = [0_u8; b"ready".len()];
            let received = match self.readiness_socket.recv(&mut signal) {
                Ok(received) => received,
                Err(source)
                    if matches!(
                        source.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) =>
                {
                    return Err(io::Error::other(
                        "escaped descendant did not complete its readiness handshake",
                    )
                    .into());
                },
                Err(source) => return Err(source.into()),
            };
            if received != signal.len() || signal != *b"ready" {
                return Err(io::Error::other(
                    "escaped descendant published an invalid readiness handshake",
                )
                .into());
            }
            Ok(())
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
