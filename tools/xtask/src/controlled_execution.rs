//! Controlled, bounded execution for external quality-harness invocations.
//!
//! This module is the sole semantic owner for child launch, process-group
//! ownership, descriptor capture, bounded waiting, termination, reaping, and
//! final execution verdicts used by `xtask` tooling. A reconciled verdict
//! proves that the direct child has exited, its process group has no remaining
//! members, and every owned capture or input worker has joined.

use std::ffi::{OsStr, OsString};
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
    /// The owned standard input contract.
    pub(crate) input: InvocationInput,
    /// The owned output-descriptor contract.
    pub(crate) output: OutputMode,
    /// The caller-owned cancellation signal for this invocation only.
    pub(crate) cancellation: Arc<AtomicBool>,
    /// The complete deadline for direct execution and reconciliation.
    pub(crate) deadline: Instant,
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
    let group = ProcessGroup::new(child.id());
    let mut workers = match OwnedWorkers::start(
        &mut child,
        &command_display,
        specification.output,
        specification.input,
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
            match workers.join(&command_display) {
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
    let workers_result = workers.join(&failure.command);
    match (cleanup, workers_result) {
        (Ok(()), Ok(_)) => ExecutionOutcome::Failed(failure),
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
    match wait_for_direct_child(child, command, grace_deadline, None) {
        Ok(_) => {},
        Err(failure) if failure.phase == FailurePhase::Deadline => {
            group.signal(Signal::Kill, command)?;
            let kill_deadline = Instant::now() + TERMINATION_GRACE;
            wait_for_direct_child(child, command, kill_deadline, None).map(|_| ())?;
        },
        Err(failure) => return Err(failure),
    }
    let group_deadline = Instant::now() + TERMINATION_GRACE;
    group.wait_until_empty(command, group_deadline)
}

#[cfg(unix)]
fn wait_for_progress(deadline: Instant) {
    let remaining = deadline.saturating_duration_since(Instant::now());
    thread::park_timeout(remaining.min(POLL_INTERVAL));
}

#[cfg(unix)]
struct ProcessGroup {
    identifier: u32,
}

#[cfg(unix)]
impl ProcessGroup {
    fn new(identifier: u32) -> Self {
        Self { identifier }
    }

    fn exists(&self, command: &str) -> Result<bool, ExecutionFailure> {
        let target = format!("-{}", self.identifier);
        let status = run_platform_kill(&[OsString::from("-0"), OsString::from(target)], command)?;
        Ok(status.success())
    }

    fn signal(&self, signal: Signal, command: &str) -> Result<(), ExecutionFailure> {
        if !self.exists(command)? {
            return Ok(());
        }
        let target = format!("-{}", self.identifier);
        let status = run_platform_kill(
            &[OsString::from(signal.flag()), OsString::from(target)],
            command,
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

    fn wait_until_empty(&self, command: &str, deadline: Instant) -> Result<(), ExecutionFailure> {
        loop {
            if !self.exists(command)? {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(ExecutionFailure::new(
                    command.to_owned(),
                    FailurePhase::Cleanup,
                    format!(
                        "controlled process group {} remained alive after bounded termination",
                        self.identifier
                    ),
                ));
            }
            wait_for_progress(deadline);
        }
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
) -> Result<ExitStatus, ExecutionFailure> {
    let mut child = std::process::Command::new("/bin/kill")
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
    stdout: Option<OutputReader>,
    stderr: Option<OutputReader>,
    stdin: Option<InputWriter>,
}

#[cfg(unix)]
impl OwnedWorkers {
    fn start(
        child: &mut Child,
        command: &str,
        output: OutputMode,
        input: InvocationInput,
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
        let stdin = input_pipe.map(|(stdin, bytes)| InputWriter::spawn(stdin, bytes));
        let (stdout, stderr) = match capture_pipes {
            Some((stdout, stderr, maximum_bytes_per_stream)) => (
                Some(OutputReader::spawn(stdout, maximum_bytes_per_stream)),
                Some(OutputReader::spawn(stderr, maximum_bytes_per_stream)),
            ),
            None => (None, None),
        };
        Ok(Self {
            stdout,
            stderr,
            stdin,
        })
    }

    fn join(&mut self, command: &str) -> Result<CapturedOutput, ExecutionFailure> {
        if let Some(writer) = self.stdin.take() {
            writer.join(command)?;
        }
        let stdout = match self.stdout.take() {
            Some(reader) => reader.join(command, "stdout")?,
            None => String::new(),
        };
        let stderr = match self.stderr.take() {
            Some(reader) => reader.join(command, "stderr")?,
            None => String::new(),
        };
        Ok(CapturedOutput { stdout, stderr })
    }
}

#[cfg(unix)]
struct InputWriter {
    worker: thread::JoinHandle<std::io::Result<()>>,
}

#[cfg(unix)]
impl InputWriter {
    fn spawn(mut input: std::process::ChildStdin, bytes: Vec<u8>) -> Self {
        let worker = thread::spawn(move || {
            input.write_all(&bytes)?;
            Ok(())
        });
        Self { worker }
    }

    fn join(self, command: &str) -> Result<(), ExecutionFailure> {
        match self.worker.join() {
            Ok(Ok(())) => Ok(()),
            Ok(Err(source)) => Err(ExecutionFailure::new(
                command.to_owned(),
                FailurePhase::Input,
                source.to_string(),
            )),
            Err(_) => Err(ExecutionFailure::new(
                command.to_owned(),
                FailurePhase::Input,
                "owned input worker terminated unexpectedly",
            )),
        }
    }
}

#[cfg(unix)]
struct OutputReader {
    worker: thread::JoinHandle<Result<String, OutputReadFailure>>,
}

#[cfg(unix)]
impl OutputReader {
    fn spawn(output: impl Read + Send + 'static, maximum_bytes: usize) -> Self {
        let worker = thread::spawn(move || read_limited_output(output, maximum_bytes));
        Self { worker }
    }

    fn join(self, command: &str, stream: &str) -> Result<String, ExecutionFailure> {
        match self.worker.join() {
            Ok(Ok(output)) => Ok(output),
            Ok(Err(failure)) => Err(ExecutionFailure::new(
                command.to_owned(),
                FailurePhase::Capture,
                format!("{stream} capture failed: {}", failure.detail),
            )),
            Err(_) => Err(ExecutionFailure::new(
                command.to_owned(),
                FailurePhase::Capture,
                format!("owned {stream} capture worker terminated unexpectedly"),
            )),
        }
    }
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

    // Keep draining after the retained limit so an owned child cannot block on
    // a full descriptor pipe. Storage remains capped; the invocation deadline
    // bounds a child that writes forever.
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
        CapturedOutput, ExecutionFailure, ExecutionOutcome, ExecutionVerdict, FailurePhase,
        InvocationInput, InvocationSpec, OutputMode, execute,
    };
    use std::error::Error;
    use std::ffi::OsString;
    use std::fs;
    use std::io;
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
}
