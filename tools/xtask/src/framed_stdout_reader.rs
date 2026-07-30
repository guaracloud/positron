//! Parent-owned nonblocking reader for registered runner frames.

#![cfg(unix)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::bounded_runner_frames::{self, ControlFrame};

const POLL_INTERVAL: Duration = Duration::from_millis(5);
const READ_CHUNK_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FailurePhase {
    Descriptor,
    Capture,
    ControlDelivery,
    Cancellation,
    Deadline,
    Cleanup,
}

#[derive(Debug)]
pub(crate) struct Failure {
    pub(crate) phase: FailurePhase,
    pub(crate) detail: String,
    pub(crate) cleanup: Option<String>,
}

impl Failure {
    fn new(phase: FailurePhase, detail: impl Into<String>) -> Self {
        Self {
            phase,
            detail: detail.into(),
            cleanup: None,
        }
    }

    fn with_cleanup(mut self, cleanup: Self) -> Self {
        self.cleanup = Some(cleanup.detail);
        self
    }
}

pub(crate) struct FramedStdoutReader {
    stdout: Option<std::process::ChildStdout>,
    stderr: Option<std::process::ChildStderr>,
    maximum_bytes: usize,
    captured: Vec<u8>,
    inspected: usize,
    captured_stderr: Vec<u8>,
    inspected_stderr: usize,
    completed: Option<String>,
}

impl FramedStdoutReader {
    pub(crate) fn start(
        stdout: std::process::ChildStdout,
        stderr: std::process::ChildStderr,
        maximum_bytes: usize,
    ) -> Result<Self, Failure> {
        if maximum_bytes == 0 {
            return Err(Failure::new(
                FailurePhase::Capture,
                "framed stdout byte bound must be positive",
            ));
        }
        make_nonblocking(&stdout, "stdout")?;
        make_nonblocking(&stderr, "stderr")?;
        Ok(Self {
            stdout: Some(stdout),
            stderr: Some(stderr),
            maximum_bytes,
            captured: Vec::with_capacity(maximum_bytes.min(1_024)),
            inspected: 0,
            captured_stderr: Vec::with_capacity(maximum_bytes.min(1_024)),
            inspected_stderr: 0,
            completed: None,
        })
    }

    pub(crate) fn poll_control_frame(&mut self) -> Result<(), Failure> {
        self.poll_stderr()?;
        self.poll_stdout()
    }

    pub(crate) fn join_until(
        mut self,
        deadline: Instant,
        cancellation: &AtomicBool,
    ) -> Result<String, Failure> {
        loop {
            if let Err(failure) = self.poll_control_frame() {
                return match self.abort(deadline) {
                    Ok(()) => Err(failure),
                    Err(cleanup) => Err(failure.with_cleanup(cleanup)),
                };
            }
            if cancellation.load(Ordering::Acquire) {
                let failure = Failure::new(
                    FailurePhase::Cancellation,
                    "the caller requested cancellation before reconciliation completed",
                );
                return match self.abort(deadline) {
                    Ok(()) => Err(failure),
                    Err(cleanup) => Err(failure.with_cleanup(cleanup)),
                };
            }
            if self.completed.is_some() {
                return self.finish();
            }
            if Instant::now() >= deadline {
                let failure = Failure::new(
                    FailurePhase::Deadline,
                    "framed stdout descriptor remained open after the invocation deadline",
                );
                return match self.abort(deadline) {
                    Ok(()) => Err(failure),
                    Err(cleanup) => Err(failure.with_cleanup(cleanup)),
                };
            }
            wait_for_progress(deadline);
        }
    }

    pub(crate) fn abort(mut self, deadline: Instant) -> Result<(), Failure> {
        let descriptors_already_closed = self.stdout.is_none() && self.stderr.is_none();
        self.close_descriptors();
        if !descriptors_already_closed && Instant::now() > deadline {
            return Err(Failure::new(
                FailurePhase::Cleanup,
                "framed stdout reader exceeded the registered shutdown deadline",
            ));
        }
        Ok(())
    }

    pub(crate) fn close_descriptors(&mut self) {
        self.stdout.take();
        self.stderr.take();
    }

    fn poll_stdout(&mut self) -> Result<(), Failure> {
        if self.completed.is_some() {
            return Ok(());
        }
        let mut chunk = [0_u8; READ_CHUNK_BYTES];
        loop {
            let state = match self.stdout.as_ref() {
                Some(stdout) => read_nonblocking(stdout, &mut chunk, "stdout")?,
                None => return Ok(()),
            };
            match state {
                ReadState::NoData => return Ok(()),
                ReadState::End => {
                    self.stdout.take();
                    let captured = std::mem::take(&mut self.captured);
                    let stdout = String::from_utf8(captured).map_err(|_| {
                        Failure::new(FailurePhase::Capture, "framed stdout was not valid UTF-8")
                    })?;
                    bounded_runner_frames::parse_captured(&stdout).map_err(|source| {
                        Failure::new(
                            FailurePhase::Capture,
                            format!(
                                "framed stdout reader completed before a valid outcome: {source}"
                            ),
                        )
                    })?;
                    self.completed = Some(stdout);
                    return Ok(());
                },
                ReadState::Bytes(count) => {
                    append_bounded(
                        &mut self.captured,
                        &chunk,
                        count,
                        self.maximum_bytes,
                        "stdout",
                    )?;
                    while let Some(line) = next_line(&self.captured, &mut self.inspected, "stdout")?
                    {
                        match bounded_runner_frames::control_frame(line) {
                            Some(ControlFrame::RunnerReady) => {
                                return Err(Failure::new(
                                    FailurePhase::Cancellation,
                                    "bounded runner reported runner-ready-v1 and requested controlled shutdown",
                                ));
                            },
                            Some(ControlFrame::LifecycleStalled) => {
                                return Err(Failure::new(
                                    FailurePhase::Deadline,
                                    "bounded runner reported lifecycle-stalled-v1 and retained live task ownership",
                                ));
                            },
                            None => {},
                        }
                    }
                },
            }
        }
    }

    fn poll_stderr(&mut self) -> Result<(), Failure> {
        let mut chunk = [0_u8; READ_CHUNK_BYTES];
        loop {
            let state = match self.stderr.as_ref() {
                Some(stderr) => read_nonblocking(stderr, &mut chunk, "stderr")?,
                None => return Ok(()),
            };
            match state {
                ReadState::NoData => return Ok(()),
                ReadState::End => {
                    self.stderr.take();
                    return Ok(());
                },
                ReadState::Bytes(count) => {
                    append_bounded(
                        &mut self.captured_stderr,
                        &chunk,
                        count,
                        self.maximum_bytes,
                        "stderr",
                    )?;
                    while let Some(line) =
                        next_line(&self.captured_stderr, &mut self.inspected_stderr, "stderr")?
                    {
                        match bounded_runner_frames::control_delivery_failure(line) {
                            Ok(Some(detail)) => {
                                return Err(Failure::new(FailurePhase::ControlDelivery, detail));
                            },
                            Ok(None) => {},
                            Err(source) => {
                                return Err(Failure::new(
                                    FailurePhase::Capture,
                                    source.to_string(),
                                ));
                            },
                        }
                    }
                },
            }
        }
    }

    fn finish(mut self) -> Result<String, Failure> {
        self.close_descriptors();
        self.completed.take().ok_or_else(|| {
            Failure::new(
                FailurePhase::Capture,
                "framed stdout reader omitted its completed outcome",
            )
        })
    }
}

enum ReadState {
    NoData,
    End,
    Bytes(usize),
}

fn read_nonblocking<F: std::os::fd::AsFd>(
    descriptor: &F,
    buffer: &mut [u8],
    name: &str,
) -> Result<ReadState, Failure> {
    match rustix::io::read(descriptor, buffer) {
        Ok(0) => Ok(ReadState::End),
        Ok(count) => Ok(ReadState::Bytes(count)),
        Err(source)
            if source == rustix::io::Errno::AGAIN || source == rustix::io::Errno::WOULDBLOCK =>
        {
            Ok(ReadState::NoData)
        },
        Err(source) => Err(Failure::new(
            FailurePhase::Capture,
            format!(
                "read framed {name}: {}",
                std::io::Error::from_raw_os_error(source.raw_os_error())
            ),
        )),
    }
}

fn append_bounded(
    captured: &mut Vec<u8>,
    chunk: &[u8],
    count: usize,
    maximum_bytes: usize,
    name: &str,
) -> Result<(), Failure> {
    let new_length = captured.len().checked_add(count).ok_or_else(|| {
        Failure::new(
            FailurePhase::Capture,
            format!("framed {name} byte count cannot be represented"),
        )
    })?;
    if new_length > maximum_bytes {
        return Err(Failure::new(
            FailurePhase::Capture,
            format!("framed {name} exceeded its exact byte bound"),
        ));
    }
    let retained = chunk.get(..count).ok_or_else(|| {
        Failure::new(
            FailurePhase::Capture,
            format!("framed {name} read escaped its fixed buffer boundary"),
        )
    })?;
    captured.extend_from_slice(retained);
    Ok(())
}

fn next_line<'captured>(
    captured: &'captured [u8],
    inspected: &mut usize,
    name: &str,
) -> Result<Option<&'captured [u8]>, Failure> {
    let Some(relative_end) = captured
        .get(*inspected..)
        .and_then(|bytes| bytes.iter().position(|byte| *byte == b'\n'))
    else {
        return Ok(None);
    };
    let end = inspected
        .checked_add(relative_end)
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| {
            Failure::new(
                FailurePhase::Capture,
                format!("framed {name} line boundary cannot be represented"),
            )
        })?;
    let line = captured.get(*inspected..end).ok_or_else(|| {
        Failure::new(
            FailurePhase::Capture,
            format!("framed {name} line escaped its captured boundary"),
        )
    })?;
    *inspected = end;
    Ok(Some(line))
}

fn make_nonblocking<F: std::os::fd::AsFd>(descriptor: &F, name: &str) -> Result<(), Failure> {
    let flags = rustix::fs::fcntl_getfl(descriptor).map_err(|source| {
        Failure::new(
            FailurePhase::Descriptor,
            format!(
                "inspect framed {name} descriptor flags: {}",
                std::io::Error::from_raw_os_error(source.raw_os_error())
            ),
        )
    })?;
    rustix::fs::fcntl_setfl(descriptor, flags | rustix::fs::OFlags::NONBLOCK).map_err(|source| {
        Failure::new(
            FailurePhase::Descriptor,
            format!(
                "make framed {name} descriptor nonblocking: {}",
                std::io::Error::from_raw_os_error(source.raw_os_error())
            ),
        )
    })
}

fn wait_for_progress(deadline: Instant) {
    let remaining = deadline.saturating_duration_since(Instant::now());
    std::thread::park_timeout(remaining.min(POLL_INTERVAL));
}
