//! Parent-owned bounded stdout broker for registered runner frames.

#![cfg(unix)]

use std::io::Read;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc::{Receiver, SyncSender, TryRecvError, TrySendError},
};
use std::thread;
use std::time::{Duration, Instant};

use crate::bounded_runner_frames::{self, ControlFrame};

const POLL_INTERVAL: Duration = Duration::from_millis(5);

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

#[derive(Debug)]
enum Event {
    Control(ControlFrame),
    ControlDeliveryFailed(String),
    Failure(String),
}

pub(crate) struct FramedStdoutBroker {
    handle: Option<thread::JoinHandle<Result<String, String>>>,
    events: Receiver<Event>,
    stop: Arc<AtomicBool>,
    completed: Option<Result<String, String>>,
}

impl FramedStdoutBroker {
    pub(crate) fn start(
        mut stdout: std::process::ChildStdout,
        mut stderr: std::process::ChildStderr,
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
        let (sender, events) = std::sync::mpsc::sync_channel(4);
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let handle = thread::Builder::new()
            .name("controlled-framed-stdout-broker".to_owned())
            // positron-concurrency-spawn: FramedStdoutBroker::start\tcontrolled-framed-stdout-broker-v1
            .spawn(move || {
                read_bounded_framed_stdout(
                    &mut stdout,
                    &mut stderr,
                    maximum_bytes,
                    worker_stop.as_ref(),
                    &sender,
                )
            })
            .map_err(|source| {
                Failure::new(
                    FailurePhase::Capture,
                    format!("start framed stdout broker: {source}"),
                )
            })?;
        Ok(Self {
            handle: Some(handle),
            events,
            stop,
            completed: None,
        })
    }

    pub(crate) fn poll_control_frame(&mut self) -> Result<(), Failure> {
        match self.events.try_recv() {
            Ok(Event::Control(ControlFrame::RunnerReady)) => Err(Failure::new(
                FailurePhase::Cancellation,
                "bounded runner reported runner-ready-v1 and requested controlled shutdown",
            )),
            Ok(Event::Control(ControlFrame::LifecycleStalled)) => Err(Failure::new(
                FailurePhase::Deadline,
                "bounded runner reported lifecycle-stalled-v1 and retained live task ownership",
            )),
            Ok(Event::ControlDeliveryFailed(detail)) => {
                Err(Failure::new(FailurePhase::ControlDelivery, detail))
            },
            Ok(Event::Failure(detail)) => Err(Failure::new(FailurePhase::Capture, detail)),
            Err(TryRecvError::Empty) => {
                self.observe_worker_completion()?;
                self.validate_completed_outcome()
            },
            Err(TryRecvError::Disconnected) => {
                self.observe_worker_completion()?;
                if self.completed.is_none() {
                    Err(Failure::new(
                        FailurePhase::Capture,
                        "framed stdout event receiver disconnected before broker completion",
                    ))
                } else {
                    self.validate_completed_outcome()
                }
            },
        }
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
        self.request_stop();
        while self
            .handle
            .as_ref()
            .is_some_and(|handle| !handle.is_finished())
        {
            if Instant::now() >= deadline {
                return Err(Failure::new(
                    FailurePhase::Cleanup,
                    "framed stdout broker exceeded the registered shutdown deadline",
                ));
            }
            wait_for_progress(deadline);
        }
        self.observe_worker_completion()?;
        match self.completed.take() {
            Some(Ok(_)) => Ok(()),
            Some(Err(detail)) => Err(Failure::new(
                FailurePhase::Cleanup,
                format!("framed stdout broker failed during shutdown: {detail}"),
            )),
            None => Err(Failure::new(
                FailurePhase::Cleanup,
                "framed stdout broker lost its finished worker outcome",
            )),
        }
    }

    pub(crate) fn request_stop(&self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.handle.as_ref() {
            handle.thread().unpark();
        }
    }

    fn observe_worker_completion(&mut self) -> Result<(), Failure> {
        if self.completed.is_some()
            || !self
                .handle
                .as_ref()
                .is_some_and(thread::JoinHandle::is_finished)
        {
            return Ok(());
        }
        let handle = self.handle.take().ok_or_else(|| {
            Failure::new(
                FailurePhase::Capture,
                "framed stdout broker lost its registered worker handle",
            )
        })?;
        self.completed =
            Some(handle.join().map_err(|_| {
                Failure::new(FailurePhase::Capture, "framed stdout broker panicked")
            })?);
        if let Some(Err(detail)) = self.completed.as_ref() {
            return Err(Failure::new(FailurePhase::Capture, detail.clone()));
        }
        Ok(())
    }

    fn validate_completed_outcome(&self) -> Result<(), Failure> {
        match self.completed.as_ref() {
            Some(Ok(stdout)) => bounded_runner_frames::parse_captured(stdout)
                .map(|_| ())
                .map_err(|source| {
                    Failure::new(
                        FailurePhase::Capture,
                        format!("framed stdout broker completed before a valid outcome: {source}"),
                    )
                }),
            Some(Err(detail)) => Err(Failure::new(FailurePhase::Capture, detail.clone())),
            None => Ok(()),
        }
    }

    fn finish(mut self) -> Result<String, Failure> {
        match self.completed.take() {
            Some(Ok(stdout)) => Ok(stdout),
            Some(Err(detail)) => Err(Failure::new(FailurePhase::Capture, detail)),
            None => Err(Failure::new(
                FailurePhase::Capture,
                "framed stdout broker omitted its completed outcome",
            )),
        }
    }
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

fn read_bounded_framed_stdout<R: Read, E: Read>(
    stdout: &mut R,
    stderr: &mut E,
    maximum_bytes: usize,
    stop: &AtomicBool,
    events: &SyncSender<Event>,
) -> Result<String, String> {
    let mut captured = Vec::with_capacity(maximum_bytes.min(1024));
    let mut inspected = 0;
    let mut captured_stderr = Vec::with_capacity(maximum_bytes.min(1024));
    let mut inspected_stderr = 0;
    let mut stderr_closed = false;
    let mut chunk = [0_u8; 512];
    loop {
        if stop.load(Ordering::Acquire) {
            return Ok(String::new());
        }
        if !stderr_closed {
            stderr_closed = read_control_delivery_failures(
                stderr,
                &mut captured_stderr,
                &mut inspected_stderr,
                maximum_bytes,
                events,
            )?;
        }
        match stdout.read(&mut chunk) {
            Ok(0) => {
                return String::from_utf8(captured)
                    .map_err(|_| "framed stdout was not valid UTF-8".to_owned());
            },
            Ok(count) => {
                let new_length = captured.len().checked_add(count).ok_or_else(|| {
                    report_failure(events, "framed stdout byte count cannot be represented")
                })?;
                if new_length > maximum_bytes {
                    return Err(report_failure(
                        events,
                        "framed stdout exceeded its exact byte bound",
                    ));
                }
                let retained = chunk.get(..count).ok_or_else(|| {
                    "framed stdout read escaped its fixed buffer boundary".to_owned()
                })?;
                captured.extend_from_slice(retained);
                while let Some(relative_end) = captured
                    .get(inspected..)
                    .and_then(|bytes| bytes.iter().position(|byte| *byte == b'\n'))
                {
                    let end = inspected + relative_end + 1;
                    let line = captured.get(inspected..end).ok_or_else(|| {
                        report_failure(events, "framed stdout line escaped its captured boundary")
                    })?;
                    if let Some(frame) = bounded_runner_frames::control_frame(line) {
                        send_event(events, Event::Control(frame))?;
                    }
                    inspected = end;
                }
            },
            Err(source) if source.kind() == std::io::ErrorKind::WouldBlock => {
                thread::park_timeout(POLL_INTERVAL);
            },
            Err(source) => {
                return Err(report_failure(
                    events,
                    &format!("read framed stdout: {source}"),
                ));
            },
        }
    }
}

fn read_control_delivery_failures<R: Read>(
    stderr: &mut R,
    captured: &mut Vec<u8>,
    inspected: &mut usize,
    maximum_bytes: usize,
    events: &SyncSender<Event>,
) -> Result<bool, String> {
    let mut chunk = [0_u8; 512];
    match stderr.read(&mut chunk) {
        Ok(0) => Ok(true),
        Ok(count) => {
            let new_length = captured.len().checked_add(count).ok_or_else(|| {
                report_failure(events, "framed stderr byte count cannot be represented")
            })?;
            if new_length > maximum_bytes {
                return Err(report_failure(
                    events,
                    "framed stderr exceeded its exact byte bound",
                ));
            }
            let retained = chunk
                .get(..count)
                .ok_or_else(|| "framed stderr read escaped its fixed buffer boundary".to_owned())?;
            captured.extend_from_slice(retained);
            while let Some(relative_end) = captured
                .get(*inspected..)
                .and_then(|bytes| bytes.iter().position(|byte| *byte == b'\n'))
            {
                let end = *inspected + relative_end + 1;
                let line = captured.get(*inspected..end).ok_or_else(|| {
                    report_failure(events, "framed stderr line escaped its captured boundary")
                })?;
                match bounded_runner_frames::control_delivery_failure(line) {
                    Ok(Some(detail)) => {
                        send_event(events, Event::ControlDeliveryFailed(detail))?;
                    },
                    Ok(None) => {},
                    Err(source) => {
                        return Err(report_failure(events, &source.to_string()));
                    },
                }
                *inspected = end;
            }
            Ok(false)
        },
        Err(source) if source.kind() == std::io::ErrorKind::WouldBlock => Ok(false),
        Err(source) => Err(report_failure(
            events,
            &format!("read framed stderr: {source}"),
        )),
    }
}

fn report_failure(events: &SyncSender<Event>, detail: &str) -> String {
    match send_event(events, Event::Failure(detail.to_owned())) {
        Ok(()) => detail.to_owned(),
        Err(delivery) => format!("{detail}; {delivery}"),
    }
}

fn send_event(events: &SyncSender<Event>, event: Event) -> Result<(), String> {
    events.try_send(event).map_err(|source| match source {
        TrySendError::Full(_) => "framed stdout event channel exceeded its exact bound".to_owned(),
        TrySendError::Disconnected(_) => {
            "framed stdout parent event receiver disappeared before delivery".to_owned()
        },
    })
}

fn wait_for_progress(deadline: Instant) {
    let remaining = deadline.saturating_duration_since(Instant::now());
    thread::park_timeout(remaining.min(POLL_INTERVAL));
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::sync::atomic::AtomicBool;

    use super::{Event, read_bounded_framed_stdout};

    #[test]
    fn reports_parent_receiver_disappearance_as_a_typed_broker_failure()
    -> Result<(), std::io::Error> {
        let (sender, receiver) = std::sync::mpsc::sync_channel::<Event>(1);
        drop(receiver);
        let mut input = Cursor::new(b"lifecycle-stalled-v1\n");
        let mut stderr = Cursor::new([]);
        let result = read_bounded_framed_stdout(
            &mut input,
            &mut stderr,
            128,
            &AtomicBool::new(false),
            &sender,
        );
        match result {
            Err(failure) => {
                assert!(failure.contains("parent event receiver disappeared"));
                Ok(())
            },
            Ok(stdout) => Err(std::io::Error::other(format!(
                "receiver disappearance captured an outcome: {stdout}"
            ))),
        }
    }
}
