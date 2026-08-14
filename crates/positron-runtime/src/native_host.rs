use std::error::Error;
use std::fmt::{Display, Formatter};
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::net::UnixListener;

use crate::{
    BoundEndpoint, BoundListener, HealthState, ListenerFactory, ListenerFailure, ListenerRequest,
    ListenerRole, RegisteredTask, RunningTask, ServiceHandle, TaskCancellation, TaskFailure,
    TaskJoinOutcome, TaskRegistrar, TaskRole,
};

mod native_http;
mod otlp_grpc;

#[derive(Clone, Debug)]
pub struct NativeBindings {
    control: PathBuf,
    operations: SocketAddr,
    api: SocketAddr,
    otlp_grpc: SocketAddr,
    otlp_http: SocketAddr,
}

impl NativeBindings {
    pub fn new(
        control: PathBuf,
        operations: SocketAddr,
        api: SocketAddr,
        otlp_grpc: SocketAddr,
        otlp_http: SocketAddr,
    ) -> Result<Self, NativeHostFailure> {
        BoundEndpoint::control(control.clone()).map_err(|_| NativeHostFailure::InvalidBinding)?;
        for (role, address) in [
            (ListenerRole::Operations, operations),
            (ListenerRole::Api, api),
            (ListenerRole::OtlpGrpc, otlp_grpc),
            (ListenerRole::OtlpHttp, otlp_http),
        ] {
            BoundEndpoint::tcp(role, address).map_err(|_| NativeHostFailure::InvalidBinding)?;
        }
        Ok(Self {
            control,
            operations,
            api,
            otlp_grpc,
            otlp_http,
        })
    }

    fn address(&self, role: ListenerRole) -> Option<SocketAddr> {
        match role {
            ListenerRole::Operations => Some(self.operations),
            ListenerRole::Api => Some(self.api),
            ListenerRole::OtlpGrpc => Some(self.otlp_grpc),
            ListenerRole::OtlpHttp => Some(self.otlp_http),
            ListenerRole::Control => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeHostFailure {
    InvalidBinding,
}

impl Display for NativeHostFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("native host configuration is invalid")
    }
}

impl Error for NativeHostFailure {}

pub struct NativeHost {
    bindings: NativeBindings,
    admissions: AdmissionRegistry,
}

impl NativeHost {
    #[must_use]
    pub fn new(bindings: NativeBindings) -> Self {
        Self {
            bindings,
            admissions: Arc::new(Mutex::new(Vec::with_capacity(4))),
        }
    }
}

enum NativeListener {
    Tcp(TcpListener),
    #[cfg(unix)]
    Unix(UnixListener),
}

struct Admission {
    role: ListenerRole,
    listener: NativeListener,
    accepting: AtomicBool,
    control_path: Option<PathBuf>,
}

type AdmissionRegistry = Arc<Mutex<Vec<(ListenerRole, Arc<Admission>)>>>;

impl Admission {
    fn stop(&self) {
        self.accepting.store(false, Ordering::Release);
    }

    fn is_accepting(&self) -> bool {
        self.accepting.load(Ordering::Acquire)
    }

    fn tcp_listener(&self) -> Result<TcpListener, ListenerFailure> {
        match &self.listener {
            NativeListener::Tcp(listener) => listener
                .try_clone()
                .map_err(|_| ListenerFailure::BindUnavailable),
            #[cfg(unix)]
            NativeListener::Unix(_) => Err(ListenerFailure::InvalidEndpoint),
        }
    }
}

impl Drop for Admission {
    fn drop(&mut self) {
        if let Some(path) = &self.control_path {
            match std::fs::remove_file(path) {
                Ok(()) => {},
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
                Err(_) => {},
            }
        }
    }
}

struct NativeBoundListener {
    endpoint: BoundEndpoint,
    admission: Arc<Admission>,
}

impl BoundListener for NativeBoundListener {
    fn endpoint(&self) -> &BoundEndpoint {
        &self.endpoint
    }

    fn close(&mut self) -> Result<(), ListenerFailure> {
        self.admission.stop();
        Ok(())
    }
}

impl Drop for NativeBoundListener {
    fn drop(&mut self) {
        match self.close() {
            Ok(()) | Err(_) => {},
        }
    }
}

impl ListenerFactory for NativeHost {
    fn bind(&self, request: ListenerRequest) -> Result<Box<dyn BoundListener>, ListenerFailure> {
        let role = request.role();
        let (endpoint, listener, control_path) = if role == ListenerRole::Control {
            #[cfg(unix)]
            {
                if let Some(parent) = self.bindings.control.parent() {
                    std::fs::create_dir_all(parent)
                        .map_err(|_| ListenerFailure::BindUnavailable)?;
                }
                let listener = UnixListener::bind(&self.bindings.control)
                    .map_err(|_| ListenerFailure::BindUnavailable)?;
                listener
                    .set_nonblocking(true)
                    .map_err(|_| ListenerFailure::BindUnavailable)?;
                (
                    BoundEndpoint::control(self.bindings.control.clone())?,
                    NativeListener::Unix(listener),
                    Some(self.bindings.control.clone()),
                )
            }
            #[cfg(not(unix))]
            {
                return Err(ListenerFailure::BindUnavailable);
            }
        } else {
            let address = self
                .bindings
                .address(role)
                .ok_or(ListenerFailure::InvalidEndpoint)?;
            let listener =
                TcpListener::bind(address).map_err(|_| ListenerFailure::BindUnavailable)?;
            listener
                .set_nonblocking(true)
                .map_err(|_| ListenerFailure::BindUnavailable)?;
            let local = listener
                .local_addr()
                .map_err(|_| ListenerFailure::BindUnavailable)?;
            (
                BoundEndpoint::tcp(role, local)?,
                NativeListener::Tcp(listener),
                None,
            )
        };
        let admission = Arc::new(Admission {
            role,
            listener,
            accepting: AtomicBool::new(true),
            control_path,
        });
        self.admissions
            .lock()
            .map_err(|_| ListenerFailure::BindUnavailable)?
            .push((role, Arc::clone(&admission)));
        Ok(Box::new(NativeBoundListener {
            endpoint,
            admission,
        }))
    }
}

impl TaskRegistrar for NativeHost {
    fn register(&self, role: TaskRole) -> Result<Box<dyn RegisteredTask>, TaskFailure> {
        Ok(Box::new(NativeRegisteredTask {
            role,
            admissions: Arc::clone(&self.admissions),
        }))
    }
}

struct NativeRegisteredTask {
    role: TaskRole,
    admissions: AdmissionRegistry,
}

impl RegisteredTask for NativeRegisteredTask {
    fn spawn(
        self: Box<Self>,
        cancellation: TaskCancellation,
        health: HealthState,
        services: Option<ServiceHandle>,
    ) -> Result<Box<dyn RunningTask>, TaskFailure> {
        let listener_role = match self.role {
            TaskRole::Control => ListenerRole::Control,
            TaskRole::Operations => ListenerRole::Operations,
            TaskRole::Api => ListenerRole::Api,
            TaskRole::OtlpGrpc => ListenerRole::OtlpGrpc,
            TaskRole::OtlpHttp => ListenerRole::OtlpHttp,
        };
        let mut admissions = self
            .admissions
            .lock()
            .map_err(|_| TaskFailure::SpawnUnavailable)?;
        let index = admissions
            .iter()
            .position(|(role, _)| *role == listener_role)
            .ok_or(TaskFailure::SpawnUnavailable)?;
        let admission = admissions.remove(index).1;
        drop(admissions);
        let task_cancellation = cancellation.clone();
        let handle = std::thread::Builder::new()
            .name(format!("positron-{listener_role:?}"))
            .spawn(move || {
                if listener_role == ListenerRole::OtlpGrpc {
                    otlp_grpc::serve(admission, task_cancellation, services)
                        .map_err(|_| TaskFailure::JoinUnavailable)
                } else {
                    serve_http(admission, task_cancellation, health, services);
                    Ok(())
                }
            })
            .map_err(|_| TaskFailure::SpawnUnavailable)?;
        Ok(Box::new(NativeRunningTask {
            cancellation,
            handle: Some(handle),
        }))
    }
}

struct NativeRunningTask {
    cancellation: TaskCancellation,
    handle: Option<JoinHandle<Result<(), TaskFailure>>>,
}

impl RunningTask for NativeRunningTask {
    fn poll_join(&mut self) -> Result<Option<TaskJoinOutcome>, TaskFailure> {
        if self.handle.as_ref().is_none_or(JoinHandle::is_finished) {
            join_thread(&mut self.handle)?;
            Ok(Some(TaskJoinOutcome::Joined))
        } else {
            Ok(None)
        }
    }

    fn join(&mut self) -> Result<TaskJoinOutcome, TaskFailure> {
        join_thread(&mut self.handle)?;
        Ok(TaskJoinOutcome::Joined)
    }

    fn abort(&mut self) -> Result<(), TaskFailure> {
        self.cancellation.cancel();
        join_thread(&mut self.handle)
    }
}

fn join_thread(
    handle: &mut Option<JoinHandle<Result<(), TaskFailure>>>,
) -> Result<(), TaskFailure> {
    if let Some(handle) = handle.take() {
        return handle.join().map_err(|_| TaskFailure::JoinUnavailable)?;
    }
    Ok(())
}

fn serve_http(
    admission: Arc<Admission>,
    cancellation: TaskCancellation,
    health: HealthState,
    services: Option<ServiceHandle>,
) {
    while admission.accepting.load(Ordering::Acquire) && !cancellation.is_cancelled() {
        let accepted = match &admission.listener {
            NativeListener::Tcp(listener) => listener.accept().map(|(stream, _)| stream),
            #[cfg(unix)]
            NativeListener::Unix(listener) => match listener.accept() {
                Ok((mut stream, _)) => {
                    match std::io::Write::write_all(&mut stream, b"positron-control-v1\n") {
                        Ok(()) => continue,
                        Err(_) => break,
                    }
                },
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                },
                Err(_) => break,
            },
        };
        match accepted {
            Ok(mut stream) => {
                match native_http::serve_connection(
                    &mut stream,
                    admission.role,
                    &health,
                    services.as_ref(),
                ) {
                    Ok(()) | Err(_) => {},
                }
            },
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
            },
            Err(_) => break,
        }
    }
}
