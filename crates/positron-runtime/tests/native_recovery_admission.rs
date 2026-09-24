//! Native listener admission must remain closed until bootstrap recovery completes.

#[path = "support/process_roots.rs"]
mod roots;

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use positron_runtime::{
    ApplicationRuntime, BootstrapFailureCode, HostInputs, InitializationMode, NativeBindings,
    NativeHost, RecoveryAttempt, RecoveryAttemptHost, RecoveryDecision, ServeConfiguration,
    ShutdownTrigger,
};
use roots::TestRoots;

struct RecoveryGate {
    state: Arc<(Mutex<GateState>, Condvar)>,
}

#[derive(Default)]
struct GateState {
    entered: bool,
    released: bool,
}

impl RecoveryGate {
    fn new() -> (Self, Arc<(Mutex<GateState>, Condvar)>) {
        let state = Arc::new((Mutex::new(GateState::default()), Condvar::new()));
        (
            Self {
                state: Arc::clone(&state),
            },
            state,
        )
    }
}

impl RecoveryAttemptHost for RecoveryGate {
    fn prerequisite_status(&self) -> Result<(), BootstrapFailureCode> {
        let (lock, changed) = &*self.state;
        let mut state = lock
            .lock()
            .map_err(|_| BootstrapFailureCode::ResourceUnavailable)?;
        state.entered = true;
        changed.notify_all();
        while !state.released {
            state = changed
                .wait(state)
                .map_err(|_| BootstrapFailureCode::ResourceUnavailable)?;
        }
        Ok(())
    }

    fn after_failure(&self, _: RecoveryAttempt) -> RecoveryDecision {
        RecoveryDecision::Exhausted
    }
}

#[test]
fn native_data_admission_opens_only_after_recovery_releases_bootstrap()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("native-recovery-admission")?;
    let addresses = reserve_addresses(5)?;
    let [operations, api, otlp_grpc, otlp_http, loki_push] = addresses;
    let host = NativeHost::new(NativeBindings::new(
        std::env::temp_dir().join(format!(
            "native-recovery-admission-{}.sock",
            std::process::id()
        )),
        operations,
        api,
        otlp_grpc,
        otlp_http,
        loki_push,
    )?);
    let (recovery, gate) = RecoveryGate::new();
    let paths = roots.bootstrap_paths()?;
    let (ready, ready_receiver) = mpsc::sync_channel(1);
    let (shutdown, shutdown_receiver) = mpsc::sync_channel(1);
    let started = std::thread::spawn(move || -> Result<positron_runtime::ExitOutcome, String> {
        let process = ApplicationRuntime::start(
            ServeConfiguration::new(paths, InitializationMode::InitializeIfEmpty),
            HostInputs::with_recovery(&host, &host, &recovery),
        )
        .map_err(|outcome| format!("native startup failed: {outcome:?}"))?;
        ready
            .send(())
            .map_err(|_| "recovery test lost its ready receiver".to_owned())?;
        shutdown_receiver
            .recv()
            .map_err(|_| "recovery test lost its shutdown sender".to_owned())?;
        Ok(process.shutdown(ShutdownTrigger::FirstSignal))
    });

    let (lock, changed) = &*gate;
    let state = lock.lock().map_err(|_| "recovery gate poisoned")?;
    let (mut state, timeout) = changed
        .wait_timeout_while(state, Duration::from_secs(2), |state| !state.entered)
        .map_err(|_| "recovery gate poisoned")?;
    assert!(
        !timeout.timed_out(),
        "startup never reached the recovery gate"
    );
    assert!(
        TcpStream::connect_timeout(&api, Duration::from_millis(100)).is_err(),
        "API listener accepted a connection before bootstrap recovery completed"
    );
    state.released = true;
    changed.notify_all();
    drop(state);

    ready_receiver
        .recv_timeout(Duration::from_secs(2))
        .map_err(|_| "native listener never reached serving")?;
    TcpStream::connect_timeout(&api, Duration::from_secs(1))?;
    shutdown
        .send(())
        .map_err(|_| "native startup dropped before shutdown")?;
    assert_eq!(
        started
            .join()
            .map_err(|_| "native startup thread panicked")??,
        positron_runtime::ExitOutcome::Graceful
    );
    assert!(roots.acquire_volume_again().is_ok());
    Ok(())
}

fn reserve_addresses(count: usize) -> Result<[SocketAddr; 5], Box<dyn std::error::Error>> {
    let mut reservations = Vec::with_capacity(count);
    let mut addresses = Vec::with_capacity(count);
    for _ in 0..count {
        let listener =
            TcpListener::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))?;
        addresses.push(listener.local_addr()?);
        reservations.push(listener);
    }
    drop(reservations);
    let [operations, api, otlp_grpc, otlp_http, loki_push]: [SocketAddr; 5] = addresses
        .try_into()
        .map_err(|_| "incorrect native address reservation count")?;
    Ok([operations, api, otlp_grpc, otlp_http, loki_push])
}
