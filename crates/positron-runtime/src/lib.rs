//! Positron process runtime boundaries.
//!
//! It owns transactional Instance Bootstrap and the single process lifecycle.

#![forbid(unsafe_code)]

mod health;
mod instance_bootstrap;
mod listener;
mod native_host;
mod process;
mod services;
mod task;

pub use health::{HealthState, Liveness, ProcessPhase, Readiness};
pub use instance_bootstrap::{
    BootstrapClaim, BootstrapFailure, BootstrapFailureCode, BootstrapPaths, BootstrapState,
    InitializationPlan, InitializedInstance, InstanceBootstrap,
};
pub use listener::{
    BoundEndpoint, BoundListener, ListenerFactory, ListenerFailure, ListenerRequest, ListenerRole,
};
pub use native_host::{NativeBindings, NativeHost, NativeHostFailure};
pub use process::{
    ApplicationRuntime, CleanupFailure, CleanupPrimary, CleanupRole, DrainingProcess, ExitOutcome,
    HostInputs, InitializationMode, RecoveryAttempt, RecoveryAttemptHost, RecoveryDecision,
    RunningProcess, ServeConfiguration, ShutdownTrigger,
};
pub use services::{
    SchemaDiscoveryCursor, SchemaDiscoveryOperation, ServiceFailure, ServiceHandle,
};
pub use task::{
    RegisteredTask, RunningTask, TaskCancellation, TaskFailure, TaskJoinOutcome, TaskRegistrar,
    TaskRole,
};

#[cfg(fuzzing)]
#[doc(hidden)]
pub fn fuzz_process_inputs(data: &[u8]) {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::path::PathBuf;

    for byte in data.iter().copied().take(4_096) {
        let role = match byte % 6 {
            0 => ListenerRole::Control,
            1 => ListenerRole::Operations,
            2 => ListenerRole::Api,
            3 => ListenerRole::OtlpGrpc,
            4 => ListenerRole::OtlpHttp,
            _ => ListenerRole::LokiPush,
        };
        let address = SocketAddr::V4(SocketAddrV4::new(
            if byte & 0x80 == 0 {
                Ipv4Addr::LOCALHOST
            } else {
                Ipv4Addr::UNSPECIFIED
            },
            u16::from(byte),
        ));
        let endpoint = BoundEndpoint::tcp(role, address);
        assert_eq!(
            endpoint.is_ok(),
            role != ListenerRole::Control && address.ip().is_loopback()
        );
        let control = BoundEndpoint::control(PathBuf::from(format!("/tmp/{byte}.sock")));
        assert!(control.is_ok());
    }
}
