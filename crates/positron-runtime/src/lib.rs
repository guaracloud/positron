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
#[cfg(any(test, feature = "test-support"))]
pub use instance_bootstrap::GovernanceTestFixture;
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
pub use services::{ServiceFailure, ServiceHandle};
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

#[cfg(fuzzing)]
#[doc(hidden)]
pub fn fuzz_tail_state_machine(data: &[u8]) {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use positron_domain::routing::{SignalKind, VirtualShardId};
    use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
    use positron_kernel::{ActiveSegmentLedger, Catalog, SegmentProtectionKey, SegmentScope};
    use positron_query::{QueryBudget, QueryService, TailEvent, TailSourceSet, TailStart};

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

    struct FuzzRoot(PathBuf);

    impl FuzzRoot {
        fn new() -> Option<Self> {
            let root = std::env::temp_dir().join(format!(
                "positron-query-tail-fuzz-{}-{}",
                std::process::id(),
                NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(root.join("data")).ok()?;
            fs::create_dir_all(root.join("secrets")).ok()?;
            Some(Self(root))
        }

        fn paths(&self) -> Result<BootstrapPaths, BootstrapFailure> {
            BootstrapPaths::new(
                self.0.join("data").as_path(),
                self.0.join("secrets").as_path(),
                positron_kernel::MountQualification::LocalHost,
            )
        }
    }

    impl Drop for FuzzRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn budget() -> Option<QueryBudget> {
        QueryBudget::new(1_048_576, 16, 1, 1_048_576, 1_048_576, 60)
            .ok()?
            .with_cpu_work_units(64)
            .ok()
    }

    fn sources<'kernel, 'catalog>(
        first: &ActiveSegmentLedger<'kernel, 'catalog>,
        second: &ActiveSegmentLedger<'kernel, 'catalog>,
    ) -> Option<TailSourceSet<'kernel, 'catalog>> {
        TailSourceSet::new(vec![first.reader().ok()?, second.reader().ok()?]).ok()
    }

    let result = (|| -> Option<()> {
        let root = FuzzRoot::new()?;
        let Ok(paths) = root.paths() else {
            return None;
        };
        if InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive()).is_err() {
            return None;
        }
        let Ok(claim) = InstanceBootstrap::claim(&paths) else {
            return None;
        };
        let Ok(instance) = InstanceBootstrap::reopen(&paths) else {
            return None;
        };
        let Some(query_secret) = claim.query_secret() else {
            return None;
        };
        let Ok(context) = instance.attribute(
            PresentedCredential::parse(query_secret).ok()?,
            RequestedIntent::Query,
            CompatibilityHints::none(),
        ) else {
            return None;
        };
        let Ok(secret) = instance.key.catalog_secret(instance.instance) else {
            return None;
        };
        let Ok(catalog) = Catalog::open(&instance._authority, instance.instance, secret) else {
            return None;
        };
        let second_shard = VirtualShardId::new(2).ok()?;
        if second_shard == instance.logs_shard {
            return None;
        }
        let first_ledger = ActiveSegmentLedger::open(
            &instance._authority,
            &catalog,
            SegmentScope::new(instance.tenant, SignalKind::Logs, instance.logs_shard),
            SegmentProtectionKey::from_owned(Box::new([0x41; 32])),
        )
        .ok()?;
        let second_ledger = ActiveSegmentLedger::open(
            &instance._authority,
            &catalog,
            SegmentScope::new(instance.tenant, SignalKind::Logs, second_shard),
            SegmentProtectionKey::from_owned(Box::new([0x42; 32])),
        )
        .ok()?;
        let service = QueryService::new(instance._authority.governor(), &first_ledger, 1);
        let source = "pipeline:v1 logs | range query_time -100 100 | limit 1";
        let Some(query) = service.plan_pipeline(context, source, budget()?).ok() else {
            return None;
        };
        let Some(mut session) = service
            .tail_with_sources(
                query,
                TailStart::Now,
                sources(&first_ledger, &second_ledger)?,
            )
            .ok()
        else {
            return None;
        };

        for action in data.iter().copied().take(256) {
            match action % 8 {
                0 | 1 | 2 => {
                    let _ = session.poll();
                },
                3 => {
                    let sequence = u64::from(action);
                    let _ = session.acknowledge(sequence, [action; 32]);
                },
                4 => {
                    session.disconnect();
                    let _ = session.poll();
                },
                5 | 6 | 7 => {
                    let cursor = session.cursor().clone();
                    drop(session);
                    let Some(query) = service.plan_pipeline(context, source, budget()?).ok() else {
                        return None;
                    };
                    let Some(next) = service
                        .resume_tail_with_sources(
                            query,
                            &cursor,
                            sources(&first_ledger, &second_ledger)?,
                        )
                        .ok()
                    else {
                        return None;
                    };
                    session = next;
                },
                _ => unreachable!(),
            }
            if matches!(session.poll(), Some(TailEvent::Terminal(_))) {
                let cursor = session.cursor().clone();
                drop(session);
                let Some(query) = service.plan_pipeline(context, source, budget()?).ok() else {
                    return None;
                };
                let Some(next) = service
                    .resume_tail_with_sources(
                        query,
                        &cursor,
                        sources(&first_ledger, &second_ledger)?,
                    )
                    .ok()
                else {
                    return None;
                };
                session = next;
            }
        }
        Some(())
    })();
    let _ = result;
}
