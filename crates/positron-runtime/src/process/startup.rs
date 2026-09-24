use super::*;

impl ApplicationRuntime {
    pub fn start(
        configuration: ServeConfiguration,
        host: HostInputs<'_>,
    ) -> Result<RunningProcess, ExitOutcome> {
        let state = ProcessState::starting();
        let drain_deadline = configuration.drain_deadline();
        let listener_generation_factory = host.listeners.generation_factory();
        let plaintext_listener_intents =
            configuration.effective_configuration.as_ref().map_or_else(
                || configuration.plaintext_listener_intents().to_vec(),
                |effective| super::plaintext_listener_intents_for(effective),
            );
        state.set_plaintext_listener_warnings(&plaintext_listener_intents);
        // A native host has already resolved every profile before it reaches
        // this boundary. Validate that it is a complete generation now, but
        // do not open data sockets until bootstrap has established ownership,
        // integrity, identity, and the catalog below.
        let _candidate = complete_candidate(host.listeners);
        let mut listeners = Vec::with_capacity(6);
        bind(
            ListenerRole::Control,
            &state,
            host.listeners,
            &mut listeners,
        )?;
        bind(
            ListenerRole::Operations,
            &state,
            host.listeners,
            &mut listeners,
        )?;
        state.transition(ProcessPhase::Recovering);
        let cancellation = TaskCancellation::new();
        let registered = match register_tasks(host.tasks) {
            Ok(registered) => registered,
            Err(failure) => {
                return Err(cleanup_startup(
                    failure,
                    &cancellation,
                    &mut listeners,
                    &mut Vec::new(),
                ));
            },
        };
        let (control_registered, data_registered): (RegisteredTasks, RegisteredTasks) = registered
            .into_iter()
            .partition(|(role, _)| matches!(role, TaskRole::Control | TaskRole::Operations));
        let mut tasks = match spawn_registered(control_registered, &cancellation, &state, None) {
            Ok(tasks) => tasks,
            Err(failure) => {
                return Err(cleanup_startup(
                    failure,
                    &cancellation,
                    &mut listeners,
                    &mut Vec::new(),
                ));
            },
        };
        let mut attempt = 0_u8;
        let (_classified, mut instance) = loop {
            let bootstrap = host
                .recovery
                .prerequisite_status()
                .map_err(|code| BootstrapAttemptFailure {
                    classified: None,
                    failure: BootstrapFailure::new(code),
                })
                .and_then(|()| bootstrap_once(&configuration));
            let failure = match bootstrap {
                Ok(ready) => break ready,
                Err(failure) => failure,
            };
            if !recoverable(failure.failure.code()) {
                if failure.classified.is_some_and(|classified| {
                    fences(failure.failure.code())
                        && !(configuration.initialization == InitializationMode::ExistingOnly
                            && classified == crate::BootstrapState::Empty)
                }) {
                    let fenced_volume = match configuration.paths.retain_volume() {
                        Ok(volume) => volume,
                        Err(retain_failure) => {
                            return Err(cleanup_startup(
                                ExitOutcome::StartupUnavailable(retain_failure.code()),
                                &cancellation,
                                &mut listeners,
                                &mut tasks,
                            ));
                        },
                    };
                    state.transition(ProcessPhase::Fenced);
                    return Ok(RunningProcess {
                        state,
                        listeners: std::sync::Mutex::new(listeners),
                        listener_generation_factory,
                        reload_lock: std::sync::Mutex::new(()),
                        tasks: std::sync::Mutex::new(tasks),
                        listener_task_cancellations: std::sync::Mutex::new(Vec::new()),
                        cancellation,
                        instance: None,
                        fenced_volume: Some(fenced_volume),
                        services: None,
                        configuration: None,
                        configuration_publication: None,
                        cleanup: CleanupAccumulator::empty(),
                        drain_deadline,
                        terminal_cleanup_complete: false,
                    });
                }
                return Err(cleanup_startup(
                    ExitOutcome::StartupUnavailable(failure.failure.code()),
                    &cancellation,
                    &mut listeners,
                    &mut tasks,
                ));
            }
            attempt = attempt.saturating_add(1);
            let retained_volume = configuration.paths.retain_volume().ok();
            let decision = host.recovery.after_failure(RecoveryAttempt {
                number: attempt,
                failure: failure.failure.code(),
                ownership_held: retained_volume.is_some(),
            });
            drop(retained_volume);
            match decision {
                RecoveryDecision::Retry => {},
                RecoveryDecision::Exhausted => {
                    return Err(cleanup_startup(
                        ExitOutcome::StartupUnavailable(failure.failure.code()),
                        &cancellation,
                        &mut listeners,
                        &mut tasks,
                    ));
                },
                RecoveryDecision::Terminate(trigger) => {
                    let outcome = if trigger == ShutdownTrigger::FirstSignal {
                        ExitOutcome::Graceful
                    } else {
                        ExitOutcome::Forced
                    };
                    return Err(cleanup_startup(
                        outcome,
                        &cancellation,
                        &mut listeners,
                        &mut tasks,
                    ));
                },
            }
        };
        if let Some(planner) = configuration.admission_group_planner.as_ref() {
            instance.admission_group_planner = Arc::clone(planner);
        }
        for intent in &plaintext_listener_intents {
            if let Err(failure) = instance.activate_public_plaintext_api_transport(*intent) {
                return Err(cleanup_startup(
                    ExitOutcome::StartupUnavailable(failure.code()),
                    &cancellation,
                    &mut listeners,
                    &mut tasks,
                ));
            }
        }
        let instance = Arc::new(instance);
        state
            .set_inspection_authority(Arc::clone(&instance))
            .map_err(|_| {
                cleanup_startup(
                    ExitOutcome::StartupUnavailable(BootstrapFailureCode::CatalogUnavailable),
                    &cancellation,
                    &mut listeners,
                    &mut tasks,
                )
            })?;
        let (runtime_configuration, configuration_publication) =
            match configuration.effective_configuration.as_ref() {
                Some(effective) => {
                    let publication = CatalogConfigurationPublication::new(Arc::clone(&instance));
                    let generation = match publication.establish(effective) {
                        Ok(generation) => generation,
                        Err(ConfigurationRuntimeFailure::ImmutableConfiguration) => {
                            return Err(cleanup_startup(
                                ExitOutcome::InvalidConfiguration,
                                &cancellation,
                                &mut listeners,
                                &mut tasks,
                            ));
                        },
                        Err(_) => {
                            return Err(cleanup_startup(
                                ExitOutcome::StartupUnavailable(
                                    BootstrapFailureCode::CatalogUnavailable,
                                ),
                                &cancellation,
                                &mut listeners,
                                &mut tasks,
                            ));
                        },
                    };
                    (
                        Some(Arc::new(RuntimeConfiguration::new_at_generation(
                            Arc::clone(effective),
                            generation,
                        ))),
                        Some(publication),
                    )
                },
                None => (None, None),
            };
        if let Some(runtime) = runtime_configuration.as_ref() {
            state
                .set_configuration_runtime(Arc::clone(runtime))
                .map_err(|_| {
                    cleanup_startup(
                        ExitOutcome::StartupUnavailable(BootstrapFailureCode::CatalogUnavailable),
                        &cancellation,
                        &mut listeners,
                        &mut tasks,
                    )
                })?;
        }
        let export_destination_resolver = configuration.export_destination_resolver.or_else(|| {
            runtime_configuration.as_ref().map(|runtime| {
                Arc::new(crate::ConfiguredExportDestinationResolver::from_runtime(
                    Arc::clone(runtime),
                )) as Arc<dyn positron_query::ExportDestinationResolver>
            })
        });
        let services = match ServiceHandle::new_with_export_destination_resolver(
            Arc::clone(&instance),
            Some(&cancellation),
            export_destination_resolver,
        ) {
            Ok(services) => services,
            Err(failure) => {
                return Err(cleanup_startup(
                    service_failure_outcome(failure),
                    &cancellation,
                    &mut listeners,
                    &mut tasks,
                ));
            },
        };
        for role in [
            ListenerRole::Api,
            ListenerRole::OtlpGrpc,
            ListenerRole::OtlpHttp,
            ListenerRole::LokiPush,
        ] {
            if let Err(failure) = bind(role, &state, host.listeners, &mut listeners) {
                return Err(cleanup_startup(
                    failure,
                    &cancellation,
                    &mut listeners,
                    &mut tasks,
                ));
            }
        }
        match spawn_tasks(
            data_registered,
            &cancellation,
            &state,
            &services,
            &mut tasks,
        ) {
            Ok(()) => {},
            Err(failure) => {
                return Err(cleanup_startup(
                    failure,
                    &cancellation,
                    &mut listeners,
                    &mut tasks,
                ));
            },
        }
        state.transition(ProcessPhase::Serving);
        Ok(RunningProcess {
            state,
            listeners: std::sync::Mutex::new(listeners),
            listener_generation_factory,
            reload_lock: std::sync::Mutex::new(()),
            tasks: std::sync::Mutex::new(tasks),
            listener_task_cancellations: std::sync::Mutex::new(Vec::new()),
            cancellation,
            instance: Some(instance),
            fenced_volume: None,
            services: Some(services),
            configuration: runtime_configuration,
            configuration_publication,
            cleanup: CleanupAccumulator::empty(),
            drain_deadline,
            terminal_cleanup_complete: false,
        })
    }
}

fn complete_candidate(factory: &dyn ListenerFactory) -> Option<crate::ValidatedListenerSet> {
    let [control, operations, api, otlp_grpc, otlp_http, loki_push] =
        ListenerRole::all().map(|role| factory.profile_for(role));
    crate::ValidatedListenerSet::new([
        control?,
        operations?,
        api?,
        otlp_grpc?,
        otlp_http?,
        loki_push?,
    ])
    .ok()
}

type RegisteredTasks = Vec<(TaskRole, Box<dyn RegisteredTask>)>;

fn register_tasks(registrar: &dyn TaskRegistrar) -> Result<RegisteredTasks, ExitOutcome> {
    [
        TaskRole::Control,
        TaskRole::Operations,
        TaskRole::Api,
        TaskRole::OtlpGrpc,
        TaskRole::OtlpHttp,
        TaskRole::LokiPush,
    ]
    .into_iter()
    .map(|role| {
        registrar
            .register(role)
            .map(|registered| (role, registered))
            .map_err(|_| ExitOutcome::TaskUnavailable(role))
    })
    .collect()
}

fn spawn_registered(
    registered: RegisteredTasks,
    cancellation: &TaskCancellation,
    state: &ProcessState,
    services: Option<&ServiceHandle>,
) -> Result<RunningTasks, ExitOutcome> {
    let mut running = Vec::with_capacity(registered.len());
    for (role, registered) in registered {
        match registered.spawn(cancellation.clone(), state.health(), services.cloned()) {
            Ok(task) => running.push((role, task)),
            Err(_) => {
                let mut cleanup = CleanupAccumulator::new(ExitOutcome::TaskUnavailable(role));
                cleanup.cleanup_tasks(cancellation, &mut running);
                return Err(cleanup.outcome());
            },
        }
    }
    Ok(running)
}

fn spawn_tasks(
    registered: RegisteredTasks,
    cancellation: &TaskCancellation,
    state: &ProcessState,
    services: &ServiceHandle,
    running: &mut RunningTasks,
) -> Result<(), ExitOutcome> {
    let mut started = spawn_registered(registered, cancellation, state, Some(services))?;
    running.append(&mut started);
    Ok(())
}

fn cleanup_startup(
    primary: ExitOutcome,
    cancellation: &TaskCancellation,
    listeners: &mut Vec<Box<dyn BoundListener>>,
    tasks: &mut RunningTasks,
) -> ExitOutcome {
    let mut cleanup = CleanupAccumulator::new(primary);
    cleanup.cleanup_tasks(cancellation, tasks);
    cleanup.cleanup_listeners(listeners);
    cleanup.outcome()
}

struct BootstrapAttemptFailure {
    classified: Option<crate::BootstrapState>,
    failure: BootstrapFailure,
}

fn bootstrap_once(
    configuration: &ServeConfiguration,
) -> Result<(crate::BootstrapState, crate::InitializedInstance), BootstrapAttemptFailure> {
    let classified = InstanceBootstrap::classify(&configuration.paths).map_err(|failure| {
        BootstrapAttemptFailure {
            classified: None,
            failure,
        }
    })?;
    let instance = match configuration.initialization {
        InitializationMode::ExistingOnly => InstanceBootstrap::reopen_with_max_registered_tenants(
            &configuration.paths,
            configuration.max_registered_tenants,
        ),
        InitializationMode::InitializeIfEmpty => {
            InstanceBootstrap::initialize_with_max_registered_tenants(
                &configuration.paths,
                InitializationPlan::non_interactive(),
                configuration.max_registered_tenants,
            )
        },
    };
    instance
        .map(|instance| (classified, instance))
        .map_err(|failure| BootstrapAttemptFailure {
            classified: Some(classified),
            failure,
        })
}

fn bind(
    role: ListenerRole,
    state: &ProcessState,
    factory: &dyn ListenerFactory,
    listeners: &mut Vec<Box<dyn BoundListener>>,
) -> Result<(), ExitOutcome> {
    let request = factory
        .profile_for(role)
        .map(|profile| ListenerRequest::for_profile(profile, state.health()))
        .unwrap_or_else(|| ListenerRequest::new(role, state.health()));
    let listener = factory
        .bind(request)
        .map_err(|_| ExitOutcome::ListenerUnavailable(role))?;
    if listener.endpoint().role() != role {
        return Err(ExitOutcome::ListenerUnavailable(role));
    }
    listeners.push(listener);
    Ok(())
}

const fn fences(code: BootstrapFailureCode) -> bool {
    matches!(
        code,
        BootstrapFailureCode::InconsistentRoots
            | BootstrapFailureCode::CorruptState
            | BootstrapFailureCode::IdentityMismatch
    )
}

const fn recoverable(code: BootstrapFailureCode) -> bool {
    matches!(
        code,
        BootstrapFailureCode::StorageUnavailable
            | BootstrapFailureCode::KeyCustodyUnavailable
            | BootstrapFailureCode::ResourceUnavailable
            | BootstrapFailureCode::CatalogUnavailable
            | BootstrapFailureCode::LedgerUnavailable
    )
}

const fn service_failure_outcome(failure: crate::ServiceFailure) -> ExitOutcome {
    match failure {
        crate::ServiceFailure::Cancelled => ExitOutcome::Graceful,
        failure => ExitOutcome::StartupUnavailable(failure.bootstrap_code()),
    }
}

#[cfg(test)]
mod tests {
    use super::service_failure_outcome;
    use crate::{BootstrapFailureCode, ExitOutcome, ServiceFailure};

    #[test]
    fn service_cancellation_stops_startup_without_a_retryable_outcome() {
        assert_eq!(
            service_failure_outcome(ServiceFailure::Cancelled),
            ExitOutcome::Graceful
        );
        assert_eq!(
            service_failure_outcome(ServiceFailure::Internal),
            ExitOutcome::StartupUnavailable(BootstrapFailureCode::ResourceUnavailable)
        );
    }
}
