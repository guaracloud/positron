use super::*;

impl ApplicationRuntime {
    pub fn start(
        configuration: ServeConfiguration,
        host: HostInputs<'_>,
    ) -> Result<RunningProcess, ExitOutcome> {
        let state = ProcessState::starting();
        let mut listeners = Vec::with_capacity(5);
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
        let (_classified, instance) = loop {
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
                        listeners,
                        tasks,
                        cancellation,
                        instance: None,
                        fenced_volume: Some(fenced_volume),
                        services: None,
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
        let instance = Arc::new(Mutex::new(instance));
        let services = ServiceHandle::new(Arc::clone(&instance));
        for role in [ListenerRole::Api, ListenerRole::OtlpHttp] {
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
            listeners,
            tasks,
            cancellation,
            instance: Some(instance),
            fenced_volume: None,
            services: Some(services),
        })
    }
}

type RegisteredTasks = Vec<(TaskRole, Box<dyn RegisteredTask>)>;

fn register_tasks(registrar: &dyn TaskRegistrar) -> Result<RegisteredTasks, ExitOutcome> {
    [
        TaskRole::Control,
        TaskRole::Operations,
        TaskRole::Api,
        TaskRole::OtlpHttp,
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
                return Err(cancel_and_abort(cancellation, &mut running)
                    .err()
                    .unwrap_or(ExitOutcome::TaskUnavailable(role)));
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

fn cancel_and_abort(
    cancellation: &TaskCancellation,
    running: &mut RunningTasks,
) -> Result<(), ExitOutcome> {
    cancellation.cancel();
    let mut cleanup = CleanupFailure::none();
    let mut failed = Vec::new();
    for (index, (role, task)) in running.iter_mut().enumerate().rev() {
        if task.abort().is_err() {
            cleanup.first_task.get_or_insert(*role);
            failed.push(index);
        }
    }
    for index in failed {
        let (_, task) = &mut running[index];
        if task.abort().is_err() {
            cleanup.task_failures = cleanup.task_failures.saturating_add(1);
        }
    }
    running.clear();
    if cleanup.task_failures > 0 {
        Err(ExitOutcome::InternalCleanupFailure(cleanup))
    } else {
        Ok(())
    }
}

fn cleanup_startup(
    primary: ExitOutcome,
    cancellation: &TaskCancellation,
    listeners: &mut Vec<Box<dyn BoundListener>>,
    tasks: &mut RunningTasks,
) -> ExitOutcome {
    let mut cleanup = match cancel_and_abort(cancellation, tasks) {
        Err(ExitOutcome::InternalCleanupFailure(cleanup)) => cleanup,
        Ok(()) | Err(_) => CleanupFailure::none(),
    };
    for listener in listeners.iter_mut().rev() {
        if listener.close().is_err() {
            cleanup.listener_failures = cleanup.listener_failures.saturating_add(1);
        }
    }
    listeners.clear();
    if cleanup.task_failures > 0 || cleanup.listener_failures > 0 {
        ExitOutcome::InternalCleanupFailure(cleanup)
    } else {
        primary
    }
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
        InitializationMode::ExistingOnly => InstanceBootstrap::reopen(&configuration.paths),
        InitializationMode::InitializeIfEmpty => InstanceBootstrap::initialize(
            &configuration.paths,
            InitializationPlan::non_interactive(),
        ),
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
    let listener = factory
        .bind(ListenerRequest::new(role, state.health()))
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
