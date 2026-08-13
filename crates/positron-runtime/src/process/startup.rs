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
        let classified = InstanceBootstrap::classify(&configuration.paths)
            .map_err(|failure| ExitOutcome::StartupUnavailable(failure.code()))?;
        let instance = match configuration.initialization {
            InitializationMode::ExistingOnly => InstanceBootstrap::reopen(&configuration.paths),
            InitializationMode::InitializeIfEmpty => InstanceBootstrap::initialize(
                &configuration.paths,
                InitializationPlan::non_interactive(),
            ),
        };
        let instance = match instance {
            Ok(instance) => instance,
            Err(failure)
                if fences(failure.code())
                    && !(configuration.initialization == InitializationMode::ExistingOnly
                        && classified == crate::BootstrapState::Empty) =>
            {
                let fenced_volume = configuration
                    .paths
                    .retain_volume()
                    .map_err(|failure| ExitOutcome::StartupUnavailable(failure.code()))?;
                state.transition(ProcessPhase::Fenced);
                let cancellation = TaskCancellation::new();
                let tasks = spawn_control_tasks(
                    host.tasks,
                    &cancellation,
                    &state,
                    [TaskRole::Control, TaskRole::Operations],
                )?;
                return Ok(RunningProcess {
                    state,
                    listeners,
                    tasks,
                    cancellation,
                    instance: None,
                    fenced_volume: Some(fenced_volume),
                    services: None,
                });
            },
            Err(failure) => return Err(ExitOutcome::StartupUnavailable(failure.code())),
        };
        let instance = Arc::new(Mutex::new(instance));
        let services = ServiceHandle::new(Arc::clone(&instance));
        let registered = register_tasks(host.tasks)?;
        for role in [ListenerRole::Api, ListenerRole::OtlpHttp] {
            bind(role, &state, host.listeners, &mut listeners)?;
        }
        let cancellation = TaskCancellation::new();
        let tasks = spawn_tasks(registered, &cancellation, &state, &services)?;
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
    [TaskRole::Operations, TaskRole::Api, TaskRole::OtlpHttp]
        .into_iter()
        .map(|role| {
            registrar
                .register(role)
                .map(|registered| (role, registered))
                .map_err(|_| ExitOutcome::TaskUnavailable(role))
        })
        .collect()
}

fn spawn_control_tasks(
    registrar: &dyn TaskRegistrar,
    cancellation: &TaskCancellation,
    state: &ProcessState,
    roles: [TaskRole; 2],
) -> Result<Vec<Box<dyn RunningTask>>, ExitOutcome> {
    let registered = roles
        .into_iter()
        .map(|role| {
            registrar
                .register(role)
                .map(|task| (role, task))
                .map_err(|_| ExitOutcome::TaskUnavailable(role))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut running = Vec::with_capacity(roles.len());
    for (role, registered) in registered {
        match registered.spawn(cancellation.clone(), state.health(), None) {
            Ok(task) => running.push(task),
            Err(_) => {
                cancel_and_abort(cancellation, &mut running);
                return Err(ExitOutcome::TaskUnavailable(role));
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
) -> Result<Vec<Box<dyn RunningTask>>, ExitOutcome> {
    let mut running = Vec::with_capacity(registered.len());
    for (role, task) in registered {
        match task.spawn(cancellation.clone(), state.health(), Some(services.clone())) {
            Ok(task) => running.push(task),
            Err(_) => {
                cancel_and_abort(cancellation, &mut running);
                return Err(ExitOutcome::TaskUnavailable(role));
            },
        }
    }
    Ok(running)
}

fn cancel_and_abort(cancellation: &TaskCancellation, running: &mut [Box<dyn RunningTask>]) {
    cancellation.cancel();
    for task in running {
        match task.abort() {
            Ok(()) | Err(_) => {},
        }
    }
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
