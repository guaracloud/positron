use super::*;

const MAX_CLEANUP_ROLES: usize = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanupRole {
    Task(TaskRole),
    Listener(ListenerRole),
    SchemaCheckpoint,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanupPrimary {
    None,
    Forced,
    Graceful,
    InvalidConfiguration,
    StartupUnavailable(BootstrapFailureCode),
    ListenerUnavailable(ListenerRole),
    TaskUnavailable(TaskRole),
    Fenced,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CleanupFailure {
    primary: CleanupPrimary,
    roles: [Option<CleanupRole>; MAX_CLEANUP_ROLES],
    role_count: u8,
    task_mask: u8,
    listener_mask: u8,
    task_failures: u8,
    listener_failures: u8,
    schema_checkpoint_failed: bool,
    overflowed: bool,
}

impl Default for CleanupFailure {
    fn default() -> Self {
        Self::none()
    }
}

impl CleanupFailure {
    #[must_use]
    pub const fn none() -> Self {
        Self {
            primary: CleanupPrimary::None,
            roles: [None; MAX_CLEANUP_ROLES],
            role_count: 0,
            task_mask: 0,
            listener_mask: 0,
            task_failures: 0,
            listener_failures: 0,
            schema_checkpoint_failed: false,
            overflowed: false,
        }
    }

    #[must_use]
    pub const fn primary(self) -> CleanupPrimary {
        self.primary
    }

    #[must_use]
    pub fn first_task(self) -> Option<TaskRole> {
        self.failed_roles().find_map(|role| match role {
            CleanupRole::Task(role) => Some(role),
            CleanupRole::Listener(_) | CleanupRole::SchemaCheckpoint => None,
        })
    }

    #[must_use]
    pub const fn task_failures(self) -> u8 {
        self.task_failures
    }

    #[must_use]
    pub const fn listener_failures(self) -> u8 {
        self.listener_failures
    }

    #[must_use]
    pub const fn schema_checkpoint_failed(self) -> bool {
        self.schema_checkpoint_failed
    }

    pub fn failed_roles(self) -> impl Iterator<Item = CleanupRole> {
        self.roles.into_iter().flatten()
    }

    #[must_use]
    pub const fn overflowed(self) -> bool {
        self.overflowed
    }
}

pub(crate) struct CleanupAccumulator {
    failure: CleanupFailure,
}

impl CleanupAccumulator {
    pub(crate) const fn empty() -> Self {
        Self {
            failure: CleanupFailure::none(),
        }
    }

    pub(crate) fn new(primary: ExitOutcome) -> Self {
        match primary {
            ExitOutcome::InternalCleanupFailure(failure) => {
                let mut cleanup = Self::empty();
                cleanup.merge(failure);
                cleanup
            },
            primary => Self {
                failure: CleanupFailure {
                    primary: primary_context(primary),
                    ..CleanupFailure::none()
                },
            },
        }
    }

    pub(crate) fn cleanup_tasks(
        &mut self,
        cancellation: &TaskCancellation,
        tasks: &mut RunningTasks,
    ) {
        cancellation.cancel();
        let mut retry = Vec::new();
        for (index, (_, task)) in tasks.iter_mut().enumerate().rev() {
            if task.abort().is_err() {
                retry.push(index);
            }
        }
        for index in retry {
            let (role, task) = &mut tasks[index];
            if task.abort().is_err() {
                self.record(CleanupRole::Task(*role));
            }
        }
        tasks.clear();
    }

    pub(crate) fn cleanup_listeners(&mut self, listeners: &mut Vec<Box<dyn BoundListener>>) {
        for listener in listeners.iter_mut().rev() {
            if listener.close().is_err() && listener.close().is_err() {
                self.record(CleanupRole::Listener(listener.endpoint().role()));
            }
        }
        listeners.clear();
    }

    pub(crate) fn record_listener(&mut self, role: ListenerRole) {
        self.record(CleanupRole::Listener(role));
    }

    pub(crate) fn merge(&mut self, other: CleanupFailure) {
        if self.failure.primary == CleanupPrimary::None {
            self.failure.primary = other.primary;
        }
        for role in other.failed_roles() {
            self.record(role);
        }
        self.failure.task_mask |= other.task_mask;
        self.failure.listener_mask |= other.listener_mask;
        self.failure.task_failures = self.failure.task_mask.count_ones() as u8;
        self.failure.listener_failures = self.failure.listener_mask.count_ones() as u8;
        self.failure.schema_checkpoint_failed |= other.schema_checkpoint_failed;
        self.failure.overflowed |= other.overflowed
            || self.failure.task_failures
                + self.failure.listener_failures
                + u8::from(self.failure.schema_checkpoint_failed)
                > self.failure.role_count;
    }

    pub(crate) fn set_primary(&mut self, primary: ExitOutcome) {
        match primary {
            ExitOutcome::InternalCleanupFailure(failure) => self.merge(failure),
            primary if self.failure.primary == CleanupPrimary::None => {
                self.failure.primary = primary_context(primary);
            },
            _ => {},
        }
    }

    pub(crate) fn has_failures(&self) -> bool {
        self.failure.task_failures > 0
            || self.failure.listener_failures > 0
            || self.failure.schema_checkpoint_failed
    }

    pub(crate) fn record_schema_checkpoint(&mut self) {
        self.record(CleanupRole::SchemaCheckpoint);
    }

    pub(crate) fn outcome(&self) -> ExitOutcome {
        if self.has_failures() {
            ExitOutcome::InternalCleanupFailure(self.failure)
        } else {
            outcome_from_primary(self.failure.primary)
        }
    }

    fn record(&mut self, role: CleanupRole) {
        match role {
            CleanupRole::Task(role) => {
                let bit = task_bit(role);
                if self.failure.task_mask & bit != 0 {
                    return;
                }
                self.failure.task_mask |= bit;
                self.failure.task_failures = self.failure.task_mask.count_ones() as u8;
            },
            CleanupRole::Listener(role) => {
                let bit = listener_bit(role);
                if self.failure.listener_mask & bit != 0 {
                    return;
                }
                self.failure.listener_mask |= bit;
                self.failure.listener_failures = self.failure.listener_mask.count_ones() as u8;
            },
            CleanupRole::SchemaCheckpoint => {
                if self.failure.schema_checkpoint_failed {
                    return;
                }
                self.failure.schema_checkpoint_failed = true;
            },
        }
        let index = usize::from(self.failure.role_count);
        if index < MAX_CLEANUP_ROLES {
            self.failure.roles[index] = Some(role);
            self.failure.role_count = self.failure.role_count.saturating_add(1);
        } else {
            self.failure.overflowed = true;
        }
    }
}

const fn task_bit(role: TaskRole) -> u8 {
    1 << match role {
        TaskRole::Control => 0,
        TaskRole::Operations => 1,
        TaskRole::Api => 2,
        TaskRole::OtlpGrpc => 3,
        TaskRole::OtlpHttp => 4,
        TaskRole::LokiPush => 5,
    }
}

const fn listener_bit(role: ListenerRole) -> u8 {
    1 << match role {
        ListenerRole::Control => 0,
        ListenerRole::Operations => 1,
        ListenerRole::Api => 2,
        ListenerRole::OtlpGrpc => 3,
        ListenerRole::OtlpHttp => 4,
        ListenerRole::LokiPush => 5,
    }
}

const fn primary_context(outcome: ExitOutcome) -> CleanupPrimary {
    match outcome {
        ExitOutcome::Graceful => CleanupPrimary::Graceful,
        ExitOutcome::Forced => CleanupPrimary::Forced,
        ExitOutcome::InvalidConfiguration => CleanupPrimary::InvalidConfiguration,
        ExitOutcome::StartupUnavailable(code) => CleanupPrimary::StartupUnavailable(code),
        ExitOutcome::ListenerUnavailable(role) => CleanupPrimary::ListenerUnavailable(role),
        ExitOutcome::TaskUnavailable(role) => CleanupPrimary::TaskUnavailable(role),
        ExitOutcome::Fenced => CleanupPrimary::Fenced,
        ExitOutcome::InternalCleanupFailure(failure) => failure.primary,
    }
}

const fn outcome_from_primary(primary: CleanupPrimary) -> ExitOutcome {
    match primary {
        CleanupPrimary::None | CleanupPrimary::Forced => ExitOutcome::Forced,
        CleanupPrimary::Graceful => ExitOutcome::Graceful,
        CleanupPrimary::InvalidConfiguration => ExitOutcome::InvalidConfiguration,
        CleanupPrimary::StartupUnavailable(code) => ExitOutcome::StartupUnavailable(code),
        CleanupPrimary::ListenerUnavailable(role) => ExitOutcome::ListenerUnavailable(role),
        CleanupPrimary::TaskUnavailable(role) => ExitOutcome::TaskUnavailable(role),
        CleanupPrimary::Fenced => ExitOutcome::Fenced,
    }
}
