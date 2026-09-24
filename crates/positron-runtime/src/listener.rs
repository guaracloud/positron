use std::error::Error;
use std::fmt::{Display, Formatter};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::{HealthState, RunningTask, ServiceHandle, TaskCancellation, TaskRole};
use positron_config::EffectiveConfiguration;

/// Closed M1 listener roles. Control and Operations never carry tenant data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ListenerRole {
    Control,
    Operations,
    Api,
    OtlpGrpc,
    OtlpHttp,
    LokiPush,
}

impl ListenerRole {
    /// The complete, stable Release 1 listener topology.
    #[must_use]
    pub const fn all() -> [Self; 6] {
        [
            Self::Control,
            Self::Operations,
            Self::Api,
            Self::OtlpGrpc,
            Self::OtlpHttp,
            Self::LokiPush,
        ]
    }

    #[must_use]
    pub const fn is_data(self) -> bool {
        matches!(
            self,
            Self::Api | Self::OtlpGrpc | Self::OtlpHttp | Self::LokiPush
        )
    }

    #[must_use]
    pub const fn is_network(self) -> bool {
        !matches!(self, Self::Control)
    }
}

/// The deliberate transport selection for one network listener profile.
///
/// `PlaintextOptOut` is never an automatic fallback. Callers must construct it
/// explicitly so configuration, health, and governance surfaces can retain the
/// operator's intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ListenerTransport {
    Tls,
    MutualTls,
    PlaintextOptOut,
}

impl ListenerTransport {
    #[must_use]
    pub const fn is_tls(self) -> bool {
        matches!(self, Self::Tls | Self::MutualTls)
    }

    #[must_use]
    pub const fn is_mutual_tls(self) -> bool {
        matches!(self, Self::MutualTls)
    }

    #[must_use]
    pub const fn is_plaintext_opt_out(self) -> bool {
        matches!(self, Self::PlaintextOptOut)
    }
}

/// One validated local or network listener policy before any socket is bound.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ListenerProfile {
    Control {
        path: PathBuf,
    },
    Network {
        role: ListenerRole,
        address: SocketAddr,
        transport: ListenerTransport,
    },
}

impl ListenerProfile {
    pub fn control(path: PathBuf) -> Result<Self, ListenerFailure> {
        BoundEndpoint::control(path.clone())?;
        Ok(Self::Control { path })
    }

    pub fn network(
        role: ListenerRole,
        address: SocketAddr,
        transport: ListenerTransport,
    ) -> Result<Self, ListenerFailure> {
        if !role.is_network() {
            return Err(ListenerFailure::InvalidEndpoint);
        }
        if role == ListenerRole::Operations && !address.ip().is_loopback() && !transport.is_tls() {
            return Err(ListenerFailure::InvalidTransport);
        }
        Ok(Self::Network {
            role,
            address,
            transport,
        })
    }

    #[must_use]
    pub const fn role(&self) -> ListenerRole {
        match self {
            Self::Control { .. } => ListenerRole::Control,
            Self::Network { role, .. } => *role,
        }
    }

    #[must_use]
    pub const fn transport(&self) -> Option<ListenerTransport> {
        match self {
            Self::Control { .. } => None,
            Self::Network { transport, .. } => Some(*transport),
        }
    }

    #[must_use]
    pub const fn has_plaintext_opt_out(&self) -> bool {
        matches!(self.transport(), Some(ListenerTransport::PlaintextOptOut))
    }
}

/// A complete listener candidate. Constructing it proves every Release 1 role
/// has exactly one policy before activation or replacement can begin.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedListenerSet {
    profiles: [ListenerProfile; 6],
}

/// An owned, fully activated listener generation.
///
/// The generation boundary ensures a failed candidate has only temporary
/// sockets to clean up; callers do not touch their active generation until
/// `activate` has succeeded for every role.
pub struct ListenerGeneration {
    candidate: ValidatedListenerSet,
    listeners: Vec<Box<dyn BoundListener>>,
    tasks: ListenerTasks,
    cancellation: Option<TaskCancellation>,
    activation: Option<Box<dyn ListenerGenerationActivation>>,
    material_identity: Option<[u8; 32]>,
}

pub type ListenerTasks = Vec<(TaskRole, Box<dyn RunningTask>)>;
pub type ActiveListenerGeneration = (
    Vec<Box<dyn BoundListener>>,
    ListenerTasks,
    Option<TaskCancellation>,
);

/// Native staging keeps workers parked until the durable configuration commit
/// has succeeded. The gate is generation-owned so a discarded candidate never
/// shares workers with the serving generation.
pub trait ListenerGenerationActivation: Send {
    /// Starts parked workers and proves they are ready while their admissions
    /// remain closed. This must complete before durable publication.
    fn prepare_and_wait_ready(&self) -> Result<(), ListenerFailure>;

    /// Opens already prepared admissions. Implementations must not perform a
    /// fallible operation here because publication has already succeeded.
    fn open_admission(&self);
}

impl std::fmt::Debug for ListenerGeneration {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ListenerGeneration")
            .field("profile_count", &self.candidate.len())
            .field("bound_count", &self.listeners.len())
            .field("task_count", &self.tasks.len())
            .field("has_material_identity", &self.material_identity.is_some())
            .finish()
    }
}

impl ListenerGeneration {
    /// Binds every role in a complete candidate before returning an owned
    /// generation. Any partial candidate is synchronously closed.
    pub fn activate(
        candidate: ValidatedListenerSet,
        factory: &dyn ListenerFactory,
        health: HealthState,
    ) -> Result<Self, ListenerFailure> {
        Self::activate_with_failure_role(candidate, factory, health).map_err(|(_, failure)| failure)
    }

    pub(crate) fn activate_with_failure_role(
        candidate: ValidatedListenerSet,
        factory: &dyn ListenerFactory,
        health: HealthState,
    ) -> Result<Self, (ListenerRole, ListenerFailure)> {
        let mut listeners = Vec::with_capacity(candidate.len());
        for profile in candidate.profiles() {
            let request = ListenerRequest::for_profile(profile.clone(), health.clone());
            let listener = match factory.bind(request) {
                Ok(listener) if listener.endpoint().role() == profile.role() => listener,
                Ok(mut listener) => {
                    let cleanup_failed =
                        listener.close().is_err() || close_all(&mut listeners).is_err();
                    if cleanup_failed {
                        return Err((profile.role(), ListenerFailure::BindUnavailable));
                    }
                    return Err((profile.role(), ListenerFailure::BindUnavailable));
                },
                Err(error) => {
                    if close_all(&mut listeners).is_err() {
                        return Err((profile.role(), ListenerFailure::BindUnavailable));
                    }
                    return Err((profile.role(), error));
                },
            };
            listeners.push(listener);
        }
        Ok(Self {
            candidate,
            listeners,
            tasks: Vec::new(),
            cancellation: None,
            activation: None,
            material_identity: None,
        })
    }

    pub(crate) fn with_material_identity(mut self, identity: [u8; 32]) -> Self {
        self.material_identity = Some(identity);
        self
    }

    #[must_use]
    pub(crate) const fn material_identity(&self) -> Option<[u8; 32]> {
        self.material_identity
    }

    /// Stages a complete replacement without disturbing this active
    /// generation. Once the replacement is bound, old admission closes; the
    /// caller retains this generation and drains it under its old policy.
    pub fn replace(
        &mut self,
        candidate: ValidatedListenerSet,
        factory: &dyn ListenerFactory,
        health: HealthState,
    ) -> Result<Self, ListenerFailure> {
        let replacement = Self::activate(candidate, factory, health)?;
        self.stop_admission()?;
        Ok(replacement)
    }

    /// Stops admission for all roles. Connection completion remains owned by
    /// the host task that accepted each connection under this generation.
    pub fn stop_admission(&mut self) -> Result<(), ListenerFailure> {
        let mut failed = false;
        for listener in &mut self.listeners {
            if listener.close().is_err() {
                failed = true;
            }
        }
        if failed {
            Err(ListenerFailure::BindUnavailable)
        } else {
            Ok(())
        }
    }

    /// Releases the listener-owned sockets after admission is closed.
    pub fn drain(mut self) -> Result<(), ListenerFailure> {
        self.cancel_staged_tasks()?;
        self.stop_admission()
    }

    #[must_use]
    pub fn candidate(&self) -> &ValidatedListenerSet {
        &self.candidate
    }

    #[must_use]
    pub fn endpoints(&self) -> Vec<BoundEndpoint> {
        self.listeners
            .iter()
            .map(|listener| listener.endpoint().clone())
            .collect()
    }

    /// Attaches workers that were registered and spawned for these exact
    /// admissions. The factory calls this only after every worker has parked.
    pub fn with_staged_tasks(
        mut self,
        tasks: ListenerTasks,
        cancellation: TaskCancellation,
        activation: Box<dyn ListenerGenerationActivation>,
    ) -> Self {
        self.tasks = tasks;
        self.cancellation = Some(cancellation);
        self.activation = Some(activation);
        self
    }

    /// Starts the staged workers and waits for readiness while their listener
    /// admissions remain closed. Callers can discard a failed preparation
    /// before any durable configuration or audit publication.
    pub fn prepare_tasks(&self) -> Result<(), ListenerFailure> {
        self.activation
            .as_ref()
            .map_or(Ok(()), |activation| activation.prepare_and_wait_ready())
    }

    /// Opens admissions after publication and after the retiring generation
    /// has stopped accepting new work.
    pub fn open_admission(&self) {
        if let Some(activation) = self.activation.as_ref() {
            activation.open_admission();
        }
    }

    /// Cancels and joins a discarded candidate before its descriptors are
    /// released. A candidate never borrows the active generation's tasks.
    pub fn discard(mut self) -> Result<(), ListenerFailure> {
        self.cancel_staged_tasks()?;
        self.stop_admission()
    }

    fn cancel_staged_tasks(&mut self) -> Result<(), ListenerFailure> {
        if let Some(cancellation) = self.cancellation.as_ref() {
            cancellation.cancel();
        }
        for (_, task) in &mut self.tasks {
            task.abort().map_err(|_| ListenerFailure::BindUnavailable)?;
        }
        self.tasks.clear();
        Ok(())
    }

    /// Transfers exactly one complete listener generation to the runtime.
    /// Descriptors and their role workers move together; neither can be
    /// adopted by a later generation.
    #[must_use]
    pub fn into_active(mut self) -> ActiveListenerGeneration {
        (
            std::mem::take(&mut self.listeners),
            std::mem::take(&mut self.tasks),
            self.cancellation.take(),
        )
    }
}

fn close_all(listeners: &mut [Box<dyn BoundListener>]) -> Result<(), ListenerFailure> {
    let mut failed = false;
    for listener in listeners {
        if listener.close().is_err() {
            failed = true;
        }
    }
    if failed {
        Err(ListenerFailure::BindUnavailable)
    } else {
        Ok(())
    }
}

impl ValidatedListenerSet {
    pub fn new(profiles: [ListenerProfile; 6]) -> Result<Self, ListenerFailure> {
        for role in ListenerRole::all() {
            if profiles
                .iter()
                .filter(|profile| profile.role() == role)
                .count()
                != 1
            {
                return Err(ListenerFailure::IncompleteGeneration);
            }
        }
        Ok(Self { profiles })
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.profiles.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }

    #[must_use]
    pub fn profiles(&self) -> &[ListenerProfile; 6] {
        &self.profiles
    }

    #[must_use]
    pub fn has_plaintext_opt_out(&self) -> bool {
        self.profiles
            .iter()
            .any(ListenerProfile::has_plaintext_opt_out)
    }
}

/// A verified endpoint returned by the listener boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BoundEndpoint {
    Control {
        path: PathBuf,
    },
    Tcp {
        role: ListenerRole,
        address: SocketAddr,
    },
}

impl BoundEndpoint {
    pub fn control(path: PathBuf) -> Result<Self, ListenerFailure> {
        if !path.is_absolute() {
            return Err(ListenerFailure::InvalidEndpoint);
        }
        Ok(Self::Control { path })
    }

    pub fn tcp(role: ListenerRole, address: SocketAddr) -> Result<Self, ListenerFailure> {
        if role == ListenerRole::Control {
            return Err(ListenerFailure::InvalidEndpoint);
        }
        Ok(Self::Tcp { role, address })
    }

    #[must_use]
    pub const fn role(&self) -> ListenerRole {
        match self {
            Self::Control { .. } => ListenerRole::Control,
            Self::Tcp { role, .. } => *role,
        }
    }

    #[must_use]
    pub fn control_path(&self) -> Option<&Path> {
        match self {
            Self::Control { path } => Some(path),
            Self::Tcp { .. } => None,
        }
    }

    #[must_use]
    pub const fn socket_address(&self) -> Option<SocketAddr> {
        match self {
            Self::Control { .. } => None,
            Self::Tcp { address, .. } => Some(*address),
        }
    }
}

/// A bounded request to bind one role with the authoritative health view.
#[derive(Clone, Debug)]
pub struct ListenerRequest {
    role: ListenerRole,
    health: HealthState,
    profile: Option<ListenerProfile>,
}

impl ListenerRequest {
    pub(crate) fn new(role: ListenerRole, health: HealthState) -> Self {
        Self {
            role,
            health,
            profile: None,
        }
    }

    #[must_use]
    pub fn for_profile(profile: ListenerProfile, health: HealthState) -> Self {
        let role = profile.role();
        Self {
            role,
            health,
            profile: Some(profile),
        }
    }

    #[must_use]
    pub const fn role(&self) -> ListenerRole {
        self.role
    }

    #[must_use]
    pub fn health(&self) -> HealthState {
        self.health.clone()
    }

    #[must_use]
    pub fn profile(&self) -> Option<&ListenerProfile> {
        self.profile.as_ref()
    }
}

/// One owned listener. Dropping it must synchronously close new admission.
pub trait BoundListener {
    fn endpoint(&self) -> &BoundEndpoint;
    fn close(&mut self) -> Result<(), ListenerFailure> {
        Ok(())
    }

    /// Closes new admission and waits only for work accepted by this listener
    /// generation to complete within its established drain budget.
    fn drain_within(&mut self, _: std::time::Duration) -> Result<bool, ListenerFailure> {
        self.close()?;
        Ok(true)
    }
}

/// Host boundary for binding control, operational, and data endpoints.
pub trait ListenerFactory {
    fn bind(&self, request: ListenerRequest) -> Result<Box<dyn BoundListener>, ListenerFailure>;

    /// Returns the canonical profile for a native role when this host owns a
    /// complete resolved Listener Set. Test and embedded hosts may omit it.
    fn profile_for(&self, _role: ListenerRole) -> Option<ListenerProfile> {
        None
    }

    /// Returns the host-owned staging boundary when this factory can build a
    /// successor from a resolved Configuration Contract. Embedded test hosts
    /// may omit it; they retain the explicit `RequiresDrain` outcome.
    fn generation_factory(&self) -> Option<Arc<dyn ListenerGenerationFactory>> {
        None
    }
}

/// Host boundary for staging a complete replacement Listener Set from the
/// canonical resolved Configuration Contract.
///
/// The returned generation owns every successor descriptor. It is therefore
/// safe to discard before publication when certificate loading or a fresh bind
/// fails, leaving the serving generation untouched.
pub trait ListenerGenerationFactory: Send + Sync {
    fn stage(
        &self,
        configuration: &EffectiveConfiguration,
        health: HealthState,
        services: Option<ServiceHandle>,
    ) -> Result<ListenerGeneration, ListenerFailure>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ListenerFailure {
    InvalidEndpoint,
    InvalidTransport,
    IncompleteGeneration,
    BindUnavailable,
}

impl Display for ListenerFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("listener activation failed")
    }
}

impl Error for ListenerFailure {}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::path::PathBuf;
    use std::rc::Rc;

    use super::{
        BoundEndpoint, BoundListener, ListenerFactory, ListenerGeneration, ListenerProfile,
        ListenerRequest, ListenerRole, ListenerTransport, ValidatedListenerSet,
    };
    use crate::health::ProcessState;

    #[test]
    fn failed_candidate_keeps_the_active_generation_bound() -> Result<(), Box<dyn std::error::Error>>
    {
        let control = PathBuf::from("/run/positron/listener-generation.sock");
        let host = BindingHost::default();
        let candidate = candidate(control)?;
        let state = ProcessState::starting();
        let mut active = ListenerGeneration::activate(candidate.clone(), &host, state.health())?;
        let endpoints = active.endpoints();
        host.fail_at.set(Some(ListenerRole::OtlpHttp));

        let failure = active
            .replace(candidate, &host, state.health())
            .expect_err("the candidate must be discarded before active admission closes");
        assert_eq!(failure, super::ListenerFailure::BindUnavailable);
        assert_eq!(active.endpoints(), endpoints);
        assert_eq!(host.closed.borrow().len(), 4);
        active.drain()?;
        Ok(())
    }

    #[derive(Default)]
    struct BindingHost {
        fail_at: Cell<Option<ListenerRole>>,
        closed: Rc<RefCell<Vec<ListenerRole>>>,
    }

    impl ListenerFactory for BindingHost {
        fn bind(
            &self,
            request: ListenerRequest,
        ) -> Result<Box<dyn BoundListener>, super::ListenerFailure> {
            if self.fail_at.get() == Some(request.role()) {
                return Err(super::ListenerFailure::BindUnavailable);
            }
            let endpoint = if request.role() == ListenerRole::Control {
                BoundEndpoint::control(PathBuf::from("/run/positron/listener-generation.sock"))?
            } else {
                BoundEndpoint::tcp(request.role(), loopback(0))?
            };
            Ok(Box::new(BindingListener {
                endpoint,
                closed: Rc::clone(&self.closed),
            }))
        }
    }

    struct BindingListener {
        endpoint: BoundEndpoint,
        closed: Rc<RefCell<Vec<ListenerRole>>>,
    }

    impl BoundListener for BindingListener {
        fn endpoint(&self) -> &BoundEndpoint {
            &self.endpoint
        }

        fn close(&mut self) -> Result<(), super::ListenerFailure> {
            self.closed.borrow_mut().push(self.endpoint.role());
            Ok(())
        }
    }

    fn candidate(control: PathBuf) -> Result<ValidatedListenerSet, super::ListenerFailure> {
        ValidatedListenerSet::new([
            ListenerProfile::control(control)?,
            ListenerProfile::network(
                ListenerRole::Operations,
                loopback(0),
                ListenerTransport::PlaintextOptOut,
            )?,
            ListenerProfile::network(ListenerRole::Api, loopback(0), ListenerTransport::Tls)?,
            ListenerProfile::network(
                ListenerRole::OtlpGrpc,
                loopback(0),
                ListenerTransport::PlaintextOptOut,
            )?,
            ListenerProfile::network(
                ListenerRole::OtlpHttp,
                loopback(0),
                ListenerTransport::PlaintextOptOut,
            )?,
            ListenerProfile::network(
                ListenerRole::LokiPush,
                loopback(0),
                ListenerTransport::PlaintextOptOut,
            )?,
        ])
    }

    const fn loopback(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
    }
}
