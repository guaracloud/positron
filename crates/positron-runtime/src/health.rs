use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, OnceLock, Weak};

use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};

use crate::{
    ConfigurationObservation, ConfigurationRuntimeFailure, InitializedInstance, ListenerRole,
    RuntimeConfiguration,
};

/// The one runtime phase that controls admission and shutdown behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ProcessPhase {
    Starting = 0,
    Recovering = 1,
    Serving = 2,
    Draining = 3,
    Fenced = 4,
    Stopping = 5,
    Stopped = 6,
}

/// Whether data traffic can be admitted safely.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Readiness {
    Ready,
    NotReady,
}

/// Whether the process can still make progress and answer operational probes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Liveness {
    Live,
    Dead,
}

/// A bounded operator-visible security condition that does not affect readiness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HealthWarning {
    /// One listener role is using the explicit plaintext transport opt-out.
    PlaintextListener(ListenerRole),
    /// Compatibility view for the public API plaintext opt-out.
    PublicPlaintextApi,
}

impl HealthWarning {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::PlaintextListener(ListenerRole::Operations) => "operations_plaintext",
            Self::PlaintextListener(ListenerRole::Api) | Self::PublicPlaintextApi => {
                "public_plaintext_api"
            },
            Self::PlaintextListener(ListenerRole::OtlpGrpc) => "otlp_grpc_plaintext",
            Self::PlaintextListener(ListenerRole::OtlpHttp) => "otlp_http_plaintext",
            Self::PlaintextListener(ListenerRole::LokiPush) => "loki_push_plaintext",
            Self::PlaintextListener(ListenerRole::Control) => "control_plaintext",
        }
    }
}

/// A read-only view of the runtime's single phase authority.
#[derive(Clone)]
pub struct HealthState {
    phase: Arc<AtomicU8>,
    plaintext_listener_roles: Arc<AtomicU8>,
    configuration: Arc<OnceLock<Arc<RuntimeConfiguration>>>,
    inspection_authority: Arc<OnceLock<Weak<InitializedInstance>>>,
}

impl std::fmt::Debug for HealthState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HealthState")
            .field("phase", &self.phase())
            .field(
                "configuration_available",
                &self.configuration.get().is_some(),
            )
            .finish()
    }
}

impl HealthState {
    #[must_use]
    pub fn phase(&self) -> ProcessPhase {
        decode_phase(self.phase.load(Ordering::Acquire))
    }

    #[must_use]
    pub fn readiness(&self) -> Readiness {
        if self.phase() == ProcessPhase::Serving {
            Readiness::Ready
        } else {
            Readiness::NotReady
        }
    }

    #[must_use]
    pub fn liveness(&self) -> Liveness {
        if self.phase() == ProcessPhase::Stopped {
            Liveness::Dead
        } else {
            Liveness::Live
        }
    }

    /// Returns the active transport warning without changing admission readiness.
    #[must_use]
    pub fn security_warning(&self) -> Option<HealthWarning> {
        self.security_warnings().into_iter().next()
    }

    /// Returns every active, bounded plaintext transport warning.
    #[must_use]
    pub fn security_warnings(&self) -> Vec<HealthWarning> {
        let roles = self.plaintext_listener_roles.load(Ordering::Acquire);
        ListenerRole::all()
            .into_iter()
            .filter(|role| plaintext_role_bit(*role).is_some_and(|bit| roles & bit != 0))
            .map(|role| {
                if role == ListenerRole::Api {
                    HealthWarning::PublicPlaintextApi
                } else {
                    HealthWarning::PlaintextListener(role)
                }
            })
            .collect()
    }

    /// Returns the one canonical configuration observation available to
    /// authenticated Operations inspection.
    pub fn configuration_status(
        &self,
    ) -> Result<Option<ConfigurationObservation>, ConfigurationRuntimeFailure> {
        self.configuration
            .get()
            .map(|runtime| runtime.observed())
            .transpose()
    }

    /// Authorizes inspection through the immutable governance authority shared
    /// with runtime services.
    pub(crate) fn authorize_configuration_status(&self, bearer: &str) -> Result<(), ()> {
        self.inspection_authority
            .get()
            .and_then(Weak::upgrade)
            .ok_or(())?
            .attribute(
                PresentedCredential::parse(bearer).map_err(|_| ())?,
                RequestedIntent::SystemAdministration,
                CompatibilityHints::none(),
            )
            .map(|_| ())
            .map_err(|_| ())
    }
}

pub(crate) struct ProcessState {
    health: HealthState,
}

impl ProcessState {
    pub(crate) fn starting() -> Self {
        Self {
            health: HealthState {
                phase: Arc::new(AtomicU8::new(ProcessPhase::Starting as u8)),
                plaintext_listener_roles: Arc::new(AtomicU8::new(0)),
                configuration: Arc::new(OnceLock::new()),
                inspection_authority: Arc::new(OnceLock::new()),
            },
        }
    }

    pub(crate) fn health(&self) -> HealthState {
        self.health.clone()
    }

    pub(crate) fn transition(&self, phase: ProcessPhase) {
        self.health.phase.store(phase as u8, Ordering::Release);
    }

    pub(crate) fn set_plaintext_listener_warnings(
        &self,
        intents: &[crate::PublicPlaintextApiStartupIntent],
    ) {
        let roles = intents.iter().fold(0_u8, |roles, intent| {
            plaintext_role_bit(intent.role()).map_or(roles, |bit| roles | bit)
        });
        self.health
            .plaintext_listener_roles
            .store(roles, Ordering::Release);
    }

    pub(crate) fn set_configuration_runtime(
        &self,
        runtime: Arc<RuntimeConfiguration>,
    ) -> Result<(), ConfigurationRuntimeFailure> {
        self.health
            .configuration
            .set(runtime)
            .map_err(|_| ConfigurationRuntimeFailure::Unavailable)
    }

    pub(crate) fn set_inspection_authority(
        &self,
        authority: Arc<InitializedInstance>,
    ) -> Result<(), ConfigurationRuntimeFailure> {
        self.health
            .inspection_authority
            .set(Arc::downgrade(&authority))
            .map_err(|_| ConfigurationRuntimeFailure::Unavailable)
    }
}

fn plaintext_role_bit(role: ListenerRole) -> Option<u8> {
    match role {
        ListenerRole::Control => None,
        ListenerRole::Operations => Some(1),
        ListenerRole::Api => Some(1 << 1),
        ListenerRole::OtlpGrpc => Some(1 << 2),
        ListenerRole::OtlpHttp => Some(1 << 3),
        ListenerRole::LokiPush => Some(1 << 4),
    }
}

fn decode_phase(value: u8) -> ProcessPhase {
    match value {
        0 => ProcessPhase::Starting,
        1 => ProcessPhase::Recovering,
        2 => ProcessPhase::Serving,
        3 => ProcessPhase::Draining,
        4 => ProcessPhase::Fenced,
        5 => ProcessPhase::Stopping,
        _ => ProcessPhase::Stopped,
    }
}
