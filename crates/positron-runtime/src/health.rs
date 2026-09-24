use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, OnceLock, Weak};

use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};

use crate::{
    ConfigurationObservation, ConfigurationRuntimeFailure, InitializedInstance,
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
    /// The API listener is using the explicit plaintext transport opt-out.
    PublicPlaintextApi,
}

/// A read-only view of the runtime's single phase authority.
#[derive(Clone)]
pub struct HealthState {
    phase: Arc<AtomicU8>,
    public_plaintext_api: Arc<AtomicBool>,
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
        self.public_plaintext_api
            .load(Ordering::Acquire)
            .then_some(HealthWarning::PublicPlaintextApi)
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
                public_plaintext_api: Arc::new(AtomicBool::new(false)),
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

    pub(crate) fn set_public_plaintext_api_warning(&self, enabled: bool) {
        self.health
            .public_plaintext_api
            .store(enabled, Ordering::Release);
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
