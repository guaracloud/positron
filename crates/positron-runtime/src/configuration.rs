use std::fmt::{Display, Formatter};
use std::sync::{Arc, RwLock};

use positron_config::{
    ConfigurationDiff, ConfigurationDiffPlan, ConfigurationDrift, ConfigurationDriftDisposition,
    EffectiveConfiguration,
};

/// A complete, immutable effective configuration observed by one runtime
/// consumer. Cloning this value cannot expose a mix of two generations.
#[derive(Clone)]
pub struct ConfigurationObservation {
    generation: u64,
    effective: Arc<EffectiveConfiguration>,
    desired: Arc<EffectiveConfiguration>,
    drift_disposition: ConfigurationDriftDisposition,
    pending_restart: Option<PendingRestart>,
}

impl ConfigurationObservation {
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub fn effective(&self) -> &Arc<EffectiveConfiguration> {
        &self.effective
    }

    #[must_use]
    pub fn desired(&self) -> &Arc<EffectiveConfiguration> {
        &self.desired
    }

    #[must_use]
    pub const fn drift_disposition(&self) -> ConfigurationDriftDisposition {
        self.drift_disposition
    }

    #[must_use]
    pub fn pending_restart(&self) -> Option<&PendingRestart> {
        self.pending_restart.as_ref()
    }
}

impl std::fmt::Debug for ConfigurationObservation {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConfigurationObservation")
            .field("generation", &self.generation)
            .field("drift_disposition", &self.drift_disposition)
            .field("pending_restart", &self.pending_restart.is_some())
            .finish_non_exhaustive()
    }
}

/// A validated complete candidate that becomes active only on the next
/// process start because it includes restart-required settings.
#[derive(Clone)]
pub struct PendingRestart {
    candidate: Arc<EffectiveConfiguration>,
    diff: ConfigurationDiff,
}

impl PendingRestart {
    #[must_use]
    pub fn candidate(&self) -> &Arc<EffectiveConfiguration> {
        &self.candidate
    }

    #[must_use]
    pub const fn diff(&self) -> &ConfigurationDiff {
        &self.diff
    }
}

impl std::fmt::Debug for PendingRestart {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PendingRestart")
            .field("change_count", &self.diff.changes().len())
            .finish_non_exhaustive()
    }
}

/// The externally observable disposition of one fully validated candidate.
#[derive(Clone, Debug)]
pub enum ConfigurationReloadOutcome {
    NoChange {
        generation: u64,
    },
    PublishedLive {
        generation: u64,
        diff: ConfigurationDiff,
    },
    PendingRestart {
        generation: u64,
        diff: ConfigurationDiff,
    },
    RejectedImmutable {
        diff: ConfigurationDiff,
    },
    RequiresDrain {
        diff: ConfigurationDiff,
    },
}

/// The redacted configuration disposition that must commit through the Catalog
/// Writer before a runtime may expose its successor state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigurationPublicationDisposition {
    PublishedLive,
    PendingRestart,
    RejectedImmutable,
    RequiresDrain,
    FencedDrift,
}

/// Durable publication boundary for Configuration-owned semantics.
///
/// Implementations must bind the disposition and complete redacted candidate
/// digest to one Catalog generation and Governance Audit Record, or fail.
pub trait ConfigurationPublication: Send + Sync {
    fn publish(
        &self,
        active: &EffectiveConfiguration,
        candidate: &EffectiveConfiguration,
        diff: &ConfigurationDiff,
        disposition: ConfigurationPublicationDisposition,
    ) -> Result<u64, ConfigurationRuntimeFailure>;

    fn publish_with_plaintext_listener_opt_outs(
        &self,
        active: &EffectiveConfiguration,
        candidate: &EffectiveConfiguration,
        diff: &ConfigurationDiff,
        disposition: ConfigurationPublicationDisposition,
        plaintext_listener_opt_outs: &[positron_governance::ListenerTransportAuditRequest],
    ) -> Result<u64, ConfigurationRuntimeFailure> {
        if plaintext_listener_opt_outs.is_empty() {
            self.publish(active, candidate, diff, disposition)
        } else {
            Err(ConfigurationRuntimeFailure::PublicationUnavailable)
        }
    }
}

impl ConfigurationReloadOutcome {
    #[must_use]
    pub const fn diff(&self) -> Option<&ConfigurationDiff> {
        match self {
            Self::NoChange { .. } => None,
            Self::PublishedLive { diff, .. }
            | Self::PendingRestart { diff, .. }
            | Self::RejectedImmutable { diff }
            | Self::RequiresDrain { diff } => Some(diff),
        }
    }
}

/// Runtime access to the one complete active configuration generation.
///
/// It deliberately accepts only an already resolved `EffectiveConfiguration`.
/// Source loading and validation remain the Configuration module's authority.
pub struct RuntimeConfiguration {
    state: RwLock<ConfigurationObservation>,
}

impl RuntimeConfiguration {
    #[must_use]
    pub fn new(initial: Arc<EffectiveConfiguration>) -> Self {
        Self::new_at_generation(initial, 1)
    }

    #[must_use]
    pub fn new_at_generation(initial: Arc<EffectiveConfiguration>, generation: u64) -> Self {
        Self {
            state: RwLock::new(ConfigurationObservation {
                generation,
                effective: Arc::clone(&initial),
                desired: initial,
                drift_disposition: ConfigurationDriftDisposition::None,
                pending_restart: None,
            }),
        }
    }

    pub fn observed(&self) -> Result<ConfigurationObservation, ConfigurationRuntimeFailure> {
        self.state
            .read()
            .map(|state| state.clone())
            .map_err(|_| ConfigurationRuntimeFailure::Unavailable)
    }

    /// Computes the redacted operator-visible difference between the observed
    /// active generation and one resolved desired generation.
    pub fn drift_against(
        &self,
        desired: Arc<EffectiveConfiguration>,
    ) -> Result<ConfigurationDrift, ConfigurationRuntimeFailure> {
        self.state
            .read()
            .map(|state| state.effective.drift_against(&desired))
            .map_err(|_| ConfigurationRuntimeFailure::Unavailable)
    }

    /// Clears a superseded desired candidate only when the supplied desired
    /// configuration is still equal to the active configuration under the
    /// canonical state lock. This is an observation update, so it does not
    /// publish a new Catalog generation or Governance Audit record.
    pub(crate) fn clear_matching_desired_configuration(
        &self,
        desired: &EffectiveConfiguration,
    ) -> Result<Option<ConfigurationDrift>, ConfigurationRuntimeFailure> {
        let mut state = self
            .state
            .write()
            .map_err(|_| ConfigurationRuntimeFailure::Unavailable)?;
        Ok(clear_matching_desired_state(&mut state, desired))
    }

    /// Reloads through the durable Catalog and Governance Audit boundary.
    /// The write lock remains held until the publication succeeds, preventing
    /// readers from observing an in-memory successor without its audit-bound
    /// Catalog generation.
    pub fn reload_with(
        &self,
        candidate: Arc<EffectiveConfiguration>,
        publication: &dyn ConfigurationPublication,
    ) -> Result<ConfigurationReloadOutcome, ConfigurationRuntimeFailure> {
        let mut state = self
            .state
            .write()
            .map_err(|_| ConfigurationRuntimeFailure::Unavailable)?;
        let diff = state.effective.semantic_diff(&candidate);
        match diff.plan() {
            ConfigurationDiffPlan::NoChange => {
                clear_matching_desired_state(&mut state, &candidate);
                Ok(ConfigurationReloadOutcome::NoChange {
                    generation: state.generation,
                })
            },
            ConfigurationDiffPlan::PublishLive => {
                let generation = publication.publish(
                    &state.effective,
                    &candidate,
                    &diff,
                    ConfigurationPublicationDisposition::PublishedLive,
                )?;
                validate_successor_generation(state.generation, generation)?;
                state.generation = generation;
                state.effective = Arc::clone(&candidate);
                state.desired = candidate;
                state.drift_disposition = ConfigurationDriftDisposition::None;
                state.pending_restart = None;
                Ok(ConfigurationReloadOutcome::PublishedLive { generation, diff })
            },
            ConfigurationDiffPlan::RestartRequired => {
                let active = Arc::new(state.effective.with_live_changes_from(&candidate));
                let generation = publication.publish(
                    &active,
                    &candidate,
                    &diff,
                    ConfigurationPublicationDisposition::PendingRestart,
                )?;
                validate_successor_generation(state.generation, generation)?;
                state.generation = generation;
                if active.as_ref() != state.effective.as_ref() {
                    state.effective = active;
                }
                state.desired = Arc::clone(&candidate);
                state.drift_disposition = ConfigurationDriftDisposition::Reconcile;
                state.pending_restart = Some(PendingRestart {
                    candidate,
                    diff: diff.clone(),
                });
                Ok(ConfigurationReloadOutcome::PendingRestart {
                    generation: state.generation,
                    diff,
                })
            },
            ConfigurationDiffPlan::RequiresMigration => {
                publication.publish(
                    &state.effective,
                    &candidate,
                    &diff,
                    ConfigurationPublicationDisposition::RejectedImmutable,
                )?;
                Ok(ConfigurationReloadOutcome::RejectedImmutable { diff })
            },
            ConfigurationDiffPlan::DrainThenPublish => {
                publication.publish(
                    &state.effective,
                    &candidate,
                    &diff,
                    ConfigurationPublicationDisposition::RequiresDrain,
                )?;
                Ok(ConfigurationReloadOutcome::RequiresDrain { diff })
            },
        }
    }

    /// Commits a candidate whose drain-and-reload Listener Set has already
    /// been staged by the process owner. Staging happens before this durable
    /// Catalog and Governance Audit publication; only a successful
    /// publication may make the successor configuration observable.
    pub(crate) fn publish_staged_listener_reload(
        &self,
        candidate: Arc<EffectiveConfiguration>,
        publication: &dyn ConfigurationPublication,
        plaintext_listener_opt_outs: &[positron_governance::ListenerTransportAuditRequest],
    ) -> Result<ConfigurationReloadOutcome, ConfigurationRuntimeFailure> {
        let mut state = self
            .state
            .write()
            .map_err(|_| ConfigurationRuntimeFailure::Unavailable)?;
        let diff = state.effective.semantic_diff(&candidate);
        if diff.plan() != ConfigurationDiffPlan::DrainThenPublish {
            return Err(ConfigurationRuntimeFailure::Unavailable);
        }
        let generation = publication.publish_with_plaintext_listener_opt_outs(
            &state.effective,
            &candidate,
            &diff,
            ConfigurationPublicationDisposition::PublishedLive,
            plaintext_listener_opt_outs,
        )?;
        validate_successor_generation(state.generation, generation)?;
        state.generation = generation;
        state.effective = Arc::clone(&candidate);
        state.desired = candidate;
        state.drift_disposition = ConfigurationDriftDisposition::None;
        state.pending_restart = None;
        Ok(ConfigurationReloadOutcome::PublishedLive { generation, diff })
    }

    /// Records a security- or identity-sensitive desired-state drift while
    /// retaining the active configuration. Callers fence data admission only
    /// after this durable evidence has been accepted.
    pub fn record_fenced_drift_with(
        &self,
        desired: Arc<EffectiveConfiguration>,
        publication: &dyn ConfigurationPublication,
    ) -> Result<ConfigurationDrift, ConfigurationRuntimeFailure> {
        let mut state = self
            .state
            .write()
            .map_err(|_| ConfigurationRuntimeFailure::Unavailable)?;
        let drift = state.effective.drift_against(&desired);
        if drift.disposition() == ConfigurationDriftDisposition::Fence {
            publication.publish(
                &state.effective,
                &desired,
                drift.diff(),
                ConfigurationPublicationDisposition::FencedDrift,
            )?;
            state.desired = desired;
            state.drift_disposition = ConfigurationDriftDisposition::Fence;
        }
        Ok(drift)
    }
}

fn clear_matching_desired_state(
    state: &mut ConfigurationObservation,
    desired: &EffectiveConfiguration,
) -> Option<ConfigurationDrift> {
    let drift = state.effective.drift_against(desired);
    if drift.disposition() != ConfigurationDriftDisposition::None {
        return None;
    }
    state.desired = Arc::clone(&state.effective);
    state.drift_disposition = ConfigurationDriftDisposition::None;
    state.pending_restart = None;
    Some(drift)
}

fn validate_successor_generation(
    current: u64,
    successor: u64,
) -> Result<(), ConfigurationRuntimeFailure> {
    (successor > current)
        .then_some(())
        .ok_or(ConfigurationRuntimeFailure::PublicationUnavailable)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigurationRuntimeFailure {
    Unavailable,
    PublicationUnavailable,
    ListenerUnavailable,
    ImmutableConfiguration,
}

impl Display for ConfigurationRuntimeFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "configuration runtime is unavailable",
            Self::PublicationUnavailable => "configuration publication is unavailable",
            Self::ListenerUnavailable => "listener replacement is unavailable",
            Self::ImmutableConfiguration => {
                "configuration changes an immutable initialized setting"
            },
        })
    }
}

impl std::error::Error for ConfigurationRuntimeFailure {}
