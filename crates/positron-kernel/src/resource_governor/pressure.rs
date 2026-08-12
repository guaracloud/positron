//! Observation-driven disk-pressure hysteresis.

use super::accounting::GovernorInner;
use super::failure::{DiskPressureState, GovernorFailure};
use super::inventory::{DiskObservation, DiskPressureThresholds};
use super::lifecycle::GovernorLifecycle;

impl DiskPressureThresholds {
    pub(super) const fn initial(self, observation: DiskObservation) -> DiskPressureState {
        if observation.usable_bytes <= self.hard_enter {
            DiskPressureState::HardPressure
        } else if observation.usable_bytes <= self.soft_enter {
            DiskPressureState::SoftPressure
        } else {
            DiskPressureState::Healthy
        }
    }

    const fn transition(
        self,
        current: DiskPressureState,
        observation: DiskObservation,
    ) -> DiskPressureState {
        match current {
            DiskPressureState::Healthy => self.initial(observation),
            DiskPressureState::SoftPressure => {
                if observation.usable_bytes <= self.hard_enter {
                    DiskPressureState::HardPressure
                } else if observation.usable_bytes >= self.soft_exit {
                    DiskPressureState::Healthy
                } else {
                    DiskPressureState::SoftPressure
                }
            },
            DiskPressureState::HardPressure => {
                if observation.usable_bytes >= self.soft_exit {
                    DiskPressureState::Healthy
                } else if observation.usable_bytes >= self.hard_exit {
                    DiskPressureState::SoftPressure
                } else {
                    DiskPressureState::HardPressure
                }
            },
        }
    }
}

impl GovernorInner {
    pub(super) fn apply_disk_observation(
        &self,
        observation: DiskObservation,
    ) -> Result<DiskPressureState, GovernorFailure> {
        let mut state = self.try_lock_for_control()?;
        if state.lifecycle == GovernorLifecycle::Fenced {
            return Err(GovernorFailure::InternalFenced);
        }
        let pressure = self
            .disk_thresholds
            .transition(state.disk_pressure, observation);
        state.usable_disk_bytes = observation.usable_bytes;
        if pressure != state.disk_pressure {
            state.pressure_transition_count = state
                .pressure_transition_count
                .checked_add(1)
                .ok_or_else(|| {
                    state.lifecycle = GovernorLifecycle::Fenced;
                    GovernorFailure::InternalFenced
                })?;
            state.disk_pressure = pressure;
            self.publish_pressure(pressure);
        }
        Ok(pressure)
    }
}
