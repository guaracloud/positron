use std::error::Error;
use std::fmt::{Display, Formatter};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use crate::HealthState;

/// Closed M1 listener roles. Control and Operations never carry tenant data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ListenerRole {
    Control,
    Operations,
    Api,
    OtlpHttp,
}

impl ListenerRole {
    #[must_use]
    pub const fn is_data(self) -> bool {
        matches!(self, Self::Api | Self::OtlpHttp)
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
        if role == ListenerRole::Control || !address.ip().is_loopback() {
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
}

impl ListenerRequest {
    pub(crate) fn new(role: ListenerRole, health: HealthState) -> Self {
        Self { role, health }
    }

    #[must_use]
    pub const fn role(&self) -> ListenerRole {
        self.role
    }

    #[must_use]
    pub fn health(&self) -> HealthState {
        self.health.clone()
    }
}

/// One owned listener. Dropping it must synchronously close new admission.
pub trait BoundListener {
    fn endpoint(&self) -> &BoundEndpoint;
    fn close(&mut self) -> Result<(), ListenerFailure> {
        Ok(())
    }
}

/// Host boundary for binding control, operational, and data endpoints.
pub trait ListenerFactory {
    fn bind(&self, request: ListenerRequest) -> Result<Box<dyn BoundListener>, ListenerFailure>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ListenerFailure {
    InvalidEndpoint,
    BindUnavailable,
}

impl Display for ListenerFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("listener activation failed")
    }
}

impl Error for ListenerFailure {}
