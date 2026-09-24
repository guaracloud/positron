//! Pre-authentication socket reservations owned by one listener generation.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::num::NonZeroU16;
use std::sync::{Arc, Mutex};

/// Bounds accepted sockets before TLS, HTTP, gRPC, or credential parsing.
#[derive(Debug)]
pub(super) struct ConnectionAdmission {
    global_limit: NonZeroU16,
    per_address_limit: NonZeroU16,
    state: Mutex<ReservationState>,
}

#[derive(Debug, Default)]
struct ReservationState {
    total: u16,
    by_address: BTreeMap<IpAddr, u16>,
}

/// Owns one accepted socket's pre-authentication reservation until the
/// transport connection is dropped.
#[derive(Debug)]
pub(super) struct ConnectionReservation {
    admission: Arc<ConnectionAdmission>,
    address: IpAddr,
}

impl ConnectionAdmission {
    pub(super) fn new(global_limit: NonZeroU16, per_address_limit: NonZeroU16) -> Self {
        Self {
            global_limit,
            per_address_limit,
            state: Mutex::new(ReservationState::default()),
        }
    }

    pub(super) fn reserve(self: &Arc<Self>, address: IpAddr) -> Option<ConnectionReservation> {
        let mut state = self.state.lock().ok()?;
        let by_address = state.by_address.get(&address).copied().unwrap_or(0);
        if state.total >= self.global_limit.get() || by_address >= self.per_address_limit.get() {
            return None;
        }
        state.total = state.total.saturating_add(1);
        state
            .by_address
            .insert(address, by_address.saturating_add(1));
        Some(ConnectionReservation {
            admission: Arc::clone(self),
            address,
        })
    }
}

impl Drop for ConnectionReservation {
    fn drop(&mut self) {
        let Ok(mut state) = self.admission.state.lock() else {
            return;
        };
        let Some(by_address) = state.by_address.get_mut(&self.address) else {
            return;
        };
        *by_address = by_address.saturating_sub(1);
        if *by_address == 0 {
            state.by_address.remove(&self.address);
        }
        state.total = state.total.saturating_sub(1);
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::num::NonZeroU16;
    use std::sync::Arc;

    use super::ConnectionAdmission;

    #[test]
    fn preauthentication_reservations_bound_global_and_peer_sockets_until_drop() {
        let admission = Arc::new(ConnectionAdmission::new(
            NonZeroU16::new(2).expect("nonzero"),
            NonZeroU16::new(1).expect("nonzero"),
        ));
        let first = admission
            .reserve(IpAddr::V4(Ipv4Addr::LOCALHOST))
            .expect("first localhost socket");
        assert!(admission.reserve(IpAddr::V4(Ipv4Addr::LOCALHOST)).is_none());
        let second = admission
            .reserve(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)))
            .expect("second peer fits global capacity");
        assert!(
            admission
                .reserve(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)))
                .is_none()
        );
        drop(first);
        assert!(admission.reserve(IpAddr::V4(Ipv4Addr::LOCALHOST)).is_some());
        drop(second);
    }
}
