//! Pre-authentication socket reservations owned by one listener generation.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::num::NonZeroU16;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::ConnectionProtection;

/// Bounds accepted sockets before TLS, HTTP, gRPC, or credential parsing.
#[derive(Debug)]
pub(super) struct ConnectionAdmission {
    global_limit: NonZeroU16,
    per_address_limit: NonZeroU16,
    global_attempt_rate: NonZeroU16,
    per_address_attempt_rate: NonZeroU16,
    tls_handshake_limit: NonZeroU16,
    state: Mutex<ReservationState>,
}

#[derive(Debug, Default)]
struct ReservationState {
    total: u16,
    by_address: BTreeMap<IpAddr, u16>,
    tls_handshakes: u16,
    attempts: Option<AttemptWindow>,
}

#[derive(Debug)]
struct AttemptWindow {
    started: Instant,
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

/// Owns one in-progress TLS handshake reservation until it completes or fails.
#[derive(Debug)]
pub(super) struct HandshakeReservation {
    admission: Arc<ConnectionAdmission>,
}

impl ConnectionAdmission {
    pub(super) fn new(
        global_limit: NonZeroU16,
        per_address_limit: NonZeroU16,
        protection: ConnectionProtection,
        global_attempt_rate: NonZeroU16,
        per_address_attempt_rate: NonZeroU16,
    ) -> Self {
        Self {
            global_limit,
            per_address_limit,
            global_attempt_rate,
            per_address_attempt_rate,
            tls_handshake_limit: protection.tls_handshake_limit(),
            state: Mutex::new(ReservationState::default()),
        }
    }

    pub(super) fn reserve_tls_handshake(self: &Arc<Self>) -> Option<HandshakeReservation> {
        let mut state = self.state.lock().ok()?;
        if state.tls_handshakes >= self.tls_handshake_limit.get() {
            return None;
        }
        state.tls_handshakes = state.tls_handshakes.saturating_add(1);
        Some(HandshakeReservation {
            admission: Arc::clone(self),
        })
    }

    pub(super) fn reserve(self: &Arc<Self>, address: IpAddr) -> Option<ConnectionReservation> {
        self.reserve_at(address, Instant::now())
    }

    fn reserve_at(
        self: &Arc<Self>,
        address: IpAddr,
        now: Instant,
    ) -> Option<ConnectionReservation> {
        let mut state = self.state.lock().ok()?;
        if !self.record_attempt(&mut state, address, now) {
            return None;
        }
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

    pub(super) fn reserve_attempt(self: &Arc<Self>, address: IpAddr) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        self.record_attempt(&mut state, address, Instant::now())
    }

    pub(super) fn rate_retry_after(&self) -> Option<Duration> {
        let state = self.state.lock().ok()?;
        let window = state.attempts.as_ref()?;
        if window.total < self.global_attempt_rate.get() {
            return None;
        }
        let deadline = window.started + Duration::from_secs(1);
        let remaining = deadline.saturating_duration_since(Instant::now());
        (!remaining.is_zero()).then_some(remaining)
    }

    fn record_attempt(&self, state: &mut ReservationState, address: IpAddr, now: Instant) -> bool {
        let expired = state.attempts.as_ref().is_none_or(|window| {
            now.saturating_duration_since(window.started) >= Duration::from_secs(1)
        });
        if expired {
            state.attempts = Some(AttemptWindow {
                started: now,
                total: 0,
                by_address: BTreeMap::new(),
            });
        }
        let Some(window) = state.attempts.as_mut() else {
            return false;
        };
        if window.total >= self.global_attempt_rate.get() {
            return false;
        }
        window.total = window.total.saturating_add(1);
        let attempts = window.by_address.get(&address).copied().unwrap_or(0);
        if attempts >= self.per_address_attempt_rate.get() {
            return false;
        }
        window
            .by_address
            .insert(address, attempts.saturating_add(1));
        true
    }
}

impl Drop for HandshakeReservation {
    fn drop(&mut self) {
        let Ok(mut state) = self.admission.state.lock() else {
            return;
        };
        state.tls_handshakes = state.tls_handshakes.saturating_sub(1);
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
    use crate::ConnectionProtection;
    use std::time::{Duration, Instant};

    fn protection(limit: u16) -> ConnectionProtection {
        ConnectionProtection::new(
            NonZeroU16::new(limit).expect("nonzero test handshake limit"),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
    }

    #[test]
    fn preauthentication_reservations_bound_global_and_peer_sockets_until_drop() {
        let admission = Arc::new(ConnectionAdmission::new(
            NonZeroU16::new(2).expect("nonzero"),
            NonZeroU16::new(1).expect("nonzero"),
            protection(1),
            NonZeroU16::new(16).expect("nonzero"),
            NonZeroU16::new(16).expect("nonzero"),
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

    #[test]
    fn tls_handshake_reservations_are_bounded_and_release_on_drop() {
        let admission = Arc::new(ConnectionAdmission::new(
            NonZeroU16::new(2).expect("nonzero"),
            NonZeroU16::new(2).expect("nonzero"),
            protection(1),
            NonZeroU16::new(16).expect("nonzero"),
            NonZeroU16::new(16).expect("nonzero"),
        ));
        let first = admission.reserve_tls_handshake().expect("first handshake");
        assert!(admission.reserve_tls_handshake().is_none());
        drop(first);
        assert!(admission.reserve_tls_handshake().is_some());
    }

    #[test]
    fn preauthentication_attempts_have_global_and_per_peer_windows() {
        let admission = Arc::new(ConnectionAdmission::new(
            NonZeroU16::new(4).expect("nonzero socket limit"),
            NonZeroU16::new(4).expect("nonzero peer socket limit"),
            protection(4),
            NonZeroU16::new(3).expect("nonzero global rate limit"),
            NonZeroU16::new(1).expect("nonzero peer rate limit"),
        ));
        let started = Instant::now();
        let first_peer = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let second_peer = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));

        let first = admission
            .reserve_at(first_peer, started)
            .expect("the first peer fits both rate windows");
        assert!(
            admission.reserve_at(first_peer, started).is_none(),
            "the same peer must not spend another peer budget in one window"
        );
        let second = admission
            .reserve_at(second_peer, started)
            .expect("a distinct peer may use the remaining global attempt after a peer refusal");
        assert!(
            admission
                .reserve_at(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)), started)
                .is_none(),
            "the global window must reject another unauthenticated attempt"
        );
        drop(first);
        drop(second);

        assert!(
            admission
                .reserve_at(first_peer, started + Duration::from_secs(1))
                .is_some(),
            "the next fixed window restores admission without retaining stale peer state"
        );
    }
}
