use std::error::Error;
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroU8;
use std::sync::Arc;

const IPV4_MAX_PREFIX_LENGTH: u8 = 32;
const IPV6_MAX_PREFIX_LENGTH: u8 = 128;

/// A canonical network range allowed to be an immediate forwarding peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrustedCidr {
    network: IpAddr,
    prefix_length: u8,
}

impl TrustedCidr {
    /// Creates a network range and masks host bits from its address.
    pub fn new(address: IpAddr, prefix_length: u8) -> Result<Self, ProxyTrustFailure> {
        let network = match address {
            IpAddr::V4(address) => {
                if prefix_length > IPV4_MAX_PREFIX_LENGTH {
                    return Err(ProxyTrustFailure::InvalidCidrPrefix);
                }
                IpAddr::V4(Ipv4Addr::from(
                    u32::from(address) & ipv4_mask(prefix_length),
                ))
            },
            IpAddr::V6(address) => {
                if prefix_length > IPV6_MAX_PREFIX_LENGTH {
                    return Err(ProxyTrustFailure::InvalidCidrPrefix);
                }
                IpAddr::V6(Ipv6Addr::from(
                    u128::from(address) & ipv6_mask(prefix_length),
                ))
            },
        };
        Ok(Self {
            network,
            prefix_length,
        })
    }

    /// Returns whether an address belongs to this CIDR and IP family.
    #[must_use]
    pub fn contains(self, address: IpAddr) -> bool {
        match (self.network, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                u32::from(network) == (u32::from(address) & ipv4_mask(self.prefix_length))
            },
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                u128::from(network) == (u128::from(address) & ipv6_mask(self.prefix_length))
            },
            _ => false,
        }
    }
}

/// A bounded policy for accepting a forwarded-address chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedProxyPolicy {
    cidrs: Arc<[TrustedCidr]>,
    fixed_hops: NonZeroU8,
}

impl TrustedProxyPolicy {
    /// Creates a policy with at least one trusted immediate-peer CIDR.
    pub fn new(cidrs: Vec<TrustedCidr>, fixed_hops: NonZeroU8) -> Result<Self, ProxyTrustFailure> {
        if cidrs.is_empty() {
            return Err(ProxyTrustFailure::EmptyTrustedProxyCidrs);
        }
        Ok(Self {
            cidrs: cidrs.into(),
            fixed_hops,
        })
    }

    /// Validates the immediate peer and an exactly-sized literal IP chain.
    ///
    /// The returned boolean deliberately carries no asserted forwarding value;
    /// callers retain authority over whether any validated header has a use.
    #[must_use]
    pub fn validates(&self, peer: SocketAddr, forwarded_for: Option<&str>) -> bool {
        if !self.cidrs.iter().any(|cidr| cidr.contains(peer.ip())) {
            return false;
        }
        let Some(forwarded_for) = forwarded_for else {
            return false;
        };

        let mut hop_count = 0_u8;
        for address in forwarded_for.split(',') {
            let address = address.trim_matches([' ', '\t']);
            if address.is_empty() || address.parse::<IpAddr>().is_err() {
                return false;
            }
            let Some(next_hop_count) = hop_count.checked_add(1) else {
                return false;
            };
            hop_count = next_hop_count;
            if hop_count > self.fixed_hops.get() {
                return false;
            }
        }
        hop_count == self.fixed_hops.get()
    }
}

/// Configuration failures for trusted-proxy CIDRs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyTrustFailure {
    EmptyTrustedProxyCidrs,
    InvalidCidrPrefix,
}

impl Display for ProxyTrustFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyTrustedProxyCidrs => formatter.write_str("trusted proxy CIDRs are empty"),
            Self::InvalidCidrPrefix => formatter.write_str("trusted proxy CIDR prefix is invalid"),
        }
    }
}

impl Error for ProxyTrustFailure {}

fn ipv4_mask(prefix_length: u8) -> u32 {
    if prefix_length == 0 {
        0
    } else {
        u32::MAX << (u32::BITS - u32::from(prefix_length))
    }
}

fn ipv6_mask(prefix_length: u8) -> u128 {
    if prefix_length == 0 {
        0
    } else {
        u128::MAX << (u128::BITS - u32::from(prefix_length))
    }
}
