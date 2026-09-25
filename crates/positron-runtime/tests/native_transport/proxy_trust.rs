use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroU8;

use positron_runtime::{ProxyTrustFailure, TrustedCidr, TrustedProxyPolicy};

fn ipv4(value: &str) -> IpAddr {
    value.parse().expect("valid IPv4 fixture")
}

fn ipv6(value: &str) -> IpAddr {
    value.parse().expect("valid IPv6 fixture")
}

fn policy(hops: u8) -> TrustedProxyPolicy {
    TrustedProxyPolicy::new(
        vec![
            TrustedCidr::new(ipv4("198.51.100.55"), 24).expect("valid IPv4 CIDR"),
            TrustedCidr::new(ipv6("2001:db8:feed::99"), 64).expect("valid IPv6 CIDR"),
        ],
        NonZeroU8::new(hops).expect("non-zero fixed hop fixture"),
    )
    .expect("non-empty proxy CIDRs")
}

fn peer(address: &str) -> SocketAddr {
    address.parse().expect("valid peer fixture")
}

#[test]
fn accepts_an_exact_fixed_hop_chain_from_an_immediate_trusted_ipv4_peer() {
    let policy = policy(2);

    assert!(policy.validates(
        peer("198.51.100.10:443"),
        Some("192.0.2.24, 2001:db8:1::24"),
    ));
}

#[test]
fn accepts_an_exact_fixed_hop_chain_from_an_immediate_trusted_ipv6_peer() {
    let policy = policy(1);

    assert!(policy.validates(peer("[2001:db8:feed::3]:443"), Some("\t2001:db8:2::44 \t"),));
}

#[test]
fn rejects_forwarded_addresses_from_an_untrusted_immediate_peer() {
    let policy = policy(1);

    assert!(!policy.validates(peer("203.0.113.8:443"), Some("192.0.2.24")));
}

#[test]
fn rejects_missing_malformed_or_non_exact_forwarded_chains() {
    let policy = policy(2);
    let peer = peer("198.51.100.10:443");

    for forwarded_for in [
        None,
        Some("192.0.2.24"),
        Some("192.0.2.24, 198.51.100.9, 203.0.113.10"),
        Some("192.0.2.24, unknown"),
        Some("192.0.2.24, "),
        Some("192.0.2.24, [2001:db8::1]:443"),
    ] {
        assert!(
            !policy.validates(peer, forwarded_for),
            "forwarded chain {forwarded_for:?} must fail closed"
        );
    }
}

#[test]
fn canonical_cidrs_match_only_their_ip_family_and_network() {
    let ipv4_cidr = TrustedCidr::new(ipv4("198.51.100.55"), 24).expect("valid IPv4 CIDR");
    let ipv6_cidr = TrustedCidr::new(ipv6("2001:db8:feed::99"), 64).expect("valid IPv6 CIDR");

    assert!(ipv4_cidr.contains(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))));
    assert!(!ipv4_cidr.contains(IpAddr::V4(Ipv4Addr::new(198, 51, 101, 1))));
    assert!(!ipv4_cidr.contains(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    assert!(ipv6_cidr.contains(ipv6("2001:db8:feed::1")));
    assert!(!ipv6_cidr.contains(ipv6("2001:db8:beef::1")));
    assert!(!ipv6_cidr.contains(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))));
}

#[test]
fn rejects_empty_cidr_sets_and_ip_family_prefix_overflow() {
    assert_eq!(
        TrustedProxyPolicy::new(
            Vec::new(),
            NonZeroU8::new(1).expect("non-zero fixed hop fixture"),
        ),
        Err(ProxyTrustFailure::EmptyTrustedProxyCidrs)
    );
    assert_eq!(
        TrustedCidr::new(ipv4("198.51.100.1"), 33),
        Err(ProxyTrustFailure::InvalidCidrPrefix)
    );
    assert_eq!(
        TrustedCidr::new(ipv6("2001:db8::1"), 129),
        Err(ProxyTrustFailure::InvalidCidrPrefix)
    );
}
