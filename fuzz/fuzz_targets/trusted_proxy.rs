#![no_main]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroU8;

use libfuzzer_sys::fuzz_target;
use positron_runtime::{ProxyTrustFailure, TrustedCidr, TrustedProxyPolicy};

const MAX_INPUT_BYTES: usize = 512;
const MAX_CIDRS: u8 = 4;
const MAX_HEADER_BYTES: usize = 256;
const MAX_FIXED_HOPS: u8 = 8;

#[derive(Clone, Copy)]
struct CidrInput {
    address: IpAddr,
    prefix_length: u8,
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 || data.len() > MAX_INPUT_BYTES {
        return;
    }

    let Some(fixed_hops) = NonZeroU8::new(data[0] % MAX_FIXED_HOPS + 1) else {
        panic!("bounded fixed-hop value must be non-zero");
    };
    let cidr_count = usize::from(data[1] % MAX_CIDRS) + 1;
    let candidates = (0..cidr_count)
        .map(|index| cidr_input(data, 2 + index * 18))
        .collect::<Vec<_>>();

    let mut cidrs = Vec::with_capacity(candidates.len());
    for candidate in candidates.iter().copied() {
        match TrustedCidr::new(candidate.address, candidate.prefix_length) {
            Ok(cidr) => cidrs.push(cidr),
            Err(error) => {
                assert_eq!(error, ProxyTrustFailure::InvalidCidrPrefix);
                assert!(candidate.prefix_length > maximum_prefix(candidate.address));
            },
        }
    }

    match TrustedProxyPolicy::new(cidrs, fixed_hops) {
        Ok(policy) => {
            let peer = SocketAddr::new(ip_from(data, 94), port_from(data, 110));
            let header = String::from_utf8_lossy(header_bytes(data));
            assert_eq!(
                policy.validates(peer, Some(&header)),
                policy.validates(peer, Some(&header)),
                "trusted-proxy validation must be deterministic for bounded input"
            );
        },
        Err(error) => assert_eq!(error, ProxyTrustFailure::EmptyTrustedProxyCidrs),
    }

    let primary = candidates[0];
    let Ok(cidr) = TrustedCidr::new(primary.address, primary.prefix_length) else {
        return;
    };
    let policy = match TrustedProxyPolicy::new(vec![cidr], fixed_hops) {
        Ok(policy) => policy,
        Err(_) => panic!("a non-empty valid CIDR set must construct a policy"),
    };
    let trusted_peer = SocketAddr::new(primary.address, port_from(data, 112));
    let exact_header = exact_header(data, fixed_hops.get());
    let malformed_header = format!("{exact_header},");
    let spoofed_peer = SocketAddr::new(
        spoofed_address(primary.address, primary.prefix_length),
        port_from(data, 114),
    );

    assert!(
        policy.validates(trusted_peer, Some(&exact_header)),
        "a trusted immediate peer with exactly the configured literal-IP hops must validate"
    );
    assert!(
        !policy.validates(trusted_peer, None),
        "a trusted peer without a forwarded chain must fail closed"
    );
    assert!(
        !policy.validates(trusted_peer, Some(&malformed_header)),
        "a malformed forwarded chain must fail closed"
    );
    assert!(
        !policy.validates(spoofed_peer, Some(&exact_header)),
        "a spoofed immediate peer must fail closed before forwarded data is trusted"
    );
});

fn cidr_input(data: &[u8], offset: usize) -> CidrInput {
    CidrInput {
        address: ip_from(data, offset),
        prefix_length: byte_at(data, offset + 17),
    }
}

fn ip_from(data: &[u8], offset: usize) -> IpAddr {
    if byte_at(data, offset) & 1 == 0 {
        IpAddr::V4(Ipv4Addr::new(
            byte_at(data, offset + 1),
            byte_at(data, offset + 2),
            byte_at(data, offset + 3),
            byte_at(data, offset + 4),
        ))
    } else {
        let mut octets = [0_u8; 16];
        for (index, octet) in octets.iter_mut().enumerate() {
            *octet = byte_at(data, offset + 1 + index);
        }
        IpAddr::V6(Ipv6Addr::from(octets))
    }
}

fn maximum_prefix(address: IpAddr) -> u8 {
    match address {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

fn spoofed_address(address: IpAddr, prefix_length: u8) -> IpAddr {
    match (address, prefix_length) {
        (IpAddr::V4(_), 0) => IpAddr::V6(Ipv6Addr::LOCALHOST),
        (IpAddr::V6(_), 0) => IpAddr::V4(Ipv4Addr::LOCALHOST),
        (IpAddr::V4(address), prefix_length) => {
            let changed_network_bit = 1_u32 << (u32::from(32 - prefix_length));
            IpAddr::V4(Ipv4Addr::from(u32::from(address) ^ changed_network_bit))
        },
        (IpAddr::V6(address), prefix_length) => {
            let changed_network_bit = 1_u128 << (u32::from(128 - prefix_length));
            IpAddr::V6(Ipv6Addr::from(u128::from(address) ^ changed_network_bit))
        },
    }
}

fn exact_header(data: &[u8], fixed_hops: u8) -> String {
    let mut header = String::new();
    for hop in 0..usize::from(fixed_hops) {
        if !header.is_empty() {
            header.push_str(", ");
        }
        header.push_str(&ip_from(data, 128 + hop * 17).to_string());
    }
    header
}

fn header_bytes(data: &[u8]) -> &[u8] {
    let start = usize::from(byte_at(data, 80)) % data.len();
    let end = start.saturating_add(MAX_HEADER_BYTES).min(data.len());
    &data[start..end]
}

fn port_from(data: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([byte_at(data, offset), byte_at(data, offset + 1)])
}

fn byte_at(data: &[u8], offset: usize) -> u8 {
    data[offset % data.len()]
}
