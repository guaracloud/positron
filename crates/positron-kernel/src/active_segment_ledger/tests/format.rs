use positron_domain::identity::TenantId;
use positron_domain::routing::{CommitPosition, SignalKind, VirtualShardId};

use crate::active_segment_ledger::format::{
    METADATA_BYTES, SegmentMetadata, SegmentState, decode_header, decode_metadata, encode_header,
    encode_metadata, position_from_value,
};
use crate::active_segment_ledger::{LedgerFailureCode, SegmentId, SegmentKeyRoute, SegmentScope};

fn route() -> SegmentKeyRoute {
    SegmentKeyRoute {
        provider_family: 1,
        provider_reference: [5; 16],
        provider_key_epoch: 7,
    }
}

fn metadata(state: SegmentState, signal: SignalKind) -> SegmentMetadata {
    SegmentMetadata {
        scope: SegmentScope::new(
            TenantId::from_bytes([1; 16]).expect("fixed tenant"),
            signal,
            VirtualShardId::new(7).expect("fixed shard"),
        ),
        id: SegmentId::new([2; 16]).expect("fixed segment"),
        state,
        base_position: position_from_value(9).expect("fixed position"),
    }
}

#[test]
fn metadata_and_header_v3_round_trip_every_closed_tag() {
    for (state, signal) in [
        (SegmentState::Active, SignalKind::Logs),
        (SegmentState::Sealed, SignalKind::Traces),
        (SegmentState::Retired, SignalKind::Logs),
    ] {
        let expected = metadata(state, signal);
        let encoded = encode_metadata(expected);
        assert_eq!(encoded.len(), METADATA_BYTES);
        assert_eq!(
            decode_metadata(&encoded).expect("metadata decodes"),
            Some(expected)
        );

        let header = encode_header(route(), &[3; 40], &[4; 80]).expect("bounded header");
        let decoded = decode_header(&header).expect("header decodes");
        assert_eq!(decoded.route, route());
        assert_eq!(decoded.wrapped_key, &[3; 40]);
        assert_eq!(decoded.encrypted_metadata, &[4; 80]);
        assert_eq!(decoded.encoded_bytes, header.len());
    }
    assert_eq!(
        position_from_value(0).expect("origin"),
        CommitPosition::origin()
    );
    assert_eq!(
        decode_metadata(b"unrelated").expect("unrelated object"),
        None
    );
}

#[test]
fn metadata_and_header_decoders_fail_closed_at_format_and_shape_boundaries() {
    let expected = metadata(SegmentState::Active, SignalKind::Logs);
    let encoded = encode_metadata(expected);
    let mut cases = Vec::new();
    let mut version = encoded.clone();
    version[9] = 2;
    cases.push((version, LedgerFailureCode::UnsupportedFormat));
    let mut state = encoded.clone();
    state[10] = 9;
    cases.push((state, LedgerFailureCode::IntegrityCorruption));
    let mut signal = encoded.clone();
    signal[27] = 9;
    cases.push((signal, LedgerFailureCode::IntegrityCorruption));
    let mut zero_tenant = encoded.clone();
    zero_tenant[11..27].fill(0);
    cases.push((zero_tenant, LedgerFailureCode::IntegrityCorruption));
    let mut zero_shard = encoded.clone();
    zero_shard[28..32].fill(0);
    cases.push((zero_shard, LedgerFailureCode::IntegrityCorruption));
    for (candidate, code) in cases {
        assert_eq!(
            decode_metadata(&candidate)
                .expect_err("invalid metadata")
                .code(),
            code
        );
    }

    assert_eq!(
        encode_header(route(), &[], &[4; 80])
            .expect_err("empty envelope")
            .code(),
        LedgerFailureCode::LimitExceeded
    );
    assert_eq!(
        encode_header(route(), &[0; 257], &[4; 80])
            .expect_err("oversized envelope")
            .code(),
        LedgerFailureCode::LimitExceeded
    );
    let header = encode_header(route(), &[4; 32], &[5; 80]).expect("valid header");
    for candidate in [&header[..9], &header[..header.len() - 1]] {
        assert!(matches!(
            decode_header(candidate)
                .err()
                .expect("truncated header")
                .code(),
            LedgerFailureCode::UnsupportedFormat | LedgerFailureCode::IntegrityCorruption
        ));
    }
    let mut bad_length = header;
    bad_length[40..44].copy_from_slice(&0_u32.to_be_bytes());
    assert_eq!(
        decode_header(&bad_length)
            .err()
            .expect("zero wrapped-key length")
            .code(),
        LedgerFailureCode::IntegrityCorruption
    );
    let mut bad_algorithm = encode_header(route(), &[4; 32], &[5; 80]).expect("valid header");
    bad_algorithm[11] = 9;
    assert_eq!(
        decode_header(&bad_algorithm)
            .err()
            .expect("unknown algorithm")
            .code(),
        LedgerFailureCode::UnsupportedFormat
    );
    let mut retired_v1 = encode_header(route(), &[4; 32], &[5; 80]).expect("valid header");
    retired_v1[..8].copy_from_slice(b"PSEGACT2");
    assert_eq!(
        decode_header(&retired_v1)
            .err()
            .expect("route-unbound draft v2 has no implicit migration")
            .code(),
        LedgerFailureCode::UnsupportedFormat
    );
    for range in [14..16, 16..32, 32..40, 76..80] {
        let mut invalid = encode_header(route(), &[4; 32], &[5; 80]).expect("valid header");
        invalid[range].fill(0);
        assert_eq!(
            decode_header(&invalid)
                .err()
                .expect("zero routing or encrypted metadata length")
                .code(),
            LedgerFailureCode::IntegrityCorruption
        );
    }
}
