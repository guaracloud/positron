use positron_domain::identity::{PrincipalId, TenantId};
use positron_kernel::{BootstrapKeyIdentity, InstanceId, TransactionId};
use zeroize::Zeroizing;

use super::super::BootstrapFailureCode;
use super::super::codec::{BootstrapIngestIdentity, BootstrapRecord, decode_claim, encode_claim};

#[test]
fn literal_v1_initialized_record_remains_readable() {
    let record = BootstrapRecord::decode(&literal_v1_record(false)).expect("v1 initialized");

    assert_eq!(record.instance.to_bytes(), [1; 16]);
    assert_eq!(record.administrator.to_bytes(), [5; 16]);
    assert!(record.api_key_secret.is_none());
}

#[test]
fn literal_v1_pending_record_remains_readable() {
    let record = BootstrapRecord::decode(&literal_v1_record(true)).expect("v1 pending");

    assert_eq!(record.transaction.to_bytes(), [6; 16]);
    assert_eq!(record.api_key_secret.as_deref(), Some(&[10; 32]));
    assert_eq!(record.integrity_key_secret.as_deref(), Some(&[11; 32]));
    assert!(record.ingest.is_none());
}

#[test]
fn current_bootstrap_records_round_trip_with_v2_magics() {
    let pending = current_record();
    let encoded = pending.encode();
    assert!(encoded.starts_with(b"POSIPN02"));
    assert_eq!(encoded.len(), 400);
    assert_eq!(
        BootstrapRecord::decode(&encoded).expect("pending").encode(),
        encoded
    );

    let initialized = pending.initialized().encode();
    assert!(initialized.starts_with(b"POSINI02"));
    assert_eq!(initialized.len(), 304);
    assert_eq!(
        BootstrapRecord::decode(&initialized)
            .expect("initialized")
            .encode(),
        initialized,
    );
}

#[test]
fn current_bootstrap_records_and_claims_use_v2_magics() {
    let instance = InstanceId::new([1; 16]).expect("instance");
    let principal = PrincipalId::from_bytes([3; 16]).expect("principal");
    let ingest = PrincipalId::from_bytes([5; 16]).expect("ingest");
    let claim = encode_claim(instance, principal, &[4; 32], ingest, &[6; 32]);

    assert!(claim.starts_with(b"POSCLM02"));
}

#[test]
fn literal_v1_claim_remains_readable() {
    let instance = InstanceId::new([1; 16]).expect("instance");
    let claim = decode_claim(instance, &literal_v1_claim()).expect("v1 claim");
    assert_eq!(claim.principal.to_bytes(), [3; 16]);
    assert_eq!(claim.secret.as_ref(), &[4; 32]);
    assert!(claim.ingest.is_none());
}

#[test]
fn unknown_or_layout_mismatched_versions_fail_closed() {
    let mut record = literal_v1_record(false);
    record[..8].copy_from_slice(b"POSINI03");
    assert!(BootstrapRecord::decode(&record).is_err());
    let mut claim = literal_v1_claim();
    claim[..8].copy_from_slice(b"POSCLM03");
    assert!(decode_claim(InstanceId::new([1; 16]).expect("instance"), &claim).is_err());

    let mut mismatched = literal_v1_record(false);
    mismatched[..8].copy_from_slice(b"POSINI02");
    assert!(BootstrapRecord::decode(&mismatched).is_err());
}

#[test]
fn claim_codec_rejects_malformed_and_substituted_authority() {
    let instance = InstanceId::new([1; 16]).expect("nonzero instance");
    let other = InstanceId::new([2; 16]).expect("nonzero instance");
    let principal = PrincipalId::from_bytes([3; 16]).expect("nonzero principal");
    let ingest = PrincipalId::from_bytes([5; 16]).expect("ingest principal");
    let encoded = encode_claim(instance, principal, &[4; 32], ingest, &[6; 32]);

    assert_eq!(
        decode_claim(instance, &encoded[..119])
            .expect_err("truncated claim")
            .code(),
        BootstrapFailureCode::CorruptState
    );
    assert_eq!(
        decode_claim(other, &encoded)
            .expect_err("substituted instance")
            .code(),
        BootstrapFailureCode::IdentityMismatch
    );
    let failure = match super::super::codec::BootstrapRecord::decode(b"bad") {
        Ok(_) => panic!("malformed record"),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), BootstrapFailureCode::CorruptState);
}

fn literal_v1_record(pending: bool) -> Vec<u8> {
    let mut bytes = if pending {
        b"POSIPN01".to_vec()
    } else {
        b"POSINI01".to_vec()
    };
    bytes.extend_from_slice(&[1; 16]);
    bytes.extend_from_slice(&[2; 16]);
    bytes.extend_from_slice(&[3; 32]);
    bytes.extend_from_slice(&1_u64.to_be_bytes());
    bytes.extend_from_slice(&[4; 16]);
    bytes.extend_from_slice(&[5; 16]);
    bytes.extend_from_slice(&[6; 16]);
    bytes.extend_from_slice(&[7; 32]);
    bytes.extend_from_slice(&[8; 32]);
    bytes.extend_from_slice(&[9; 32]);
    if pending {
        bytes.extend_from_slice(&[10; 32]);
        bytes.extend_from_slice(&[11; 32]);
    }
    assert_eq!(bytes.len(), if pending { 288 } else { 224 });
    bytes
}

fn literal_v1_claim() -> Vec<u8> {
    let mut bytes = b"POSCLM01".to_vec();
    bytes.extend_from_slice(&[1; 16]);
    bytes.extend_from_slice(&[3; 16]);
    bytes.extend_from_slice(&[4; 32]);
    assert_eq!(bytes.len(), 72);
    bytes
}

fn current_record() -> BootstrapRecord {
    BootstrapRecord {
        instance: InstanceId::new([1; 16]).expect("instance"),
        key: BootstrapKeyIdentity::from_parts([2; 16], [3; 32], 1).expect("key"),
        tenant: TenantId::from_bytes([4; 16]).expect("tenant"),
        administrator: PrincipalId::from_bytes([5; 16]).expect("administrator"),
        transaction: TransactionId::new([6; 16]).expect("transaction"),
        api_key_salt: [7; 32],
        api_key_hash: [8; 32],
        integrity_fingerprint: [9; 32],
        ingest: Some(BootstrapIngestIdentity {
            principal: PrincipalId::from_bytes([12; 16]).expect("ingest"),
            api_key_salt: [13; 32],
            api_key_hash: [14; 32],
            api_key_secret: Some(Zeroizing::new([15; 32])),
        }),
        api_key_secret: Some(Zeroizing::new([10; 32])),
        integrity_key_secret: Some(Zeroizing::new([11; 32])),
    }
}
