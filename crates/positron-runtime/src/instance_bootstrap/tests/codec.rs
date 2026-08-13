use positron_domain::identity::PrincipalId;
use positron_kernel::InstanceId;

use super::super::BootstrapFailureCode;
use super::super::codec::{decode_claim, encode_claim};

#[test]
fn claim_codec_rejects_malformed_and_substituted_authority() {
    let instance = InstanceId::new([1; 16]).expect("nonzero instance");
    let other = InstanceId::new([2; 16]).expect("nonzero instance");
    let principal = PrincipalId::from_bytes([3; 16]).expect("nonzero principal");
    let encoded = encode_claim(instance, principal, &[4; 32]);

    assert_eq!(
        decode_claim(instance, &encoded[..71])
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
