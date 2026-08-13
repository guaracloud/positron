use std::cell::Cell;
use std::rc::Rc;

use super::{CryptoBackend, CryptoBackendFailure, SecretKeyBytes};

#[test]
fn ed25519_public_derivation_matches_rfc_8032_and_zeroizes_seed() {
    let seed = Box::new([
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ]);
    let expected = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];
    let zeroized = Rc::new(Cell::new(false));
    let input = super::SecretKeyInput::from_owned_for_test(seed, Rc::clone(&zeroized));
    assert_eq!(
        super::DataProtection::ed25519_public_key(input).expect("RFC seed"),
        expected
    );
    assert!(zeroized.get());
}

#[test]
fn selected_backend_failure_and_default_primitive_are_observed() {
    let failure = super::DataProtection::with_backend(SignatureBackend(true))
        .ed25519_public_key(super::SecretKeyInput::from_test_bytes([7; 32]))
        .expect_err("selected backend failure");
    assert_eq!(failure.code(), super::FrameFailureCode::SealFailed);
    let public = super::DataProtection::with_backend(SignatureBackend(false))
        .ed25519_public_key(super::SecretKeyInput::from_test_bytes([8; 32]))
        .expect("default primitive");
    assert!(public.iter().any(|byte| *byte != 0));
}

struct SignatureBackend(bool);

impl CryptoBackend for SignatureBackend {
    fn seal_aes_256_gcm(
        &self,
        _: &SecretKeyBytes,
        _: [u8; 12],
        _: &[u8],
        _: &[u8],
    ) -> Result<Vec<u8>, CryptoBackendFailure> {
        unreachable!()
    }
    fn open_aes_256_gcm(
        &self,
        _: &SecretKeyBytes,
        _: [u8; 12],
        _: &[u8],
        _: &[u8],
    ) -> Result<super::SecretPlaintext, CryptoBackendFailure> {
        unreachable!()
    }
    fn sha256(&self, _: &[u8]) -> Result<[u8; 32], CryptoBackendFailure> {
        unreachable!()
    }
    fn fill_random(&self, _: &mut [u8]) -> Result<(), CryptoBackendFailure> {
        unreachable!()
    }
    fn ed25519_public_key(&self, seed: &SecretKeyBytes) -> Result<[u8; 32], CryptoBackendFailure> {
        if self.0 {
            Err(CryptoBackendFailure::SignatureFailed)
        } else {
            super::RustCryptoBackend.ed25519_public_key(seed)
        }
    }
}
