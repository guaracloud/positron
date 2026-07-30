//! Deterministic self-checks for the pre-product cryptography gate runner.
//!
//! These checks exercise only Quality Engineering harness behavior. They are
//! not a Data Protection implementation and cannot qualify a product target.

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

use crate::error::XtaskError;

const SHA256_ABC: [u8; 32] = [
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
];

pub(crate) fn run_crypto_self_test() -> Result<&'static str, XtaskError> {
    verify_known_answer_vector()?;
    verify_nonce_reuse_rejected()?;
    verify_provider_failure_is_closed()?;
    verify_test_secret_is_cleared()?;
    Ok("crypto-self-test-v1=known-answer-vectors|nonce-safety|provider-failures|zeroization")
}

fn verify_known_answer_vector() -> Result<(), XtaskError> {
    let observed = Sha256::digest(b"abc");
    if observed.as_slice() != SHA256_ABC {
        return Err(XtaskError::invalid(
            "crypto self-test",
            "the registered SHA-256 known-answer vector did not match",
        ));
    }
    Ok(())
}

fn verify_nonce_reuse_rejected() -> Result<(), XtaskError> {
    let mut issued = BTreeSet::new();
    issue_nonce(&mut issued, "fixture-nonce-a")?;
    issue_nonce(&mut issued, "fixture-nonce-b")?;
    if issue_nonce(&mut issued, "fixture-nonce-a").is_ok() {
        return Err(XtaskError::invalid(
            "crypto self-test",
            "the nonce safety fixture accepted a duplicate nonce",
        ));
    }
    Ok(())
}

fn issue_nonce(issued: &mut BTreeSet<&'static str>, nonce: &'static str) -> Result<(), XtaskError> {
    if issued.insert(nonce) {
        return Ok(());
    }
    Err(XtaskError::invalid(
        "crypto self-test nonce registry",
        "duplicate nonce is a closed failure",
    ))
}

fn verify_provider_failure_is_closed() -> Result<(), XtaskError> {
    if provider_round_trip(ProviderResponse::Unavailable).is_ok() {
        return Err(XtaskError::invalid(
            "crypto self-test",
            "the provider failure fixture was represented as success",
        ));
    }
    Ok(())
}

enum ProviderResponse {
    Unavailable,
}

fn provider_round_trip(response: ProviderResponse) -> Result<(), XtaskError> {
    match response {
        ProviderResponse::Unavailable => Err(XtaskError::invalid(
            "crypto provider fixture",
            "provider unavailable is a closed failure",
        )),
    }
}

fn verify_test_secret_is_cleared() -> Result<(), XtaskError> {
    let mut secret = *b"m0-crypto-canary";
    secret.fill(0);
    if secret.iter().any(|byte| *byte != 0) {
        return Err(XtaskError::invalid(
            "crypto self-test",
            "the test-only secret buffer was not cleared",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crypto_self_test_covers_the_registered_harness_obligations() {
        assert!(run_crypto_self_test().is_ok());
    }

    #[test]
    fn duplicate_nonce_is_rejected() {
        let mut issued = BTreeSet::new();
        assert!(issue_nonce(&mut issued, "nonce").is_ok());
        assert!(issue_nonce(&mut issued, "nonce").is_err());
    }
}
