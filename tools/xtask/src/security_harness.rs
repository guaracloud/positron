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

pub(crate) fn run_security_probe_harness() -> Result<&'static str, XtaskError> {
    let tenant_a = ProbeTenant::Alpha;
    let tenant_b = ProbeTenant::Beta;
    if authorize(ProbeRequest::missing_principal(tenant_a)) != ProbeOutcome::Unauthenticated
        || authorize(ProbeRequest::wrong_scope(tenant_a)) != ProbeOutcome::Forbidden
        || authorize(ProbeRequest::cross_tenant(tenant_a, tenant_b)) != ProbeOutcome::TenantMismatch
        || authorize(ProbeRequest::allowed(tenant_a)) != ProbeOutcome::Allowed
    {
        return Err(XtaskError::invalid(
            "security probe harness",
            "the typed authentication, authorization, or tenant-isolation outcome drifted",
        ));
    }
    Ok("security-probe-v1=authn|authz|tenant-isolation")
}

pub(crate) fn run_secret_canary_harness() -> Result<String, XtaskError> {
    let records = CanarySink::ALL
        .into_iter()
        .map(CanaryRecord::seeded)
        .collect::<Vec<_>>();
    verify_canaries(&records)?;
    let mut digest = Sha256::new();
    digest.update(b"positron-secret-canary-harness-v1\0");
    for record in &records {
        digest.update(record.sink.label().as_bytes());
        digest.update(b"\0");
        digest.update(&record.bytes);
        digest.update(b"\0");
    }
    Ok(format!(
        "secret-canary-harness-v1=sinks:{}; digest=sha256:{:x}",
        records.len(),
        digest.finalize()
    ))
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ProbeTenant {
    Alpha,
    Beta,
}

#[derive(Clone, Copy)]
struct ProbeRequest {
    principal: bool,
    allowed_scope: bool,
    attributed: ProbeTenant,
    requested: ProbeTenant,
}

impl ProbeRequest {
    const fn missing_principal(tenant: ProbeTenant) -> Self {
        Self {
            principal: false,
            allowed_scope: true,
            attributed: tenant,
            requested: tenant,
        }
    }
    const fn wrong_scope(tenant: ProbeTenant) -> Self {
        Self {
            principal: true,
            allowed_scope: false,
            attributed: tenant,
            requested: tenant,
        }
    }
    const fn cross_tenant(attributed: ProbeTenant, requested: ProbeTenant) -> Self {
        Self {
            principal: true,
            allowed_scope: true,
            attributed,
            requested,
        }
    }
    const fn allowed(tenant: ProbeTenant) -> Self {
        Self {
            principal: true,
            allowed_scope: true,
            attributed: tenant,
            requested: tenant,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ProbeOutcome {
    Unauthenticated,
    Forbidden,
    TenantMismatch,
    Allowed,
}

fn authorize(request: ProbeRequest) -> ProbeOutcome {
    if !request.principal {
        ProbeOutcome::Unauthenticated
    } else if !request.allowed_scope {
        ProbeOutcome::Forbidden
    } else if request.attributed != request.requested {
        ProbeOutcome::TenantMismatch
    } else {
        ProbeOutcome::Allowed
    }
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
enum CanarySink {
    Logs,
    Errors,
    Metrics,
    Traces,
    Diagnostics,
    Evidence,
    Binaries,
    Packages,
    SupportArtifacts,
}

impl CanarySink {
    const ALL: [Self; 9] = [
        Self::Logs,
        Self::Errors,
        Self::Metrics,
        Self::Traces,
        Self::Diagnostics,
        Self::Evidence,
        Self::Binaries,
        Self::Packages,
        Self::SupportArtifacts,
    ];
    const fn label(self) -> &'static str {
        match self {
            Self::Logs => "logs",
            Self::Errors => "errors",
            Self::Metrics => "metrics",
            Self::Traces => "traces",
            Self::Diagnostics => "diagnostics",
            Self::Evidence => "evidence",
            Self::Binaries => "binaries",
            Self::Packages => "packages",
            Self::SupportArtifacts => "support-artifacts",
        }
    }
}

struct CanaryRecord {
    sink: CanarySink,
    bytes: Vec<u8>,
}

impl CanaryRecord {
    fn seeded(sink: CanarySink) -> Self {
        let mut bytes = b"POSITRON_SYNTHETIC_CANARY_V1:".to_vec();
        bytes.extend_from_slice(sink.label().as_bytes());
        Self { sink, bytes }
    }
}

fn verify_canaries(records: &[CanaryRecord]) -> Result<(), XtaskError> {
    if records.len() != CanarySink::ALL.len() {
        return Err(XtaskError::invalid(
            "secret canary harness",
            "the sink inventory is incomplete",
        ));
    }
    let mut observed = BTreeSet::new();
    for record in records {
        let expected = CanaryRecord::seeded(record.sink);
        if record.bytes != expected.bytes || !observed.insert(record.sink) {
            return Err(XtaskError::invalid(
                "secret canary harness",
                "a seeded canary sink is malformed, tampered, or duplicated",
            ));
        }
    }
    if observed.len() != CanarySink::ALL.len() {
        return Err(XtaskError::invalid(
            "secret canary harness",
            "a required seeded canary sink is missing",
        ));
    }
    Ok(())
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

    #[test]
    fn security_probe_and_canary_harnesses_fail_closed() -> Result<(), XtaskError> {
        assert!(run_security_probe_harness().is_ok());
        let mut records = CanarySink::ALL
            .into_iter()
            .map(CanaryRecord::seeded)
            .collect::<Vec<_>>();
        records.pop();
        assert!(verify_canaries(&records).is_err());
        let mut records = CanarySink::ALL
            .into_iter()
            .map(CanaryRecord::seeded)
            .collect::<Vec<_>>();
        let record = records.first_mut().ok_or_else(|| {
            XtaskError::invalid(
                "secret canary harness test",
                "seeded records are unexpectedly empty",
            )
        })?;
        record.bytes.push(b'x');
        assert!(verify_canaries(&records).is_err());
        Ok(())
    }
}
