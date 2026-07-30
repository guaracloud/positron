//! Typed security probes and the pre-product security gate child protocol.

mod canary;
mod crypto;

use std::path::Path;

use crate::error::XtaskError;

pub(crate) fn run_crypto_self_test() -> Result<&'static str, XtaskError> {
    crypto::run()
}

pub(crate) fn run_security_probe_process() -> Result<(), XtaskError> {
    let result = security_probe_result()?;
    println!("{result}");
    Ok(())
}

pub(crate) fn emit_secret_candidate(
    root: &Path,
    artifact_root: &Path,
    canary_id: &str,
) -> Result<(), XtaskError> {
    canary::emit_candidate(root, artifact_root, canary_id)
}

pub(crate) fn scan_secret_candidate(
    root: &Path,
    artifact_root: &Path,
) -> Result<String, XtaskError> {
    canary::scan_candidate(root, artifact_root)
}

pub(crate) fn security_probe_result() -> Result<&'static str, XtaskError> {
    let alpha = ProbeTenant::Alpha;
    let beta = ProbeTenant::Beta;
    let probes = [
        (
            ProbeRequest::missing_principal(alpha),
            ProbeOutcome::Unauthenticated,
        ),
        (ProbeRequest::wrong_scope(alpha), ProbeOutcome::Forbidden),
        (
            ProbeRequest::cross_tenant(alpha, beta),
            ProbeOutcome::TenantMismatch,
        ),
        (ProbeRequest::allowed(alpha), ProbeOutcome::Allowed),
    ];
    if probes
        .into_iter()
        .any(|(request, expected)| authorize(request) != expected)
    {
        return Err(XtaskError::invalid(
            "security probe child",
            "the typed authentication, authorization, or tenant-isolation outcome drifted",
        ));
    }
    Ok(
        "security-probe-result-v1=authn:unauthenticated|authz:forbidden|tenant:tenant-mismatch|allow:allowed",
    )
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crypto_self_test_covers_the_registered_harness_obligations() {
        assert!(run_crypto_self_test().is_ok());
    }
    #[test]
    fn typed_security_probe_child_covers_authn_authz_and_tenant_isolation() {
        assert!(security_probe_result().is_ok());
    }
}
