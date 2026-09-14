use super::*;

pub struct BootstrapClaim {
    pub(in crate::instance_bootstrap) principal: PrincipalId,
    pub(in crate::instance_bootstrap) secret: Zeroizing<String>,
    pub(in crate::instance_bootstrap) ingest: Option<(PrincipalId, Zeroizing<String>)>,
    pub(in crate::instance_bootstrap) query: Option<(PrincipalId, Zeroizing<String>)>,
}

impl BootstrapClaim {
    #[must_use]
    pub const fn principal_id(&self) -> PrincipalId {
        self.principal
    }

    #[must_use]
    pub fn secret(&self) -> &str {
        self.secret.as_str()
    }

    #[must_use]
    pub fn ingest_principal_id(&self) -> Option<PrincipalId> {
        self.ingest.as_ref().map(|(principal, _)| *principal)
    }

    #[must_use]
    pub fn ingest_secret(&self) -> Option<&str> {
        self.ingest.as_ref().map(|(_, secret)| secret.as_str())
    }

    #[must_use]
    pub fn query_principal_id(&self) -> Option<PrincipalId> {
        self.query.as_ref().map(|(principal, _)| *principal)
    }

    #[must_use]
    pub fn query_secret(&self) -> Option<&str> {
        self.query.as_ref().map(|(_, secret)| secret.as_str())
    }
}

impl std::fmt::Debug for BootstrapClaim {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BootstrapClaim { <redacted> }")
    }
}
