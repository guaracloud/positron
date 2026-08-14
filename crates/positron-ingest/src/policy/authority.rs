use std::error::Error;
use std::fmt::{Display, Formatter};
use std::sync::{Arc, RwLock};

use super::IngestPolicy;

/// The single initialized tenant policy publication authority.
#[derive(Clone, Debug)]
pub struct IngestPolicyAuthority {
    active: Arc<RwLock<Arc<IngestPolicy>>>,
}

/// One immutable generation pinned for an admitted request.
#[derive(Clone, Debug)]
pub struct IngestPolicySnapshot {
    policy: Arc<IngestPolicy>,
}

/// Stable failure while snapshotting or atomically publishing policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyPublicationFailure {
    AuthorityUnavailable,
    GenerationNotAdvanced,
}

impl Display for PolicyPublicationFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Ingest Policy publication failed")
    }
}

impl Error for PolicyPublicationFailure {}

impl IngestPolicyAuthority {
    #[must_use]
    pub fn new(initial: IngestPolicy) -> Self {
        Self {
            active: Arc::new(RwLock::new(Arc::new(initial))),
        }
    }

    pub fn snapshot(&self) -> Result<IngestPolicySnapshot, PolicyPublicationFailure> {
        let policy = self
            .active
            .read()
            .map_err(|_| PolicyPublicationFailure::AuthorityUnavailable)?
            .clone();
        Ok(IngestPolicySnapshot { policy })
    }

    pub fn publish(&self, policy: IngestPolicy) -> Result<(), PolicyPublicationFailure> {
        let mut active = self
            .active
            .write()
            .map_err(|_| PolicyPublicationFailure::AuthorityUnavailable)?;
        if policy.provenance().generation() <= active.provenance().generation() {
            return Err(PolicyPublicationFailure::GenerationNotAdvanced);
        }
        *active = Arc::new(policy);
        Ok(())
    }
}

impl IngestPolicySnapshot {
    #[must_use]
    pub fn policy(&self) -> &IngestPolicy {
        &self.policy
    }
}
