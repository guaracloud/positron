use positron_signals::{LogStoreFailure, PolicyProvenance};

use crate::NativeLogCandidate;

const RELEASE_1_DEFAULT_POLICY_DIGEST: [u8; 32] = [
    0xd7, 0x16, 0x14, 0x7f, 0xd9, 0xe5, 0xe7, 0xf4, 0xd2, 0x0d, 0xe7, 0x45, 0x05, 0xcb, 0x1b, 0x18,
    0x2f, 0x91, 0x44, 0x17, 0x7d, 0x95, 0xc3, 0x54, 0xd8, 0xb9, 0x9d, 0x29, 0x9c, 0x8f, 0x0f, 0xe1,
];

/// One immutable bounded policy snapshot for a complete admitted request.
#[derive(Clone, Debug)]
pub struct IngestPolicy {
    provenance: PolicyProvenance,
    rejection: Option<ExactBodyRejection>,
}

#[derive(Clone, Debug)]
struct ExactBodyRejection {
    body: String,
}

pub(crate) enum PolicyDecision {
    Accept(PolicyProvenance),
    Reject,
}

impl IngestPolicy {
    /// Returns the single accepted Release 1 preserving policy snapshot.
    pub fn release_1_default() -> Result<Self, LogStoreFailure> {
        Self::preserving(1, RELEASE_1_DEFAULT_POLICY_DIGEST)
    }

    #[must_use]
    pub const fn provenance(&self) -> &PolicyProvenance {
        &self.provenance
    }

    pub fn preserving(generation: u64, digest: [u8; 32]) -> Result<Self, LogStoreFailure> {
        let provenance = PolicyProvenance::new(generation, digest, Vec::new())?;
        Ok(Self {
            provenance,
            rejection: None,
        })
    }

    pub fn reject_exact_text_body(
        generation: u64,
        digest: [u8; 32],
        rule_id: &str,
        body: &str,
    ) -> Result<Self, LogStoreFailure> {
        let provenance = PolicyProvenance::new(generation, digest, vec![rule_id.to_owned()])?;
        Ok(Self {
            provenance,
            rejection: Some(ExactBodyRejection {
                body: body.to_owned(),
            }),
        })
    }

    pub(crate) fn evaluate(
        &self,
        record: &NativeLogCandidate,
    ) -> Result<PolicyDecision, LogStoreFailure> {
        if let Some(rejection) = &self.rejection
            && record
                .body()
                .and_then(|body| match body {
                    positron_domain::value::CandidateAttributeValue::String(value) => Some(value),
                    _ => None,
                })
                .is_some_and(|body| body == &rejection.body)
        {
            return Ok(PolicyDecision::Reject);
        }
        Ok(PolicyDecision::Accept(self.provenance.clone()))
    }
}
