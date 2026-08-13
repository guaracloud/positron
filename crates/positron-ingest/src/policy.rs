use positron_signals::{LogStoreFailure, PolicyProvenance};

use crate::NativeLogCandidate;

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
