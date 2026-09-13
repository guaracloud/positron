use positron_governance::{
    AdministrativeIdempotencyKey, AuthorizedContext, IngestPolicyActivation,
    IngestPolicyAdministration, IngestPolicyServingSnapshot, PolicyAdministrationFailure,
    PolicyAdministrationFailureCode, ResourceGeneration,
};
use positron_ingest::IngestPolicy;
use positron_kernel::Catalog;
use positron_policy::PolicyPreviewPolicy;
use positron_policy::{
    PolicyPreview, PolicyPreviewCandidate, PolicyPreviewOutcome, PolicyPreviewSemanticChange,
};

use super::{ServiceFailure, ServiceHandle, failure::classify_catalog_failure_code};

pub(crate) enum PolicyActivateHttpFailure {
    Code(u16, &'static str),
    StaleGeneration(ResourceGeneration),
}

enum PolicyActivationDurableFailure {
    Core(PolicyAdministrationFailure),
    Unavailable,
}

impl ServiceHandle {
    pub(crate) fn activate_ingest_policy_http(
        &self,
        bearer: &str,
        body: &[u8],
    ) -> Result<positron_api::policy::PolicyActivateResponse, PolicyActivateHttpFailure> {
        let context = self
            .instance
            .attribute(
                positron_governance::PresentedCredential::parse(bearer)
                    .map_err(|_| PolicyActivateHttpFailure::Code(401, "authentication_rejected"))?,
                positron_governance::RequestedIntent::TenantAdministration,
                positron_governance::CompatibilityHints::none(),
            )
            .map_err(|_| PolicyActivateHttpFailure::Code(401, "authentication_rejected"))?;
        let request = positron_api::policy::PolicyActivateRequest::decode(body)
            .map_err(|_| PolicyActivateHttpFailure::Code(400, "invalid_request"))?;
        let expected = ResourceGeneration::new(request.expected_generation())
            .map_err(|_| PolicyActivateHttpFailure::Code(400, "invalid_request"))?;
        let key =
            positron_domain::identity::PrincipalId::parse_canonical(request.idempotency_key())
                .map_err(|_| PolicyActivateHttpFailure::Code(400, "invalid_request"))?;
        let key = AdministrativeIdempotencyKey::new(key.to_bytes())
            .map_err(|_| PolicyActivateHttpFailure::Code(400, "invalid_request"))?;
        let candidate = PolicyPreviewPolicy::from_json(request.policy_json().as_bytes())
            .map_err(|_| PolicyActivateHttpFailure::Code(400, "invalid_request"))?
            .into_ingest_policy();
        let activation = self
            .activate_ingest_policy_durable(context, expected, key, candidate)
            .map_err(map_policy_activation_durable_failure)?;
        Ok(positron_api::policy::PolicyActivateResponse {
            resource_generation: activation.resource_generation().get(),
            policy_digest: hex_digest(activation.digest()),
            audit_position: activation.audit_position(),
        })
    }

    pub(crate) fn explain_ingest_policy(
        &self,
        bearer: &str,
        body: &[u8],
    ) -> Result<positron_api::policy::PolicyExplainResponse, (u16, &'static str)> {
        self.instance
            .attribute(
                positron_governance::PresentedCredential::parse(bearer)
                    .map_err(|_| (401, "authentication_rejected"))?,
                positron_governance::RequestedIntent::TenantAdministration,
                positron_governance::CompatibilityHints::none(),
            )
            .map_err(|_| (401, "authentication_rejected"))?;
        let request = positron_api::policy::PolicyTestRequest::decode(body)
            .map_err(|_| (400, "invalid_request"))?;
        let policy = PolicyPreviewPolicy::from_json(request.policy_json().as_bytes())
            .map_err(|_| (400, "invalid_request"))?;
        let candidate = PolicyPreviewCandidate::from_json(request.candidate_json().as_bytes())
            .map_err(|_| (400, "invalid_request"))?;
        let result = PolicyPreview::test(&policy, candidate)
            .map_err(|_| (503, "administration_unavailable"))?;
        let explanation = PolicyPreview::explain(&policy, result.clone())
            .map_err(|_| (503, "administration_unavailable"))?;
        if explanation.rendered().len() > 4096 {
            return Err((503, "administration_unavailable"));
        }
        Ok(positron_api::policy::PolicyExplainResponse {
            policy_generation: result.generation(),
            policy_digest: hex_digest(result.digest()),
            outcome: match result.outcome() {
                PolicyPreviewOutcome::Accepted => "accepted",
                PolicyPreviewOutcome::Rejected => "rejected",
            }
            .to_owned(),
            explanation: explanation.rendered().to_owned(),
        })
    }
    /// Computes bounded, redacted evidence for two prospective policies after
    /// tenant-scoped authentication. Neither candidate reaches the catalog.
    pub(crate) fn diff_ingest_policy(
        &self,
        bearer: &str,
        body: &[u8],
    ) -> Result<positron_api::policy::PolicyDiffResponse, (u16, &'static str)> {
        self.instance
            .attribute(
                positron_governance::PresentedCredential::parse(bearer)
                    .map_err(|_| (401, "authentication_rejected"))?,
                positron_governance::RequestedIntent::TenantAdministration,
                positron_governance::CompatibilityHints::none(),
            )
            .map_err(|_| (401, "authentication_rejected"))?;
        let request = positron_api::policy::PolicyDiffRequest::decode(body)
            .map_err(|_| (400, "invalid_request"))?;
        let before = PolicyPreviewPolicy::from_json(request.before_policy_json().as_bytes())
            .map_err(|_| (400, "invalid_request"))?;
        let after = PolicyPreviewPolicy::from_json(request.after_policy_json().as_bytes())
            .map_err(|_| (400, "invalid_request"))?;
        let before_validation = before.validation();
        let after_validation = after.validation();
        let semantic_changes = PolicyPreview::diff(&before, &after)
            .changes()
            .iter()
            .map(policy_diff_category)
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if semantic_changes.len() > positron_api::policy::MAX_DIFF_SEMANTIC_CHANGES {
            return Err((503, "administration_unavailable"));
        }
        Ok(positron_api::policy::PolicyDiffResponse {
            before_policy_generation: before_validation.generation(),
            before_policy_digest: hex_digest(before_validation.digest()),
            after_policy_generation: after_validation.generation(),
            after_policy_digest: hex_digest(after_validation.digest()),
            semantic_changes,
        })
    }

    pub(crate) fn test_ingest_policy(
        &self,
        bearer: &str,
        body: &[u8],
    ) -> Result<positron_api::policy::PolicyTestResponse, (u16, &'static str)> {
        self.instance
            .attribute(
                positron_governance::PresentedCredential::parse(bearer)
                    .map_err(|_| (401, "authentication_rejected"))?,
                positron_governance::RequestedIntent::TenantAdministration,
                positron_governance::CompatibilityHints::none(),
            )
            .map_err(|_| (401, "authentication_rejected"))?;
        let request = positron_api::policy::PolicyTestRequest::decode(body)
            .map_err(|_| (400, "invalid_request"))?;
        let policy = PolicyPreviewPolicy::from_json(request.policy_json().as_bytes())
            .map_err(|_| (400, "invalid_request"))?;
        let candidate = PolicyPreviewCandidate::from_json(request.candidate_json().as_bytes())
            .map_err(|_| (400, "invalid_request"))?;
        let result = PolicyPreview::test(&policy, candidate)
            .map_err(|_| (503, "administration_unavailable"))?;
        let applied_rule_count = u32::try_from(result.applied_rule_count())
            .map_err(|_| (503, "administration_unavailable"))?;
        Ok(positron_api::policy::PolicyTestResponse {
            policy_generation: result.generation(),
            policy_digest: result
                .digest()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
            accepted: result.outcome() == PolicyPreviewOutcome::Accepted,
            applied_rule_count,
        })
    }

    /// Validates a candidate only after tenant-scoped authorization. The
    /// candidate never reaches catalog activation or the serving snapshot.
    pub(crate) fn validate_ingest_policy(
        &self,
        bearer: &str,
        body: &[u8],
    ) -> Result<positron_api::policy::PolicyValidateResponse, (u16, &'static str)> {
        self.instance
            .attribute(
                positron_governance::PresentedCredential::parse(bearer)
                    .map_err(|_| (401, "authentication_rejected"))?,
                positron_governance::RequestedIntent::TenantAdministration,
                positron_governance::CompatibilityHints::none(),
            )
            .map_err(|_| (401, "authentication_rejected"))?;
        let request = positron_api::policy::PolicyPreviewRequest::decode(body)
            .map_err(|_| (400, "invalid_request"))?;
        let policy = PolicyPreviewPolicy::from_json(request.policy_json().as_bytes())
            .map_err(|_| (400, "invalid_request"))?;
        let validation = policy.validation();
        let rule_count = u32::try_from(validation.rule_count())
            .map_err(|_| (503, "administration_unavailable"))?;
        let policy_digest = hex_digest(validation.digest());
        Ok(positron_api::policy::PolicyValidateResponse {
            policy_generation: validation.generation(),
            policy_digest,
            rule_count,
        })
    }

    /// Pins the policy that is durable for the authenticated tenant. A service
    /// never borrows the default tenant's serving cache for another tenant.
    pub(super) fn tenant_ingest_policy(
        &self,
        tenant: positron_domain::identity::TenantId,
    ) -> Result<IngestPolicyServingSnapshot, ServiceFailure> {
        let instance = &self.instance;
        let catalog = Catalog::open(
            &instance._authority,
            instance.instance,
            instance
                .key
                .catalog_secret(instance.instance)
                .map_err(|_| ServiceFailure::KeyUnavailable)?,
        )
        .map_err(|failure| classify_catalog_failure_code(failure.code()))?;
        IngestPolicyAdministration::open(&catalog, tenant)
            .map(|administration| administration.serving())
            .map_err(|failure| match failure.code() {
                PolicyAdministrationFailureCode::PersistenceUnavailable => {
                    ServiceFailure::StorageUnavailable
                },
                PolicyAdministrationFailureCode::CorruptState => ServiceFailure::CorruptState,
                _ => ServiceFailure::Internal,
            })
    }

    pub fn activate_ingest_policy(
        &self,
        context: AuthorizedContext,
        expected: ResourceGeneration,
        key: AdministrativeIdempotencyKey,
        candidate: IngestPolicy,
    ) -> Result<IngestPolicyActivation, ServiceFailure> {
        self.activate_ingest_policy_durable(context, expected, key, candidate)
            .map_err(map_policy_activation_service_failure)
    }

    fn activate_ingest_policy_durable(
        &self,
        context: AuthorizedContext,
        expected: ResourceGeneration,
        key: AdministrativeIdempotencyKey,
        candidate: IngestPolicy,
    ) -> Result<IngestPolicyActivation, PolicyActivationDurableFailure> {
        let instance = &self.instance;
        let tenant = context
            .tenant_attribution()
            .map(|attribution| attribution.tenant_id())
            .unwrap_or(instance.tenant);
        let catalog = Catalog::open(
            &instance._authority,
            instance.instance,
            instance
                .key
                .catalog_secret(instance.instance)
                .map_err(|_| PolicyActivationDurableFailure::Unavailable)?,
        )
        .map_err(|_| PolicyActivationDurableFailure::Unavailable)?;
        let identity = positron_governance::Identity::open(
            &catalog
                .pin()
                .map_err(|_| PolicyActivationDurableFailure::Unavailable)?,
        )
        .map_err(|_| PolicyActivationDurableFailure::Unavailable)?;
        IngestPolicyAdministration::open(&catalog, tenant)
            .map_err(PolicyActivationDurableFailure::Core)?
            .activate(&catalog, &identity, context, expected, key, candidate)
            .map_err(PolicyActivationDurableFailure::Core)
    }
}

fn map_policy_activation_durable_failure(
    failure: PolicyActivationDurableFailure,
) -> PolicyActivateHttpFailure {
    match failure {
        PolicyActivationDurableFailure::Core(failure) => map_policy_activation_failure(failure),
        PolicyActivationDurableFailure::Unavailable => {
            PolicyActivateHttpFailure::Code(503, "administration_unavailable")
        },
    }
}

fn map_policy_activation_failure(
    failure: PolicyAdministrationFailure,
) -> PolicyActivateHttpFailure {
    match failure.code() {
        PolicyAdministrationFailureCode::Unauthorized => {
            PolicyActivateHttpFailure::Code(401, "authentication_rejected")
        },
        PolicyAdministrationFailureCode::StaleResourceGeneration => failure
            .current_generation()
            .map(PolicyActivateHttpFailure::StaleGeneration)
            .unwrap_or(PolicyActivateHttpFailure::Code(
                503,
                "administration_unavailable",
            )),
        PolicyAdministrationFailureCode::IdempotencyConflict => {
            PolicyActivateHttpFailure::Code(409, "idempotency_conflict")
        },
        PolicyAdministrationFailureCode::InvalidInput
        | PolicyAdministrationFailureCode::InvalidResourceGeneration => {
            PolicyActivateHttpFailure::Code(400, "invalid_request")
        },
        PolicyAdministrationFailureCode::PersistenceUnavailable
        | PolicyAdministrationFailureCode::CorruptState => {
            PolicyActivateHttpFailure::Code(503, "administration_unavailable")
        },
    }
}

fn map_policy_activation_service_failure(
    failure: PolicyActivationDurableFailure,
) -> ServiceFailure {
    match failure {
        PolicyActivationDurableFailure::Core(failure) => match failure.code() {
            PolicyAdministrationFailureCode::Unauthorized => ServiceFailure::Unauthorized,
            PolicyAdministrationFailureCode::PersistenceUnavailable
            | PolicyAdministrationFailureCode::CorruptState => ServiceFailure::StorageUnavailable,
            _ => ServiceFailure::InvalidRequest,
        },
        PolicyActivationDurableFailure::Unavailable => ServiceFailure::StorageUnavailable,
    }
}

fn hex_digest(digest: [u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn policy_diff_category(change: &PolicyPreviewSemanticChange) -> &'static str {
    match change {
        PolicyPreviewSemanticChange::GenerationChanged { .. } => "generation_changed",
        PolicyPreviewSemanticChange::RuleAdded { .. } => "rule_added",
        PolicyPreviewSemanticChange::RuleRemoved { .. } => "rule_removed",
        PolicyPreviewSemanticChange::RulePredicatesChanged { .. } => "rule_predicates_changed",
        PolicyPreviewSemanticChange::RuleActionChanged { .. } => "rule_action_changed",
    }
}
