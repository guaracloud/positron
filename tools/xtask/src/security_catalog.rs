//! Frozen descriptors for security, cryptography, and secret-canary runners.
//!
//! The catalog records the complete Release 1 harness obligations without
//! activating scaffold-only product behavior. Each selected runner obtains its
//! immutable descriptor before executing its bounded detector command.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::error::XtaskError;
use crate::registry::Registry;

const CATALOG_PATH: &str = "qualification/engineering/security-runners.tsv";
const HEADER: &str = "runner_id\tgate_id\tstages\tactivation\tevidence_schema\tthreat_model\tattack_surface\trequired_checks\tcanary_sinks";
const MAXIMUM_CATALOG_BYTES: usize = 16_384;
const MAXIMUM_FIELD_BYTES: usize = 1_024;
const REQUIRED_DESCRIPTORS: [DescriptorContract; 3] = [
    DescriptorContract {
        id: "security-runner-v1",
        gate: "EG-SECURITY",
        stages: "PR|EXT|QUAL",
        activation: "risk",
        evidence_schema: "security-orchestration-v1",
        threat_model: "TM-0001-m0-04-toml-parser",
        attack_surface: "configuration-parser-before-typed-construction-v1",
        required_checks: "threat-model|attack-surface|authn-authz|tenant-isolation",
        canary_sinks: "-",
    },
    DescriptorContract {
        id: "crypto-runner-v1",
        gate: "EG-CRYPTO",
        stages: "PR|EXT|QUAL",
        activation: "risk",
        evidence_schema: "crypto-orchestration-v1",
        threat_model: "TM-0010-m0-10-runner-crypto",
        attack_surface: "xtask-crypto-known-answer-provider-boundary-v1",
        required_checks: "known-answer-vectors|nonce-safety|provider-failures|zeroization",
        canary_sinks: "-",
    },
    DescriptorContract {
        id: "secret-canary-runner-v1",
        gate: "EG-SECRETS",
        stages: "PR|EXT|QUAL",
        activation: "always",
        evidence_schema: "secret-canary-orchestration-v1",
        threat_model: "TM-0011-m0-10-runner-artifacts",
        attack_surface: "xtask-candidate-artifact-disclosure-boundary-v1",
        required_checks: "current-tree-scan|full-history-scan|artifact-canary-scan",
        canary_sinks: "logs|errors|metrics|traces|diagnostics|evidence|binaries|packages|support-artifacts",
    },
];

#[derive(Clone, Copy)]
struct DescriptorContract {
    id: &'static str,
    gate: &'static str,
    stages: &'static str,
    activation: &'static str,
    evidence_schema: &'static str,
    threat_model: &'static str,
    attack_surface: &'static str,
    required_checks: &'static str,
    canary_sinks: &'static str,
}

#[derive(Debug)]
pub(crate) struct SecurityDescriptor {
    id: String,
    evidence_summary: String,
}

impl SecurityDescriptor {
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    pub(crate) fn evidence_summary(&self) -> &str {
        &self.evidence_summary
    }
}

#[derive(Debug)]
pub(crate) struct FrozenSecurityCatalog {
    descriptors: BTreeMap<String, SecurityDescriptor>,
}

impl FrozenSecurityCatalog {
    pub(crate) fn load(
        root: &Path,
        registry: &Registry,
        budget: &mut crate::bounded_input::ExternalInputBudget,
    ) -> Result<Self, XtaskError> {
        let threat_surfaces =
            crate::security_threat_surface::ThreatSurfaceRegistry::load(root, budget)?;
        let path = root.join(CATALOG_PATH);
        let bytes = crate::bounded_input::read_external(
            &path,
            MAXIMUM_CATALOG_BYTES,
            "security runner catalog",
            budget,
        )?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| XtaskError::invalid_path(&path, "security runner catalog is not UTF-8"))?;
        let mut lines = text.lines();
        let Some(header) = lines.next() else {
            return Err(XtaskError::invalid_path(
                &path,
                "security runner catalog is empty",
            ));
        };
        if header != HEADER {
            return Err(XtaskError::invalid_path(
                &path,
                "security runner catalog header does not match the registered schema",
            ));
        }
        let mut records = BTreeMap::new();
        for (index, line) in lines.enumerate() {
            let fields = line.split('\t').collect::<Vec<_>>();
            let [
                id,
                gate,
                stages,
                activation,
                evidence_schema,
                threat_model,
                attack_surface,
                required_checks,
                canary_sinks,
            ] = fields.as_slice()
            else {
                return Err(XtaskError::invalid_path(
                    &path,
                    format!(
                        "security runner catalog row {} has the wrong field count",
                        index + 2
                    ),
                ));
            };
            for field in &fields {
                if field.is_empty() || field.len() > MAXIMUM_FIELD_BYTES {
                    return Err(XtaskError::invalid_path(
                        &path,
                        format!(
                            "security runner catalog row {} has an invalid bounded field",
                            index + 2
                        ),
                    ));
                }
            }
            let Some(contract) = REQUIRED_DESCRIPTORS
                .iter()
                .find(|contract| contract.id == *id)
            else {
                return Err(XtaskError::invalid_path(
                    &path,
                    "security runner catalog has an unknown descriptor",
                ));
            };
            validate_contract(
                &path,
                contract,
                [
                    gate,
                    stages,
                    activation,
                    evidence_schema,
                    threat_model,
                    attack_surface,
                    required_checks,
                    canary_sinks,
                ],
            )?;
            let registered = registry
                .gates
                .iter()
                .find(|registered| registered.id == *gate)
                .ok_or_else(|| {
                    XtaskError::invalid_path(
                        &path,
                        format!("security runner descriptor references unknown gate `{gate}`"),
                    )
                })?;
            if registered.activation != *activation || !stages_match(&registered.stages, stages) {
                return Err(XtaskError::invalid_path(
                    &path,
                    format!(
                        "security runner descriptor `{id}` drifted from gate activation or stages"
                    ),
                ));
            }
            if records.insert((*gate).to_owned(), SecurityDescriptor {
                id: (*id).to_owned(),
                evidence_summary: format!(
                    "schema={evidence_schema}; threat-model={threat_model}; attack-surface={attack_surface}; checks={required_checks}; canary-sinks={canary_sinks}; {}",
                    threat_surfaces.summary(id)?
                ),
            }).is_some() {
                return Err(XtaskError::invalid_path(&path, format!("security runner catalog repeats gate `{gate}`")));
            }
        }
        if records.len() != REQUIRED_DESCRIPTORS.len()
            || REQUIRED_DESCRIPTORS
                .iter()
                .any(|contract| !records.contains_key(contract.gate))
        {
            return Err(XtaskError::invalid_path(
                &path,
                "security runner catalog must contain exactly the registered security, crypto, and secret-canary descriptors",
            ));
        }
        let digest = digest(&bytes);
        for descriptor in records.values_mut() {
            descriptor.evidence_summary.push_str("; catalog-digest=");
            descriptor.evidence_summary.push_str(&digest);
        }
        Ok(Self {
            descriptors: records,
        })
    }

    pub(crate) fn descriptor_for(&self, gate: &str) -> Result<&SecurityDescriptor, XtaskError> {
        self.descriptors.get(gate).ok_or_else(|| {
            XtaskError::invalid(
                "security runner catalog",
                format!("missing descriptor for `{gate}`"),
            )
        })
    }
}

fn validate_contract(
    path: &Path,
    contract: &DescriptorContract,
    fields: [&str; 8],
) -> Result<(), XtaskError> {
    let expected = [
        contract.gate,
        contract.stages,
        contract.activation,
        contract.evidence_schema,
        contract.threat_model,
        contract.attack_surface,
        contract.required_checks,
        contract.canary_sinks,
    ];
    if fields != expected {
        return Err(XtaskError::invalid_path(
            path,
            format!(
                "security runner descriptor `{}` drifted from its frozen contract",
                contract.id
            ),
        ));
    }
    Ok(())
}

fn stages_match(registered: &BTreeSet<String>, descriptor: &str) -> bool {
    let declared = descriptor
        .split('|')
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    declared == *registered
}

fn digest(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    format!("sha256:{:x}", Sha256::digest(bytes))
}
