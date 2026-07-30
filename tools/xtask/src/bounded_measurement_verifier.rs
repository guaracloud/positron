//! Parent-owned verification of bounded-runner measurement records.
//!
//! Schema parsing and semantic verification are separate from this thin owner.

use sha2::{Digest, Sha256};

use crate::controlled_execution::ExecutionVerdict;
use crate::error::XtaskError;
use crate::registry::Gate;

mod schema;
mod semantic;

const VERIFIER_IDENTITY: &str = "parent-bounded-measurement-verifier-v1";
const VERIFIER_VERSION: &str = "1";
const VERIFIER_CONTRACT: &str = "parent-bounded-measurement-verifier-v1|exact-gate-descriptor|exact-scenario-registry|exact-spawn-registry|measurement-v1|canonical-fields|closed-semantics";
const VERIFIER_CONTRACT_SHA256: &str =
    "sha256:20a2dc38a14b0fdf864234b574144df77cfadf33b79335fe7124f68832d20be3";
pub(super) const SCENARIO_HEADER: &str = "scenario_id\tgate_id\tspawn_site\tschedule\tseed\tmax_tasks\tqueue_capacity\treservation_capacity\tretry_limit\tshutdown_ms\texpected";
pub(super) const SPAWN_HEADER: &str = "path\tsymbol\tkind\tid";
pub(super) const MEASUREMENT_FIELDS: [&str; 10] = [
    "scenario",
    "schedule",
    "seed",
    "registered",
    "workers",
    "retries",
    "reservations",
    "queue-empty",
    "joined-ids",
    "shutdown-ms",
];
pub(super) const MAXIMUM_REGISTRY_BYTES: usize = 16_384;
pub(super) const MAXIMUM_MEASUREMENT_BYTES: usize = 4_096;
pub(super) const MAXIMUM_FIELD_BYTES: usize = 96;

pub(crate) struct VerificationInput<'input> {
    pub(crate) gate: &'input Gate,
    pub(crate) scenario_registry: &'input [u8],
    pub(crate) spawn_registry: &'input [u8],
    pub(crate) measurement: &'input str,
    pub(crate) execution: &'input ExecutionVerdict,
}

pub(crate) struct VerifiedMeasurement {
    evidence: String,
}

impl VerifiedMeasurement {
    pub(crate) fn evidence(&self) -> &str {
        &self.evidence
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum GateKind {
    Concurrency,
    Resource,
}

impl GateKind {
    fn from_gate(gate: &Gate) -> Result<Self, XtaskError> {
        match gate.id.as_str() {
            "EG-CONCURRENCY" => Ok(Self::Concurrency),
            "EG-RESOURCE" => Ok(Self::Resource),
            _ => closed("parent verifier received an unsupported gate descriptor"),
        }
    }

    pub(super) fn id(self) -> &'static str {
        match self {
            Self::Concurrency => "EG-CONCURRENCY",
            Self::Resource => "EG-RESOURCE",
        }
    }
}

#[derive(Debug)]
pub(super) struct Scenario {
    pub(super) id: String,
    pub(super) gate: GateKind,
    pub(super) spawn_site: String,
    pub(super) schedule: String,
    pub(super) seed: String,
    pub(super) max_tasks: usize,
    pub(super) queue_capacity: usize,
    pub(super) reservation_capacity: usize,
    pub(super) retry_limit: usize,
    pub(super) shutdown_ms: usize,
    pub(super) expected: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Completion {
    Executed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Worker {
    pub(super) id: usize,
    pub(super) slot: usize,
    pub(super) completion: Completion,
}

pub(crate) fn verify(input: VerificationInput<'_>) -> Result<VerifiedMeasurement, XtaskError> {
    let verifier_digest = sha256(VERIFIER_CONTRACT.as_bytes());
    if verifier_digest != VERIFIER_CONTRACT_SHA256 {
        return closed("stable verifier contract digest does not match its registered identity");
    }
    let gate_kind = GateKind::from_gate(input.gate)?;
    semantic::validate_gate_descriptor(input.gate, gate_kind)?;
    if !input.execution.status.success() {
        return closed("controlled child did not return a successful reconciled execution verdict");
    }
    let scenarios = schema::parse_scenarios(input.scenario_registry)?;
    semantic::validate_registered_scenarios(&scenarios)?;
    let scenario = scenarios.get(gate_kind.id()).ok_or_else(|| {
        verifier_error("parent-captured scenario registry omitted the selected gate")
    })?;
    schema::validate_spawn_registry(input.spawn_registry, scenario)?;
    semantic::verify_measurement(input.measurement, scenario)?;

    let evidence = format!(
        "parent-measurement-verification-v1;identity={VERIFIER_IDENTITY};version={VERIFIER_VERSION};verifier-sha256={verifier_digest};verdict=passed;gate={};gate-descriptor-sha256={};scenario-registry-sha256={};spawn-registry-sha256={};measurement-sha256={};child-self-verification=diagnostic-only;process-reaped=true;live=0",
        gate_kind.id(),
        semantic::gate_descriptor_digest(input.gate),
        sha256(input.scenario_registry),
        sha256(input.spawn_registry),
        sha256(input.measurement.as_bytes()),
    );
    Ok(VerifiedMeasurement { evidence })
}

pub(super) fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

pub(super) fn closed<T>(detail: impl Into<String>) -> Result<T, XtaskError> {
    Err(verifier_error(detail))
}

pub(super) fn verifier_error(detail: impl Into<String>) -> XtaskError {
    XtaskError::invalid("parent bounded measurement verifier", detail)
}
