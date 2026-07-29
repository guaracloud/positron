use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::error::XtaskError;

const REGISTRY_PATH: &str = "qualification/engineering/quality-fixtures.tsv";
const INTEGRITY_REGISTRY_PATH: &str = "qualification/engineering/integrity-fixtures.tsv";
const ADVERSARIAL_MANIFEST_PATH: &str = "qualification/fixtures/adversarial/manifest.json";
const HARNESS_REGISTRY_PATH: &str = "qualification/engineering/fixture-harness.tsv";
const REGISTRY_HEADER: &str = "fixture_id\tgate_id\tpublication_point\tfault_schedule\tseed\tpredecessor\tsuccessor\texpected_reopen";
const INTEGRITY_REGISTRY_HEADER: &str = "fixture_id\tmutation\tseed\texpected_reopen";
const HARNESS_REGISTRY_HEADER: &str = "interface_id\texecutable\twriter_operation\trecovery_operation\tready_protocol\tmaximum_wait_ms\ttermination\trecovery_protocol\twriter_arguments\trecovery_arguments";
const MAXIMUM_REGISTRY_BYTES: usize = 16_384;
const MAXIMUM_IDENTITY_REGISTRY_BYTES: usize = 65_536;
const MAXIMUM_FIXTURES: usize = 32;
const MAXIMUM_FIELD_BYTES: usize = 96;
const MAXIMUM_STATE_BYTES: usize = 1_024;
const MAXIMUM_INTEGRITY_OBJECT_BYTES: usize = 8_192;
const MAXIMUM_PROCESS_RECORD_BYTES: usize = 1_024;
const CORRECTNESS_GATE: &str = "EG-CORRECT";
const FAULT_GATE: &str = "EG-FAULT";

const CORRECTNESS_PUBLICATION_POINTS: [PublicationPoint; 2] = [
    PublicationPoint::BeforePublication,
    PublicationPoint::AfterPublication,
];
const FAULT_PUBLICATION_POINTS: [PublicationPoint; 9] = [
    PublicationPoint::PartialWriteBoundary,
    PublicationPoint::CrashBoundary,
    PublicationPoint::RestartBoundary,
    PublicationPoint::CorruptionBoundary,
    PublicationPoint::FullDiskBoundary,
    PublicationPoint::ClockBoundary,
    PublicationPoint::CancellationBoundary,
    PublicationPoint::NetworkBoundary,
    PublicationPoint::ProviderBoundary,
];

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum PublicationPoint {
    BeforePublication,
    AfterPublication,
    PartialWriteBoundary,
    CrashBoundary,
    RestartBoundary,
    CorruptionBoundary,
    FullDiskBoundary,
    ClockBoundary,
    CancellationBoundary,
    NetworkBoundary,
    ProviderBoundary,
}

impl PublicationPoint {
    fn parse(value: &str) -> Result<Self, XtaskError> {
        match value {
            "before-publication" => Ok(Self::BeforePublication),
            "after-publication" => Ok(Self::AfterPublication),
            "partial-write-boundary" => Ok(Self::PartialWriteBoundary),
            "crash-boundary" => Ok(Self::CrashBoundary),
            "restart-boundary" => Ok(Self::RestartBoundary),
            "corruption-boundary" => Ok(Self::CorruptionBoundary),
            "full-disk-boundary" => Ok(Self::FullDiskBoundary),
            "clock-boundary" => Ok(Self::ClockBoundary),
            "cancellation-boundary" => Ok(Self::CancellationBoundary),
            "network-boundary" => Ok(Self::NetworkBoundary),
            "provider-boundary" => Ok(Self::ProviderBoundary),
            _ => Err(XtaskError::invalid(
                "quality fixture registry",
                format!("unknown publication point `{value}`"),
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::BeforePublication => "before-publication",
            Self::AfterPublication => "after-publication",
            Self::PartialWriteBoundary => "partial-write-boundary",
            Self::CrashBoundary => "crash-boundary",
            Self::RestartBoundary => "restart-boundary",
            Self::CorruptionBoundary => "corruption-boundary",
            Self::FullDiskBoundary => "full-disk-boundary",
            Self::ClockBoundary => "clock-boundary",
            Self::CancellationBoundary => "cancellation-boundary",
            Self::NetworkBoundary => "network-boundary",
            Self::ProviderBoundary => "provider-boundary",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CrashSchedule {
    AfterCandidateSync,
    AfterPublicationSync,
    PartialWrite,
    Crash,
    Restart,
    Corruption,
    FullDisk,
    Clock,
    Cancellation,
    Network,
    Provider,
}

impl CrashSchedule {
    fn parse(value: &str) -> Result<Self, XtaskError> {
        match value {
            "crash-after-candidate-sync" => Ok(Self::AfterCandidateSync),
            "crash-after-publication-sync" => Ok(Self::AfterPublicationSync),
            "inject-partial-write" => Ok(Self::PartialWrite),
            "inject-crash" => Ok(Self::Crash),
            "inject-restart" => Ok(Self::Restart),
            "inject-corruption" => Ok(Self::Corruption),
            "inject-full-disk" => Ok(Self::FullDisk),
            "inject-clock" => Ok(Self::Clock),
            "inject-cancellation" => Ok(Self::Cancellation),
            "inject-network" => Ok(Self::Network),
            "inject-provider" => Ok(Self::Provider),
            _ => Err(XtaskError::invalid(
                "quality fixture registry",
                format!("unknown crash schedule `{value}`"),
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::AfterCandidateSync => "crash-after-candidate-sync",
            Self::AfterPublicationSync => "crash-after-publication-sync",
            Self::PartialWrite => "inject-partial-write",
            Self::Crash => "inject-crash",
            Self::Restart => "inject-restart",
            Self::Corruption => "inject-corruption",
            Self::FullDisk => "inject-full-disk",
            Self::Clock => "inject-clock",
            Self::Cancellation => "inject-cancellation",
            Self::Network => "inject-network",
            Self::Provider => "inject-provider",
        }
    }
}

#[derive(Debug)]
struct FixtureCase {
    fixture_id: String,
    gate_id: String,
    publication_point: PublicationPoint,
    fault_schedule: CrashSchedule,
    seed: String,
    predecessor: String,
    successor: String,
    expected_reopen: String,
}

#[derive(Debug)]
struct FixtureRegistry {
    cases: Vec<FixtureCase>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IntegrityMutation {
    None,
    CorruptPayload,
    DeleteObject,
}

impl IntegrityMutation {
    fn parse(value: &str) -> Result<Self, XtaskError> {
        match value {
            "none" => Ok(Self::None),
            "corrupt-payload" => Ok(Self::CorruptPayload),
            "delete-object" => Ok(Self::DeleteObject),
            _ => Err(XtaskError::invalid(
                "integrity fixture registry",
                format!("unknown integrity mutation `{value}`"),
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::CorruptPayload => "corrupt-payload",
            Self::DeleteObject => "delete-object",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IntegrityExpectedReopen {
    Verified,
    DigestMismatch,
    MissingObject,
}

impl IntegrityExpectedReopen {
    fn parse(value: &str) -> Result<Self, XtaskError> {
        match value {
            "verified" => Ok(Self::Verified),
            "digest-mismatch" => Ok(Self::DigestMismatch),
            "missing-object" => Ok(Self::MissingObject),
            _ => Err(XtaskError::invalid(
                "integrity fixture registry",
                format!("unknown expected reopen outcome `{value}`"),
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::DigestMismatch => "digest-mismatch",
            Self::MissingObject => "missing-object",
        }
    }
}

#[derive(Debug)]
struct IntegrityCase {
    fixture_id: String,
    mutation: IntegrityMutation,
    seed: String,
    expected_reopen: IntegrityExpectedReopen,
}

#[derive(Debug)]
struct IntegrityRegistry {
    cases: Vec<IntegrityCase>,
}

#[derive(Debug)]
struct HarnessInterface {
    interface_id: String,
    writer_operation: String,
    recovery_operation: String,
    ready_protocol: String,
    maximum_wait: Duration,
    recovery_protocol: String,
}

#[derive(Debug)]
struct OwnedFixtureRoot {
    path: PathBuf,
    active: bool,
}

#[derive(Debug)]
struct ChildReconciliation {
    status: std::process::ExitStatus,
    kill_sent: bool,
}

#[derive(Debug)]
enum FrozenRegistry<Registry> {
    Valid(Registry),
    Invalid(String),
}

impl<Registry> FrozenRegistry<Registry> {
    fn get(&self, label: &str) -> Result<&Registry, XtaskError> {
        match self {
            Self::Valid(registry) => Ok(registry),
            Self::Invalid(error) => Err(XtaskError::invalid(label, error)),
        }
    }
}

#[derive(Debug)]
pub(crate) struct FrozenQualificationFixtures {
    adversarial_manifest: Box<[u8]>,
    quality_registry_bytes: Box<[u8]>,
    integrity_registry_bytes: Box<[u8]>,
    harness_registry_bytes: Box<[u8]>,
    quality_registry: FrozenRegistry<FixtureRegistry>,
    integrity_registry: FrozenRegistry<IntegrityRegistry>,
    harness: HarnessInterface,
    seed_digest: String,
    fault_schedule_digest: String,
}

#[derive(Debug)]
pub(crate) struct IntegrityIdentity {
    pub(crate) revision: String,
    pub(crate) artifact: String,
    pub(crate) target: String,
    pub(crate) environment: String,
    pub(crate) command: String,
    pub(crate) fixtures: String,
    pub(crate) result: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IntegrityReadFailure {
    MissingObject,
    DigestMismatch,
    InvalidObject,
    IdentityMismatch,
    Io,
}

impl FixtureRegistry {
    fn parse(path: &Path, bytes: &[u8]) -> Result<Self, XtaskError> {
        if bytes.len() > MAXIMUM_REGISTRY_BYTES {
            return Err(XtaskError::invalid_path(
                path,
                format!("fixture registry exceeds {MAXIMUM_REGISTRY_BYTES} bytes"),
            ));
        }
        let content = std::str::from_utf8(bytes)
            .map_err(|_| XtaskError::invalid_path(path, "fixture registry is not UTF-8"))?;
        let mut lines = content.lines();
        if lines.next() != Some(REGISTRY_HEADER) {
            return Err(XtaskError::invalid_path(
                path,
                "fixture registry header is not exact",
            ));
        }
        let mut cases = Vec::new();
        let mut fixture_ids = BTreeSet::new();
        for (offset, line) in lines.enumerate() {
            if cases.len() >= MAXIMUM_FIXTURES {
                return Err(XtaskError::invalid_path(
                    path,
                    format!("fixture registry exceeds {MAXIMUM_FIXTURES} rows"),
                ));
            }
            let fields = line.split('\t').collect::<Vec<_>>();
            let [
                fixture_id,
                gate_id,
                publication_point,
                fault_schedule,
                seed,
                predecessor,
                successor,
                expected_reopen,
            ] = fields.as_slice()
            else {
                return Err(XtaskError::invalid_path(
                    path,
                    format!(
                        "fixture row {} does not contain exactly 8 fields",
                        offset + 2
                    ),
                ));
            };
            for (field_name, value) in [
                ("fixture_id", *fixture_id),
                ("gate_id", *gate_id),
                ("publication_point", *publication_point),
                ("fault_schedule", *fault_schedule),
                ("seed", *seed),
                ("predecessor", *predecessor),
                ("successor", *successor),
                ("expected_reopen", *expected_reopen),
            ] {
                validate_field(path, offset + 2, field_name, value)?;
            }
            if !fixture_ids.insert((*fixture_id).to_owned()) {
                return Err(XtaskError::invalid_path(
                    path,
                    format!("fixture id `{fixture_id}` is duplicated"),
                ));
            }
            cases.push(FixtureCase {
                fixture_id: (*fixture_id).to_owned(),
                gate_id: (*gate_id).to_owned(),
                publication_point: PublicationPoint::parse(publication_point)?,
                fault_schedule: CrashSchedule::parse(fault_schedule)?,
                seed: (*seed).to_owned(),
                predecessor: (*predecessor).to_owned(),
                successor: (*successor).to_owned(),
                expected_reopen: (*expected_reopen).to_owned(),
            });
        }
        if cases.is_empty() {
            return Err(XtaskError::invalid_path(
                path,
                "fixture registry contains no cases",
            ));
        }
        Ok(Self { cases })
    }

    fn cases_for(&self, gate_id: &str) -> Vec<&FixtureCase> {
        self.cases
            .iter()
            .filter(|case| case.gate_id == gate_id)
            .collect()
    }
}

impl IntegrityRegistry {
    fn parse(path: &Path, bytes: &[u8]) -> Result<Self, XtaskError> {
        if bytes.len() > MAXIMUM_REGISTRY_BYTES {
            return Err(XtaskError::invalid_path(
                path,
                format!("integrity fixture registry exceeds {MAXIMUM_REGISTRY_BYTES} bytes"),
            ));
        }
        let content = std::str::from_utf8(bytes).map_err(|_| {
            XtaskError::invalid_path(path, "integrity fixture registry is not UTF-8")
        })?;
        let mut lines = content.lines();
        if lines.next() != Some(INTEGRITY_REGISTRY_HEADER) {
            return Err(XtaskError::invalid_path(
                path,
                "integrity fixture registry header is not exact",
            ));
        }
        let mut cases = Vec::new();
        let mut fixture_ids = BTreeSet::new();
        let mut mutations = BTreeSet::new();
        for (offset, line) in lines.enumerate() {
            if cases.len() >= MAXIMUM_FIXTURES {
                return Err(XtaskError::invalid_path(
                    path,
                    format!("integrity fixture registry exceeds {MAXIMUM_FIXTURES} rows"),
                ));
            }
            let fields = line.split('\t').collect::<Vec<_>>();
            let [fixture_id, mutation, seed, expected_reopen] = fields.as_slice() else {
                return Err(XtaskError::invalid_path(
                    path,
                    format!(
                        "integrity fixture row {} does not contain exactly 4 fields",
                        offset + 2
                    ),
                ));
            };
            for (field_name, value) in [
                ("fixture_id", *fixture_id),
                ("mutation", *mutation),
                ("seed", *seed),
                ("expected_reopen", *expected_reopen),
            ] {
                validate_field(path, offset + 2, field_name, value)?;
            }
            let mutation = IntegrityMutation::parse(mutation)?;
            if !fixture_ids.insert((*fixture_id).to_owned()) {
                return Err(XtaskError::invalid_path(
                    path,
                    format!("integrity fixture id `{fixture_id}` is duplicated"),
                ));
            }
            if !mutations.insert(mutation.as_str()) {
                return Err(XtaskError::invalid_path(
                    path,
                    format!(
                        "integrity mutation `{}` must have exactly one fixture",
                        mutation.as_str()
                    ),
                ));
            }
            cases.push(IntegrityCase {
                fixture_id: (*fixture_id).to_owned(),
                mutation,
                seed: (*seed).to_owned(),
                expected_reopen: IntegrityExpectedReopen::parse(expected_reopen)?,
            });
        }
        let expected = ["none", "corrupt-payload", "delete-object"];
        if cases.len() != expected.len()
            || expected
                .iter()
                .any(|mutation| !mutations.contains(mutation))
        {
            return Err(XtaskError::invalid(
                "EG-INTEGRITY fixture registry",
                "expected exactly one none, corrupt-payload, and delete-object fixture",
            ));
        }
        for case in &cases {
            let expected = match case.mutation {
                IntegrityMutation::None => IntegrityExpectedReopen::Verified,
                IntegrityMutation::CorruptPayload => IntegrityExpectedReopen::DigestMismatch,
                IntegrityMutation::DeleteObject => IntegrityExpectedReopen::MissingObject,
            };
            if case.expected_reopen != expected {
                return Err(XtaskError::invalid(
                    format!("integrity fixture `{}`", case.fixture_id),
                    "registered expected outcome does not match its mutation",
                ));
            }
        }
        Ok(Self { cases })
    }
}

impl HarnessInterface {
    fn parse(path: &Path, bytes: &[u8]) -> Result<Self, XtaskError> {
        if bytes.len() > MAXIMUM_REGISTRY_BYTES {
            return Err(XtaskError::invalid_path(
                path,
                format!("fixture harness registry exceeds {MAXIMUM_REGISTRY_BYTES} bytes"),
            ));
        }
        let content = std::str::from_utf8(bytes)
            .map_err(|_| XtaskError::invalid_path(path, "fixture harness registry is not UTF-8"))?;
        let mut lines = content.lines();
        if lines.next() != Some(HARNESS_REGISTRY_HEADER) {
            return Err(XtaskError::invalid_path(
                path,
                "fixture harness registry header is not exact",
            ));
        }
        let row = lines.next().ok_or_else(|| {
            XtaskError::invalid_path(path, "fixture harness registry contains no interface")
        })?;
        if lines.next().is_some() {
            return Err(XtaskError::invalid_path(
                path,
                "fixture harness registry must contain exactly one interface",
            ));
        }
        let fields = row.split('\t').collect::<Vec<_>>();
        let [
            interface_id,
            executable,
            writer_operation,
            recovery_operation,
            ready_protocol,
            maximum_wait_ms,
            termination,
            recovery_protocol,
            writer_arguments,
            recovery_arguments,
        ] = fields.as_slice()
        else {
            return Err(XtaskError::invalid_path(
                path,
                "fixture harness registry row does not contain exactly 10 fields",
            ));
        };
        for (field_name, value) in [
            ("interface_id", *interface_id),
            ("executable", *executable),
            ("writer_operation", *writer_operation),
            ("recovery_operation", *recovery_operation),
            ("ready_protocol", *ready_protocol),
            ("termination", *termination),
            ("recovery_protocol", *recovery_protocol),
            ("writer_arguments", *writer_arguments),
            ("recovery_arguments", *recovery_arguments),
        ] {
            validate_field(path, 2, field_name, value)?;
        }
        if (
            *interface_id,
            *executable,
            *writer_operation,
            *recovery_operation,
            *ready_protocol,
            *termination,
            *recovery_protocol,
            *writer_arguments,
            *recovery_arguments,
        ) != (
            "quality-engineering-state-v1",
            "current-xtask",
            "writer",
            "recover",
            "publication-point-ready-v1",
            "force-kill-and-reap",
            "recovery-v1",
            "owned-root-case-root-publication-point-fault-schedule-predecessor-successor",
            "owned-root-case-root-result-path-recovery-protocol",
        ) {
            return Err(XtaskError::invalid_path(
                path,
                "fixture harness process interface does not match its registered contract",
            ));
        }
        let maximum_wait_ms = maximum_wait_ms.parse::<u64>().map_err(|_| {
            XtaskError::invalid_path(path, "fixture harness maximum_wait_ms is not an integer")
        })?;
        if !(1..=30_000).contains(&maximum_wait_ms) {
            return Err(XtaskError::invalid_path(
                path,
                "fixture harness maximum_wait_ms must be in 1..=30000",
            ));
        }
        Ok(Self {
            interface_id: (*interface_id).to_owned(),
            writer_operation: (*writer_operation).to_owned(),
            recovery_operation: (*recovery_operation).to_owned(),
            ready_protocol: (*ready_protocol).to_owned(),
            maximum_wait: Duration::from_millis(maximum_wait_ms),
            recovery_protocol: (*recovery_protocol).to_owned(),
        })
    }
}

impl FrozenQualificationFixtures {
    pub(crate) fn capture(root: &Path) -> Result<Self, XtaskError> {
        let adversarial_manifest = read_frozen_input(
            root,
            ADVERSARIAL_MANIFEST_PATH,
            MAXIMUM_IDENTITY_REGISTRY_BYTES,
        )?;
        let quality_registry_bytes =
            read_frozen_input(root, REGISTRY_PATH, MAXIMUM_IDENTITY_REGISTRY_BYTES)?;
        let integrity_registry_bytes = read_frozen_input(
            root,
            INTEGRITY_REGISTRY_PATH,
            MAXIMUM_IDENTITY_REGISTRY_BYTES,
        )?;
        let harness_registry_bytes =
            read_frozen_input(root, HARNESS_REGISTRY_PATH, MAXIMUM_IDENTITY_REGISTRY_BYTES)?;
        let quality_registry =
            match FixtureRegistry::parse(&root.join(REGISTRY_PATH), &quality_registry_bytes) {
                Ok(registry) => FrozenRegistry::Valid(registry),
                Err(error) => FrozenRegistry::Invalid(error.to_string()),
            };
        let integrity_registry = match IntegrityRegistry::parse(
            &root.join(INTEGRITY_REGISTRY_PATH),
            &integrity_registry_bytes,
        ) {
            Ok(registry) => FrozenRegistry::Valid(registry),
            Err(error) => FrozenRegistry::Invalid(error.to_string()),
        };
        let harness =
            HarnessInterface::parse(&root.join(HARNESS_REGISTRY_PATH), &harness_registry_bytes)?;
        let (seed_digest, fault_schedule_digest) =
            seed_and_schedule_digests(&quality_registry_bytes, &integrity_registry_bytes);
        Ok(Self {
            adversarial_manifest: adversarial_manifest.into_boxed_slice(),
            quality_registry_bytes: quality_registry_bytes.into_boxed_slice(),
            integrity_registry_bytes: integrity_registry_bytes.into_boxed_slice(),
            harness_registry_bytes: harness_registry_bytes.into_boxed_slice(),
            quality_registry,
            integrity_registry,
            harness,
            seed_digest,
            fault_schedule_digest,
        })
    }

    pub(crate) fn identity_payload(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        for (relative, bytes) in [
            (
                ADVERSARIAL_MANIFEST_PATH,
                self.adversarial_manifest.as_ref(),
            ),
            (REGISTRY_PATH, self.quality_registry_bytes.as_ref()),
            (
                INTEGRITY_REGISTRY_PATH,
                self.integrity_registry_bytes.as_ref(),
            ),
            (HARNESS_REGISTRY_PATH, self.harness_registry_bytes.as_ref()),
        ] {
            payload.extend_from_slice(relative.as_bytes());
            payload.push(0);
            payload.extend_from_slice(bytes);
            payload.push(0);
        }
        payload
    }

    pub(crate) fn seed_digest(&self) -> &str {
        &self.seed_digest
    }

    pub(crate) fn fault_schedule_digest(&self) -> &str {
        &self.fault_schedule_digest
    }
}

pub(crate) fn run_correctness(
    fixtures: &FrozenQualificationFixtures,
    temporary_root: &Path,
) -> Result<String, XtaskError> {
    let cases = fixtures
        .quality_registry
        .get("frozen quality fixture registry")?
        .cases_for(CORRECTNESS_GATE);
    validate_exact_publication_points(CORRECTNESS_GATE, &cases, &CORRECTNESS_PUBLICATION_POINTS)?;
    let fixture_root = OwnedFixtureRoot::create(temporary_root, "correctness")?;
    let outcome = (|| {
        let mut outcomes = Vec::with_capacity(cases.len());
        for case in cases {
            outcomes.push(execute_state_transition(
                &fixture_root,
                case,
                &fixtures.harness,
            )?);
        }
        Ok(format!(
            "quality-engineering-fixtures={}; process-interface={}; interface-id={}; {}",
            REGISTRY_PATH,
            HARNESS_REGISTRY_PATH,
            fixtures.harness.interface_id,
            outcomes.join(",")
        ))
    })();
    fixture_root.finish(outcome)
}

pub(crate) fn run_fault(
    fixtures: &FrozenQualificationFixtures,
    temporary_root: &Path,
) -> Result<String, XtaskError> {
    let cases = fixtures
        .quality_registry
        .get("frozen quality fixture registry")?
        .cases_for(FAULT_GATE);
    validate_exact_publication_points(FAULT_GATE, &cases, &FAULT_PUBLICATION_POINTS)?;
    let fixture_root = OwnedFixtureRoot::create(temporary_root, "fault")?;
    let outcome = (|| {
        let publication_point_count = cases.len();
        let mut outcomes = Vec::with_capacity(cases.len());
        for case in cases {
            outcomes.push(execute_state_transition(
                &fixture_root,
                case,
                &fixtures.harness,
            )?);
        }
        Ok(format!(
            "quality-engineering-fixtures={}; process-interface={}; interface-id={}; one-to-one-publication-points={}; exact-fault-classes=partial-write+crash+restart+corruption+full-disk+clock+cancellation+network+provider; {}",
            REGISTRY_PATH,
            HARNESS_REGISTRY_PATH,
            fixtures.harness.interface_id,
            publication_point_count,
            outcomes.join(",")
        ))
    })();
    fixture_root.finish(outcome)
}

pub(crate) fn run_integrity(
    fixtures: &FrozenQualificationFixtures,
    temporary_root: &Path,
    identity: &IntegrityIdentity,
) -> Result<String, XtaskError> {
    let integrity_registry = fixtures
        .integrity_registry
        .get("frozen integrity fixture registry")?;
    let fixture_root = OwnedFixtureRoot::create(temporary_root, "integrity")?;
    let outcome = (|| {
        let mut outcomes = Vec::with_capacity(integrity_registry.cases.len());
        for case in &integrity_registry.cases {
            outcomes.push(execute_integrity_case(&fixture_root, case, identity)?);
        }
        Ok(format!(
            "quality-engineering-fixtures={}; identity=revision+artifact+target+environment+command+fixtures+seed+schedule+result; {}",
            INTEGRITY_REGISTRY_PATH,
            outcomes.join(",")
        ))
    })();
    fixture_root.finish(outcome)
}

fn seed_and_schedule_digests(quality: &[u8], integrity: &[u8]) -> (String, String) {
    let mut seed_hasher = Sha256::new();
    seed_hasher.update(b"positron-quality-fixture-seeds-v1\0");
    seed_hasher.update(quality);
    seed_hasher.update(b"\0");
    seed_hasher.update(integrity);
    let mut schedule_hasher = Sha256::new();
    schedule_hasher.update(b"positron-quality-fault-schedules-v1\0");
    schedule_hasher.update(quality);
    schedule_hasher.update(b"\0");
    schedule_hasher.update(integrity);
    (
        format!("sha256:{:x}", seed_hasher.finalize()),
        format!("sha256:{:x}", schedule_hasher.finalize()),
    )
}

fn read_frozen_input(
    root: &Path,
    relative: &str,
    maximum_bytes: usize,
) -> Result<Vec<u8>, XtaskError> {
    let path = root.join(relative);
    let bytes = fs::read(&path)
        .map_err(|source| XtaskError::io(format!("read {}", path.display()), source))?;
    if bytes.len() > maximum_bytes {
        return Err(XtaskError::invalid_path(
            &path,
            format!("fixture identity input exceeds {maximum_bytes} bytes"),
        ));
    }
    Ok(bytes)
}

fn execute_integrity_case(
    fixture_root: &OwnedFixtureRoot,
    case: &IntegrityCase,
    identity: &IntegrityIdentity,
) -> Result<String, XtaskError> {
    let case_root = fixture_root.create_case(&case.fixture_id)?;
    let original = case_root.join("prior-attempt.evidence");
    write_integrity_object(&original, identity, case)?;
    sync_directory(&case_root)?;
    let reopened = case_root.join("reopen.evidence");
    fs::copy(&original, &reopened).map_err(|source| {
        XtaskError::io(
            format!(
                "copy integrity fixture {} to {}",
                original.display(),
                reopened.display()
            ),
            source,
        )
    })?;
    sync_file(&reopened)?;
    sync_directory(&case_root)?;

    match case.mutation {
        IntegrityMutation::None => {},
        IntegrityMutation::CorruptPayload => corrupt_integrity_payload(&reopened)?,
        IntegrityMutation::DeleteObject => {
            fs::remove_file(&reopened).map_err(|source| {
                XtaskError::io(
                    format!("delete integrity fixture {}", reopened.display()),
                    source,
                )
            })?;
            sync_directory(&case_root)?;
        },
    }

    let outcome = match read_integrity_object(&reopened, identity, case) {
        Ok(()) => IntegrityExpectedReopen::Verified,
        Err(IntegrityReadFailure::DigestMismatch) => IntegrityExpectedReopen::DigestMismatch,
        Err(IntegrityReadFailure::MissingObject) => IntegrityExpectedReopen::MissingObject,
        Err(
            IntegrityReadFailure::InvalidObject
            | IntegrityReadFailure::IdentityMismatch
            | IntegrityReadFailure::Io,
        ) => {
            return Err(XtaskError::invalid(
                format!("integrity fixture `{}`", case.fixture_id),
                "reopen returned a non-canonical failure classification",
            ));
        },
    };
    if outcome != case.expected_reopen {
        return Err(XtaskError::invalid(
            format!("integrity fixture `{}`", case.fixture_id),
            format!(
                "reopen returned `{}`, expected `{}`",
                outcome.as_str(),
                case.expected_reopen.as_str()
            ),
        ));
    }
    read_integrity_object(&original, identity, case).map_err(|failure| {
        XtaskError::invalid(
            format!("integrity fixture `{}`", case.fixture_id),
            format!("prior attempt was not preserved: {failure:?}"),
        )
    })?;
    Ok(format!(
        "{}:{}:original-preserved:seed={}:schedule={}",
        case.fixture_id,
        outcome.as_str(),
        case.seed,
        case.mutation.as_str()
    ))
}

fn write_integrity_object(
    path: &Path,
    identity: &IntegrityIdentity,
    case: &IntegrityCase,
) -> Result<(), XtaskError> {
    let payload = format!("fixture-payload-{}", case.fixture_id);
    let payload_digest = integrity_payload_digest(payload.as_bytes());
    let content = format!(
        "schema=1\nrevision={}\nartifact={}\ntarget={}\nenvironment={}\ncommand={}\nfixtures={}\nseed={}\nschedule={}\nresult={}\npayload={payload}\npayload_digest={payload_digest}\n",
        identity.revision,
        identity.artifact,
        identity.target,
        identity.environment,
        identity.command,
        identity.fixtures,
        case.seed,
        case.mutation.as_str(),
        identity.result,
    );
    if content.len() > MAXIMUM_INTEGRITY_OBJECT_BYTES {
        return Err(XtaskError::invalid_path(
            path,
            format!("integrity object exceeds {MAXIMUM_INTEGRITY_OBJECT_BYTES} bytes"),
        ));
    }
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|source| XtaskError::io(format!("create {}", path.display()), source))?;
    file.write_all(content.as_bytes())
        .and_then(|()| file.flush())
        .and_then(|()| file.sync_all())
        .map_err(|source| XtaskError::io(format!("persist {}", path.display()), source))
}

fn read_integrity_object(
    path: &Path,
    identity: &IntegrityIdentity,
    case: &IntegrityCase,
) -> Result<(), IntegrityReadFailure> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(IntegrityReadFailure::MissingObject);
        },
        Err(_) => return Err(IntegrityReadFailure::Io),
    };
    if bytes.len() > MAXIMUM_INTEGRITY_OBJECT_BYTES {
        return Err(IntegrityReadFailure::InvalidObject);
    }
    let content = std::str::from_utf8(&bytes).map_err(|_| IntegrityReadFailure::InvalidObject)?;
    let lines = content.lines().collect::<Vec<_>>();
    let [
        schema,
        revision,
        artifact,
        target,
        environment,
        command,
        fixtures,
        seed,
        schedule,
        result,
        payload,
        payload_digest,
    ] = lines.as_slice()
    else {
        return Err(IntegrityReadFailure::InvalidObject);
    };
    let expected = [
        ("schema", "1"),
        ("revision", identity.revision.as_str()),
        ("artifact", identity.artifact.as_str()),
        ("target", identity.target.as_str()),
        ("environment", identity.environment.as_str()),
        ("command", identity.command.as_str()),
        ("fixtures", identity.fixtures.as_str()),
        ("seed", case.seed.as_str()),
        ("schedule", case.mutation.as_str()),
        ("result", identity.result.as_str()),
    ];
    for (line, (expected_key, expected_value)) in [
        *schema,
        *revision,
        *artifact,
        *target,
        *environment,
        *command,
        *fixtures,
        *seed,
        *schedule,
        *result,
    ]
    .into_iter()
    .zip(expected)
    {
        let Some((key, value)) = line.split_once('=') else {
            return Err(IntegrityReadFailure::InvalidObject);
        };
        if key != expected_key || value != expected_value {
            return Err(IntegrityReadFailure::IdentityMismatch);
        }
    }
    let Some(payload) = payload.strip_prefix("payload=") else {
        return Err(IntegrityReadFailure::InvalidObject);
    };
    let Some(payload_digest) = payload_digest.strip_prefix("payload_digest=") else {
        return Err(IntegrityReadFailure::InvalidObject);
    };
    if integrity_payload_digest(payload.as_bytes()) != payload_digest {
        return Err(IntegrityReadFailure::DigestMismatch);
    }
    Ok(())
}

fn corrupt_integrity_payload(path: &Path) -> Result<(), XtaskError> {
    let mut bytes = fs::read(path)
        .map_err(|source| XtaskError::io(format!("read {}", path.display()), source))?;
    let marker = b"payload=fixture-payload-";
    let start = bytes
        .windows(marker.len())
        .position(|window| window == marker)
        .and_then(|offset| offset.checked_add(marker.len()))
        .ok_or_else(|| {
            XtaskError::invalid_path(path, "integrity fixture payload marker is missing")
        })?;
    let byte = bytes.get_mut(start).ok_or_else(|| {
        XtaskError::invalid_path(path, "integrity fixture payload is unexpectedly empty")
    })?;
    *byte = if *byte == b'x' { b'y' } else { b'x' };
    let mut file = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .map_err(|source| XtaskError::io(format!("open {}", path.display()), source))?;
    file.write_all(&bytes)
        .and_then(|()| file.flush())
        .and_then(|()| file.sync_all())
        .map_err(|source| XtaskError::io(format!("corrupt {}", path.display()), source))
}

fn sync_file(path: &Path) -> Result<(), XtaskError> {
    fs::OpenOptions::new()
        .read(true)
        .open(path)
        .and_then(|file| file.sync_all())
        .map_err(|source| XtaskError::io(format!("synchronize {}", path.display()), source))
}

fn integrity_payload_digest(payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"positron-quality-integrity-object-v1\0");
    hasher.update(payload);
    format!("sha256:{:x}", hasher.finalize())
}

fn validate_exact_publication_points(
    gate_id: &str,
    cases: &[&FixtureCase],
    expected_points: &[PublicationPoint],
) -> Result<(), XtaskError> {
    if cases.len() != expected_points.len() {
        return Err(XtaskError::invalid(
            format!("{gate_id} fixture registry"),
            format!(
                "expected exactly {} publication-point fixtures, found {}",
                expected_points.len(),
                cases.len()
            ),
        ));
    }
    for expected in expected_points {
        let matching = cases
            .iter()
            .filter(|case| case.publication_point == *expected)
            .count();
        if matching != 1 {
            return Err(XtaskError::invalid(
                format!("{gate_id} fixture registry"),
                format!(
                    "publication point `{}` must have exactly one fixture, found {matching}",
                    expected.as_str()
                ),
            ));
        }
    }
    Ok(())
}

fn execute_state_transition(
    fixture_root: &OwnedFixtureRoot,
    case: &FixtureCase,
    harness: &HarnessInterface,
) -> Result<String, XtaskError> {
    validate_schedule_mapping(case)?;
    let case_root = fixture_root.create_case(&case.fixture_id)?;
    let ready = case_root.join("writer.ready");
    let executable = std::env::current_exe()
        .map_err(|source| XtaskError::io("resolve current xtask executable", source))?;
    let mut writer = Command::new(&executable)
        .env_clear()
        .current_dir(&case_root)
        .args([
            "quality-fixture",
            harness.writer_operation.as_str(),
            fixture_root.path.to_str().ok_or_else(|| {
                XtaskError::invalid_path(&fixture_root.path, "fixture root is not valid UTF-8")
            })?,
            case_root.to_str().ok_or_else(|| {
                XtaskError::invalid_path(&case_root, "fixture path is not valid UTF-8")
            })?,
            case.publication_point.as_str(),
            case.fault_schedule.as_str(),
            case.predecessor.as_str(),
            case.successor.as_str(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|source| XtaskError::io("launch fixture writer process", source))?;
    let writer_pid = writer.id();
    if let Err(error) = wait_for_ready_acknowledgement(
        &mut writer,
        &ready,
        harness,
        case.publication_point,
        writer_pid,
    ) {
        return match force_terminate_and_reap(&mut writer, "fixture writer process") {
            Ok(_) => Err(error),
            Err(reconciliation) => Err(XtaskError::invalid(
                "fixture writer process",
                format!("{error}; process reconciliation also failed: {reconciliation}"),
            )),
        };
    }
    let writer_reconciliation = force_terminate_and_reap(&mut writer, "fixture writer process")?;
    if !writer_reconciliation.kill_sent || writer_reconciliation.status.success() {
        return Err(XtaskError::invalid(
            format!("fixture writer `{}`", case.fixture_id),
            format!(
                "writer was not forcibly terminated and reaped as registered: status={}, kill-sent={}",
                writer_reconciliation.status, writer_reconciliation.kill_sent
            ),
        ));
    }

    let recovery_result = case_root.join("recovery.result");
    let mut recovery = Command::new(&executable)
        .env_clear()
        .current_dir(&case_root)
        .args([
            "quality-fixture",
            harness.recovery_operation.as_str(),
            fixture_root.path.to_str().ok_or_else(|| {
                XtaskError::invalid_path(&fixture_root.path, "fixture root is not valid UTF-8")
            })?,
            case_root.to_str().ok_or_else(|| {
                XtaskError::invalid_path(&case_root, "fixture path is not valid UTF-8")
            })?,
            recovery_result.to_str().ok_or_else(|| {
                XtaskError::invalid_path(&recovery_result, "recovery path is not valid UTF-8")
            })?,
            harness.recovery_protocol.as_str(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|source| XtaskError::io("launch fresh fixture recovery process", source))?;
    let recovery_pid = recovery.id();
    if let Err(error) = wait_for_successful_child(
        &mut recovery,
        harness.maximum_wait,
        "fixture recovery process",
    ) {
        return match force_terminate_and_reap(&mut recovery, "fixture recovery process") {
            Ok(_) => Err(error),
            Err(reconciliation) => Err(XtaskError::invalid(
                "fixture recovery process",
                format!("{error}; process reconciliation also failed: {reconciliation}"),
            )),
        };
    }
    if recovery_pid == writer_pid {
        return Err(XtaskError::invalid(
            format!("fixture recovery `{}`", case.fixture_id),
            "fresh recovery process reused the writer process identity",
        ));
    }
    let (reopened, recovery_digest) =
        read_recovery_result(&recovery_result, harness, recovery_pid)?;
    let predecessor_or_successor = reopened == case.predecessor || reopened == case.successor;
    if !predecessor_or_successor || reopened != case.expected_reopen {
        return Err(XtaskError::invalid(
            format!("state-transition fixture `{}`", case.fixture_id),
            format!(
                "restart observed `{reopened}`; expected exact predecessor-or-successor `{}`",
                case.expected_reopen
            ),
        ));
    }
    Ok(format!(
        "{}:{}:{}:seed={}:ack={}:writer=forcibly-terminated-and-reaped:writer-pid={writer_pid}:recovery-pid={recovery_pid}:recovery=fresh-process:recovery-digest={recovery_digest}",
        case.fixture_id,
        case.fault_schedule.as_str(),
        reopened,
        case.seed,
        harness.ready_protocol,
    ))
}

fn validate_schedule_mapping(case: &FixtureCase) -> Result<(), XtaskError> {
    let exact = matches!(
        (case.publication_point, case.fault_schedule),
        (
            PublicationPoint::BeforePublication,
            CrashSchedule::AfterCandidateSync
        ) | (
            PublicationPoint::AfterPublication,
            CrashSchedule::AfterPublicationSync
        ) | (
            PublicationPoint::PartialWriteBoundary,
            CrashSchedule::PartialWrite
        ) | (PublicationPoint::CrashBoundary, CrashSchedule::Crash)
            | (PublicationPoint::RestartBoundary, CrashSchedule::Restart)
            | (
                PublicationPoint::CorruptionBoundary,
                CrashSchedule::Corruption
            )
            | (PublicationPoint::FullDiskBoundary, CrashSchedule::FullDisk)
            | (PublicationPoint::ClockBoundary, CrashSchedule::Clock)
            | (
                PublicationPoint::CancellationBoundary,
                CrashSchedule::Cancellation
            )
            | (PublicationPoint::NetworkBoundary, CrashSchedule::Network)
            | (PublicationPoint::ProviderBoundary, CrashSchedule::Provider)
    );
    if !exact {
        return Err(XtaskError::invalid(
            format!("fixture `{}`", case.fixture_id),
            format!(
                "publication point `{}` does not own schedule `{}`",
                case.publication_point.as_str(),
                case.fault_schedule.as_str()
            ),
        ));
    }
    let expected = match case.publication_point {
        PublicationPoint::AfterPublication | PublicationPoint::RestartBoundary => &case.successor,
        PublicationPoint::BeforePublication
        | PublicationPoint::PartialWriteBoundary
        | PublicationPoint::CrashBoundary
        | PublicationPoint::CorruptionBoundary
        | PublicationPoint::FullDiskBoundary
        | PublicationPoint::ClockBoundary
        | PublicationPoint::CancellationBoundary
        | PublicationPoint::NetworkBoundary
        | PublicationPoint::ProviderBoundary => &case.predecessor,
    };
    if &case.expected_reopen != expected {
        return Err(XtaskError::invalid(
            format!("fixture `{}`", case.fixture_id),
            "expected reopen state does not match the registered publication-point oracle",
        ));
    }
    Ok(())
}

fn wait_for_ready_acknowledgement(
    writer: &mut std::process::Child,
    ready: &Path,
    harness: &HarnessInterface,
    publication_point: PublicationPoint,
    expected_pid: u32,
) -> Result<(), XtaskError> {
    let deadline = Instant::now() + harness.maximum_wait;
    loop {
        if ready.try_exists().map_err(|source| {
            XtaskError::io(
                format!("inspect fixture acknowledgement {}", ready.display()),
                source,
            )
        })? {
            let bytes = read_bounded_file(ready, MAXIMUM_PROCESS_RECORD_BYTES)?;
            let content = std::str::from_utf8(&bytes).map_err(|_| {
                XtaskError::invalid_path(ready, "fixture acknowledgement is not UTF-8")
            })?;
            let fields = content.trim_end().split('\t').collect::<Vec<_>>();
            let [protocol, pid, point] = fields.as_slice() else {
                return Err(XtaskError::invalid_path(
                    ready,
                    "fixture acknowledgement does not contain exactly three fields",
                ));
            };
            if *protocol != harness.ready_protocol || *point != publication_point.as_str() {
                return Err(XtaskError::invalid_path(
                    ready,
                    "fixture acknowledgement does not match the registered interface",
                ));
            }
            let pid = pid.parse::<u32>().map_err(|_| {
                XtaskError::invalid_path(ready, "fixture acknowledgement PID is invalid")
            })?;
            if pid != expected_pid {
                return Err(XtaskError::invalid_path(
                    ready,
                    "fixture acknowledgement PID does not match the owned writer",
                ));
            }
            return Ok(());
        }
        if let Some(status) = writer
            .try_wait()
            .map_err(|source| XtaskError::io("observe fixture writer process", source))?
        {
            return Err(XtaskError::invalid(
                "fixture writer process",
                format!(
                    "writer exited with {status} before the registered publication-point acknowledgement"
                ),
            ));
        }
        if Instant::now() >= deadline {
            return Err(XtaskError::invalid(
                "fixture writer process",
                "writer did not acknowledge its publication point before the registered deadline",
            ));
        }
        thread::sleep(Duration::from_millis(1));
    }
}

fn wait_for_successful_child(
    child: &mut std::process::Child,
    maximum_wait: Duration,
    label: &str,
) -> Result<(), XtaskError> {
    let deadline = Instant::now() + maximum_wait;
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|source| XtaskError::io(format!("observe {label}"), source))?
        {
            if status.success() {
                return Ok(());
            }
            return Err(XtaskError::invalid(
                label,
                format!("child returned abnormal status {status}"),
            ));
        }
        if Instant::now() >= deadline {
            return Err(XtaskError::invalid(
                label,
                "child did not complete before the registered deadline",
            ));
        }
        thread::sleep(Duration::from_millis(1));
    }
}

fn force_terminate_and_reap(
    child: &mut std::process::Child,
    label: &str,
) -> Result<ChildReconciliation, XtaskError> {
    if let Some(status) = child
        .try_wait()
        .map_err(|source| XtaskError::io(format!("observe {label} before termination"), source))?
    {
        return Ok(ChildReconciliation {
            status,
            kill_sent: false,
        });
    }
    let kill = child.kill();
    let status = child
        .wait()
        .map_err(|source| XtaskError::io(format!("reap {label}"), source))?;
    if let Err(source) = kill {
        return Err(XtaskError::invalid(
            format!("{label} termination"),
            format!("kill failed with `{source}`; child was still reaped with {status}"),
        ));
    }
    Ok(ChildReconciliation {
        status,
        kill_sent: true,
    })
}

fn read_recovery_result(
    path: &Path,
    harness: &HarnessInterface,
    expected_pid: u32,
) -> Result<(String, String), XtaskError> {
    let bytes = read_bounded_file(path, MAXIMUM_PROCESS_RECORD_BYTES)?;
    let content = std::str::from_utf8(&bytes)
        .map_err(|_| XtaskError::invalid_path(path, "recovery result is not UTF-8"))?;
    let fields = content.trim_end().split('\t').collect::<Vec<_>>();
    let [protocol, pid, state, digest] = fields.as_slice() else {
        return Err(XtaskError::invalid_path(
            path,
            "recovery result does not contain exactly four fields",
        ));
    };
    if *protocol != harness.recovery_protocol {
        return Err(XtaskError::invalid_path(
            path,
            "recovery result protocol is not registered",
        ));
    }
    let pid = pid
        .parse::<u32>()
        .map_err(|_| XtaskError::invalid_path(path, "recovery result PID is invalid"))?;
    if pid != expected_pid {
        return Err(XtaskError::invalid_path(
            path,
            "recovery result PID does not match the fresh child",
        ));
    }
    let expected_digest = recovered_state_digest(state);
    if *digest != expected_digest {
        return Err(XtaskError::invalid_path(
            path,
            "recovery result digest does not bind the observed durable state",
        ));
    }
    Ok(((*state).to_owned(), (*digest).to_owned()))
}

fn read_bounded_file(path: &Path, maximum_bytes: usize) -> Result<Vec<u8>, XtaskError> {
    let bytes = fs::read(path)
        .map_err(|source| XtaskError::io(format!("read {}", path.display()), source))?;
    if bytes.len() > maximum_bytes {
        return Err(XtaskError::invalid_path(
            path,
            format!("process record exceeds {maximum_bytes} bytes"),
        ));
    }
    Ok(bytes)
}

pub(crate) fn run_process(arguments: impl Iterator<Item = String>) -> Result<(), XtaskError> {
    let arguments = arguments.take(8).collect::<Vec<_>>();
    match arguments.as_slice() {
        [
            operation,
            owned_root,
            case_root,
            publication_point,
            fault_schedule,
            predecessor,
            successor,
        ] if operation == "writer" => run_writer_process(
            Path::new(owned_root),
            Path::new(case_root),
            PublicationPoint::parse(publication_point)?,
            CrashSchedule::parse(fault_schedule)?,
            predecessor,
            successor,
        ),
        [
            operation,
            owned_root,
            case_root,
            result_path,
            recovery_protocol,
        ] if operation == "recover" => run_recovery_process(
            Path::new(owned_root),
            Path::new(case_root),
            Path::new(result_path),
            recovery_protocol,
        ),
        _ => Err(XtaskError::usage(
            "quality-fixture requires an exact registered writer or recover invocation",
        )),
    }
}

fn run_writer_process(
    owned_root: &Path,
    case_root: &Path,
    publication_point: PublicationPoint,
    fault_schedule: CrashSchedule,
    predecessor: &str,
    successor: &str,
) -> Result<(), XtaskError> {
    validate_process_root(owned_root, case_root)?;
    validate_field(case_root, 0, "predecessor", predecessor)?;
    validate_field(case_root, 0, "successor", successor)?;
    let published = case_root.join("published.state");
    let candidate = case_root.join("candidate.state");
    write_state(&published, predecessor)?;
    sync_directory(case_root)?;
    match fault_schedule {
        CrashSchedule::PartialWrite => {
            write_fault_bytes(&candidate, b"partial-state")?;
        },
        CrashSchedule::FullDisk
        | CrashSchedule::Clock
        | CrashSchedule::Network
        | CrashSchedule::Provider => {
            let marker = case_root.join(format!("{}.fault", fault_schedule.as_str()));
            write_fault_bytes(&marker, fault_schedule.as_str().as_bytes())?;
        },
        CrashSchedule::AfterCandidateSync | CrashSchedule::Crash | CrashSchedule::Cancellation => {
            write_state(&candidate, successor)?;
        },
        CrashSchedule::Corruption => {
            write_state(&candidate, successor)?;
            corrupt_state_file(&candidate)?;
        },
        CrashSchedule::AfterPublicationSync | CrashSchedule::Restart => {
            write_state(&candidate, successor)?;
            fs::rename(&candidate, &published).map_err(|source| {
                XtaskError::io(
                    format!(
                        "publish state-transition fixture {} as {}",
                        candidate.display(),
                        published.display()
                    ),
                    source,
                )
            })?;
            sync_directory(case_root)?;
        },
    }
    let ready = case_root.join("writer.ready");
    let content = format!(
        "publication-point-ready-v1\t{}\t{}\n",
        std::process::id(),
        publication_point.as_str()
    );
    write_process_record(&ready, content.as_bytes())?;
    sync_directory(case_root)?;
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    Err(XtaskError::invalid(
        "fixture writer process",
        "parent did not forcibly terminate the acknowledged writer before its safety deadline",
    ))
}

fn run_recovery_process(
    owned_root: &Path,
    case_root: &Path,
    result_path: &Path,
    recovery_protocol: &str,
) -> Result<(), XtaskError> {
    validate_process_root(owned_root, case_root)?;
    if recovery_protocol != "recovery-v1" {
        return Err(XtaskError::invalid(
            "fixture recovery process",
            "recovery protocol is not registered",
        ));
    }
    if result_path.parent() != Some(case_root) {
        return Err(XtaskError::invalid_path(
            result_path,
            "recovery result must remain directly beneath the case root",
        ));
    }
    let state = read_state(&case_root.join("published.state"))?;
    let digest = recovered_state_digest(&state);
    let content = format!(
        "{recovery_protocol}\t{}\t{state}\t{digest}\n",
        std::process::id()
    );
    write_process_record(result_path, content.as_bytes())?;
    sync_directory(case_root)
}

fn validate_process_root(owned_root: &Path, case_root: &Path) -> Result<(), XtaskError> {
    if !owned_root.is_absolute() || !case_root.is_absolute() {
        return Err(XtaskError::invalid_path(
            case_root,
            "fixture process owned root and case root must be absolute",
        ));
    }
    let owned_metadata = fs::symlink_metadata(owned_root).map_err(|source| {
        XtaskError::io(
            format!("inspect fixture process root {}", owned_root.display()),
            source,
        )
    })?;
    if !owned_metadata.file_type().is_dir() {
        return Err(XtaskError::invalid_path(
            owned_root,
            "fixture process owned root is not a directory",
        ));
    }
    let canonical_owned_root = fs::canonicalize(owned_root).map_err(|source| {
        XtaskError::io(
            format!("canonicalize fixture process root {}", owned_root.display()),
            source,
        )
    })?;
    if canonical_owned_root != owned_root || case_root.parent() != Some(owned_root) {
        return Err(XtaskError::invalid_path(
            case_root,
            "fixture process case root is not a direct child of the exact owned root",
        ));
    }
    let case_metadata = fs::symlink_metadata(case_root).map_err(|source| {
        XtaskError::io(
            format!("inspect fixture process case {}", case_root.display()),
            source,
        )
    })?;
    if !case_metadata.file_type().is_dir() {
        return Err(XtaskError::invalid_path(
            case_root,
            "fixture process case root is not a directory",
        ));
    }
    let canonical = fs::canonicalize(case_root).map_err(|source| {
        XtaskError::io(
            format!("canonicalize fixture case root {}", case_root.display()),
            source,
        )
    })?;
    if canonical != case_root || !canonical.is_dir() || !canonical.starts_with(owned_root) {
        return Err(XtaskError::invalid_path(
            case_root,
            "fixture process case root must be a canonical directory",
        ));
    }
    Ok(())
}

fn write_process_record(path: &Path, bytes: &[u8]) -> Result<(), XtaskError> {
    if bytes.len() > MAXIMUM_PROCESS_RECORD_BYTES {
        return Err(XtaskError::invalid_path(
            path,
            format!("process record exceeds {MAXIMUM_PROCESS_RECORD_BYTES} bytes"),
        ));
    }
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|source| XtaskError::io(format!("create {}", path.display()), source))?;
    file.write_all(bytes)
        .and_then(|()| file.flush())
        .and_then(|()| file.sync_all())
        .map_err(|source| XtaskError::io(format!("persist {}", path.display()), source))
}

fn write_fault_bytes(path: &Path, bytes: &[u8]) -> Result<(), XtaskError> {
    write_process_record(path, bytes)?;
    let parent = path
        .parent()
        .ok_or_else(|| XtaskError::invalid_path(path, "fault artifact has no parent"))?;
    sync_directory(parent)
}

fn corrupt_state_file(path: &Path) -> Result<(), XtaskError> {
    let mut bytes = read_bounded_file(path, MAXIMUM_STATE_BYTES)?;
    let byte = bytes
        .first_mut()
        .ok_or_else(|| XtaskError::invalid_path(path, "state candidate is unexpectedly empty"))?;
    *byte = if *byte == b'x' { b'y' } else { b'x' };
    let mut file = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .map_err(|source| XtaskError::io(format!("open {}", path.display()), source))?;
    file.write_all(&bytes)
        .and_then(|()| file.flush())
        .and_then(|()| file.sync_all())
        .map_err(|source| XtaskError::io(format!("corrupt {}", path.display()), source))
}

fn write_state(path: &Path, state: &str) -> Result<(), XtaskError> {
    let catalog = format!("catalog-{state}");
    let audit = format!("audit-{state}");
    let digest = state_digest(state, &catalog, &audit);
    let content = format!("{state}\n{catalog}\n{audit}\n{digest}\n");
    if content.len() > MAXIMUM_STATE_BYTES {
        return Err(XtaskError::invalid_path(
            path,
            format!("fixture state exceeds {MAXIMUM_STATE_BYTES} bytes"),
        ));
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| XtaskError::io(format!("create {}", path.display()), source))?;
    file.write_all(content.as_bytes())
        .and_then(|()| file.flush())
        .and_then(|()| file.sync_all())
        .map_err(|source| XtaskError::io(format!("persist {}", path.display()), source))
}

fn read_state(path: &Path) -> Result<String, XtaskError> {
    let bytes = fs::read(path)
        .map_err(|source| XtaskError::io(format!("reopen {}", path.display()), source))?;
    if bytes.len() > MAXIMUM_STATE_BYTES {
        return Err(XtaskError::invalid_path(
            path,
            format!("reopened fixture state exceeds {MAXIMUM_STATE_BYTES} bytes"),
        ));
    }
    let content = std::str::from_utf8(&bytes)
        .map_err(|_| XtaskError::invalid_path(path, "reopened fixture state is not UTF-8"))?;
    let fields = content.lines().collect::<Vec<_>>();
    let [state, catalog, audit, digest] = fields.as_slice() else {
        return Err(XtaskError::invalid_path(
            path,
            "reopened fixture state does not contain exactly four fields",
        ));
    };
    if *catalog != format!("catalog-{state}")
        || *audit != format!("audit-{state}")
        || *digest != state_digest(state, catalog, audit)
    {
        return Err(XtaskError::invalid_path(
            path,
            "reopened fixture state is mixed or corrupted",
        ));
    }
    Ok((*state).to_owned())
}

fn state_digest(state: &str, catalog: &str, audit: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"positron-quality-state-fixture-v1\0");
    hasher.update(state.as_bytes());
    hasher.update(b"\0");
    hasher.update(catalog.as_bytes());
    hasher.update(b"\0");
    hasher.update(audit.as_bytes());
    format!("sha256:{:x}", hasher.finalize())
}

fn recovered_state_digest(state: &str) -> String {
    let catalog = format!("catalog-{state}");
    let audit = format!("audit-{state}");
    let state_digest = state_digest(state, &catalog, &audit);
    let bytes = format!("{state}\n{catalog}\n{audit}\n{state_digest}\n");
    let mut hasher = Sha256::new();
    hasher.update(b"positron-quality-recovered-state-v1\0");
    hasher.update(bytes.as_bytes());
    format!("sha256:{:x}", hasher.finalize())
}

impl OwnedFixtureRoot {
    fn create(temporary_root: &Path, name: &str) -> Result<Self, XtaskError> {
        validate_owned_directory(temporary_root, temporary_root, "attempt temporary root")?;
        validate_field(temporary_root, 0, "fixture_root_name", name)?;
        let path = temporary_root.join(format!("qualification-fixtures-{name}"));
        match fs::create_dir(&path) {
            Ok(()) => {
                sync_directory(&path)?;
                sync_directory(temporary_root)?;
            },
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
                let metadata = fs::symlink_metadata(&path).map_err(|inspect| {
                    XtaskError::io(
                        format!("inspect occupied fixture root {}", path.display()),
                        inspect,
                    )
                })?;
                if !metadata.file_type().is_dir() {
                    return Err(XtaskError::invalid_path(
                        &path,
                        "owned fixture directory component is not a directory",
                    ));
                }
                return Err(XtaskError::invalid_path(
                    &path,
                    "owned fixture directory is already occupied",
                ));
            },
            Err(source) => {
                return Err(XtaskError::io(
                    format!("create owned fixture root {}", path.display()),
                    source,
                ));
            },
        }
        validate_owned_directory(temporary_root, &path, "owned fixture root")?;
        Ok(Self { path, active: true })
    }

    fn create_case(&self, fixture_id: &str) -> Result<PathBuf, XtaskError> {
        validate_owned_directory(
            self.path.parent().ok_or_else(|| {
                XtaskError::invalid_path(&self.path, "owned fixture root has no parent")
            })?,
            &self.path,
            "owned fixture root",
        )?;
        validate_field(&self.path, 0, "fixture_id", fixture_id)?;
        let case = self.path.join(fixture_id);
        fs::create_dir(&case).map_err(|source| {
            XtaskError::io(
                format!("create owned fixture case {}", case.display()),
                source,
            )
        })?;
        sync_directory(&case)?;
        sync_directory(&self.path)?;
        validate_owned_directory(&self.path, &case, "owned fixture case")?;
        Ok(case)
    }

    fn finish<T>(mut self, outcome: Result<T, XtaskError>) -> Result<T, XtaskError> {
        let cleanup = self.cleanup();
        match (outcome, cleanup) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(cleanup_error)) => Err(cleanup_error),
            (Err(error), Err(cleanup_error)) => Err(XtaskError::invalid(
                "qualification fixture cleanup",
                format!("{error}; cleanup also failed: {cleanup_error}"),
            )),
        }
    }

    fn cleanup(&mut self) -> Result<(), XtaskError> {
        if !self.active {
            return Ok(());
        }
        let parent = self.path.parent().ok_or_else(|| {
            XtaskError::invalid_path(&self.path, "owned fixture root has no parent")
        })?;
        validate_owned_directory(parent, &self.path, "owned fixture root during cleanup")?;
        fs::remove_dir_all(&self.path).map_err(|source| {
            XtaskError::io(
                format!("remove owned fixture tree {}", self.path.display()),
                source,
            )
        })?;
        sync_directory(parent).map_err(|error| {
            XtaskError::invalid(
                "qualification fixture cleanup",
                format!(
                    "removed {} but could not synchronize its parent: {error}",
                    self.path.display()
                ),
            )
        })?;
        self.active = false;
        Ok(())
    }
}

impl Drop for OwnedFixtureRoot {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            eprintln!("qualification fixture RAII cleanup failed: {error}");
        }
    }
}

fn validate_owned_directory(root: &Path, path: &Path, label: &str) -> Result<(), XtaskError> {
    if !path.starts_with(root) {
        return Err(XtaskError::invalid_path(
            path,
            format!("{label} escaped its owned root"),
        ));
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| XtaskError::io(format!("inspect {label} {}", path.display()), source))?;
    if !metadata.file_type().is_dir() {
        return Err(XtaskError::invalid_path(
            path,
            "owned fixture directory component is not a directory",
        ));
    }
    let canonical = fs::canonicalize(path)
        .map_err(|source| XtaskError::io(format!("canonicalize {label}"), source))?;
    if canonical != path || !canonical.starts_with(root) {
        return Err(XtaskError::invalid_path(
            path,
            format!("{label} changed identity or escaped its owned root"),
        ));
    }
    Ok(())
}

fn validate_field(path: &Path, line: usize, field: &str, value: &str) -> Result<(), XtaskError> {
    let valid = !value.is_empty()
        && value.len() <= MAXIMUM_FIELD_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-'));
    if valid {
        return Ok(());
    }
    Err(XtaskError::invalid_path(
        path,
        format!(
            "fixture row {line} field `{field}` must be 1..={MAXIMUM_FIELD_BYTES} ASCII alphanumeric or hyphen bytes"
        ),
    ))
}

fn sync_directory(path: &Path) -> Result<(), XtaskError> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| {
            XtaskError::io(
                format!("synchronize fixture directory {}", path.display()),
                source,
            )
        })
}
