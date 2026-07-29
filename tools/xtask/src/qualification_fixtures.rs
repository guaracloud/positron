use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::error::XtaskError;

const REGISTRY_PATH: &str = "qualification/engineering/quality-fixtures.tsv";
const INTEGRITY_REGISTRY_PATH: &str = "qualification/engineering/integrity-fixtures.tsv";
const REGISTRY_HEADER: &str = "fixture_id\tgate_id\tpublication_point\tfault_schedule\tseed\tpredecessor\tsuccessor\texpected_reopen";
const INTEGRITY_REGISTRY_HEADER: &str = "fixture_id\tmutation\tseed\texpected_reopen";
const MAXIMUM_REGISTRY_BYTES: usize = 16_384;
const MAXIMUM_IDENTITY_REGISTRY_BYTES: usize = 65_536;
const MAXIMUM_FIXTURES: usize = 32;
const MAXIMUM_FIELD_BYTES: usize = 96;
const MAXIMUM_STATE_BYTES: usize = 1_024;
const MAXIMUM_INTEGRITY_OBJECT_BYTES: usize = 8_192;
const CORRECTNESS_GATE: &str = "EG-CORRECT";
const FAULT_GATE: &str = "EG-FAULT";

const CORRECTNESS_PUBLICATION_POINTS: [PublicationPoint; 2] = [
    PublicationPoint::BeforePublication,
    PublicationPoint::AfterPublication,
];
const FAULT_PUBLICATION_POINTS: [PublicationPoint; 2] = [
    PublicationPoint::BeforePublication,
    PublicationPoint::AfterPublication,
];

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum PublicationPoint {
    BeforePublication,
    AfterPublication,
}

impl PublicationPoint {
    fn parse(value: &str) -> Result<Self, XtaskError> {
        match value {
            "before-publication" => Ok(Self::BeforePublication),
            "after-publication" => Ok(Self::AfterPublication),
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
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CrashSchedule {
    AfterCandidateSync,
    AfterPublicationSync,
}

impl CrashSchedule {
    fn parse(value: &str) -> Result<Self, XtaskError> {
        match value {
            "crash-after-candidate-sync" => Ok(Self::AfterCandidateSync),
            "crash-after-publication-sync" => Ok(Self::AfterPublicationSync),
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
    fn load(root: &Path) -> Result<Self, XtaskError> {
        let path = root.join(REGISTRY_PATH);
        let bytes = fs::read(&path)
            .map_err(|source| XtaskError::io(format!("read {}", path.display()), source))?;
        if bytes.len() > MAXIMUM_REGISTRY_BYTES {
            return Err(XtaskError::invalid_path(
                &path,
                format!("fixture registry exceeds {MAXIMUM_REGISTRY_BYTES} bytes"),
            ));
        }
        let content = std::str::from_utf8(&bytes)
            .map_err(|_| XtaskError::invalid_path(&path, "fixture registry is not UTF-8"))?;
        let mut lines = content.lines();
        if lines.next() != Some(REGISTRY_HEADER) {
            return Err(XtaskError::invalid_path(
                &path,
                "fixture registry header is not exact",
            ));
        }
        let mut cases = Vec::new();
        let mut fixture_ids = BTreeSet::new();
        for (offset, line) in lines.enumerate() {
            if cases.len() >= MAXIMUM_FIXTURES {
                return Err(XtaskError::invalid_path(
                    &path,
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
                    &path,
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
                validate_field(&path, offset + 2, field_name, value)?;
            }
            if !fixture_ids.insert((*fixture_id).to_owned()) {
                return Err(XtaskError::invalid_path(
                    &path,
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
                &path,
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
    fn load(root: &Path) -> Result<Self, XtaskError> {
        let path = root.join(INTEGRITY_REGISTRY_PATH);
        let bytes = fs::read(&path)
            .map_err(|source| XtaskError::io(format!("read {}", path.display()), source))?;
        if bytes.len() > MAXIMUM_REGISTRY_BYTES {
            return Err(XtaskError::invalid_path(
                &path,
                format!("integrity fixture registry exceeds {MAXIMUM_REGISTRY_BYTES} bytes"),
            ));
        }
        let content = std::str::from_utf8(&bytes).map_err(|_| {
            XtaskError::invalid_path(&path, "integrity fixture registry is not UTF-8")
        })?;
        let mut lines = content.lines();
        if lines.next() != Some(INTEGRITY_REGISTRY_HEADER) {
            return Err(XtaskError::invalid_path(
                &path,
                "integrity fixture registry header is not exact",
            ));
        }
        let mut cases = Vec::new();
        let mut fixture_ids = BTreeSet::new();
        let mut mutations = BTreeSet::new();
        for (offset, line) in lines.enumerate() {
            if cases.len() >= MAXIMUM_FIXTURES {
                return Err(XtaskError::invalid_path(
                    &path,
                    format!("integrity fixture registry exceeds {MAXIMUM_FIXTURES} rows"),
                ));
            }
            let fields = line.split('\t').collect::<Vec<_>>();
            let [fixture_id, mutation, seed, expected_reopen] = fields.as_slice() else {
                return Err(XtaskError::invalid_path(
                    &path,
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
                validate_field(&path, offset + 2, field_name, value)?;
            }
            let mutation = IntegrityMutation::parse(mutation)?;
            if !fixture_ids.insert((*fixture_id).to_owned()) {
                return Err(XtaskError::invalid_path(
                    &path,
                    format!("integrity fixture id `{fixture_id}` is duplicated"),
                ));
            }
            if !mutations.insert(mutation.as_str()) {
                return Err(XtaskError::invalid_path(
                    &path,
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

pub(crate) fn run_correctness(root: &Path, temporary_root: &Path) -> Result<String, XtaskError> {
    let registry = FixtureRegistry::load(root)?;
    let cases = registry.cases_for(CORRECTNESS_GATE);
    validate_exact_publication_points(CORRECTNESS_GATE, &cases, &CORRECTNESS_PUBLICATION_POINTS)?;
    let fixture_root = create_fixture_root(temporary_root, "correctness")?;
    let mut outcomes = Vec::with_capacity(cases.len());
    for case in cases {
        outcomes.push(execute_state_transition(&fixture_root, case)?);
    }
    Ok(format!(
        "quality-engineering-fixtures={}; {}",
        REGISTRY_PATH,
        outcomes.join(",")
    ))
}

pub(crate) fn run_fault(root: &Path, temporary_root: &Path) -> Result<String, XtaskError> {
    let registry = FixtureRegistry::load(root)?;
    let cases = registry.cases_for(FAULT_GATE);
    validate_exact_publication_points(FAULT_GATE, &cases, &FAULT_PUBLICATION_POINTS)?;
    let fixture_root = create_fixture_root(temporary_root, "fault")?;
    let publication_point_count = cases.len();
    let mut outcomes = Vec::with_capacity(cases.len());
    for case in cases {
        outcomes.push(execute_state_transition(&fixture_root, case)?);
    }
    Ok(format!(
        "quality-engineering-fixtures={}; one-to-one-publication-points={}; {}",
        REGISTRY_PATH,
        publication_point_count,
        outcomes.join(",")
    ))
}

pub(crate) fn run_integrity(
    root: &Path,
    temporary_root: &Path,
    identity: &IntegrityIdentity,
) -> Result<String, XtaskError> {
    let registry = IntegrityRegistry::load(root)?;
    let fixture_root = create_fixture_root(temporary_root, "integrity")?;
    let mut outcomes = Vec::with_capacity(registry.cases.len());
    for case in &registry.cases {
        outcomes.push(execute_integrity_case(&fixture_root, case, identity)?);
    }
    Ok(format!(
        "quality-engineering-fixtures={}; identity=revision+artifact+target+environment+command+fixtures+seed+schedule+result; {}",
        INTEGRITY_REGISTRY_PATH,
        outcomes.join(",")
    ))
}

pub(crate) fn seed_and_schedule_digests(root: &Path) -> Result<(String, String), XtaskError> {
    let quality = read_identity_registry(root, REGISTRY_PATH)?;
    let integrity = read_identity_registry(root, INTEGRITY_REGISTRY_PATH)?;
    let mut seed_hasher = Sha256::new();
    seed_hasher.update(b"positron-quality-fixture-seeds-v1\0");
    seed_hasher.update(&quality);
    seed_hasher.update(b"\0");
    seed_hasher.update(&integrity);
    let mut schedule_hasher = Sha256::new();
    schedule_hasher.update(b"positron-quality-fault-schedules-v1\0");
    schedule_hasher.update(&quality);
    schedule_hasher.update(b"\0");
    schedule_hasher.update(&integrity);
    Ok((
        format!("sha256:{:x}", seed_hasher.finalize()),
        format!("sha256:{:x}", schedule_hasher.finalize()),
    ))
}

fn read_identity_registry(root: &Path, relative: &str) -> Result<Vec<u8>, XtaskError> {
    let path = root.join(relative);
    let bytes = fs::read(&path)
        .map_err(|source| XtaskError::io(format!("read {}", path.display()), source))?;
    if bytes.len() > MAXIMUM_IDENTITY_REGISTRY_BYTES {
        return Err(XtaskError::invalid_path(
            &path,
            format!("fixture identity input exceeds {MAXIMUM_IDENTITY_REGISTRY_BYTES} bytes"),
        ));
    }
    Ok(bytes)
}

fn execute_integrity_case(
    fixture_root: &Path,
    case: &IntegrityCase,
    identity: &IntegrityIdentity,
) -> Result<String, XtaskError> {
    let case_root = fixture_root.join(&case.fixture_id);
    fs::create_dir(&case_root).map_err(|source| {
        XtaskError::io(
            format!("create integrity fixture {}", case_root.display()),
            source,
        )
    })?;
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

fn execute_state_transition(fixture_root: &Path, case: &FixtureCase) -> Result<String, XtaskError> {
    validate_schedule_mapping(case)?;
    let case_root = fixture_root.join(&case.fixture_id);
    fs::create_dir(&case_root).map_err(|source| {
        XtaskError::io(
            format!("create state-transition fixture {}", case_root.display()),
            source,
        )
    })?;
    let published = case_root.join("published.state");
    let candidate = case_root.join("candidate.state");
    write_state(&published, &case.predecessor)?;
    sync_directory(&case_root)?;
    write_state(&candidate, &case.successor)?;
    match case.fault_schedule {
        CrashSchedule::AfterCandidateSync => {},
        CrashSchedule::AfterPublicationSync => {
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
            sync_directory(&case_root)?;
        },
    }
    let reopened = read_state(&published)?;
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
        "{}:{}:{}:seed={}",
        case.fixture_id,
        case.fault_schedule.as_str(),
        reopened,
        case.seed
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
        )
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
        PublicationPoint::BeforePublication => &case.predecessor,
        PublicationPoint::AfterPublication => &case.successor,
    };
    if &case.expected_reopen != expected {
        return Err(XtaskError::invalid(
            format!("fixture `{}`", case.fixture_id),
            "expected reopen state does not match the registered publication-point oracle",
        ));
    }
    Ok(())
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

fn create_fixture_root(temporary_root: &Path, name: &str) -> Result<PathBuf, XtaskError> {
    let root = temporary_root.join("qualification-fixtures").join(name);
    let parent = root.parent().ok_or_else(|| {
        XtaskError::invalid_path(&root, "qualification fixture root has no parent")
    })?;
    fs::create_dir_all(parent).map_err(|source| {
        XtaskError::io(
            format!("create qualification fixture parent {}", parent.display()),
            source,
        )
    })?;
    fs::create_dir(&root).map_err(|source| {
        XtaskError::io(
            format!("create qualification fixture root {}", root.display()),
            source,
        )
    })?;
    Ok(root)
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
