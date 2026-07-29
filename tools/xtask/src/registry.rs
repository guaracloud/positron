use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::XtaskError;

const ENGINEERING: &str = "qualification/engineering";
const SCAFFOLD_MARKER: &str = "//! @positron-scaffold-only";

#[derive(Clone, Debug)]
pub(crate) struct Gate {
    pub(crate) id: String,
    pub(crate) stages: BTreeSet<String>,
    pub(crate) coordinator: String,
    pub(crate) timeout_seconds: u64,
    pub(crate) memory_mib: u64,
    pub(crate) exception_class: String,
    pub(crate) activation: String,
    pub(crate) runner: String,
}

#[derive(Clone, Debug)]
pub(crate) struct Scope {
    pub(crate) package: String,
    pub(crate) path: PathBuf,
    pub(crate) semantic_owner: String,
    pub(crate) kind: String,
    pub(crate) state: String,
    activation_id: String,
    activation_scope_set: BTreeSet<String>,
    allowed_edges: BTreeSet<(String, String)>,
    pub(crate) risk_gates: BTreeSet<String>,
    pub(crate) test_commands: String,
    coverage_baseline: BTreeSet<String>,
    mutation_baseline: String,
    dependency_review: String,
    contract_evidence: String,
}

#[derive(Clone, Debug)]
struct ArchitectureEdge {
    caller: String,
    dependency: String,
    activation_id: String,
}

#[derive(Clone, Debug)]
struct Threshold {
    state: String,
    value: String,
    evidence: String,
}

#[derive(Clone, Debug)]
pub(crate) struct Tool {
    pub(crate) id: String,
    pub(crate) version: String,
    pub(crate) command: String,
    pub(crate) version_arguments: Vec<String>,
    pub(crate) required_profiles: BTreeSet<String>,
}

#[derive(Clone, Debug)]
struct ArtifactScope {
    path: PathBuf,
    state: String,
    allowed_scaffold_files: BTreeSet<String>,
    risk_gates: BTreeSet<String>,
}

#[derive(Debug)]
pub(crate) struct Registry {
    pub(crate) gates: Vec<Gate>,
    pub(crate) scopes: Vec<Scope>,
    pub(crate) tools: Vec<Tool>,
    artifact_scopes: Vec<ArtifactScope>,
    allowed_edges: BTreeSet<(String, String)>,
    thresholds: BTreeMap<String, Threshold>,
    reviewed_dependencies: BTreeSet<String>,
    registry_files: Vec<PathBuf>,
}

#[derive(Debug)]
struct Table {
    rows: Vec<Row>,
}

#[derive(Debug)]
struct Row {
    path: PathBuf,
    line: usize,
    fields: BTreeMap<String, String>,
}

impl Row {
    fn field(&self, name: &str) -> Result<&str, XtaskError> {
        self.fields.get(name).map(String::as_str).ok_or_else(|| {
            XtaskError::invalid_path(
                &self.path,
                format!("line {} is missing field `{name}`", self.line),
            )
        })
    }
}

impl Registry {
    pub(crate) fn load(root: &Path) -> Result<Self, XtaskError> {
        let owners_table = read_table(
            root,
            "owners.tsv",
            &["role", "codeowner", "required_independent_approval"],
        )?;
        let owners = parse_owners(&owners_table)?;

        let gates_table = read_table(
            root,
            "gates.tsv",
            &[
                "gate_id",
                "stages",
                "coordinator",
                "timeout_seconds",
                "memory_mib",
                "exception_class",
                "activation",
                "runner",
            ],
        )?;
        let gates = parse_gates(&gates_table, &owners)?;
        let gate_ids = gates
            .iter()
            .map(|gate| gate.id.clone())
            .collect::<BTreeSet<_>>();

        let invariant_gates = validate_invariants(root, &owners, &gate_ids)?;

        let scopes_table = read_table(
            root,
            "scopes.tsv",
            &[
                "package",
                "path",
                "semantic_owner",
                "kind",
                "state",
                "activation_id",
                "activation_scope_set",
                "allowed_edges",
                "risk_gates",
                "test_commands",
                "coverage_baseline",
                "mutation_baseline",
                "dependency_review",
                "contract_evidence",
            ],
        )?;
        let scopes = parse_scopes(root, &scopes_table, &owners, &gate_ids)?;
        let artifact_scopes = parse_artifact_scopes(root, &owners, &gate_ids)?;

        let edges_table = read_table(
            root,
            "architecture-edges.tsv",
            &["caller", "dependency", "activation_id"],
        )?;
        let edges = parse_edges(&edges_table, &scopes)?;
        let allowed_edges = edges
            .iter()
            .map(|edge| (edge.caller.clone(), edge.dependency.clone()))
            .collect::<BTreeSet<_>>();

        let tools_table = read_table(
            root,
            "toolchains.tsv",
            &[
                "tool_id",
                "version",
                "command",
                "version_arguments",
                "required_profiles",
            ],
        )?;
        let tools = parse_tools(&tools_table)?;

        let thresholds = validate_thresholds(root, &scopes)?;
        let reviewed_dependencies = validate_dependencies(root)?;
        validate_activation_ledgers(root, &scopes, &edges, &thresholds, &reviewed_dependencies)?;
        validate_empty_or_owned_registries(root, &owners)?;
        validate_exceptions(root, &owners, &gates, &invariant_gates)?;
        validate_policy_seed(root)?;
        validate_target_registry(root)?;
        validate_documented_gate_set(root, &gate_ids)?;
        validate_workspace_members(root, &scopes)?;
        validate_scaffold_sources(root, &scopes)?;
        validate_active_sources(root, &scopes)?;
        validate_artifact_scaffolds(root, &artifact_scopes)?;
        validate_no_unregistered_code(root, &scopes, &artifact_scopes)?;
        validate_acyclic_edges(&allowed_edges)?;

        let registry_files = registry_files(root)?;

        Ok(Self {
            gates,
            scopes,
            tools,
            artifact_scopes,
            allowed_edges,
            thresholds,
            reviewed_dependencies,
            registry_files,
        })
    }

    pub(crate) fn allowed_edges(&self) -> &BTreeSet<(String, String)> {
        &self.allowed_edges
    }

    pub(crate) fn reviewed_dependencies(&self) -> &BTreeSet<String> {
        &self.reviewed_dependencies
    }

    pub(crate) fn measured_baseline(&self, identity: &str) -> Result<f64, XtaskError> {
        let Some(threshold) = self.thresholds.get(identity) else {
            return Err(XtaskError::invalid(
                "threshold registry",
                format!("coverage runner references unknown baseline `{identity}`"),
            ));
        };
        if threshold.state != "measured-baseline" {
            return Err(XtaskError::invalid(
                "threshold registry",
                format!("coverage runner baseline `{identity}` is not measured"),
            ));
        }
        threshold.value.parse::<f64>().map_err(|source| {
            XtaskError::invalid(
                "threshold registry",
                format!("coverage runner baseline `{identity}` is not numeric: {source}"),
            )
        })
    }

    pub(crate) fn registry_files(&self) -> &[PathBuf] {
        &self.registry_files
    }

    pub(crate) fn has_active_application_scope(&self) -> bool {
        self.scopes
            .iter()
            .any(|scope| scope.kind == "application" && scope.state == "active")
    }

    pub(crate) fn has_m0_01_foundational_scope(&self) -> bool {
        self.scopes.iter().any(|scope| {
            scope.kind == "application" && scope.state == "active" && scope.activation_id == "M0-01"
        })
    }

    pub(crate) fn has_m0_02_domain_types_scope(&self) -> bool {
        self.scopes.iter().any(|scope| {
            scope.package == "positron-domain"
                && scope.kind == "application"
                && scope.state == "active"
                && scope.activation_id == "M0-02"
        })
    }

    pub(crate) fn has_m0_03_canonical_api_scope(&self) -> bool {
        self.scopes.iter().any(|scope| {
            scope.package == "positron-api"
                && scope.kind == "application"
                && scope.state == "active"
                && scope.activation_id == "M0-03"
        })
    }

    pub(crate) fn has_m0_04_configuration_scope(&self) -> bool {
        self.scopes.iter().any(|scope| {
            scope.package == "positron-config"
                && scope.kind == "application"
                && scope.state == "active"
                && scope.activation_id == "M0-04"
        })
    }

    pub(crate) fn activated_risk_gates(&self) -> BTreeSet<String> {
        let mut activated = self
            .scopes
            .iter()
            .filter(|scope| scope.kind == "application" && scope.state == "active")
            .flat_map(|scope| scope.risk_gates.iter().cloned())
            .collect::<BTreeSet<_>>();
        activated.extend(
            self.artifact_scopes
                .iter()
                .filter(|scope| scope.state == "active")
                .flat_map(|scope| scope.risk_gates.iter().cloned()),
        );
        activated
    }
}

fn read_table(root: &Path, name: &str, expected_headers: &[&str]) -> Result<Table, XtaskError> {
    let path = root.join(ENGINEERING).join(name);
    let content = fs::read_to_string(&path)
        .map_err(|source| XtaskError::io(format!("read {}", path.display()), source))?;
    parse_table(&path, &content, expected_headers)
}

fn parse_table(path: &Path, content: &str, expected_headers: &[&str]) -> Result<Table, XtaskError> {
    let mut meaningful = content
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty() && !line.trim_start().starts_with('#'));

    let Some((header_index, header_line)) = meaningful.next() else {
        return Err(XtaskError::invalid_path(path, "registry is empty"));
    };
    let headers = header_line.split('\t').collect::<Vec<_>>();
    let expected = expected_headers.to_vec();
    if headers != expected {
        return Err(XtaskError::invalid_path(
            path,
            format!(
                "line {} headers are `{}`, expected `{}`",
                header_index + 1,
                headers.join(", "),
                expected.join(", ")
            ),
        ));
    }

    let mut rows = Vec::new();
    for (line_index, line) in meaningful {
        let values = line.split('\t').collect::<Vec<_>>();
        if values.len() != headers.len() {
            return Err(XtaskError::invalid_path(
                path,
                format!(
                    "line {} has {} fields, expected {}",
                    line_index + 1,
                    values.len(),
                    headers.len()
                ),
            ));
        }

        let fields = headers
            .iter()
            .zip(values)
            .map(|(header, value)| ((*header).to_owned(), value.to_owned()))
            .collect();
        rows.push(Row {
            path: path.to_path_buf(),
            line: line_index + 1,
            fields,
        });
    }

    Ok(Table { rows })
}

fn parse_owners(table: &Table) -> Result<BTreeSet<String>, XtaskError> {
    let mut owners = BTreeSet::new();
    for row in &table.rows {
        let role = nonempty(row, "role")?;
        let codeowner = nonempty(row, "codeowner")?;
        if !codeowner.starts_with('@') {
            return Err(row_error(row, "codeowner must begin with `@`"));
        }
        if row.field("required_independent_approval")? != "true" {
            return Err(row_error(
                row,
                "every bootstrap owner must require independent approval",
            ));
        }
        if !owners.insert(role.to_owned()) {
            return Err(row_error(row, format!("duplicate owner role `{role}`")));
        }
    }
    if owners.is_empty() {
        return Err(XtaskError::invalid(
            "owner registry",
            "at least one functional owner is required",
        ));
    }
    Ok(owners)
}

fn parse_gates(table: &Table, owners: &BTreeSet<String>) -> Result<Vec<Gate>, XtaskError> {
    let mut seen = BTreeSet::new();
    let mut gates = Vec::new();
    for row in &table.rows {
        let id = nonempty(row, "gate_id")?.to_owned();
        if !valid_gate_id(&id) {
            return Err(row_error(row, format!("invalid gate identity `{id}`")));
        }
        if !seen.insert(id.clone()) {
            return Err(row_error(row, format!("duplicate gate `{id}`")));
        }

        let coordinator = nonempty(row, "coordinator")?.to_owned();
        if !owners.contains(&coordinator) {
            return Err(row_error(
                row,
                format!("unknown coordinator `{coordinator}`"),
            ));
        }

        let stages = split_set(nonempty(row, "stages")?);
        if stages.is_empty()
            || stages
                .iter()
                .any(|stage| !matches!(stage.as_str(), "PR" | "EXT" | "QUAL"))
        {
            return Err(row_error(row, "stages must contain only PR, EXT, or QUAL"));
        }

        let timeout_seconds = parse_positive_u64(row, "timeout_seconds")?;
        let memory_mib = parse_positive_u64(row, "memory_mib")?;
        let exception_class = nonempty(row, "exception_class")?.to_owned();
        if !matches!(exception_class.as_str(), "temporary" | "non-waivable") {
            return Err(row_error(
                row,
                "exception_class must be `temporary` or `non-waivable`",
            ));
        }
        let activation = nonempty(row, "activation")?.to_owned();
        if !matches!(activation.as_str(), "always" | "risk") {
            return Err(row_error(row, "activation must be `always` or `risk`"));
        }
        let runner = nonempty(row, "runner")?.to_owned();

        gates.push(Gate {
            id,
            stages,
            coordinator,
            timeout_seconds,
            memory_mib,
            exception_class,
            activation,
            runner,
        });
    }

    if gates.len() != 25 {
        return Err(XtaskError::invalid(
            "gate registry",
            format!("contains {} gates, expected 25", gates.len()),
        ));
    }
    Ok(gates)
}

fn validate_invariants(
    root: &Path,
    owners: &BTreeSet<String>,
    gate_ids: &BTreeSet<String>,
) -> Result<BTreeMap<String, String>, XtaskError> {
    let table = read_table(
        root,
        "invariants.tsv",
        &["invariant_id", "gate_id", "accountable_owner"],
    )?;
    let mut mapped = BTreeSet::new();
    let mut invariant_gates = BTreeMap::new();
    for row in &table.rows {
        let invariant = nonempty(row, "invariant_id")?;
        if !valid_invariant_id(invariant) {
            return Err(row_error(
                row,
                format!("invalid invariant identity `{invariant}`"),
            ));
        }
        if !mapped.insert(invariant.to_owned()) {
            return Err(row_error(
                row,
                format!("invariant `{invariant}` is mapped more than once"),
            ));
        }
        let gate = nonempty(row, "gate_id")?;
        if !gate_ids.contains(gate) {
            return Err(row_error(row, format!("unknown gate `{gate}`")));
        }
        invariant_gates.insert(invariant.to_owned(), gate.to_owned());
        let owner = nonempty(row, "accountable_owner")?;
        if !owners.contains(owner) {
            return Err(row_error(row, format!("unknown owner `{owner}`")));
        }
    }

    let standards_path = root.join("docs/engineering/standards.md");
    let standards = fs::read_to_string(&standards_path)
        .map_err(|source| XtaskError::io(format!("read {}", standards_path.display()), source))?;
    let documented = extract_ids(&standards, valid_invariant_id);

    if documented != mapped {
        return Err(XtaskError::invalid_path(
            &standards_path,
            set_difference_message("invariant mapping", &documented, &mapped),
        ));
    }
    Ok(invariant_gates)
}

fn parse_scopes(
    root: &Path,
    table: &Table,
    owners: &BTreeSet<String>,
    gate_ids: &BTreeSet<String>,
) -> Result<Vec<Scope>, XtaskError> {
    let mut packages = BTreeSet::new();
    let mut paths = BTreeSet::new();
    let mut scopes = Vec::new();
    for row in &table.rows {
        let package = nonempty(row, "package")?.to_owned();
        if !packages.insert(package.clone()) {
            return Err(row_error(row, format!("duplicate package `{package}`")));
        }
        let relative_path = PathBuf::from(nonempty(row, "path")?);
        if relative_path.is_absolute()
            || relative_path
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err(row_error(row, "scope path must be repository-relative"));
        }
        if !paths.insert(relative_path.clone()) {
            return Err(row_error(
                row,
                format!("duplicate scope path `{}`", relative_path.display()),
            ));
        }

        let owner = nonempty(row, "semantic_owner")?.to_owned();
        if !owners.contains(&owner) {
            return Err(row_error(row, format!("unknown semantic owner `{owner}`")));
        }
        let kind = nonempty(row, "kind")?.to_owned();
        if !matches!(kind.as_str(), "application" | "tooling") {
            return Err(row_error(
                row,
                "scope kind must be `application` or `tooling`",
            ));
        }
        let state = nonempty(row, "state")?.to_owned();
        if !matches!(state.as_str(), "scaffold" | "active") {
            return Err(row_error(row, "scope state must be `scaffold` or `active`"));
        }
        if kind == "tooling" && state != "active" {
            return Err(row_error(row, "tooling scopes must be active"));
        }

        let activation_id = nonempty(row, "activation_id")?.to_owned();
        let activation_scope_set = parse_scope_set(row, "activation_scope_set")?;
        let allowed_edges = parse_edge_set(row, "allowed_edges")?;

        let risk_value = nonempty(row, "risk_gates")?;
        let risk_gates = if risk_value == "-" {
            BTreeSet::new()
        } else {
            split_set(risk_value)
        };
        for gate in &risk_gates {
            if !gate_ids.contains(gate) {
                return Err(row_error(row, format!("unknown risk gate `{gate}`")));
            }
        }
        let test_commands = nonempty(row, "test_commands")?.to_owned();
        let coverage_baseline = parse_scope_set(row, "coverage_baseline")?;
        let mutation_baseline = nonempty(row, "mutation_baseline")?.to_owned();
        let dependency_review = nonempty(row, "dependency_review")?.to_owned();
        let contract_evidence = nonempty(row, "contract_evidence")?.to_owned();

        if kind == "application"
            && state == "scaffold"
            && (activation_id != "-"
                || !activation_scope_set.is_empty()
                || !allowed_edges.is_empty()
                || !risk_gates.is_empty()
                || test_commands != "-"
                || !coverage_baseline.is_empty()
                || mutation_baseline != "-"
                || dependency_review != "-"
                || contract_evidence != "-")
        {
            return Err(row_error(
                row,
                "scaffold application scopes cannot advertise activation, edges, gates, tests, baselines, reviews, or evidence",
            ));
        }
        if kind == "application"
            && state == "active"
            && (activation_id == "-"
                || activation_scope_set.is_empty()
                || allowed_edges.is_empty()
                || risk_gates.is_empty()
                || test_commands == "-"
                || coverage_baseline.is_empty()
                || mutation_baseline == "-"
                || dependency_review == "-"
                || contract_evidence == "-")
        {
            return Err(row_error(
                row,
                "active application scopes require an atomic activation ledger",
            ));
        }
        if kind == "tooling"
            && (activation_id != "-"
                || !activation_scope_set.is_empty()
                || !allowed_edges.is_empty()
                || !coverage_baseline.is_empty()
                || mutation_baseline != "-"
                || dependency_review != "-"
                || contract_evidence != "-")
        {
            return Err(row_error(
                row,
                "tooling scopes cannot claim application activation ledger fields",
            ));
        }

        let manifest = root.join(&relative_path).join("Cargo.toml");
        let manifest_package = package_name_from_manifest(&manifest)?;
        if manifest_package != package {
            return Err(XtaskError::invalid_path(
                &manifest,
                format!("package is `{manifest_package}`, scope registry says `{package}`"),
            ));
        }

        scopes.push(Scope {
            package,
            path: relative_path,
            semantic_owner: owner,
            kind,
            state,
            activation_id,
            activation_scope_set,
            allowed_edges,
            risk_gates,
            test_commands,
            coverage_baseline,
            mutation_baseline,
            dependency_review,
            contract_evidence,
        });
    }
    Ok(scopes)
}

fn parse_scope_set(row: &Row, field: &str) -> Result<BTreeSet<String>, XtaskError> {
    let value = nonempty(row, field)?;
    if value == "-" {
        return Ok(BTreeSet::new());
    }
    let values = split_set(value);
    if values.contains("-") || values.is_empty() {
        return Err(row_error(
            row,
            format!("field `{field}` must be `-` or a non-empty pipe-delimited set"),
        ));
    }
    Ok(values)
}

fn parse_edge_set(row: &Row, field: &str) -> Result<BTreeSet<(String, String)>, XtaskError> {
    let value = nonempty(row, field)?;
    if value == "-" {
        return Ok(BTreeSet::new());
    }
    let mut edges = BTreeSet::new();
    for edge in split_list(value) {
        let Some((caller, dependency)) = edge.split_once("->") else {
            return Err(row_error(
                row,
                format!("field `{field}` edge `{edge}` must use `caller->dependency`"),
            ));
        };
        if caller.is_empty() || dependency.is_empty() || caller == dependency {
            return Err(row_error(
                row,
                format!("field `{field}` has an invalid edge `{edge}`"),
            ));
        }
        if !edges.insert((caller.to_owned(), dependency.to_owned())) {
            return Err(row_error(
                row,
                format!("field `{field}` repeats edge `{edge}`"),
            ));
        }
    }
    if edges.is_empty() {
        return Err(row_error(
            row,
            format!("field `{field}` must be `-` or a non-empty edge set"),
        ));
    }
    Ok(edges)
}

fn parse_artifact_scopes(
    root: &Path,
    owners: &BTreeSet<String>,
    gate_ids: &BTreeSet<String>,
) -> Result<Vec<ArtifactScope>, XtaskError> {
    let table = read_table(
        root,
        "artifact-scopes.tsv",
        &[
            "scope",
            "path",
            "semantic_owner",
            "state",
            "allowed_scaffold_files",
            "risk_gates",
        ],
    )?;
    let mut identities = BTreeSet::new();
    let mut paths = BTreeSet::new();
    let mut scopes = Vec::new();
    for row in &table.rows {
        let identity = nonempty(row, "scope")?;
        if !identities.insert(identity.to_owned()) {
            return Err(row_error(
                row,
                format!("duplicate artifact scope `{identity}`"),
            ));
        }
        let path = PathBuf::from(nonempty(row, "path")?);
        validate_relative_path(row, &path)?;
        if !paths.insert(path.clone()) {
            return Err(row_error(
                row,
                format!("duplicate artifact path `{}`", path.display()),
            ));
        }
        let owner = nonempty(row, "semantic_owner")?;
        if !owners.contains(owner) {
            return Err(row_error(row, format!("unknown artifact owner `{owner}`")));
        }
        let state = nonempty(row, "state")?.to_owned();
        if !matches!(state.as_str(), "scaffold" | "active") {
            return Err(row_error(
                row,
                "artifact state must be `scaffold` or `active`",
            ));
        }
        let allowed_value = nonempty(row, "allowed_scaffold_files")?;
        let allowed_files = if allowed_value == "-" {
            BTreeSet::new()
        } else {
            split_set(allowed_value)
        };
        for allowed in &allowed_files {
            validate_relative_path(row, Path::new(allowed))?;
        }
        let risk_gates = split_set(nonempty(row, "risk_gates")?);
        if risk_gates.is_empty() {
            return Err(row_error(
                row,
                "artifact scope requires at least one risk gate",
            ));
        }
        for gate in &risk_gates {
            if !gate_ids.contains(gate) {
                return Err(row_error(
                    row,
                    format!("artifact scope names unknown risk gate `{gate}`"),
                ));
            }
        }
        if state == "scaffold" && allowed_files.is_empty() {
            return Err(row_error(
                row,
                "scaffold artifact scope requires an exact allowed-file set",
            ));
        }
        if !root.join(&path).is_dir() {
            return Err(row_error(
                row,
                format!("artifact root `{}` does not exist", path.display()),
            ));
        }
        scopes.push(ArtifactScope {
            path,
            state,
            allowed_scaffold_files: allowed_files,
            risk_gates,
        });
    }
    Ok(scopes)
}

fn parse_edges(table: &Table, scopes: &[Scope]) -> Result<Vec<ArchitectureEdge>, XtaskError> {
    let application_packages = scopes
        .iter()
        .filter(|scope| scope.kind == "application")
        .map(|scope| scope.package.clone())
        .collect::<BTreeSet<_>>();
    let mut identities = BTreeSet::new();
    let mut edges = Vec::new();
    for row in &table.rows {
        let caller = nonempty(row, "caller")?.to_owned();
        let dependency = nonempty(row, "dependency")?.to_owned();
        let activation_id = nonempty(row, "activation_id")?.to_owned();
        if !application_packages.contains(&caller) {
            return Err(row_error(row, format!("unknown caller `{caller}`")));
        }
        if !application_packages.contains(&dependency) {
            return Err(row_error(row, format!("unknown dependency `{dependency}`")));
        }
        if caller == dependency {
            return Err(row_error(row, "self-dependencies are forbidden"));
        }
        if !identities.insert((caller.clone(), dependency.clone())) {
            return Err(row_error(
                row,
                format!("duplicate allowed edge `{caller}` -> `{dependency}`"),
            ));
        }
        if activation_id.is_empty() {
            return Err(row_error(row, "edge activation identity is empty"));
        }
        edges.push(ArchitectureEdge {
            caller,
            dependency,
            activation_id,
        });
    }
    Ok(edges)
}

fn parse_tools(table: &Table) -> Result<Vec<Tool>, XtaskError> {
    let mut identities = BTreeSet::new();
    let mut tools = Vec::new();
    for row in &table.rows {
        let id = nonempty(row, "tool_id")?.to_owned();
        if !identities.insert(id.clone()) {
            return Err(row_error(row, format!("duplicate tool `{id}`")));
        }
        let version = nonempty(row, "version")?.to_owned();
        if matches!(version.as_str(), "stable" | "latest" | "main" | "*") {
            return Err(row_error(row, format!("tool `{id}` is not exactly pinned")));
        }
        let command = nonempty(row, "command")?.to_owned();
        let version_arguments = split_list(nonempty(row, "version_arguments")?);
        let required_profiles = split_set(nonempty(row, "required_profiles")?);
        if required_profiles.is_empty() {
            return Err(row_error(row, "tool must belong to at least one profile"));
        }
        tools.push(Tool {
            id,
            version,
            command,
            version_arguments,
            required_profiles,
        });
    }
    Ok(tools)
}

fn validate_thresholds(
    root: &Path,
    scopes: &[Scope],
) -> Result<BTreeMap<String, Threshold>, XtaskError> {
    let table = read_table(
        root,
        "thresholds.tsv",
        &[
            "threshold_id",
            "state",
            "value",
            "unit",
            "scope",
            "rationale",
            "evidence",
        ],
    )?;
    let mut identities = BTreeSet::new();
    let mut thresholds = BTreeMap::new();
    let mut has_pending_application_threshold = false;
    for row in &table.rows {
        let identity = nonempty(row, "threshold_id")?;
        if !identities.insert(identity.to_owned()) {
            return Err(row_error(row, format!("duplicate threshold `{identity}`")));
        }
        let state = nonempty(row, "state")?;
        let value = nonempty(row, "value")?;
        let _unit = nonempty(row, "unit")?;
        let scope = nonempty(row, "scope")?;
        let _rationale = nonempty(row, "rationale")?;
        let evidence = nonempty(row, "evidence")?.to_owned();
        if state.starts_with("pending-") && value != "-" {
            return Err(row_error(
                row,
                "pending thresholds must not carry an invented value",
            ));
        }
        if state.starts_with("pending-") && scope == "active-application-code" {
            has_pending_application_threshold = true;
        }
        if state == "measured-baseline" {
            let measured = value.parse::<f64>().map_err(|source| {
                row_error(
                    row,
                    format!("measured baselines must use a non-negative numeric value: {source}"),
                )
            })?;
            if !measured.is_finite() || measured < 0.0 {
                return Err(row_error(
                    row,
                    "measured baselines must use a non-negative numeric value",
                ));
            }
        }
        thresholds.insert(
            identity.to_owned(),
            Threshold {
                state: state.to_owned(),
                value: value.to_owned(),
                evidence,
            },
        );
    }

    let active_application = scopes
        .iter()
        .any(|scope| scope.kind == "application" && scope.state == "active");
    if active_application && has_pending_application_threshold {
        return Err(XtaskError::invalid(
            "threshold registry",
            "application code cannot activate before measured M0 thresholds are frozen",
        ));
    }
    Ok(thresholds)
}

fn validate_activation_ledgers(
    root: &Path,
    scopes: &[Scope],
    edges: &[ArchitectureEdge],
    thresholds: &BTreeMap<String, Threshold>,
    reviewed_dependencies: &BTreeSet<String>,
) -> Result<(), XtaskError> {
    let active = scopes
        .iter()
        .filter(|scope| scope.kind == "application" && scope.state == "active")
        .collect::<Vec<_>>();
    if active.is_empty() {
        return Ok(());
    }

    let groups = active.iter().fold(
        BTreeMap::<String, BTreeSet<String>>::new(),
        |mut groups, scope| {
            groups
                .entry(scope.activation_id.clone())
                .or_default()
                .insert(scope.package.clone());
            groups
        },
    );
    let m0_01_complete =
        groups.len() == 1 && groups.get("M0-01") == Some(&foundational_scope_set());
    let m0_02_domain_transition = groups.len() == 2
        && groups.get("M0-01") == Some(&m0_01_remaining_scope_set())
        && groups.get("M0-02") == Some(&m0_02_domain_scope_set());
    let m0_03_api_transition = groups.len() == 3
        && groups.get("M0-01") == Some(&m0_01_config_scope_set())
        && groups.get("M0-02") == Some(&m0_02_domain_scope_set())
        && groups.get("M0-03") == Some(&m0_03_api_scope_set());
    let m0_04_configuration_transition = groups.len() == 3
        && groups.get("M0-02") == Some(&m0_02_domain_scope_set())
        && groups.get("M0-03") == Some(&m0_03_api_scope_set())
        && groups.get("M0-04") == Some(&m0_04_configuration_scope_set());
    if !m0_01_complete
        && !m0_02_domain_transition
        && !m0_03_api_transition
        && !m0_04_configuration_transition
    {
        return Err(XtaskError::invalid(
            "application activation ledger",
            "active application scopes must be the complete M0-01 foundation, the narrow M0-02 Domain Types transition, or the narrow M0-03 canonical API transition",
        ));
    }

    for scope in active {
        match scope.activation_id.as_str() {
            "M0-01" => {
                validate_foundational_scope_ledger(root, scope, thresholds, reviewed_dependencies)?;
            },
            "M0-02" => {
                validate_m0_02_domain_types_ledger(root, scope, thresholds, reviewed_dependencies)?;
            },
            "M0-03" => {
                validate_m0_03_canonical_api_ledger(
                    root,
                    scope,
                    thresholds,
                    reviewed_dependencies,
                )?;
            },
            "M0-04" => {
                validate_m0_04_configuration_ledger(root, scope, thresholds, reviewed_dependencies)?
            },
            _ => {
                return Err(XtaskError::invalid(
                    "application activation ledger",
                    "active application scope has an unrecognized activation identity",
                ));
            },
        }
    }
    validate_foundational_edges(
        edges,
        m0_02_domain_transition,
        m0_03_api_transition,
        m0_04_configuration_transition,
    )?;
    Ok(())
}

fn foundational_scope_set() -> BTreeSet<String> {
    ["positron-api", "positron-config", "positron-domain"]
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn m0_01_remaining_scope_set() -> BTreeSet<String> {
    ["positron-api", "positron-config"]
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn m0_01_config_scope_set() -> BTreeSet<String> {
    ["positron-config"].into_iter().map(str::to_owned).collect()
}

fn m0_02_domain_scope_set() -> BTreeSet<String> {
    ["positron-domain"].into_iter().map(str::to_owned).collect()
}

fn m0_03_api_scope_set() -> BTreeSet<String> {
    ["positron-api"].into_iter().map(str::to_owned).collect()
}

fn m0_04_configuration_scope_set() -> BTreeSet<String> {
    ["positron-config"].into_iter().map(str::to_owned).collect()
}

fn validate_m0_04_configuration_ledger(
    root: &Path,
    scope: &Scope,
    thresholds: &BTreeMap<String, Threshold>,
    reviewed_dependencies: &BTreeSet<String>,
) -> Result<(), XtaskError> {
    if scope.package != "positron-config"
        || scope.semantic_owner != "Recovery and Lifecycle"
        || scope.activation_scope_set != m0_04_configuration_scope_set()
        || scope.allowed_edges != foundational_edges(&scope.package)
        || scope.risk_gates
            != BTreeSet::from([
                "EG-COVERAGE".to_owned(),
                "EG-SAFETY".to_owned(),
                "EG-SECURITY".to_owned(),
            ])
        || scope.test_commands
            != "cargo test --locked --package positron-config --test configuration_foundation"
        || scope.coverage_baseline
            != BTreeSet::from([
                "config-coverage-branch".to_owned(),
                "config-coverage-line".to_owned(),
                "config-coverage-region".to_owned(),
            ])
        || scope.mutation_baseline != "config-mutation-score"
        || scope.dependency_review != "toml"
    {
        return Err(XtaskError::invalid(
            "application activation ledger",
            "M0-04 Configuration has an incomplete or forbidden activation ledger",
        ));
    }
    for baseline in scope
        .coverage_baseline
        .iter()
        .chain(std::iter::once(&scope.mutation_baseline))
    {
        let Some(threshold) = thresholds.get(baseline) else {
            return Err(XtaskError::invalid(
                "application activation ledger",
                format!("M0-04 Configuration references unknown baseline `{baseline}`"),
            ));
        };
        if threshold.state != "pending-measured-baseline"
            || threshold.value != "-"
            || threshold.evidence != scope.contract_evidence
        {
            return Err(XtaskError::invalid(
                "application activation ledger",
                format!(
                    "M0-04 Configuration pending baseline `{baseline}` is not traceable to its contract evidence"
                ),
            ));
        }
    }
    for dependency in split_set(&scope.dependency_review) {
        if !reviewed_dependencies.contains(&dependency) {
            return Err(XtaskError::invalid(
                "application activation ledger",
                format!("M0-04 Configuration names unreviewed dependency `{dependency}`"),
            ));
        }
    }
    let evidence = root.join(&scope.contract_evidence);
    if !evidence.is_file() {
        return Err(XtaskError::invalid_path(
            &evidence,
            "M0-04 Configuration contract evidence is missing",
        ));
    }
    Ok(())
}

fn validate_foundational_scope_ledger(
    root: &Path,
    scope: &Scope,
    thresholds: &BTreeMap<String, Threshold>,
    reviewed_dependencies: &BTreeSet<String>,
) -> Result<(), XtaskError> {
    let Some(expected_owner) = foundational_owner(&scope.package) else {
        return Err(XtaskError::invalid(
            "application activation ledger",
            format!("M0-01 cannot activate unknown scope `{}`", scope.package),
        ));
    };
    if scope.semantic_owner != expected_owner {
        return Err(XtaskError::invalid(
            "application activation ledger",
            format!(
                "scope `{}` owner `{}` does not match the M0-01 owner `{expected_owner}`",
                scope.package, scope.semantic_owner
            ),
        ));
    }
    if scope.activation_id != "M0-01" || scope.activation_scope_set != foundational_scope_set() {
        return Err(XtaskError::invalid(
            "application activation ledger",
            format!(
                "scope `{}` does not declare the complete M0-01 set",
                scope.package
            ),
        ));
    }
    let expected_edges = foundational_edges(&scope.package);
    if scope.allowed_edges != expected_edges {
        return Err(XtaskError::invalid(
            "application activation ledger",
            format!(
                "scope `{}` has an incomplete or forbidden edge set",
                scope.package
            ),
        ));
    }
    if scope.risk_gates != BTreeSet::from(["EG-COVERAGE".to_owned()]) {
        return Err(XtaskError::invalid(
            "application activation ledger",
            format!("scope `{}` must select exactly EG-COVERAGE", scope.package),
        ));
    }
    if scope.test_commands
        != "cargo test --locked --package xtask --test foundational_scope_activation"
    {
        return Err(XtaskError::invalid(
            "application activation ledger",
            format!(
                "scope `{}` has an unexpected public policy test command",
                scope.package
            ),
        ));
    }
    if scope.coverage_baseline
        != BTreeSet::from([
            "coverage-branch".to_owned(),
            "coverage-changed-code".to_owned(),
            "coverage-line".to_owned(),
            "coverage-region".to_owned(),
        ])
        || scope.mutation_baseline != "mutation-score"
    {
        return Err(XtaskError::invalid(
            "application activation ledger",
            format!(
                "scope `{}` is missing the complete M0 baseline set",
                scope.package
            ),
        ));
    }
    for baseline in scope
        .coverage_baseline
        .iter()
        .chain(std::iter::once(&scope.mutation_baseline))
    {
        let Some(threshold) = thresholds.get(baseline) else {
            return Err(XtaskError::invalid(
                "application activation ledger",
                format!(
                    "scope `{}` references unknown baseline `{baseline}`",
                    scope.package
                ),
            ));
        };
        if threshold.state != "measured-baseline" || threshold.value == "-" {
            return Err(XtaskError::invalid(
                "application activation ledger",
                format!(
                    "scope `{}` baseline `{baseline}` is not measured",
                    scope.package
                ),
            ));
        }
        if threshold.evidence != scope.contract_evidence {
            return Err(XtaskError::invalid(
                "application activation ledger",
                format!(
                    "scope `{}` baseline `{baseline}` is not traceable to its contract evidence",
                    scope.package
                ),
            ));
        }
    }
    if scope.dependency_review == "none" {
        validate_dependency_free_scope(root, scope)?;
    } else {
        for dependency in split_set(&scope.dependency_review) {
            if !reviewed_dependencies.contains(&dependency) {
                return Err(XtaskError::invalid(
                    "application activation ledger",
                    format!(
                        "scope `{}` names unreviewed dependency `{dependency}`",
                        scope.package
                    ),
                ));
            }
        }
    }
    let evidence = root.join(&scope.contract_evidence);
    if !evidence.is_file() {
        return Err(XtaskError::invalid_path(
            &evidence,
            format!("scope `{}` contract evidence is missing", scope.package),
        ));
    }
    Ok(())
}

fn validate_m0_02_domain_types_ledger(
    root: &Path,
    scope: &Scope,
    thresholds: &BTreeMap<String, Threshold>,
    reviewed_dependencies: &BTreeSet<String>,
) -> Result<(), XtaskError> {
    if scope.package != "positron-domain" || scope.semantic_owner != "Architecture" {
        return Err(XtaskError::invalid(
            "application activation ledger",
            "M0-02 can activate only the Architecture-owned `positron-domain` scope",
        ));
    }
    if scope.activation_id != "M0-02" || scope.activation_scope_set != m0_02_domain_scope_set() {
        return Err(XtaskError::invalid(
            "application activation ledger",
            "M0-02 Domain Types must declare only the exact `positron-domain` scope set",
        ));
    }
    if scope.allowed_edges != foundational_edges(&scope.package) {
        return Err(XtaskError::invalid(
            "application activation ledger",
            "M0-02 Domain Types has an incomplete or forbidden edge set",
        ));
    }
    if scope.risk_gates != BTreeSet::from(["EG-COVERAGE".to_owned(), "EG-DYNAMIC".to_owned()]) {
        return Err(XtaskError::invalid(
            "application activation ledger",
            "M0-02 Domain Types must select exactly EG-COVERAGE and EG-DYNAMIC",
        ));
    }
    if scope.test_commands != "cargo test --locked --package positron-domain" {
        return Err(XtaskError::invalid(
            "application activation ledger",
            "M0-02 Domain Types has an unexpected public contract test command",
        ));
    }
    let expected_coverage = BTreeSet::from([
        "domain-coverage-branch".to_owned(),
        "domain-coverage-line".to_owned(),
        "domain-coverage-region".to_owned(),
    ]);
    if scope.coverage_baseline != expected_coverage
        || scope.mutation_baseline != "domain-mutation-score"
    {
        return Err(XtaskError::invalid(
            "application activation ledger",
            "M0-02 Domain Types is missing its exact coverage and focused mutation baselines",
        ));
    }
    for baseline in scope
        .coverage_baseline
        .iter()
        .chain(std::iter::once(&scope.mutation_baseline))
    {
        let Some(threshold) = thresholds.get(baseline) else {
            return Err(XtaskError::invalid(
                "application activation ledger",
                format!("M0-02 Domain Types references unknown baseline `{baseline}`"),
            ));
        };
        if threshold.state != "measured-baseline" || threshold.value == "-" {
            return Err(XtaskError::invalid(
                "application activation ledger",
                format!("M0-02 Domain Types baseline `{baseline}` is not measured"),
            ));
        }
        if threshold.evidence != scope.contract_evidence {
            return Err(XtaskError::invalid(
                "application activation ledger",
                format!(
                    "M0-02 Domain Types baseline `{baseline}` is not traceable to its contract evidence"
                ),
            ));
        }
    }
    if scope.dependency_review == "none" {
        validate_dependency_free_scope(root, scope)?;
    } else {
        for dependency in split_set(&scope.dependency_review) {
            if !reviewed_dependencies.contains(&dependency) {
                return Err(XtaskError::invalid(
                    "application activation ledger",
                    format!("M0-02 Domain Types names unreviewed dependency `{dependency}`"),
                ));
            }
        }
    }
    let evidence = root.join(&scope.contract_evidence);
    if !evidence.is_file() {
        return Err(XtaskError::invalid_path(
            &evidence,
            "M0-02 Domain Types contract evidence is missing",
        ));
    }
    Ok(())
}

fn validate_m0_03_canonical_api_ledger(
    root: &Path,
    scope: &Scope,
    thresholds: &BTreeMap<String, Threshold>,
    reviewed_dependencies: &BTreeSet<String>,
) -> Result<(), XtaskError> {
    if scope.package != "positron-api" || scope.semantic_owner != "Public API and SDK" {
        return Err(XtaskError::invalid(
            "application activation ledger",
            "M0-03 can activate only the Public API and SDK-owned `positron-api` scope",
        ));
    }
    if scope.activation_id != "M0-03" || scope.activation_scope_set != m0_03_api_scope_set() {
        return Err(XtaskError::invalid(
            "application activation ledger",
            "M0-03 canonical API must declare only the exact `positron-api` scope set",
        ));
    }
    if scope.allowed_edges != foundational_edges(&scope.package) {
        return Err(XtaskError::invalid(
            "application activation ledger",
            "M0-03 canonical API has an incomplete or forbidden edge set",
        ));
    }
    if scope.risk_gates != BTreeSet::from(["EG-COVERAGE".to_owned()]) {
        return Err(XtaskError::invalid(
            "application activation ledger",
            "M0-03 canonical API must select exactly EG-COVERAGE",
        ));
    }
    if scope.test_commands
        != "cargo test --locked --package positron-api --test canonical_public_interface"
    {
        return Err(XtaskError::invalid(
            "application activation ledger",
            "M0-03 canonical API has an unexpected public contract test command",
        ));
    }
    let expected_coverage = BTreeSet::from([
        "api-coverage-branch".to_owned(),
        "api-coverage-line".to_owned(),
        "api-coverage-region".to_owned(),
    ]);
    if scope.coverage_baseline != expected_coverage
        || scope.mutation_baseline != "api-mutation-score"
    {
        return Err(XtaskError::invalid(
            "application activation ledger",
            "M0-03 canonical API is missing its exact coverage and focused mutation baselines",
        ));
    }
    for baseline in scope
        .coverage_baseline
        .iter()
        .chain(std::iter::once(&scope.mutation_baseline))
    {
        let Some(threshold) = thresholds.get(baseline) else {
            return Err(XtaskError::invalid(
                "application activation ledger",
                format!("M0-03 canonical API references unknown baseline `{baseline}`"),
            ));
        };
        if threshold.state != "measured-baseline" || threshold.value == "-" {
            return Err(XtaskError::invalid(
                "application activation ledger",
                format!("M0-03 canonical API baseline `{baseline}` is not measured"),
            ));
        }
        if threshold.evidence != scope.contract_evidence {
            return Err(XtaskError::invalid(
                "application activation ledger",
                format!(
                    "M0-03 canonical API baseline `{baseline}` is not traceable to its contract evidence"
                ),
            ));
        }
    }
    if scope.dependency_review == "none" {
        validate_dependency_free_scope(root, scope)?;
    } else {
        for dependency in split_set(&scope.dependency_review) {
            if !reviewed_dependencies.contains(&dependency) {
                return Err(XtaskError::invalid(
                    "application activation ledger",
                    format!("M0-03 canonical API names unreviewed dependency `{dependency}`"),
                ));
            }
        }
    }
    let evidence = root.join(&scope.contract_evidence);
    if !evidence.is_file() {
        return Err(XtaskError::invalid_path(
            &evidence,
            "M0-03 canonical API contract evidence is missing",
        ));
    }
    Ok(())
}

fn foundational_owner(package: &str) -> Option<&'static str> {
    match package {
        "positron-domain" => Some("Architecture"),
        "positron-api" => Some("Public API and SDK"),
        "positron-config" => Some("Recovery and Lifecycle"),
        _ => None,
    }
}

fn foundational_edges(package: &str) -> BTreeSet<(String, String)> {
    let edges = match package {
        "positron-domain" => vec![
            "positron-backup->positron-domain",
            "positron-governance->positron-domain",
            "positron-ingest->positron-domain",
            "positron-kernel->positron-domain",
            "positron-query->positron-domain",
            "positron-runtime->positron-domain",
            "positron-signals->positron-domain",
        ],
        "positron-api" => vec![
            "positron-operator->positron-api",
            "positron-runtime->positron-api",
        ],
        "positron-config" => vec!["positron-runtime->positron-config"],
        _ => Vec::new(),
    };
    edges
        .into_iter()
        .filter_map(|edge| {
            edge.split_once("->")
                .map(|(caller, dependency)| (caller.to_owned(), dependency.to_owned()))
        })
        .collect()
}

fn validate_foundational_edges(
    edges: &[ArchitectureEdge],
    m0_02_domain_transition: bool,
    m0_03_api_transition: bool,
    m0_04_configuration_transition: bool,
) -> Result<(), XtaskError> {
    let foundational = foundational_scope_set();
    let mut actual = BTreeMap::<String, BTreeSet<(String, String)>>::new();
    for edge in edges {
        let touches_foundation =
            foundational.contains(&edge.caller) || foundational.contains(&edge.dependency);
        let package = if foundational.contains(&edge.caller) {
            &edge.caller
        } else {
            &edge.dependency
        };
        let expected_activation_id =
            if (m0_02_domain_transition || m0_03_api_transition || m0_04_configuration_transition)
                && package == "positron-domain"
            {
                "M0-02"
            } else if (m0_03_api_transition || m0_04_configuration_transition)
                && package == "positron-api"
            {
                "M0-03"
            } else if m0_04_configuration_transition && package == "positron-config" {
                "M0-04"
            } else {
                "M0-01"
            };
        if touches_foundation && edge.activation_id != expected_activation_id {
            return Err(XtaskError::invalid(
                "architecture edge activation ledger",
                format!(
                    "foundation edge `{}->{}` must be activated by {expected_activation_id}",
                    edge.caller, edge.dependency,
                ),
            ));
        }
        if !touches_foundation && edge.activation_id != "-" {
            return Err(XtaskError::invalid(
                "architecture edge activation ledger",
                format!(
                    "non-foundational edge `{}->{}` cannot receive M0 activation",
                    edge.caller, edge.dependency
                ),
            ));
        }
        if touches_foundation {
            let expected = foundational_edges(package);
            if !expected.contains(&(edge.caller.clone(), edge.dependency.clone())) {
                return Err(XtaskError::invalid(
                    "architecture edge activation ledger",
                    format!(
                        "foundation edge `{}->{}` is forbidden",
                        edge.caller, edge.dependency
                    ),
                ));
            }
            actual
                .entry(package.clone())
                .or_default()
                .insert((edge.caller.clone(), edge.dependency.clone()));
        }
    }
    for package in foundational {
        let expected = foundational_edges(&package);
        if actual.get(&package) != Some(&expected) {
            return Err(XtaskError::invalid(
                "architecture edge activation ledger",
                format!("foundation edges for `{package}` do not match its activation ledger"),
            ));
        }
    }
    Ok(())
}

fn validate_dependency_free_scope(root: &Path, scope: &Scope) -> Result<(), XtaskError> {
    let manifest = root.join(&scope.path).join("Cargo.toml");
    let content = fs::read_to_string(&manifest)
        .map_err(|source| XtaskError::io(format!("read {}", manifest.display()), source))?;
    for section in [
        "[dependencies]",
        "[dev-dependencies]",
        "[build-dependencies]",
        "[target.",
        "[features]",
    ] {
        if content.contains(section) {
            return Err(XtaskError::invalid_path(
                &manifest,
                format!(
                    "scope `{}` declares `{section}` despite its `none` dependency review",
                    scope.package
                ),
            ));
        }
    }
    Ok(())
}

fn validate_dependencies(root: &Path) -> Result<BTreeSet<String>, XtaskError> {
    let table = read_table(
        root,
        "dependencies.tsv",
        &[
            "package",
            "exact_version",
            "owner",
            "purpose",
            "source",
            "license",
            "features",
            "security_review",
            "maintenance_review",
            "removal_condition",
        ],
    )?;
    let mut packages = BTreeSet::new();
    for row in &table.rows {
        for field in [
            "package",
            "exact_version",
            "owner",
            "purpose",
            "source",
            "license",
            "features",
            "security_review",
            "maintenance_review",
            "removal_condition",
        ] {
            let _value = nonempty(row, field)?;
        }
        let package = row.field("package")?;
        let version = row.field("exact_version")?;
        if version.contains('*')
            || version.starts_with('^')
            || version.starts_with('~')
            || version.contains('>')
            || version.contains('<')
        {
            return Err(row_error(
                row,
                format!("dependency `{package}` is not exactly pinned"),
            ));
        }
        if !packages.insert(package.to_owned()) {
            return Err(row_error(
                row,
                format!("duplicate dependency review `{package}`"),
            ));
        }
    }
    Ok(packages)
}

fn validate_empty_or_owned_registries(
    root: &Path,
    owners: &BTreeSet<String>,
) -> Result<(), XtaskError> {
    let unsafe_table = read_table(
        root,
        "unsafe-allowlist.tsv",
        &[
            "scope",
            "owner",
            "safety_case",
            "miri_command",
            "sanitizer_command",
            "fuzz_command",
            "property_command",
        ],
    )?;
    for row in &unsafe_table.rows {
        let owner = nonempty(row, "owner")?;
        if !owners.contains(owner) {
            return Err(row_error(row, format!("unknown unsafe owner `{owner}`")));
        }
        for field in [
            "scope",
            "safety_case",
            "miri_command",
            "sanitizer_command",
            "fuzz_command",
            "property_command",
        ] {
            let _value = nonempty(row, field)?;
        }
    }

    let temporary_table = read_table(
        root,
        "temporary-work.tsv",
        &[
            "marker",
            "path",
            "owner",
            "issue",
            "expires_at",
            "removal_condition",
        ],
    )?;
    for row in &temporary_table.rows {
        let owner = nonempty(row, "owner")?;
        if !owners.contains(owner) {
            return Err(row_error(
                row,
                format!("unknown temporary-work owner `{owner}`"),
            ));
        }
        for field in ["marker", "path", "issue", "expires_at", "removal_condition"] {
            let _value = nonempty(row, field)?;
        }
    }
    Ok(())
}

fn validate_exceptions(
    root: &Path,
    owners: &BTreeSet<String>,
    gates: &[Gate],
    invariant_gates: &BTreeMap<String, String>,
) -> Result<(), XtaskError> {
    let directory = root.join(ENGINEERING).join("exceptions");
    let entries = fs::read_dir(&directory)
        .map_err(|source| XtaskError::io(format!("read {}", directory.display()), source))?;
    for entry in entries {
        let entry = entry
            .map_err(|source| XtaskError::io(format!("read {}", directory.display()), source))?;
        let path = entry.path();
        if path.extension().and_then(std::ffi::OsStr::to_str) != Some("toml") {
            continue;
        }
        validate_exception_file(&path, owners, gates, invariant_gates)?;
    }
    Ok(())
}

fn validate_exception_file(
    path: &Path,
    owners: &BTreeSet<String>,
    gates: &[Gate],
    invariant_gates: &BTreeMap<String, String>,
) -> Result<(), XtaskError> {
    const KEYS: [&str; 18] = [
        "schema_version",
        "id",
        "invariant",
        "gate",
        "scope",
        "artifact_or_target",
        "failure_digest",
        "evidence_digest",
        "rationale",
        "risk",
        "compensating_control",
        "compensating_evidence",
        "owner",
        "independent_approver",
        "tracking_issue",
        "created_at",
        "expires_at",
        "removal_condition",
    ];
    let content = fs::read_to_string(path)
        .map_err(|source| XtaskError::io(format!("read {}", path.display()), source))?;
    let mut values = BTreeMap::new();
    for (index, raw_line) in content.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((raw_key, raw_value)) = line.split_once('=') else {
            return Err(XtaskError::invalid_path(
                path,
                format!("line {} is not a scalar key/value", index + 1),
            ));
        };
        let key = raw_key.trim();
        let value = raw_value.trim();
        let Some(unquoted) = value
            .strip_prefix('"')
            .and_then(|item| item.strip_suffix('"'))
        else {
            return Err(XtaskError::invalid_path(
                path,
                format!("line {} value must be a quoted scalar", index + 1),
            ));
        };
        if !KEYS.contains(&key) && key != "signature" {
            return Err(XtaskError::invalid_path(
                path,
                format!("line {} contains unknown key `{key}`", index + 1),
            ));
        }
        if unquoted.is_empty() || values.insert(key.to_owned(), unquoted.to_owned()).is_some() {
            return Err(XtaskError::invalid_path(
                path,
                format!("line {} has an empty or duplicate key `{key}`", index + 1),
            ));
        }
    }
    for key in KEYS.into_iter().chain(std::iter::once("signature")) {
        if !values.contains_key(key) {
            return Err(XtaskError::invalid_path(
                path,
                format!("missing required key `{key}`"),
            ));
        }
    }
    if values.get("schema_version").map(String::as_str) != Some("1") {
        return Err(XtaskError::invalid_path(path, "schema_version must be `1`"));
    }
    let id = required_value(path, &values, "id")?;
    let expected_prefix = "EXC-";
    if !id.starts_with(expected_prefix) {
        return Err(XtaskError::invalid_path(
            path,
            "exception identity must begin with `EXC-`",
        ));
    }
    let invariant = required_value(path, &values, "invariant")?;
    if !valid_invariant_id(invariant) {
        return Err(XtaskError::invalid_path(path, "invalid invariant identity"));
    }
    let gate_id = required_value(path, &values, "gate")?;
    if invariant_gates.get(invariant).map(String::as_str) != Some(gate_id) {
        return Err(XtaskError::invalid_path(
            path,
            "exception gate does not match the invariant-to-gate registry",
        ));
    }
    let Some(gate) = gates.iter().find(|candidate| candidate.id == gate_id) else {
        return Err(XtaskError::invalid_path(
            path,
            "exception names an unknown gate",
        ));
    };
    if gate.exception_class != "temporary" {
        return Err(XtaskError::invalid_path(
            path,
            format!("gate `{gate_id}` is non-waivable"),
        ));
    }
    let scope = required_value(path, &values, "scope")?;
    if matches!(scope, "." | "/" | "*" | "**") || scope.contains('*') {
        return Err(XtaskError::invalid_path(
            path,
            "exception scope must be exact and cannot be repository-wide",
        ));
    }
    for digest_key in ["failure_digest", "evidence_digest", "compensating_evidence"] {
        if !valid_sha256_digest(required_value(path, &values, digest_key)?) {
            return Err(XtaskError::invalid_path(
                path,
                format!("`{digest_key}` must be an exact SHA-256 digest"),
            ));
        }
    }
    let artifact_or_target = required_value(path, &values, "artifact_or_target")?;
    if artifact_or_target.contains('*') {
        return Err(XtaskError::invalid_path(
            path,
            "artifact_or_target cannot contain a wildcard",
        ));
    }
    let owner = required_value(path, &values, "owner")?;
    let approver = required_value(path, &values, "independent_approver")?;
    if !owners.contains(owner) || !owners.contains(approver) || owner == approver {
        return Err(XtaskError::invalid_path(
            path,
            "owner and independent approver must be distinct registered roles",
        ));
    }
    let issue = required_value(path, &values, "tracking_issue")?;
    if !issue.starts_with("https://github.com/guaracloud/positron/issues/") {
        return Err(XtaskError::invalid_path(
            path,
            "tracking_issue must be an exact Positron issue URL",
        ));
    }
    let created = parse_utc_timestamp(path, required_value(path, &values, "created_at")?)?;
    let expires = parse_utc_timestamp(path, required_value(path, &values, "expires_at")?)?;
    if expires <= created || expires - created > 14 * 24 * 60 * 60 {
        return Err(XtaskError::invalid_path(
            path,
            "exception lifetime must be positive and no more than 14 days",
        ));
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|source| XtaskError::invalid("system clock", source.to_string()))?
        .as_secs();
    if now >= expires {
        return Err(XtaskError::invalid_path(path, "exception has expired"));
    }
    Ok(())
}

fn validate_policy_seed(root: &Path) -> Result<(), XtaskError> {
    let path = root
        .join(ENGINEERING)
        .join("policy-changes/M0-INITIAL.json");
    let content = fs::read_to_string(&path)
        .map_err(|source| XtaskError::io(format!("read {}", path.display()), source))?;
    for required in [
        "\"id\": \"M0-INITIAL\"",
        "\"dual_run\": \"not-applicable-no-predecessor\"",
        "\"immutable_after_acceptance\": true",
    ] {
        if !content.contains(required) {
            return Err(XtaskError::invalid_path(
                &path,
                format!("missing required initial-policy field `{required}`"),
            ));
        }
    }
    Ok(())
}

fn validate_target_registry(root: &Path) -> Result<(), XtaskError> {
    let path = root.join("qualification/targets/registry.json");
    let content = fs::read_to_string(&path)
        .map_err(|source| XtaskError::io(format!("read {}", path.display()), source))?;
    for required in [
        "\"state\": \"specified\"",
        "\"qualification_claims_permitted\": false",
        "\"unresolved_dynamic_selectors\"",
    ] {
        if !content.contains(required) {
            return Err(XtaskError::invalid_path(
                &path,
                format!("missing target-registry safeguard `{required}`"),
            ));
        }
    }
    Ok(())
}

fn validate_documented_gate_set(
    root: &Path,
    gate_ids: &BTreeSet<String>,
) -> Result<(), XtaskError> {
    let path = root.join("docs/engineering/quality-gates.md");
    let content = fs::read_to_string(&path)
        .map_err(|source| XtaskError::io(format!("read {}", path.display()), source))?;
    let documented = extract_ids(&content, valid_gate_id);
    if &documented != gate_ids {
        return Err(XtaskError::invalid_path(
            &path,
            set_difference_message("gate registry", &documented, gate_ids),
        ));
    }
    Ok(())
}

fn validate_workspace_members(root: &Path, scopes: &[Scope]) -> Result<(), XtaskError> {
    let registered = scopes
        .iter()
        .map(|scope| scope.path.clone())
        .collect::<BTreeSet<_>>();
    for parent in ["crates", "tools"] {
        let directory = root.join(parent);
        let entries = fs::read_dir(&directory)
            .map_err(|source| XtaskError::io(format!("read {}", directory.display()), source))?;
        for entry in entries {
            let entry = entry.map_err(|source| {
                XtaskError::io(format!("read {}", directory.display()), source)
            })?;
            if !entry
                .file_type()
                .map_err(|source| XtaskError::io("read workspace entry type", source))?
                .is_dir()
            {
                continue;
            }
            let relative = PathBuf::from(parent).join(entry.file_name());
            if entry.path().join("Cargo.toml").is_file() && !registered.contains(&relative) {
                return Err(XtaskError::invalid_path(
                    &entry.path(),
                    "workspace crate is missing from the scope registry",
                ));
            }
        }
    }
    Ok(())
}

fn validate_scaffold_sources(root: &Path, scopes: &[Scope]) -> Result<(), XtaskError> {
    for scope in scopes
        .iter()
        .filter(|scope| scope.kind == "application" && scope.state == "scaffold")
    {
        let scope_root = root.join(&scope.path);
        let mut files = Vec::new();
        collect_files_with_extension(&scope_root, "rs", 0, &mut files)?;
        if files.len() != 1 {
            return Err(XtaskError::invalid_path(
                &scope_root,
                format!(
                    "scaffold scope `{}` must contain exactly one Rust source file",
                    scope.package
                ),
            ));
        }
        let Some(path) = files.first() else {
            return Err(XtaskError::invalid_path(
                &scope_root,
                "scaffold source file is missing",
            ));
        };
        if !path.starts_with(scope_root.join("src")) {
            return Err(XtaskError::invalid_path(
                path,
                "scaffold Rust source must be the single crate root under `src/`",
            ));
        }
        let content = fs::read_to_string(path)
            .map_err(|source| XtaskError::io(format!("read {}", path.display()), source))?;
        if !content.lines().any(|line| line.trim() == SCAFFOLD_MARKER) {
            return Err(XtaskError::invalid_path(
                path,
                "scaffold marker is missing; activate the registered scope before adding behavior",
            ));
        }
        for (index, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            let permitted = trimmed.is_empty()
                || trimmed.starts_with("//!")
                || trimmed == "#![forbid(unsafe_code)]"
                || (scope.package == "positron" && trimmed == "fn main() {}");
            if !permitted {
                return Err(XtaskError::invalid_path(
                    path,
                    format!(
                        "line {} adds behavior to scaffold-only scope `{}`",
                        index + 1,
                        scope.package
                    ),
                ));
            }
        }
        let manifest = scope_root.join("Cargo.toml");
        let manifest_content = fs::read_to_string(&manifest)
            .map_err(|source| XtaskError::io(format!("read {}", manifest.display()), source))?;
        for forbidden_section in [
            "[dependencies]",
            "[dev-dependencies]",
            "[build-dependencies]",
            "[target.",
            "[features]",
        ] {
            if manifest_content.contains(forbidden_section) {
                return Err(XtaskError::invalid_path(
                    &manifest,
                    format!(
                        "scaffold scope `{}` cannot declare `{forbidden_section}`",
                        scope.package
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn validate_active_sources(root: &Path, scopes: &[Scope]) -> Result<(), XtaskError> {
    for scope in scopes
        .iter()
        .filter(|scope| scope.kind == "application" && scope.state == "active")
    {
        let source_root = root.join(&scope.path).join("src");
        let mut files = Vec::new();
        collect_files_with_extension(&source_root, "rs", 0, &mut files)?;
        if files.is_empty() {
            return Err(XtaskError::invalid_path(
                &source_root,
                format!("active scope `{}` has no Rust source", scope.package),
            ));
        }
        if scope.activation_id == "M0-02" {
            validate_m0_02_domain_source_layout(root, scope)?;
        }
        if scope.activation_id == "M0-03" {
            validate_m0_03_api_source_layout(root, scope)?;
        }
        if scope.activation_id == "M0-01"
            && (files.len() != 1 || files.first() != Some(&source_root.join("lib.rs")))
        {
            return Err(XtaskError::invalid_path(
                &source_root,
                format!(
                    "activation-only scope `{}` must retain exactly its crate root source",
                    scope.package
                ),
            ));
        }
        for path in files {
            let content = fs::read_to_string(&path)
                .map_err(|source| XtaskError::io(format!("read {}", path.display()), source))?;
            if content.lines().any(|line| line.trim() == SCAFFOLD_MARKER) {
                return Err(XtaskError::invalid_path(
                    &path,
                    format!(
                        "active scope `{}` retains the scaffold marker instead of an activation ledger",
                        scope.package
                    ),
                ));
            }
            for (line_index, line) in content.lines().enumerate() {
                if let Some(symbol) = deferred_runtime_symbol(line) {
                    return Err(XtaskError::invalid_path(
                        &path,
                        format!(
                            "line {} deferred runtime symbol `{symbol}` is forbidden",
                            line_index + 1
                        ),
                    ));
                }
                if line.trim_start().starts_with("pub use ") {
                    return Err(XtaskError::invalid_path(
                        &path,
                        format!(
                            "line {} pass-through module surface is forbidden",
                            line_index + 1
                        ),
                    ));
                }
                if scope.activation_id == "M0-01" && !activation_only_source_line(line) {
                    return Err(XtaskError::invalid_path(
                        &path,
                        format!(
                            "line {} activation-only scope `{}` contains behavior or a placeholder API",
                            line_index + 1,
                            scope.package
                        ),
                    ));
                }
            }
        }
    }
    Ok(())
}

fn validate_m0_02_domain_source_layout(root: &Path, scope: &Scope) -> Result<(), XtaskError> {
    let scope_root = root.join(&scope.path);
    let mut files = Vec::new();
    collect_files_with_extension(&scope_root, "rs", 0, &mut files)?;
    let actual = files
        .iter()
        .map(|path| {
            path.strip_prefix(&scope_root)
                .map(|relative| relative.to_path_buf())
                .map_err(|source| {
                    XtaskError::invalid_path(
                        path,
                        format!("M0-02 Domain Types source escaped its scope: {source}"),
                    )
                })
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let expected = [
        "src/identity.rs",
        "src/lib.rs",
        "src/lifecycle.rs",
        "src/outcome.rs",
        "src/routing.rs",
        "src/time.rs",
        "src/value.rs",
        "tests/foundational_domain_types.rs",
    ]
    .into_iter()
    .map(PathBuf::from)
    .collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(XtaskError::invalid_path(
            &scope_root,
            "M0-02 Domain Types source layout differs from its registered file set",
        ));
    }
    Ok(())
}

fn validate_m0_03_api_source_layout(root: &Path, scope: &Scope) -> Result<(), XtaskError> {
    let scope_root = root.join(&scope.path);
    let mut files = Vec::new();
    collect_files_with_extension(&scope_root, "rs", 0, &mut files)?;
    let actual = files
        .iter()
        .map(|path| {
            path.strip_prefix(&scope_root)
                .map(|relative| relative.to_path_buf())
                .map_err(|source| {
                    XtaskError::invalid_path(
                        path,
                        format!("M0-03 canonical API source escaped its scope: {source}"),
                    )
                })
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let expected = [
        "src/generated.rs",
        "src/lib.rs",
        "tests/canonical_public_interface.rs",
    ]
    .into_iter()
    .map(PathBuf::from)
    .collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(XtaskError::invalid_path(
            &scope_root,
            "M0-03 canonical API source layout differs from its registered file set",
        ));
    }
    Ok(())
}

fn activation_only_source_line(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.is_empty() || trimmed.starts_with("//!") || trimmed == "#![forbid(unsafe_code)]"
}

fn deferred_runtime_symbol(line: &str) -> Option<&'static str> {
    const SYMBOLS: [&str; 8] = [
        "MetricsStore",
        "ProfileStore",
        "Replication",
        "Cluster",
        "Consensus",
        "Failover",
        "FollowerRead",
        "ShardMigration",
    ];
    let declaration = line.trim_start();
    for prefix in ["pub struct ", "pub enum ", "pub mod ", "pub type ", "mod "] {
        let Some(remainder) = declaration.strip_prefix(prefix) else {
            continue;
        };
        for symbol in SYMBOLS {
            if let Some(suffix) = remainder.strip_prefix(symbol)
                && suffix
                    .chars()
                    .next()
                    .is_none_or(|character| !character.is_ascii_alphanumeric() && character != '_')
            {
                return Some(symbol);
            }
        }
    }
    None
}

fn validate_artifact_scaffolds(root: &Path, scopes: &[ArtifactScope]) -> Result<(), XtaskError> {
    for scope in scopes.iter().filter(|scope| scope.state == "scaffold") {
        let scope_root = root.join(&scope.path);
        let mut files = Vec::new();
        collect_all_files(&scope_root, 0, &mut files)?;
        let actual = files
            .iter()
            .map(|path| {
                path.strip_prefix(&scope_root)
                    .map(|relative| relative.to_string_lossy().into_owned())
                    .map_err(|source| {
                        XtaskError::invalid_path(
                            path,
                            format!("artifact escaped registered root: {source}"),
                        )
                    })
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        if actual != scope.allowed_scaffold_files {
            return Err(XtaskError::invalid_path(
                &scope_root,
                set_difference_message(
                    "scaffold artifact file set",
                    &scope.allowed_scaffold_files,
                    &actual,
                ),
            ));
        }
    }
    Ok(())
}

fn validate_no_unregistered_code(
    root: &Path,
    crate_scopes: &[Scope],
    artifact_scopes: &[ArtifactScope],
) -> Result<(), XtaskError> {
    let mut code_files = Vec::new();
    collect_repository_code(root, 0, &mut code_files)?;
    for file in code_files {
        let relative = file.strip_prefix(root).map_err(|source| {
            XtaskError::invalid_path(&file, format!("code file escaped workspace: {source}"))
        })?;
        let extension = relative.extension().and_then(std::ffi::OsStr::to_str);
        let registered = if extension == Some("rs") {
            crate_scopes
                .iter()
                .any(|scope| relative.starts_with(&scope.path))
        } else {
            artifact_scopes
                .iter()
                .any(|scope| relative.starts_with(&scope.path))
        };
        if !registered {
            return Err(XtaskError::invalid_path(
                &file,
                "code or executable source is outside every registered crate or artifact scope",
            ));
        }
    }
    Ok(())
}

fn collect_all_files(
    directory: &Path,
    depth: usize,
    files: &mut Vec<PathBuf>,
) -> Result<(), XtaskError> {
    if depth > 16 {
        return Err(XtaskError::invalid_path(
            directory,
            "artifact tree depth exceeds 16",
        ));
    }
    let entries = fs::read_dir(directory)
        .map_err(|source| XtaskError::io(format!("read {}", directory.display()), source))?;
    for entry in entries {
        let entry = entry
            .map_err(|source| XtaskError::io(format!("read {}", directory.display()), source))?;
        let file_type = entry
            .file_type()
            .map_err(|source| XtaskError::io("read artifact entry type", source))?;
        if file_type.is_symlink() {
            return Err(XtaskError::invalid_path(
                &entry.path(),
                "artifact symlinks are forbidden",
            ));
        }
        if file_type.is_dir() {
            collect_all_files(&entry.path(), depth + 1, files)?;
        } else if file_type.is_file() {
            files.push(entry.path());
        }
    }
    Ok(())
}

fn collect_repository_code(
    directory: &Path,
    depth: usize,
    files: &mut Vec<PathBuf>,
) -> Result<(), XtaskError> {
    if depth > 20 {
        return Err(XtaskError::invalid_path(
            directory,
            "repository tree depth exceeds 20",
        ));
    }
    let entries = fs::read_dir(directory)
        .map_err(|source| XtaskError::io(format!("read {}", directory.display()), source))?;
    for entry in entries {
        let entry = entry
            .map_err(|source| XtaskError::io(format!("read {}", directory.display()), source))?;
        let name = entry.file_name();
        if matches!(
            name.to_str(),
            Some(".git" | ".quality" | "target" | "mutants.out")
        ) {
            continue;
        }
        let file_type = entry
            .file_type()
            .map_err(|source| XtaskError::io("read repository entry type", source))?;
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            collect_repository_code(&entry.path(), depth + 1, files)?;
        } else if file_type.is_file() && is_code_extension(&entry.path()) {
            files.push(entry.path());
        }
    }
    Ok(())
}

fn is_code_extension(path: &Path) -> bool {
    matches!(
        path.extension().and_then(std::ffi::OsStr::to_str),
        Some(
            "rs" | "proto"
                | "go"
                | "py"
                | "ts"
                | "tsx"
                | "js"
                | "jsx"
                | "java"
                | "kt"
                | "cs"
                | "c"
                | "cc"
                | "cpp"
                | "h"
                | "hpp"
                | "swift"
                | "sh"
                | "bash"
                | "zsh"
        )
    )
}

fn validate_acyclic_edges(edges: &BTreeSet<(String, String)>) -> Result<(), XtaskError> {
    let mut graph = BTreeMap::<String, BTreeSet<String>>::new();
    for (caller, dependency) in edges {
        graph
            .entry(caller.clone())
            .or_default()
            .insert(dependency.clone());
        graph.entry(dependency.clone()).or_default();
    }
    let mut complete = BTreeSet::new();
    let mut visiting = BTreeSet::new();
    for node in graph.keys() {
        visit_node(node, &graph, &mut visiting, &mut complete)?;
    }
    Ok(())
}

fn visit_node(
    node: &str,
    graph: &BTreeMap<String, BTreeSet<String>>,
    visiting: &mut BTreeSet<String>,
    complete: &mut BTreeSet<String>,
) -> Result<(), XtaskError> {
    if complete.contains(node) {
        return Ok(());
    }
    if !visiting.insert(node.to_owned()) {
        return Err(XtaskError::invalid(
            "architecture edge registry",
            format!("cycle reaches `{node}`"),
        ));
    }
    if let Some(dependencies) = graph.get(node) {
        for dependency in dependencies {
            visit_node(dependency, graph, visiting, complete)?;
        }
    }
    visiting.remove(node);
    complete.insert(node.to_owned());
    Ok(())
}

fn registry_files(root: &Path) -> Result<Vec<PathBuf>, XtaskError> {
    let mut files = Vec::new();
    collect_registry_files(&root.join(ENGINEERING), 0, &mut files)?;
    for relative in [
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        "rustfmt.toml",
        "clippy.toml",
        "deny.toml",
        ".cargo/audit.toml",
        ".config/nextest.toml",
        ".gitleaks.toml",
        ".github/CODEOWNERS",
        ".github/repository-policy.json",
        ".github/workflows/quality.yml",
        ".github/workflows/extended.yml",
        ".githooks/pre-commit",
        ".githooks/pre-push",
        "AGENTS.md",
        "qualification/targets/registry.json",
        "qualification/fixtures/adversarial/manifest.json",
        "supply-chain/config.toml",
        "supply-chain/audits.toml",
        "supply-chain/imports.lock",
    ] {
        let path = root.join(relative);
        if !path.is_file() {
            return Err(XtaskError::invalid_path(
                &path,
                "required registry or policy input is missing",
            ));
        }
        files.push(path);
    }
    files.sort();
    files.dedup();
    Ok(files)
}

fn collect_registry_files(
    directory: &Path,
    depth: usize,
    files: &mut Vec<PathBuf>,
) -> Result<(), XtaskError> {
    if depth > 8 {
        return Err(XtaskError::invalid_path(
            directory,
            "registry directory depth exceeds 8",
        ));
    }
    let entries = fs::read_dir(directory)
        .map_err(|source| XtaskError::io(format!("read {}", directory.display()), source))?;
    for entry in entries {
        let entry = entry
            .map_err(|source| XtaskError::io(format!("read {}", directory.display()), source))?;
        let file_type = entry
            .file_type()
            .map_err(|source| XtaskError::io("read registry entry type", source))?;
        if file_type.is_symlink() {
            return Err(XtaskError::invalid_path(
                &entry.path(),
                "registry symlinks are forbidden",
            ));
        }
        if file_type.is_dir() {
            collect_registry_files(&entry.path(), depth + 1, files)?;
        } else if file_type.is_file() {
            files.push(entry.path());
        }
    }
    Ok(())
}

pub(crate) fn collect_files_with_extension(
    directory: &Path,
    extension: &str,
    depth: usize,
    files: &mut Vec<PathBuf>,
) -> Result<(), XtaskError> {
    if depth > 16 {
        return Err(XtaskError::invalid_path(
            directory,
            "source tree depth exceeds 16",
        ));
    }
    let entries = fs::read_dir(directory)
        .map_err(|source| XtaskError::io(format!("read {}", directory.display()), source))?;
    for entry in entries {
        let entry = entry
            .map_err(|source| XtaskError::io(format!("read {}", directory.display()), source))?;
        let file_type = entry
            .file_type()
            .map_err(|source| XtaskError::io("read source entry type", source))?;
        if file_type.is_symlink() {
            return Err(XtaskError::invalid_path(
                &entry.path(),
                "source symlinks are forbidden",
            ));
        }
        if file_type.is_dir() {
            collect_files_with_extension(&entry.path(), extension, depth + 1, files)?;
        } else if file_type.is_file()
            && entry.path().extension().and_then(std::ffi::OsStr::to_str) == Some(extension)
        {
            files.push(entry.path());
        }
    }
    Ok(())
}

fn package_name_from_manifest(path: &Path) -> Result<String, XtaskError> {
    let content = fs::read_to_string(path)
        .map_err(|source| XtaskError::io(format!("read {}", path.display()), source))?;
    let mut in_package = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_package = trimmed == "[package]";
            continue;
        }
        if in_package
            && let Some(value) = trimmed.strip_prefix("name = \"")
            && let Some(name) = value.strip_suffix('"')
        {
            return Ok(name.to_owned());
        }
    }
    Err(XtaskError::invalid_path(
        path,
        "could not find [package] name",
    ))
}

fn validate_relative_path(row: &Row, path: &Path) -> Result<(), XtaskError> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(row_error(
            row,
            format!(
                "path `{}` must be a non-empty repository-relative path",
                path.display()
            ),
        ));
    }
    Ok(())
}

fn extract_ids(content: &str, predicate: fn(&str) -> bool) -> BTreeSet<String> {
    content
        .split('`')
        .filter(|candidate| predicate(candidate))
        .map(str::to_owned)
        .collect()
}

fn valid_invariant_id(candidate: &str) -> bool {
    let Some((prefix, number)) = candidate.split_once('-') else {
        return false;
    };
    matches!(
        prefix,
        "ARC" | "RUST" | "SAFE" | "CON" | "ERR" | "SEC" | "DOC" | "TEST" | "PERF"
    ) && number.len() == 2
        && number.chars().all(|character| character.is_ascii_digit())
}

fn valid_gate_id(candidate: &str) -> bool {
    candidate == "EG-00"
        || candidate.strip_prefix("EG-").is_some_and(|suffix| {
            !suffix.is_empty()
                && suffix
                    .chars()
                    .all(|character| character.is_ascii_uppercase() || character == '-')
        })
}

fn valid_sha256_digest(candidate: &str) -> bool {
    candidate.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .chars()
                .all(|character| character.is_ascii_hexdigit())
    })
}

fn split_set(value: &str) -> BTreeSet<String> {
    split_list(value).into_iter().collect()
}

fn split_list(value: &str) -> Vec<String> {
    value
        .split('|')
        .filter(|item| !item.is_empty())
        .map(str::to_owned)
        .collect()
}

fn nonempty<'row>(row: &'row Row, name: &str) -> Result<&'row str, XtaskError> {
    let value = row.field(name)?;
    if value.trim().is_empty() {
        return Err(row_error(row, format!("field `{name}` is empty")));
    }
    Ok(value)
}

fn parse_positive_u64(row: &Row, name: &str) -> Result<u64, XtaskError> {
    let value = nonempty(row, name)?;
    let parsed = value.parse::<u64>().map_err(|source| {
        row_error(
            row,
            format!("field `{name}` is not an unsigned integer: {source}"),
        )
    })?;
    if parsed == 0 {
        return Err(row_error(row, format!("field `{name}` must be positive")));
    }
    Ok(parsed)
}

fn row_error(row: &Row, detail: impl Into<String>) -> XtaskError {
    XtaskError::invalid_path(&row.path, format!("line {}: {}", row.line, detail.into()))
}

fn set_difference_message(
    subject: &str,
    documented: &BTreeSet<String>,
    registered: &BTreeSet<String>,
) -> String {
    let missing = documented
        .difference(registered)
        .cloned()
        .collect::<Vec<_>>();
    let extra = registered
        .difference(documented)
        .cloned()
        .collect::<Vec<_>>();
    format!(
        "{subject} drift; missing [{}], extra [{}]",
        missing.join(", "),
        extra.join(", ")
    )
}

fn required_value<'values>(
    path: &Path,
    values: &'values BTreeMap<String, String>,
    key: &str,
) -> Result<&'values str, XtaskError> {
    values.get(key).map(String::as_str).ok_or_else(|| {
        XtaskError::invalid_path(path, format!("missing required exception key `{key}`"))
    })
}

fn parse_utc_timestamp(path: &Path, value: &str) -> Result<u64, XtaskError> {
    let Some((date, raw_time)) = value.split_once('T') else {
        return Err(XtaskError::invalid_path(path, "timestamp must contain `T`"));
    };
    let Some(time) = raw_time.strip_suffix('Z') else {
        return Err(XtaskError::invalid_path(
            path,
            "timestamp must use UTC suffix `Z`",
        ));
    };
    let mut date_parts = date.split('-');
    let year = parse_time_part(path, date_parts.next(), "year")?;
    let month = parse_time_part(path, date_parts.next(), "month")?;
    let day = parse_time_part(path, date_parts.next(), "day")?;
    if date_parts.next().is_some() {
        return Err(XtaskError::invalid_path(
            path,
            "timestamp date has extra fields",
        ));
    }
    let mut time_parts = time.split(':');
    let hour = parse_time_part(path, time_parts.next(), "hour")?;
    let minute = parse_time_part(path, time_parts.next(), "minute")?;
    let second = parse_time_part(path, time_parts.next(), "second")?;
    if time_parts.next().is_some()
        || !(1970..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(XtaskError::invalid_path(
            path,
            "timestamp components are out of range",
        ));
    }
    let days = days_since_unix_epoch(year, month, day).ok_or_else(|| {
        XtaskError::invalid_path(path, "timestamp does not represent a valid calendar date")
    })?;
    let seconds = days
        .checked_mul(86_400)
        .and_then(|value| value.checked_add(hour * 3_600))
        .and_then(|value| value.checked_add(minute * 60))
        .and_then(|value| value.checked_add(second))
        .ok_or_else(|| XtaskError::invalid_path(path, "timestamp arithmetic overflow"))?;
    u64::try_from(seconds).map_err(|source| {
        XtaskError::invalid_path(path, format!("timestamp before epoch: {source}"))
    })
}

fn parse_time_part(path: &Path, value: Option<&str>, name: &str) -> Result<i64, XtaskError> {
    let Some(value) = value else {
        return Err(XtaskError::invalid_path(
            path,
            format!("timestamp is missing {name}"),
        ));
    };
    value.parse::<i64>().map_err(|source| {
        XtaskError::invalid_path(path, format!("invalid timestamp {name}: {source}"))
    })
}

fn days_since_unix_epoch(year: i64, month: i64, day: i64) -> Option<i64> {
    let month_lengths = [31_i64, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let expected_days = if month == 2 && is_leap_year(year) {
        29
    } else {
        let index = usize::try_from(month.checked_sub(1)?).ok()?;
        *month_lengths.get(index)?
    };
    if day < 1 || day > expected_days {
        return None;
    }

    let mut days = 0_i64;
    for current_year in 1970..year {
        days = days.checked_add(if is_leap_year(current_year) { 366 } else { 365 })?;
    }
    for current_month in 1..month {
        let index = usize::try_from(current_month.checked_sub(1)?).ok()?;
        let mut length = *month_lengths.get(index)?;
        if current_month == 2 && is_leap_year(year) {
            length = 29;
        }
        days = days.checked_add(length)?;
    }
    days.checked_add(day.checked_sub(1)?)
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

#[cfg(test)]
mod tests {
    use super::{
        extract_ids, parse_table, parse_utc_timestamp, valid_gate_id, valid_invariant_id,
        valid_sha256_digest,
    };
    use std::collections::BTreeSet;
    use std::path::Path;

    #[test]
    fn parses_a_strict_tab_separated_registry() {
        let table = parse_table(
            Path::new("test.tsv"),
            "alpha\tbeta\none\ttwo\n",
            &["alpha", "beta"],
        );
        assert!(table.is_ok(), "valid strict TSV should parse");
    }

    #[test]
    fn rejects_a_registry_with_the_wrong_field_count() {
        let table = parse_table(
            Path::new("test.tsv"),
            "alpha\tbeta\none\n",
            &["alpha", "beta"],
        );
        assert!(table.is_err(), "truncated strict TSV must fail closed");
    }

    #[test]
    fn extracts_only_well_formed_contract_identities() {
        let content = "`ARC-01` `ARC-1` `EG-ARCH` `EG-lower`";
        let invariants = extract_ids(content, valid_invariant_id);
        let gates = extract_ids(content, valid_gate_id);
        assert_eq!(
            invariants,
            BTreeSet::from(["ARC-01".to_owned()]),
            "only exact invariant identities are accepted"
        );
        assert_eq!(
            gates,
            BTreeSet::from(["EG-ARCH".to_owned()]),
            "only exact gate identities are accepted"
        );
    }

    #[test]
    fn validates_exact_digests_and_utc_exception_times() {
        assert!(
            valid_sha256_digest(
                "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            ),
            "an exact lowercase SHA-256 digest should be accepted"
        );
        assert!(
            !valid_sha256_digest("sha256:not-a-digest"),
            "partial or symbolic digests must fail closed"
        );
        assert!(
            matches!(
                parse_utc_timestamp(Path::new("exception.toml"), "1970-01-01T00:00:00Z"),
                Ok(0)
            ),
            "the Unix epoch should parse exactly"
        );
        assert!(
            parse_utc_timestamp(Path::new("exception.toml"), "2026-02-30T00:00:00Z").is_err(),
            "invalid calendar dates must fail closed"
        );
    }
}
