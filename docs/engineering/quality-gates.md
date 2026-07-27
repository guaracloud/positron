# Positron engineering quality gates

> Status: binding enforcement for
> [Positron engineering standards](standards.md). Product qualification remains
> governed by the [Release 1 Qualification Matrix](../release-1-qualification.md).

## 1. Gate contract

M0 MUST provide one Rust gate runner, invoked as `cargo xtask quality`, and
machine-readable registries under `qualification/engineering/` for gates,
owners, thresholds, toolchains, scopes, and exceptions. CI calls only this
runner; duplicated shell policy is not authoritative. Each gate pins its tools,
declares a finite time and resource budget, and emits schema-validated JSON.
Uppercase requirement words use their BCP 14 meanings.

`EG-00` is the always-running aggregator. It MUST:

1. prove that every invariant in `standards.md` appears exactly once in the
   mapping below and has a gate, evidence schema, and owner, while the gate
   registry supplies its exception class;
2. select gates from the committed dependency and risk map, never from an
   untrusted path filter;
3. verify the source or merge-group revision, inputs, tool identity, result,
   and evidence digests of every selected gate; and
4. fail if a check is missing, skipped, cancelled, timed out, flaky, stale,
   produced by an untrusted source, or covered by an invalid exception.

A retry is a new attempt and cannot erase the first result. A timeout is a
failure, not a skip. Review is additional evidence and cannot turn a red gate
green.

### Execution stages

| Stage | Blocking rule |
| --- | --- |
| `PR` | Runs on every pull request and merge-group revision. All selected checks and required owner reviews MUST pass before merge. |
| `EXT` | Runs bounded smoke checks on affected pull requests and full pinned campaigns on the protected branch at the registry cadence. Failure freezes the mapped owner paths and blocks candidate qualification until fixed and rerun. |
| `QUAL` | Runs against the exact release artifact and every required target. Results enter the existing immutable Qualification Evidence contract; only `Qualified` cells permit release. |

Path selection may reduce work only when the committed dependency map proves a
gate unaffected. `EG-00` still runs and records the omission. Lightweight
format, policy, architecture, dependency, documentation, and secret checks are
never path-filtered.

## 2. Evidence and ownership

Every attempt records:

- invariant and gate IDs, result, start/end time, and attempt identity;
- source revision, merge-group revision, artifact and Release Manifest digests;
- registry, gate-definition, toolchain, dependency, fixture, corpus, seed,
  fault-schedule, configuration, environment, and target digests;
- exact command, declared resource budget, raw report, measurements with units,
  logs allowed by the diagnostic policy, and minimized failure reproducer;
- accountable owner, required approvals, and any exceptional-state identity.

`PR` and `EXT` reports are immutable CI artifacts retained by the policy
registry. `QUAL` evidence uses
`qualification/evidence/<release>/<gate>/<target>/<attempt>/` as already
defined. Passing, failing, inconclusive, and exceptional attempts are retained.

Existing Qualification Matrix roles remain authoritative for release cells.
Engineering enforcement adds three cross-cutting roles: **Architecture**,
**Rust and Toolchain**, and **Quality Engineering**. `Module owner` resolves to
the single semantic owner in `application-design.md` and the owner registry.
Every row below has one accountable role; contributors do not split
accountability.

## 3. Invariant-to-gate map

### Architecture and Rust

| Invariant | Gate / stage | Automated enforcement | Required evidence | Accountable owner |
| --- | --- | --- | --- | --- |
| `ARC-01` | `EG-ARCH` / `PR` | Contract-diff classifier requires the owning ADR/design/qualification and gate updates; authority and trace links validate. | `contract-trace.json`, changed-contract diff, decision digest | Architecture |
| `ARC-02` | `EG-ARCH` / `PR` | `cargo metadata --locked` graph is compared with the edge allowlist; cycles, forbidden imports, globals/locators, utility/manager, pass-through, and provider leaks fail. | resolved crate graph and policy diff | Architecture |
| `ARC-03` | `EG-ARCH` / `PR` | Crate, trait, adapter, feature, and public-surface diffs must match the seam registry; deferred-runtime symbols and features are denied. | architecture surface report and seam record | Architecture |
| `ARC-04` | `EG-ARCH` / `PR+EXT` | Boundary dependency rules, compile-fail type-state tests, schema validation, and hostile-input property/fuzz tests prove conversion into checked native states. | boundary report, UI-test results, minimized corpus failures | Module owner |
| `ARC-05` | `EG-CORRECT` / `PR+EXT+QUAL` | State-model and crash/fault tests cover every commit, acknowledgment, audit, idempotency, cancellation, and irreversible boundary. | publication fault matrix, commit receipts, mapped Qualification Cell results | Architecture |
| `RUST-01` | `EG-RUST` / `PR` | Workspace metadata enforces Rust-only ownership, edition 2024, resolver 3, exact stable toolchain, `rust-version`, targets, and declared layout. | toolchain and workspace manifest report | Rust and Toolchain |
| `RUST-02` | `EG-BUILD` / `PR+QUAL` | Clean locked stable/MSRV builds, isolated frozen release builds, overflow/profile checks, and twice-run generation/rebuild comparisons must agree. | build plan, lock digest, profile report, reproducibility diff | Rust and Toolchain |
| `RUST-03` | `EG-RUST` / `PR` | `rustfmt`, rustc, selected Clippy matrix, rustdoc, examples, and doctests run warning-free; lint levels and scoped expectations validate. | lint matrix, docs report, expectation registry diff | Rust and Toolchain |
| `RUST-04` | `EG-DEPS` / `PR` | Dependency/feature inventory rejects unused or duplicate capability, unapproved source/features, undeclared ownership, and public dependency-type leakage. | dependency review record, feature matrix, public API diff | Rust and Toolchain |

### Safety, concurrency, and errors

| Invariant | Gate / stage | Automated enforcement | Required evidence | Accountable owner |
| --- | --- | --- | --- | --- |
| `SAFE-01` | `EG-SAFETY` / `PR` | Source and expansion inventory rejects owned unsafe outside the exact allowlist and verifies `forbid(unsafe_code)` on ordinary crates. | unsafe inventory and allowlist diff | Security and Key Management |
| `SAFE-02` | `EG-SAFETY` / `PR+EXT` | Safety docs and adjacent `SAFETY` reasons are linted; pinned Miri, applicable sanitizers, fuzz, and property suites run for each unsafe scope. | safety case, Miri/sanitizer reports, corpus and property results | Security and Key Management |
| `SAFE-03` | `EG-SAFETY` / `PR+EXT` | Checked-arithmetic/conversion policy plus adversarial bound, allocation, decompression, nesting, and reservation tests run under resource ceilings. | bounds matrix, peak-resource report, minimized failing inputs | Module owner |
| `SAFE-04` | `EG-INTEGRITY` / `PR+EXT+QUAL` | Version, bounds, authentication, corruption, wrong-key/context, unsupported-format, and pre-decode observation tests execute across persistent object kinds. | integrity vectors, corruption/fault matrix, zeroization evidence | Security and Key Management |
| `CON-01` | `EG-CONCURRENCY` / `PR+EXT` | Spawn-call policy permits only registered task scopes; shutdown tests reconcile task registration, cancellation, join, and leak counts. | task graph and shutdown reconciliation report | Application Runtime |
| `CON-02` | `EG-RESOURCE` / `PR+EXT+QUAL` | Unbounded API denylist, capacity registry, reservation accounting, saturation, and overload tests cover every concurrency resource. | bound inventory, reservation ledger, pressure-run results | Storage Kernel |
| `CON-03` | `EG-CONCURRENCY` / `PR+EXT` | Cancellation/retry state models and fault tests exercise deadlines, idempotency, commit points, cleanup, and post-boundary recovery. | operation model traces and reservation-leak report | Module owner |
| `CON-04` | `EG-CONCURRENCY` / `PR+EXT` | Async-lock and blocking-call lints, bounded-executor tests, targeted Loom models, and applicable ThreadSanitizer jobs must pass. | lint report, executor saturation result, model schedules | Rust and Toolchain |
| `CON-05` | `EG-CONCURRENCY` / `PR+EXT+QUAL` | Virtual-time/entropy tests, retry-storm and fairness models, plus shutdown and maintenance soaks prove bounded progress. | seeds, schedules, fairness metrics, soak result | Application Runtime |
| `ERR-01` | `EG-ERROR` / `PR+QUAL` | One generated error catalog maps typed outcomes across gRPC, HTTP Problem Details, OTLP, CLI, audit, and health; compatibility tests prove parity. | catalog digest, mapping and old/new conformance report | Public API and SDK |
| `ERR-02` | `EG-ERROR` / `PR` | Workspace lints deny panic macros and assertions, unwrap/expect, unchecked indexing, ignored results, TODO stubs, and unreachable runtime paths in production targets. | lint report and exact expectation records | Rust and Toolchain |
| `ERR-03` | `EG-ERROR` / `PR+EXT` | Error-chain tests, result-use analysis, single-owner diagnostic tests, and seeded redaction canaries cover every boundary. | causal-chain snapshots and redaction report | Module owner |
| `ERR-04` | `EG-ERROR` / `PR+EXT+QUAL` | Negative and injected-failure suites prove fail-closed unknowns, explicit partial/ambiguous outcomes, retry classes, and no false success. | outcome matrix and mapped Qualification Cell results | Public API and SDK |

### Security and documentation

| Invariant | Gate / stage | Automated enforcement | Required evidence | Accountable owner |
| --- | --- | --- | --- | --- |
| `SEC-01` | `EG-SECURITY` / `PR+EXT` | Boundary-change rules require a current threat model and security owner; the mapped abuse suite must run. | threat-model digest, attack-surface diff, adversarial results | Security and Key Management |
| `SEC-02` | `EG-SECURITY` / `PR+EXT+QUAL` | Authn/authz, non-enumeration, cross-tenant property/fuzz, confused-deputy, cache-key, backup/restore/purge, and impersonation tests fail closed. | attribution/isolation matrix and exact target results | Identity and Governance |
| `SEC-03` | `EG-CRYPTO` / `PR+EXT+QUAL` | Crypto dependency/algorithm allowlist, known-answer and cross-target vectors, nonce/restart properties, and key lifecycle/provider failure suites run. | crypto inventory, vector digests, nonce and lifecycle reports | Security and Key Management |
| `SEC-04` | `EG-SECRETS` / `PR+EXT+QUAL` | Static/history secret scanners and unique canaries scan logs, errors, telemetry, panic/crash data, diagnostics, evidence, binaries, and every artifact. | scanner reports, canary manifest, redaction report | Security and Key Management |
| `SEC-05` | `EG-SUPPLY` / `PR+QUAL` | Locked source/advisory/license/ban/Vet policy passes; exact artifacts produce validated SPDX/CycloneDX SBOMs, independent payload comparison, signatures, and verified provenance. | policy reports, SBOMs, repro diff, signature/provenance verification | Release Engineering |
| `DOC-01` | `EG-DOCS` / `PR` | Missing-doc and contract-section lints cover public and sensitive internal interfaces; examples compile. | rustdoc JSON and interface-documentation report | Module owner |
| `DOC-02` | `EG-DOCS` / `PR+QUAL` | Clean pinned regeneration, rustdoc/doctests, diagrams, local/external links, schema digests, and generated-artifact cleanliness validate. | generation diff, link report, documentation artifact digest | Public API and SDK |
| `DOC-03` | `EG-POLICY` / `PR` | Contract-sensitive path and API/format diffs require an accepted ADR plus implementation, migration, test, and gate references in the same revision. | policy trace report and ADR status digest | Architecture |
| `DOC-04` | `EG-DOCS` / `PR` | User/operation change map requires compatibility, migration, failure, recovery, and release-note coverage; TODO/disabled-check registry and dead-code scan validate owner and expiry. | documentation map, temporary-work registry, scan report | Diagnostics and Operations |

### Testing and performance

| Invariant | Gate / stage | Automated enforcement | Required evidence | Accountable owner |
| --- | --- | --- | --- | --- |
| `TEST-01` | `EG-TEST` / `PR` | Change-risk map requires positive, boundary, negative, adversarial, and defect-regression cases; selected suites must pass without missing-test exception. | test-to-invariant trace and test results | Quality Engineering |
| `TEST-02` | `EG-TEST` / `PR+EXT` | Hermetic runner fixes environment and seeds, exercises parallel/order variants, detects leaks and undeclared I/O, and treats any retry pass, ignore, or quarantine as failure. | test results, seed/schedule manifest, flake report | Quality Engineering |
| `TEST-03` | `EG-MATRIX` / `PR+EXT+QUAL` | Risk map selects compile-fail, unit, contract, property, integration, end-to-end, compatibility, platform, and real-target suites; mocks cannot satisfy provider cells. | selected-matrix proof and per-target results | Quality Engineering |
| `TEST-04` | `EG-DYNAMIC` / `PR+EXT` | Scope registry requires applicable property/model/fuzz/corpus/Miri/sanitizer/Loom jobs and fails on missing, stale, or silently weakened targets. | tool/version report, corpora, models, raw detector results | Quality Engineering |
| `TEST-05` | `EG-FAULT` / `PR+EXT+QUAL` | Instrumented publication-point registry is matched one-to-one with partial-write, crash, restart, corruption, full-disk, clock, cancellation, network, and provider cases. | fault-coverage matrix and recovery-state digests | Quality Engineering |
| `TEST-06` | `EG-COVERAGE` / `PR+EXT` | Pinned line/region/branch and mutation tools enforce frozen M0 thresholds, no-regression ratchets, critical-path traceability, and exact exclusion/equivalent-mutant records. | coverage files, mutation report, ratchet and exclusion diff | Quality Engineering |
| `TEST-07` | `EG-EVIDENCE` / `PR+QUAL` | Evidence schema validates revision/artifact/target identity; black-box qualification rejects private-crate proof and aggregate or overwritten cell results. | signed evidence index, artifact digest, retained attempt chain | Release Engineering |
| `PERF-01` | `EG-RESOURCE` / `PR+EXT` | Interface budget registry, complexity checks, adversarial cardinality/size tests, and resource telemetry reject ungoverned growth and missing overload behavior. | budget map, complexity review, resource maxima | Performance Qualification |
| `PERF-02` | `EG-PERF` / `PR+QUAL` | Benchmarks compile and smoke in PR; qualification validates frozen environment/workload/objective digests before running on a dedicated host. | preregistration digest, runner identity, raw samples | Performance Qualification |
| `PERF-03` | `EG-PERF` / `QUAL` | Same-host baseline/candidate analysis checks throughput, latency distribution, CPU, RSS, allocation, I/O, amplification, availability, and recovery against frozen uncertainty-aware limits. | profiles, raw samples, confidence analysis, multidimensional verdict | Performance Qualification |
| `PERF-04` | `EG-SOAK` / `EXT+QUAL` | Exact-artifact mixed workload, fault, and recovery soaks enforce declared duration and every resource/backlog ceiling plus eventual-progress assertions. | workload/fault digests, time series, leak/backlog and recovery verdict | Performance Qualification |

## 4. Protected change policy

The protected branch and merge queue MUST require:

- a pull request; current-base and `merge_group` execution; `EG-00`; all
  selected gate checks; resolved review threads; and current CODEOWNER approval;
- approval of the latest pushed revision by someone other than its author, with
  stale approvals dismissed;
- trusted check sources, least-privilege CI permissions, full-commit pinning for
  third-party automation, and separation of untrusted test jobs from secrets;
- no direct push, force-push, branch deletion, administrator bypass, or
  self-approved change to gates, owners, CODEOWNERS, workflows, or rulesets; and
- promotion of the already verified artifact digest. Publication MUST NOT
  rebuild different bytes.

CODEOWNERS MUST protect architecture, public APIs, storage/durability,
identity/tenancy, cryptography, unsafe code, dependencies/licenses, CI/release,
engineering policy, and CODEOWNERS/ruleset definitions themselves.

## 5. Exception process

### Non-waivable

The non-waivable gates in `release-1-qualification.md` have no exception path.
Nor may an exception waive evidence integrity, permit a secret disclosure, or
turn a known correctness, safety, security, durability, isolation, or
authenticity failure into success. A fundamental change uses the superseding
ADR and release-scope process, never this process.

### Temporary exceptions

Every other exception is a signed,
`qualification/engineering/exceptions/EXC-<year>-<sequence>.toml` record. It
MUST name exactly one invariant and gate, exact paths/artifact/target, failure
and evidence digests, rationale, risk, compensating control and its passing
evidence, accountable owner, independent domain approver, tracking issue,
creation time, removal condition, and an expiry no later than 14 calendar days.
The author cannot approve it.

CI reports the gate as `exceptional`, never `passed`. Wildcard,
repository-wide, inherited, post-hoc, or open-ended exceptions are invalid.
Deadline pressure, inconvenience, flaky behavior, “existing code,” missing
tests, or an unavailable owner are not rationales. Scope expansion or expiry
fails closed.

There is no in-place renewal. One successor of at most seven days requires new
failure and compensating evidence plus fresh approval from the accountable
owner, independent domain owner, Architecture, and Quality Engineering.
Unresolved work after that blocks merge.

A production-security or data-safety emergency may defer only eligible `EXT`
work for at most 24 hours with two independent approvals, an incident ID,
rollback plan, and audit record. All `PR` checks and all non-waivable or
artifact-qualification evidence still run. The deferred work and incident
review become blocking at expiry.

### Policy and baseline changes

Changing a gate, tool, threshold, target, corpus, fixture, or performance
baseline is a policy change, not an exception. The change MUST:

1. preserve the old result and all negative evidence;
2. explain detection gained and lost, affected invariants, and migration;
3. dual-run old and new enforcement on representative revisions;
4. receive Architecture, Quality Engineering, and accountable-domain approval;
   and
5. use a superseding ADR when it affects caller knowledge, compatibility,
   durable formats, release scope, or a non-waivable invariant.

A policy change cannot silently make the behavior change in the same pull
request green. Thresholds may tighten normally; weakening after an observed
failure requires an independently approved policy change with the failed result
retained.
