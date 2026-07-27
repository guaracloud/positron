# Positron engineering standards

> Status: binding for every implementation, test, tool, integration, and
> distribution artifact in this repository.
>
> Rationale and primary sources:
> [engineering standards evidence](../research/engineering-standards-evidence.md).

## 1. Contract

Uppercase requirement words use their BCP 14 meanings; `MUST`, `MUST NOT`, and
`REQUIRED` are release-blocking. Positron does not satisfy an invariant through
review opinion alone: its mapped gate in
[quality-gates.md](quality-gates.md) must produce valid evidence for the exact
source revision and, where applicable, the exact built artifact.

The frozen [project baseline](../../project-positron.md), binding
[language](../../CONTEXT.md), accepted [ADRs](../adr/), and
[Release 1 Qualification Matrix](../release-1-qualification.md) remain
authoritative. The [whole-application design](../application-design.md) governs
implementation shape unless a superseding ADR changes a normative decision.
These standards add implementation discipline; they cannot weaken those
contracts.

M0 MUST implement the gate registry and merge protection described in
`quality-gates.md` before production feature code may merge. Generated code is
held to its generator and artifact gates; handwritten edits to generated output
are forbidden.

## 2. Architecture

| ID | Mandatory invariant |
| --- | --- |
| `ARC-01` | Code MUST preserve the authoritative contracts. A change to caller knowledge, ownership, a durable format, compatibility, a non-waivable invariant, or Release 1 scope requires an accepted superseding ADR and corresponding contract, test, and gate changes in the same change set. |
| `ARC-02` | Every behavior and durable state MUST have one semantic owner. Dependencies MUST follow the acyclic graph in `application-design.md`, enter through composition, and never use a service locator, mutable global, generic utility or manager module, forwarding module, or cross-layer provider access. |
| `ARC-03` | Modules MUST be deep and concrete by default. A trait is permitted only at a justified varying seam with at least two real adapters, or as a private deterministic fault seam owned by one module. Deferred signals and clustering MUST NOT create Release 1 runtime code or feature flags. |
| `ARC-04` | Each wire, configuration, provider, and persistence boundary MUST validate once and convert into invariant-bearing native types. Types MUST distinguish tenant, scope, signal, time, unit, lifecycle, and pre/post-validation states; later states MUST NOT expose unchecked public constructors. |
| `ARC-05` | Acknowledgment and publication MUST follow the owning durable commit. Crash recovery MUST expose a complete predecessor or successor, never mixed state; governance state and audit evidence publish jointly; long operations are idempotent, restartable, and explicit about cancellation and irreversible boundaries. |

## 3. Rust

| ID | Mandatory invariant |
| --- | --- |
| `RUST-01` | All reusable application and domain behavior MUST remain Rust. The workspace MUST use Rust 2024, resolver 3, an exact pinned stable toolchain, and an explicit `rust-version`; toolchain changes are isolated, reviewed changes. |
| `RUST-02` | `Cargo.lock`, build tools, generators, profiles, and external inputs MUST be pinned. Build, test, generation, and release commands MUST use locked resolution and reproduce from a clean checkout. Integer overflow checks remain enabled in release profiles and wrapping arithmetic MUST be explicit. A pinned nightly MAY run analysis tools, but production code MUST build on the declared stable toolchain and minimum supported Rust version. |
| `RUST-03` | Formatting, compiler warnings, rustdoc warnings, and the selected stable Clippy lint set MUST be clean across every supported target and feature combination. Workspace lints are inherited and MUST NOT be lowered. A local lint expectation requires the narrowest scope, a reason, and a tracked removal issue; blanket allowances are forbidden. |
| `RUST-04` | Dependencies and features MUST be minimal, maintained, and owned. A new dependency requires recorded necessity, source, license, security, maintenance, and feature review. Duplicate capabilities, unused dependencies, unnecessary default features, and dependency-specific types leaking across module interfaces are forbidden. |

## 4. Safety

| ID | Mandatory invariant |
| --- | --- |
| `SAFE-01` | `unsafe` Rust is forbidden by default. A need that safe Rust cannot meet MUST be isolated behind a safe interface in the smallest approved crate or module; unsafe code, unsafe macros, FFI, and unsafe trait implementations outside that boundary are forbidden. |
| `SAFE-02` | Every approved unsafe boundary MUST define its safety invariants, caller obligations, aliasing and lifetime assumptions, and failure modes. Every unsafe operation requires a local `SAFETY` justification, `unsafe_op_in_unsafe_fn` is denied, and targeted Miri, sanitizer, fuzz, and property evidence is mandatory. No safe call may make undefined behavior possible. |
| `SAFE-03` | Untrusted or durable lengths, counts, offsets, nesting, compression ratios, arithmetic, conversions, allocations, copies, and indexing MUST be checked against hard limits before use and after expansion. Work MUST acquire its resource reservation before parsing or allocation can consume that resource. |
| `SAFE-04` | Persistent and encrypted bytes MUST pass format-version, bounds, authenticity, and integrity verification before decoding or observation. Corrupt, unauthenticated, ambiguous, or unsupported data MUST never be returned as valid; sensitive transient material MUST be minimized and zeroized. |

## 5. Concurrency

| ID | Mandatory invariant |
| --- | --- |
| `CON-01` | Every task MUST have one lifecycle owner, be registered before spawn, inherit cancellation, and be joined or deterministically aborted during owner shutdown. Detached tasks and direct spawning outside the approved runtime or maintenance task scopes are forbidden. |
| `CON-02` | Every queue, channel, semaphore, buffer, cache, batch, lease, retry set, and backlog MUST have an explicit finite bound and Resource Governor charge. Unbounded concurrency APIs are forbidden; overload MUST return a stable typed outcome without consuming unreserved capacity. |
| `CON-03` | Every asynchronous operation MUST specify its deadline, cancellation point, retry class, idempotency behavior, commit point, and cleanup. Cancellation MUST release reservations and MUST NOT lose acknowledged work, publish partial state, or claim reversal after an irreversible boundary. |
| `CON-04` | Blocking I/O or CPU work MUST NOT run on asynchronous worker threads. It uses a bounded, reserved executor. A lock guard MUST NOT cross an await or blocking call; lock order and atomic memory ordering MUST be explicit and model-tested where correctness depends on interleaving. |
| `CON-05` | Time, randomness, faults, and scheduling decisions MUST be injectable in tests. Retries are bounded by attempts and elapsed budget, use jitter where synchronized retries are possible, and cannot prevent fairness, eventual maintenance progress, or bounded shutdown. |

## 6. Error handling

| ID | Mandatory invariant |
| --- | --- |
| `ERR-01` | Module boundaries MUST return closed, typed outcomes. Public failures MUST map to a versioned stable error code, safe details, retry classification, and completion state; strings MUST NOT drive control flow or compatibility. |
| `ERR-02` | Production paths MUST NOT use `unwrap`, `expect`, `panic`, panicking assertions, `todo`, `unimplemented`, `unreachable`, unchecked indexing, or ignored `Result` values for runtime-controlled state. Infallibility MUST be established by types or converted into an explicit error or fenced state. |
| `ERR-03` | Errors MUST retain their source and operation context, be classified once by the semantic owner, and redact secrets and tenant data. Errors MUST NOT be swallowed, downgraded, or logged-and-continued; the owning boundary records one actionable, bounded diagnostic. |
| `ERR-04` | Authentication, authorization, Tenant Attribution, governance audit, cryptography, integrity, and durability uncertainty MUST fail closed. Partial success, commit ambiguity, degraded service, and retryability MUST remain explicit and MUST never be represented as complete success. |

## 7. Security

| ID | Mandatory invariant |
| --- | --- |
| `SEC-01` | Every trust boundary MUST have a versioned threat model covering assets, actors, abuse cases, limits, failure behavior, and mitigations before implementation. Changes to authentication, cryptography, persistence, parsers, listeners, providers, privileges, or release trust require security-owner review and adversarial tests. |
| `SEC-02` | Principal, Scope, and exactly one Tenant ID MUST be established before payload decoding or resource admission. Least privilege, non-enumeration, scoped credentials, and physical tenant isolation are mandatory; ambient authority, forwarded authorization, and administrator data-plane impersonation are forbidden. |
| `SEC-03` | Verified TLS and authenticated encryption at rest are defaults. Only reviewed, maintained cryptographic implementations and approved algorithms may be used; custom cryptography is forbidden. Key identity, context binding, nonce uniqueness, rotation, recovery, expiry, and zeroization MUST have vectors and failure tests. |
| `SEC-04` | Secret-bearing types MUST redact output and minimize cloning and serialization. Production credentials, keys, tokens, real tenant telemetry or query results, and sensitive paths MUST NOT enter logs, errors, metrics, traces, diagnostics, crash records, build output, or artifacts. Fixtures MUST use synthetic non-production values; seeded canaries MUST traverse each subsystem and prove exclusion from prohibited outputs. |
| `SEC-05` | Dependency sources, advisories, licenses, bans, and provenance MUST pass policy. Releases require locked inputs, secret and artifact scans, SPDX and CycloneDX SBOMs, reproducible payload evidence, signatures, and verifiable provenance. A known exploitable critical issue or unexplained artifact drift blocks release. |

## 8. Documentation

| ID | Mandatory invariant |
| --- | --- |
| `DOC-01` | Every public crate, module, type, and interface MUST document the applicable purpose, ownership, invariants, valid states, ordering, errors, resource and performance bounds, concurrency and cancellation, security assumptions, and a checked example where useful. |
| `DOC-02` | API, configuration, schemas, error catalogs, durable-format specifications, and generated SDK documentation MUST have one canonical source and reproducible generation. Rustdoc, doctests, examples, diagrams, and internal links MUST be warning-free and current. Generated output MUST NOT be edited by hand. |
| `DOC-03` | An ADR is REQUIRED before changing an interface contract, ownership, durable format, compatibility promise, security or safety invariant, non-waivable gate, or release scope. The accepted decision, implementation, migration, tests, and gate updates MUST land together. |
| `DOC-04` | User-visible and operator-visible behavior MUST include compatibility, migration, failure, and recovery documentation before merge. `TODO`, `FIXME`, temporary flags, and disabled checks require an owner, linked issue, and expiry; commented-out code and undocumented permanent workarounds are forbidden. |

## 9. Testing

| ID | Mandatory invariant |
| --- | --- |
| `TEST-01` | Every behavior change MUST include positive, boundary, negative, and adversarial tests at the lowest interface that proves the contract. A reproducible defect fix begins with a failing regression test and retains the reproducer; “not tested” is not an acceptable completion state. |
| `TEST-02` | Tests MUST assert returned outcomes, durable externally readable state, or published behavior rather than private fields, helper calls, queue layouts, or incidental ordering. Tests are hermetic, deterministic, parallel-safe, and retain random seeds and fault schedules. Retry-to-green, order dependence, ignored tests, and unexplained quarantine are failures. |
| `TEST-03` | Each change MUST run its risk-mapped unit, compile-fail, contract, property, integration, end-to-end, compatibility, and platform suites. Local substitutes use real temporary resources; mocks prove only caller behavior. Named providers and platforms qualify only against pinned real targets and the built artifact. |
| `TEST-04` | Parsers, persistence, cryptography, unsafe boundaries, and concurrency MUST receive the applicable complementary property, model, fuzz, corpus-regression, Miri, sanitizer, and concurrency-interleaving checks. A clean result from one technique MUST NOT substitute for techniques that detect different defect classes. |
| `TEST-05` | Fault injection MUST cover every durability publication point and relevant cancellation, crash, restart, corruption, full-disk, clock, network, and provider boundary. Tests MUST prove predecessor-or-successor state, acknowledged-data recovery, bounded cleanup, and truthful failure. |
| `TEST-06` | M0 MUST freeze line, region, branch, changed-code, and mutation thresholds from measured harness baselines before feature implementation. Coverage and mutation results MUST never regress; critical invariant paths require explicit test traceability, and no surviving non-equivalent mutant may violate an invariant. Exclusions require an exact registered reason. Numeric scores are detector evidence, never substitutes for behavioral proof. |
| `TEST-07` | Merge evidence MUST identify the exact source revision. Qualification MUST execute through published interfaces against the exact candidate artifact and target. Passing and failing evidence is immutable and target-specific; a later pass MUST NOT erase a failure or collapse independent cells. |

## 10. Performance

| ID | Mandatory invariant |
| --- | --- |
| `PERF-01` | Every hot or externally reachable interface MUST declare finite input, work, memory, allocation, copy, I/O, task, queue, and latency budgets with explicit overload behavior. Algorithms whose resource use can grow without a governed bound are forbidden. |
| `PERF-02` | Benchmarks MUST preregister hardware, topology, limits, toolchain, dataset and seed, workload, concurrency, warm-up, samples, statistics, noise threshold, and pass criteria before candidate tuning. Baseline and raw results are versioned and retained; observed failures cannot select a new objective retroactively. |
| `PERF-03` | A change MUST stay within preregistered throughput, tail-latency, RSS, allocation, I/O, amplification, availability, and recovery budgets. An optimization requires a profile and reproducible before/after evidence and MUST report every material tradeoff; a microbenchmark alone is never an overall performance claim. |
| `PERF-04` | Mixed-workload soak and fault runs MUST prove bounded memory, descriptors, tasks, queues, caches, leases, temporary files, disk headroom, retry state, and maintenance backlog, plus eventual progress and recovery. The exact release artifact MUST pass the complete declared duration on each required profile. |

## 11. Compliance rule

A green gate proves only the declared check on its identified inputs; it is not
proof that defects are impossible. Review supplements automation but never
replaces missing gate evidence. If an invariant cannot yet be enforced, the
affected implementation is not ready to merge.
