# Engineering Standards and Quality-Gate Evidence

Research snapshot: 2026-07-27

## Purpose and evidence labels

This note is the source rationale for Positron's engineering standards and quality-gate
policy. It does not itself replace the accepted architecture or create a new normative
contract.

The labels below deliberately separate existing requirements, external facts, and
recommendations:

- **Local contract** — already binding through Positron's accepted project, design, ADR, or
  qualification documents.
- **External requirement** — normative behavior from a protocol or standard Positron has
  already selected.
- **Tool fact** — behavior or limitation documented by the primary tool or language source.
- **Recommendation** — a proposed Positron invariant or gate derived from the cited evidence;
  it becomes mandatory only when adopted in the engineering standards.

Future normative documents should use the uppercase terms from BCP 14 only in their defined
sense; RFC 8174 clarifies that the special meanings apply only to uppercase terms
([RFC 2119](https://www.rfc-editor.org/rfc/rfc2119),
[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174.html)).

## 1. Binding Positron baseline

The engineering policy must strengthen, and must not reinterpret, these accepted contracts:

| Existing contract | Consequence for engineering policy |
| --- | --- |
| Release 1 is one standalone Rust database with native Log and Trace stores and separately required integration and distribution artifacts ([scope ledger](../release-1-qualification.md#2-scope-ledger), [ADR-0027](../adr/0027-implement-the-positron-application-entirely-in-rust.md)). | The policy covers the server, operator, CLI, generated/public surfaces, qualification tooling, distributions, and host-required integration code. A green server-only build is not a product-quality result. |
| The application design defines inward dependency direction, rejects cycles, and gives the Storage Kernel no dependency on protocols, query syntax, signal-specific layouts, or provider SDKs ([dependency direction](../application-design.md#32-dependency-direction), [workspace graph](../application-design.md#8-proposed-rust-workspace)). | Architecture checks must enforce the declared crate graph and forbidden edges, not merely successful compilation. |
| Deep modules own behavior behind narrow typed interfaces; callers must not locate global dependencies, use stringly errors, or rely on hidden best-effort side effects ([module design](../application-design.md#2-design-rules)). | Interface review, visibility, dependency injection, typed outcomes, and deterministic fault seams are code-quality invariants. |
| Durability, integrity, authenticated encryption, secret protection, tenant isolation, no impersonation, governance atomicity, bounded resources, verified restore, purge, and artifact authenticity are non-waivable ([qualification gates](../release-1-qualification.md#3-non-waivable-gates)). | No lint suppression, test waiver, risk acceptance, or release exception may waive evidence needed to protect one of these properties. |
| Release 1 uses one hand-edited versioned Protobuf public definition, additive-compatible v1 evolution, pinned generation, schema digests, and generated clients ([ADR-0028](../adr/0028-use-one-versioned-protobuf-definition-for-public-apis-and-sdks.md)). | API compatibility, generated-artifact cleanliness, and cross-transport error parity are required gates. |
| Release identity binds pinned toolchains and dependencies, two SBOM formats, provenance, reproducibility, signatures, security evidence, and every artifact ([supply-chain contract](../../project-positron.md#324-supply-chain-signing-and-security-response), [ADR-0073](../adr/0073-bind-every-artifact-to-a-reproducible-signed-security-supported-release.md)). | Build success alone cannot qualify or publish an artifact. |
| Each capability-target cell moves independently through `Specified`, `Implemented`, and `Qualified`; pass and fail evidence is immutable and target-specific ([status model](../release-1-qualification.md#1-status-model), [evidence contract](../release-1-qualification.md#5-evidence-contract)). | Engineering checks must emit attributable machine-readable evidence, and aggregate success must not hide a failed target. |

## 2. Architecture and module boundaries

### Evidence

- Rust privacy makes items private by default and checks whether each use is permitted
  ([Rust Reference: visibility and privacy](https://doc.rust-lang.org/reference/visibility-and-privacy.html)).
- `cargo metadata` emits versioned machine-readable workspace members and resolved
  dependencies; callers should explicitly select a format version
  ([Cargo: external tools](https://doc.rust-lang.org/cargo/reference/external-tools.html),
  [`cargo metadata`](https://doc.rust-lang.org/cargo/commands/cargo-metadata.html)).

### Recommended invariants and enforcement

1. The checked-in architecture policy should enumerate every permitted internal crate edge and
   every forbidden external-to-private edge. An architecture test should read
   `cargo metadata --locked --format-version 1`, fail on drift, cycles, undeclared crates, or
   forbidden dependencies, and attach the graph diff as evidence.
2. Production crates should expose the smallest visibility that satisfies the owning interface.
   No adapter may import a private implementation to bypass a published capability, and the
   qualification harness must exercise built artifacts through published interfaces as required
   by the [workspace design](../application-design.md#8-proposed-rust-workspace).
3. A new crate, trait, port, provider abstraction, shared type, feature flag, or dependency
   direction should require an architecture-owner review proving the seam, ownership, and
   qualification benefit. Generic `common`, `utils`, `manager`, or pass-through modules remain
   prohibited by the accepted design.
4. Compile-time type-state should represent important ordering and authority transitions where
   practical. Runtime checks remain mandatory at trust and persistence boundaries; a type-state
   API is not evidence that hostile serialized input is valid.
5. Architecture evidence should include the graph, public API surface, exceptions, and owning
   ADR/design link. An accepted architecture change and its enforcement change should land
   atomically.

## 3. Rust toolchain, compiler, formatting, and lints

### Evidence

- A committed `rust-toolchain.toml` may pin a toolchain, components, and targets
  ([rustup toolchain files](https://rust-lang.github.io/rustup/overrides.html#the-toolchain-file)).
- Cargo's `rust-version` declares the supported minimum Rust version (MSRV), affects all package
  targets, and should match a stated and verified support policy
  ([Cargo: Rust version](https://doc.rust-lang.org/cargo/reference/rust-version.html)).
- `--locked` rejects a missing or changed lockfile; `--frozen` additionally prevents network
  access ([`cargo build`](https://doc.rust-lang.org/cargo/commands/cargo-build.html)).
- Rust lint levels are `allow`, `expect`, `warn`, `force-warn`, `deny`, and `forbid`.
  `#[expect]` can carry a reason and the compiler diagnoses a stale expectation
  ([rustc lint levels](https://doc.rust-lang.org/rustc/lints/levels.html)).
- Clippy's default groups are curated differently: `correctness` lints are deny-by-default,
  `pedantic` can produce false positives, and the entire `restriction` group should not be
  enabled wholesale ([Clippy lint groups](https://doc.rust-lang.org/clippy/usage.html)).
- Cargo supports centrally inherited workspace lint configuration
  ([Cargo: lints](https://doc.rust-lang.org/cargo/reference/manifest.html#the-lints-section)).
- Overflow checks are profile-controlled; unchecked release arithmetic can otherwise wrap
  according to the type's behavior ([Cargo profiles](https://doc.rust-lang.org/cargo/reference/profiles.html#overflow-checks)).

### Recommended invariants and enforcement

1. Pin one exact stable Rust release, `rustfmt`, Clippy, required targets, linker, and generators
   in versioned configuration. Set each package's `rust-version` to the explicitly supported
   MSRV. Required CI should test both the MSRV support claim and the pinned release toolchain;
   neither may be a moving `stable` alias.
2. Every dependency-resolving build and check should use the committed lockfile and `--locked`.
   Release/reproducibility jobs should prefetch declared inputs and then use `--frozen` or an
   equivalently isolated build.
3. Required pull-request checks should include formatting, workspace compilation, Clippy,
   tests, examples, benchmarks-as-code, and documentation for all supported targets and feature
   sets. Mutually exclusive feature sets require an explicit matrix rather than a misleading
   `--all-features` pass.
4. Workspace Rust and Clippy policy should deny warnings in CI and explicitly select reviewed
   pedantic/restriction lints. Blanket `allow` attributes and command-line warning caps are
   prohibited. A narrow suppression must use `#[expect(..., reason = "...")]`, identify a
   tracking issue and removal condition, and fail when stale.
5. Release profiles should keep integer overflow checks enabled unless a reviewed operation uses
   explicit checked, saturating, or wrapping semantics. Panic strategy, debug information,
   assertions, LTO, target CPU, and allocator choices must be frozen and evidenced per artifact;
   `target-cpu=native` is not reproducible across arbitrary builders
   ([rustc code-generation options](https://doc.rust-lang.org/rustc/codegen-options/index.html)).

## 4. Unsafe Rust and memory correctness

### Evidence

- Unsafe code must still obey all Rust validity rules, and a safe client must not be able to
  trigger undefined behavior through an unsafe implementation
  ([Rust Reference: undefined behavior](https://doc.rust-lang.org/reference/behavior-considered-undefined.html),
  [unsafety](https://doc.rust-lang.org/reference/unsafety.html)).
- `unsafe_op_in_unsafe_fn` requires unsafe operations inside an unsafe function to appear in an
  explicit unsafe block, separating the caller's contract from implementation hazards
  ([Rust 2024 Edition Guide](https://doc.rust-lang.org/edition-guide/rust-2024/unsafe-op-in-unsafe-fn.html)).
- Miri detects many classes of undefined behavior but explicitly does not prove a program sound
  or detect every violation ([Miri](https://github.com/rust-lang/miri)).
- Rust supports Address, Leak, Memory, and Thread sanitizers with toolchain and platform
  limitations; the feature is documented as unstable
  ([Rust sanitizers](https://doc.rust-lang.org/beta/unstable-book/compiler-flags/sanitizer.html)).

### Recommended invariants and enforcement

1. Ordinary Positron crates should use `#![forbid(unsafe_code)]`. Unsafe may exist only in a
   named, minimal, owner-assigned module or crate on a reviewed allowlist. Generated or
   dependency unsafe code is tracked separately and does not make Positron's own unsafe
   acceptable.
2. Each unsafe block should have a directly adjacent `SAFETY` argument covering validity,
   aliasing, lifetime, initialization, concurrency, unwind, and ownership assumptions that
   apply. Each unsafe function must document its caller obligations. Deny
   `unsafe_op_in_unsafe_fn`, missing safety documentation, and undocumented unsafe blocks in the
   allowlisted scope.
3. Adding or broadening unsafe requires independent safety-owner approval, a threat/failure
   analysis, targeted unit and property tests, Miri where supported, applicable sanitizer jobs,
   and fuzz or model evidence at exposed parser, persistence, crypto, decompression, framing, or
   FFI boundaries. Any nightly verification toolchain needed by those jobs must be pinned by
   exact date/version and kept separate from the stable production/MSRV contract.
4. Miri and sanitizers are complementary detectors, not proofs. Unsupported targets or
   primitives must be recorded as evidence gaps with a compensating verifier; a green run may
   not be described as proof of soundness.

## 5. Concurrency, cancellation, and bounded resources

### Evidence

- Tokio's bounded MPSC channel applies backpressure when its capacity is reached, while its
  unbounded channel may buffer arbitrarily and can exhaust process memory
  ([Tokio MPSC](https://docs.rs/tokio/latest/tokio/sync/mpsc/),
  [`unbounded_channel`](https://docs.rs/tokio/latest/tokio/sync/mpsc/fn.unbounded_channel.html)).
- A Tokio semaphore limits concurrent access with a fixed permit count
  ([Tokio `Semaphore`](https://docs.rs/tokio/latest/tokio/sync/struct.Semaphore.html)).
- Dropping a Tokio `JoinSet` aborts its tasks; after requesting abort, callers must continue
  joining to observe completion. Blocking tasks cannot generally be aborted after they start
  ([Tokio `JoinSet`](https://docs.rs/tokio/latest/tokio/task/struct.JoinSet.html),
  [task cancellation](https://docs.rs/tokio/latest/tokio/task/index.html#cancellation)).
- A timeout is checked before polling and therefore cannot preempt a future that does not yield;
  `select!` can drop an in-progress operation, and only documented cancellation-safe operations
  may be restarted without losing progress
  ([Tokio `timeout`](https://docs.rs/tokio/latest/tokio/time/fn.timeout.html),
  [`select!` cancellation safety](https://docs.rs/tokio/latest/tokio/macro.select.html#cancellation-safety)).
- `CancellationToken` provides explicit cancellation propagation, while `TaskTracker` can wait
  until a closed tracker is empty
  ([tokio-util `CancellationToken`](https://docs.rs/tokio-util/latest/tokio_util/sync/struct.CancellationToken.html),
  [`TaskTracker`](https://docs.rs/tokio-util/latest/tokio_util/task/task_tracker/struct.TaskTracker.html)).
- Loom explores modeled thread schedules for code using its synchronization types, but its state
  space and model substitutions make it targeted evidence rather than a proof of all production
  executions ([Loom](https://docs.rs/loom/latest/loom/)).

### Recommended invariants and enforcement

1. Every queue, channel, task set, cursor, lease, retry set, cache, temporary file set, and
   maintenance backlog must have an explicit owner, finite capacity, overload behavior, and
   observable saturation signal tied to the Resource Governor. Production unbounded channels
   and detached task growth are prohibited.
2. Backpressure must propagate to an admission boundary or produce a typed, protocol-correct
   rejection. Dropping, overwriting, retrying forever, or moving work into another unbounded
   buffer is not backpressure.
3. Every spawned task must be owned by a structured task group, have a cancellation path, and be
   joined on shutdown. Graceful shutdown should close admission, signal cancellation, drain
   within a bounded deadline, abort remaining abortable work, join it, and report the truthful
   result ([Tokio graceful shutdown](https://tokio.rs/tokio/topics/shutdown)).
4. Blocking work must be separately admitted and bounded. Because a started blocking task is not
   preemptively abortable, it must terminate cooperatively and may not hold shutdown, memory, or
   CPU capacity without a declared bound.
5. Each `select!`, timeout, retry, and cancellation point around acknowledged or durable work
   requires a cancellation-safety review: before the operation's accepted cancellation boundary
   it must roll back or remain unacknowledged; after its point of irreversibility it must resume
   or recover according to the durable-operation contract.
6. Concurrency protocols governing publication, leases, cancellation, ownership, and shutdown
   should have deterministic tests plus targeted Loom models. Qualification must add sustained
   saturation, cancellation storms, clock jumps, faults, and restart/soak evidence.

## 6. Typed errors and public protocol behavior

### Evidence

- Rust uses panics primarily for detected bugs, while `Result`, user-defined types, and the
  `Error` trait represent anticipated runtime failures and preserve lower-level sources
  ([`std::error`](https://doc.rust-lang.org/std/error/),
  [`Error::source`](https://doc.rust-lang.org/std/error/trait.Error.html#method.source)).
- gRPC assigns distinct meanings to invalid arguments, failed preconditions, exhausted
  resources, unavailable dependencies, authentication, authorization, internal failures, and
  data loss; retrying non-idempotent work after `UNAVAILABLE` may be unsafe
  ([gRPC status codes](https://grpc.io/docs/guides/status-codes/)).
- RFC 9457 defines a machine-readable HTTP Problem Details format
  ([RFC 9457](https://www.rfc-editor.org/rfc/rfc9457.html)).
- HTTP idempotency concerns the intended effect of repeated identical requests, not merely the
  response code ([RFC 9110, section 9.2.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.2.2)).
- OTLP distinguishes full success, partial success, retryable failure, and non-retryable failure.
  A partial success is successful and must not be retried; retryable HTTP statuses are narrowly
  specified ([OTLP response handling](https://opentelemetry.io/docs/specs/otlp/#full-success),
  [OTLP failures](https://opentelemetry.io/docs/specs/otlp/#failures)).

### Recommended invariants and enforcement

1. Each deep-module boundary should return an owner-defined, non-exhaustive typed error or
   outcome. String matching, erased catch-all errors, transport status types, and process exit
   codes must not cross a domain boundary. Context-wrapping error reporters belong only at
   composition and presentation edges.
2. Every anticipated error should preserve a source where safe and declare a stable semantic
   code, class, retryability, partial-result meaning, and safe operator/client message. Secret,
   credential, key, tenant-private, raw payload, filesystem, and provider details are redacted
   before crossing a diagnostic or public boundary.
3. One reviewed mapping table should translate internal outcomes into gRPC status/details,
   RFC 9457 HTTP problems, OTLP responses, CLI exits, audit events, and health effects. Generated
   contract tests must prove parity, redaction, unknown-error fail-closed behavior, and every
   retryability decision.
4. Panics, `unwrap`, and `expect` are prohibited on reachable untrusted, runtime, storage,
   provider, or shutdown failure paths. A deliberate panic may represent an impossible internal
   state only when its invariant and containment behavior are tested; no panic may acknowledge
   data, corrupt state, cross FFI, or expose a secret.
5. Automatic retries require a protocol-authorized transient error and an idempotent operation
   or durable idempotency key. Budgets, jitter, deadline propagation, and terminal evidence are
   mandatory; retry loops must be bounded by the Resource Governor.

## 7. Public API and compatibility

### Evidence

- Protobuf advises never reusing field numbers, reserving deleted numbers and names, avoiding
  field-type changes, and separating RPC messages from persistent storage messages
  ([Protobuf best practices](https://protobuf.dev/best-practices/dos-donts/)).
- ProtoJSON has stricter evolution constraints because unknown fields generally cannot be
  propagated safely ([ProtoJSON wire safety](https://protobuf.dev/programming-guides/json/#json-wire-safety)).
- Buf can compare a schema against a prior source and its `FILE` policy is stricter than package
  or wire-only policies ([Buf breaking-change detection](https://buf.build/docs/breaking/),
  [rule categories](https://buf.build/docs/breaking/rules/)).
- Semantic Versioning requires a declared public API and increments appropriate to incompatible,
  compatible, and corrective changes ([SemVer 2.0.0](https://semver.org/)).
- `cargo-semver-checks` detects many Rust API compatibility violations against an explicit
  baseline, but its own documentation says it does not yet detect every SemVer violation
  ([cargo-semver-checks](https://github.com/obi1kenobi/cargo-semver-checks#will-cargo-semver-checks-catch-every-semver-violation)).

### Recommended invariants and enforcement

1. The canonical Protobuf, generated Rust adapters, HTTP/JSON routes, OpenAPI, SDKs, examples,
   and embedded schema digest should be regenerated from a clean checkout with pinned tools.
   Required CI must fail on a dirty diff or digest mismatch.
2. Every v1 change should run formatting/linting, the strictest compatible Buf policy selected
   by the API owner, JSON/wire compatibility checks, old-client/new-server and
   new-client/old-server conformance, and stable-error mapping tests. Published Rust crates and
   the generated Rust SDK should also run a pinned `cargo-semver-checks` target/feature matrix
   against the declared release baseline, with a reviewed public-API diff because the automated
   check is intentionally incomplete.
3. Deleted fields and enum values must be reserved; field identity/type and enum-number reuse
   are prohibited. Public RPC messages must not become Store Block, catalog, or backup formats.
4. Compatibility claims must name versions, transports, producers, SDK packages, and fixtures.
   “Current,” “latest,” or a generated compile result is not compatibility evidence.

## 8. Security, cryptography, secrets, and tenant isolation

### Evidence

- NIST's Secure Software Development Framework organizes practices for preparing an
  organization, protecting software, producing well-secured software, and responding to
  vulnerabilities ([NIST SP 800-218](https://csrc.nist.gov/pubs/sp/800/218/final)).
- AES-GCM security critically depends on never repeating an IV under the same key
  ([NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final),
  [RFC 5116, section 5.1.1](https://www.rfc-editor.org/rfc/rfc5116.html#section-5.1.1)).
- TLS 1.3 is specified by RFC 8446 ([RFC 8446](https://www.rfc-editor.org/rfc/rfc8446)).
- `zeroize` is designed to prevent compiler elimination of erasure, but its own documentation
  lists copies, caches, and hardware as limits; it is not a complete proof that a secret never
  remains in memory ([zeroize](https://docs.rs/zeroize/latest/zeroize/)).
- GitHub push protection blocks detected supported secrets but can be bypassed, and secret
  scanning does not cover every token or every file indefinitely
  ([push protection](https://docs.github.com/en/code-security/concepts/secret-security/push-protection),
  [scanning scope](https://docs.github.com/en/code-security/reference/secret-security/secret-scanning-scope)).

### Recommended invariants and enforcement

1. Security-sensitive work should start with a checked-in threat model naming assets, trust
   boundaries, attacker capabilities, misuse cases, and verification. Changes to identity,
   authorization, tenant attribution, crypto, parsers, persistence, diagnostics, supply chain,
   or network exposure require security-owner review and updated abuse tests.
2. All cryptography must pass through the accepted Crypto Backend; Positron should not implement
   primitives. Algorithms, crates/providers, parameters, nonce construction, associated-data
   context, key lifetimes, and failure behavior must be reviewed and pinned.
3. Cryptographic gates should include published/independent known-answer vectors, nonce
   uniqueness and restart/property tests, wrong-key/context/substitution/corruption tests,
   cross-target results, zeroization inspection, dependency audit, and recovery/rotation
   scenarios. Algorithm naming alone is not a certification claim.
4. Secret-bearing values should use non-`Copy`, redacted wrapper types and must not implement
   revealing `Debug`/`Display`/serialization. Logs, errors, metrics, traces, panic output, crash
   data, support bundles, artifacts, fixtures, and qualification evidence require adversarial
   secret-leak tests.
5. Repository and CI secret scanning should layer a pinned local/history scanner such as
   [Gitleaks](https://github.com/gitleaks/gitleaks) with provider scanning and push protection.
   A scan pass is only detector evidence; canary fixtures and manual review of sensitive output
   remain required.
6. Every data-plane operation must consume authoritative typed Tenant Attribution and explicit
   authorization; no caller-provided tenant string may substitute for it. Cross-tenant
   property tests, confused-deputy tests, cache-key tests, backup/restore/purge tests, and
   diagnostics tests must fail closed.

## 9. Dependencies, licenses, provenance, and reproducibility

### Evidence

- RustSec maintains the RustSec Advisory Database; `cargo audit` checks `Cargo.lock` against it
  ([RustSec](https://rustsec.org/)).
- `cargo-deny` can check advisories, license expressions, duplicate/banned crates, and allowed
  registries or Git sources; Git sources can be required to use an exact revision
  ([cargo-deny checks](https://embarkstudios.github.io/cargo-deny/checks/),
  [source configuration](https://embarkstudios.github.io/cargo-deny/checks/sources/cfg.html)).
- Cargo Vet verifies dependencies against trusted audits. Initial exemptions are not audits and
  should be reduced over time; custom criteria can capture requirements such as crypto review
  ([Cargo Vet](https://mozilla.github.io/cargo-vet/),
  [initial exemptions](https://mozilla.github.io/cargo-vet/setup.html),
  [audit criteria](https://mozilla.github.io/cargo-vet/audit-criteria.html)).
- SPDX is an ISO software-bill-of-materials standard, and CycloneDX is a bill-of-materials
  standard with versioned schemas
  ([SPDX specifications](https://spdx.dev/use/specifications/),
  [CycloneDX specification](https://cyclonedx.org/specification/overview/)).
- SLSA v1.2 defines progressively stronger build provenance and hardened-build requirements
  ([SLSA v1.2](https://slsa.dev/spec/v1.2/),
  [build track](https://slsa.dev/spec/v1.2/build-track-basics)).
- GitHub states that a full commit SHA is the only immutable way to pin an action
  ([GitHub Actions security](https://docs.github.com/en/actions/reference/security/secure-use#using-third-party-actions)).
- An artifact attestation binds an artifact digest to build/source claims, but does not by itself
  prove that the artifact is secure
  ([GitHub artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations)).
- Reproducible Rust builds require controlled toolchains, sources, paths, and lockfiles; two
  sufficiently independent builds should compare the declared payload bytes
  ([Reproducible Builds: Rust](https://reproducible-builds.org/docs/rust/),
  [build plans](https://reproducible-builds.org/docs/plans/)).

### Recommended invariants and enforcement

1. Every direct dependency should have an owner, purpose, feature set, source, license,
   maintenance/security assessment, and removal condition. New runtime, parser, crypto,
   serialization, allocator, FFI, build-script, or proc-macro dependencies require
   supply-chain/security approval.
2. Commit every lockfile. Deny unknown registries, floating Git dependencies, unapproved
   licenses, unexpected duplicates, yanked/denied crates, and advisory findings under an
   explicitly versioned policy. Git dependencies must pin immutable revisions.
3. Run RustSec/cargo-audit for fresh advisories and cargo-deny for policy on each protected
   change and release. Run Cargo Vet with reviewed criteria; exemptions are visible debt,
   owner-assigned, expiring, and may not satisfy crypto/safety review criteria.
4. Generate SPDX and CycloneDX SBOMs from the exact release resolution, validate them, and bind
   their digests into the Release Manifest. License notices and source-offer obligations must be
   generated and tested as artifact contents, not treated as repository-only metadata.
5. Pin every third-party CI action by full commit SHA, minimize job/token permissions, isolate
   untrusted pull-request code from secrets, and prohibit untrusted interpolation into shell
   scripts. Release workflows should target SLSA Build Level 3 controls and signed
   digest-bound provenance, but claim a level only after independent verification.
6. Reproducible Payload gates should build the same source independently in clean, declared
   environments, normalize time and paths (including
   [`SOURCE_DATE_EPOCH`](https://reproducible-builds.org/specs/source-date-epoch/)), compare exact
   payload digests, and retain a structured diff on failure. Signing, notarization, timestamps,
   and registry wrappers remain separately evidenced nondeterministic layers.
7. A known exploitable critical issue blocks release under the accepted contract. Any allowed
   non-exploitable finding requires reproducible reachability evidence, affected artifacts,
   compensating controls, owner, independent security approval, expiry, and signed release
   evidence; expiration blocks the next protected build.

## 10. Documentation and decision discipline

### Evidence

- Rustdoc executes fenced Rust examples as documentation tests
  ([rustdoc documentation tests](https://doc.rust-lang.org/rustdoc/documentation-tests.html)).
- Rustdoc can deny broken intra-doc links, invalid code blocks, and other documentation defects
  ([rustdoc lints](https://doc.rust-lang.org/rustdoc/lints.html)).
- The accepted project contract keeps ADR history, permits refinement only through an explicit
  later ADR, and forbids a second drifting decision index
  ([project ADR policy](../../project-positron.md#20-adrs)).

### Recommended invariants and enforcement

1. Every invariant in the standards should have a stable ID, one unambiguous BCP 14 statement,
   rationale/source, scope, owner role, automated gate ID, required evidence, and exception
   classification. Advice and examples should be visibly non-normative.
2. Public APIs and safety-, durability-, concurrency-, security-, performance-, or
   compatibility-sensitive internal interfaces should document invariants, pre/postconditions,
   errors, cancellation, resource bounds, examples, and unsafe obligations.
3. Required CI should deny rustdoc warnings and broken links, run doctests, check internal and
   external document links, validate terminology against `CONTEXT.md`, and fail if generated API
   references or schemas are stale.
4. A contract-changing implementation must update the owning design, ADR or superseding ADR,
   qualification cell, fixtures, and gate in the same protected change. Comments and runbooks
   cannot silently redefine an accepted contract.
5. Generated files must identify their generator and source digest and must never be hand edited.
   A clean regeneration must be byte-identical or produce an intentional reviewed diff.

## 11. Verification strategy and limitations

No single test technique establishes Positron correctness. The gate portfolio should combine the
following independent evidence:

| Technique | Required use | Primary-source limitation or control |
| --- | --- | --- |
| Unit, integration, and documentation tests | Every protected change; all supported targets and feature matrices. | `cargo test` builds and runs unit, integration, and documentation tests, but only for compiled targets/configurations ([Cargo `test`](https://doc.rust-lang.org/cargo/commands/cargo-test.html)). |
| Property tests | Parsers, codecs, bounds, identifiers, state transitions, routing, nonce construction, policy, storage and query algebra. Persist minimal failing seeds in version control. | Proptest can persist and replay regressions; generated cases still express only the properties written ([Proptest failure persistence](https://proptest-rs.github.io/proptest/proptest/failure-persistence.html)). |
| Model/state-machine tests | Durable operations, catalog publication, tenant lifecycle, key rotation, backup/restore, cursors, retries, and client/server behavior against a simple reference model. | Proptest state-machine testing compares a SUT with a reference model and shrinks transitions; the documented facility is sequential ([Proptest state machines](https://proptest-rs.github.io/proptest/proptest/state-machine.html)). |
| Fuzzing | Every untrusted parser, decoder, decompressor, frame/schema reader, API adapter, crypto envelope, and migration reader. Run bounded PR smoke, longer scheduled campaigns, and release campaigns; retain corpora and crashes. | `cargo-fuzz`/libFuzzer searches pseudo-random inputs until a crash or sanitizer failure; CI guidance recommends bounded runs and artifact retention ([Rust Fuzz Book](https://rust-fuzz.github.io/book/), [CI guidance](https://rust-fuzz.github.io/book/cargo-fuzz/ci.html)). A `cfg(fuzzing)` shortcut can remove security behavior, so conformance fuzz targets must not disable authentication or validation ([fuzzing configuration warning](https://rust-fuzz.github.io/book/cargo-fuzz/guide.html#cfgfuzzing)). |
| Loom | Small concurrency protocols controlling ownership, publication, locks, leases, cancellation, and shutdown. | Loom sees code using its modeled primitives and faces exponential schedules; use bounded models and do not call a pass exhaustive production proof ([Loom](https://docs.rs/loom/latest/loom/)). |
| Miri and sanitizers | Miri for supported pure-Rust tests; ASan/LSan/TSan/MSan on applicable target matrices; mandatory for owned unsafe scope. | Each detects only modeled/supported behavior and platform combinations; neither proves absence of undefined behavior ([Miri](https://github.com/rust-lang/miri), [sanitizers](https://doc.rust-lang.org/beta/unstable-book/compiler-flags/sanitizer.html)). |
| Deterministic fault, crash, and recovery tests | Every persistence publication point, partial write, fsync/rename/remount boundary, provider/network outage, clock jump, disk-full state, cancellation boundary, backup/restore, purge, key migration, upgrade, and restart. | Positron's accepted qualification contract requires target-specific crash, recovery, corruption, restore, migration, and fault evidence ([qualification matrix](../release-1-qualification.md#4-qualification-matrix)). |
| Compatibility and adversarial security tests | Old/new API, SDK, format, backup, producer/provider matrices; malformed, oversized, unauthorized, cross-tenant, replay, corruption, secret-exfiltration, and resource-exhaustion cases. | Compatibility targets must be exact Qualification Cells; aggregate or alias-based success is prohibited by the [status model](../release-1-qualification.md#1-status-model). |
| Coverage | Publish line/region/branch coverage, require critical invariant paths, and ratchet changed-code/project baselines without regressions. | LLVM coverage reports which instrumented regions ran; execution is not an assertion of correctness ([LLVM `llvm-cov`](https://llvm.org/docs/CommandGuide/llvm-cov.html)). Documentation tests and some branch modes need explicit tool configuration ([cargo-llvm-cov](https://github.com/taiki-e/cargo-llvm-cov)). |
| Mutation testing | Scheduled for critical modules and changed high-risk code; surviving mutants require test improvement or reviewed equivalence/unreachability evidence. | Mutation testing measures whether tests detect injected changes and assumes a non-flaky suite; it is expensive and a raw 100% score is not a correctness proof ([cargo-mutants](https://github.com/sourcefrog/cargo-mutants)). |

Additional recommendations:

1. Required suites must be deterministic under pinned seeds, clocks, entropy adapters, locale,
   time zone, and resource limits unless the gate deliberately varies one of them. A failure
   artifact must preserve the seed, schedule, fixture, and minimized reproducer.
2. A flaky required test is a product defect. Retries may gather diagnostic evidence, but cannot
   convert a required failure into a pass; nextest supports treating an eventual retry pass as
   failure ([nextest retries](https://nexte.st/docs/features/retries/#flaky-test-mitigation)).
3. Every test must have a bounded duration and resource envelope. Timeouts diagnose a failure;
   they may not silently skip or pass incomplete verification
   ([nextest slow-test controls](https://nexte.st/docs/features/slow-tests/)).
4. Coverage and mutation scores are signals and ratchets. Critical invariant-to-test traceability,
   adversarial cases, fault evidence, and independent oracles matter more than an arbitrary
   repository-wide percentage.

## 12. Performance and regression evidence

### Evidence

- Criterion warms up, samples, performs statistical analysis, reports uncertainty, and compares
  baselines; environmental noise still affects conclusions
  ([Criterion analysis](https://bheisler.github.io/criterion.rs/book/analysis.html),
  [output interpretation](https://bheisler.github.io/criterion.rs/book/user_guide/command_line_output.html)).
- Criterion's own FAQ warns that cloud CI environments are too noisy for trustworthy performance
  measurements ([Criterion FAQ](https://bheisler.github.io/criterion.rs/book/faq.html#how-should-i-run-criterionrs-benchmarks-in-a-ci-pipeline)).
- Positron already requires preregistered hardware, workloads, durations, latency/throughput,
  resources, amplification, recovery and availability objectives, with preserved negative
  evidence ([performance preregistration](../release-1-qualification.md#6-performance-preregistration)).

### Recommended invariants and enforcement

1. Pull requests should compile and smoke-run benchmarks and may report advisory microbenchmark
   deltas. A blocking regression verdict requires a controlled, dedicated runner and a
   preregistered noise policy; shared cloud-runner noise must not approve or reject a change.
2. Release performance and soak gates must use the frozen exact machine, topology, OS/kernel,
   filesystem/storage, resource limits, binary/config/dataset/workload/fault digests, warm-up,
   sample/soak durations, and objectives from the qualification contract.
3. Compare baseline and candidate from clean builds on the same controlled environment, retain
   raw samples and confidence intervals, and measure throughput, latency distribution, CPU, RSS,
   allocation, file descriptors, tasks/queues, I/O, write/space/backup amplification,
   correctness/error/availability, and recovery—not elapsed time alone.
4. A microbenchmark, allocation reduction, or focused-path gain must not be reported as an
   overall performance win when end-to-end objectives, availability, CPU/RSS, recovery, or
   another required target regresses. Passing results may not erase negative or inconclusive
   evidence.
5. Any objective, dataset, filter, warm-up, sample exclusion, or runner change after observing a
   result requires a superseding preregistration that preserves the original result and explains
   the change.

## 13. CI, protected branches, ownership, and exceptions

### Evidence

- GitHub protected branches and rulesets can require pull requests, status checks, approvals,
  code-owner review, signed commits, linear history, and restrictions on force-push or deletion
  ([protected branches](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches),
  [ruleset rules](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets)).
- CODEOWNERS can require responsible-team approval, and the CODEOWNERS file itself should be
  protected by owners
  ([GitHub CODEOWNERS](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners)).
- Merge queues test a synthetic merge group; required Actions workflows must handle the
  `merge_group` event or the queue can wait indefinitely
  ([GitHub merge-queue checks](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/configuring-pull-request-merges/managing-a-merge-queue#triggering-merge-group-checks-with-github-actions)).
- A required check can be associated with its expected GitHub App source
  ([required status checks](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches#require-status-checks-before-merging)).

### Recommended gate topology

| Gate family | Minimum blocking evidence | Accountable owner |
| --- | --- | --- |
| Architecture | Locked dependency graph and forbidden-edge check; API/visibility diff; required design/ADR trace. | Architecture owner plus changed module owner |
| Rust hygiene | Exact toolchain identity; clean format; compile/check; lint policy; docs/doctests; supported target/feature matrix. | Rust/toolchain owner |
| Correctness | Unit, property, integration, model, deterministic fault/recovery, compatibility, and applicable concurrency evidence with retained failures. | Changed module owner |
| Safety and security | Unsafe inventory; Miri/sanitizers/fuzz where applicable; threat/abuse tests; authz/isolation/redaction; secret and vulnerability scans. | Security owner plus changed module owner |
| API and generated surfaces | Schema lint/break check; clean regeneration; schema digest parity; transport/SDK old-new conformance. | Public API and SDK owner |
| Dependencies and licenses | Lockfile and source policy; advisory, license, ban/duplicate, Cargo Vet, SBOM and notices evidence. | Supply-chain owner |
| Performance | Benchmark smoke for ordinary PRs; controlled preregistered regression, soak, and resource evidence for release/affected critical paths. | Performance owner plus Release Engineering |
| Release | Exact artifact matrix, reproducibility, provenance, signatures, install/operate/recovery checks, and complete Qualification Cells. | Release Engineering |

Protected-branch recommendations:

1. Require a pull request, current-base/merge-group checks, resolved review conversations,
   code-owner approval, dismissal of stale approvals, and approval of the latest push by someone
   other than its author. Prohibit direct push, force-push, deletion, and unreviewed rule changes.
2. Define CODEOWNERS for architecture, public API, storage/durability, identity/tenancy,
   cryptography, unsafe, dependencies/licenses, CI/release, engineering standards, and the
   CODEOWNERS/ruleset files themselves.
3. Use one always-running required gate aggregator that fails if a mandatory subgate is missing,
   skipped, expired, or produced by the wrong source. Required workflows must run for pull
   requests and `merge_group`; path-filtered absence must not appear green.
4. Give CI jobs the minimum token permissions and no production/release secret unless the
   protected job needs it. Build and test untrusted code before any trusted publication job, and
   promote the already verified digest rather than rebuild it.

Exception recommendations:

1. The [non-waivable gates](../release-1-qualification.md#3-non-waivable-gates) have no exception
   path. A fundamental change requires the already specified superseding-ADR and release-scope
   process.
2. Every other temporary exception must name one invariant/gate, exact code/artifact/target
   scope, evidence gap, rationale, risk, compensating control, owner, independent domain
   approver, tracking issue, creation time, fixed short expiry, and removal criterion.
   Open-ended, inherited, repository-wide, or post-hoc exceptions are invalid.
3. Exceptions live in a machine-readable registry. CI validates scope and expiry and keeps the
   affected result visibly exceptional; it must not fabricate an ordinary pass. Expired,
   broadened, missing, or unapproved entries fail closed.
4. Lint exceptions additionally use scoped `#[expect(..., reason = "...")]`; test, security,
   compatibility, and performance exceptions retain the failed evidence. Renewals require fresh
   evidence and a new independent approval, not an edited date.

## 14. Decisions to freeze before M0 implementation

The standards and gate documents should make these choices explicit before code can silently
choose them:

1. Exact stable toolchain, MSRV policy, targets, profiles, lint set, formatting version, and
   generated-tool versions.
2. Allowed crate graph, public/private surfaces, feature matrix, unsafe allowlist, and owner map.
3. Typed internal error taxonomy and its gRPC, HTTP Problem Details, OTLP, CLI, audit, and health
   mappings.
4. Dependency sources, approved licenses, audit criteria, vulnerability severity/exploitability
   policy, SBOM schemas, provenance target, and pinned CI actions.
5. Required test/fuzz/model/sanitizer/Miri matrices, corpus ownership, time/resource budgets,
   coverage ratchets, mutation scope, and flake policy.
6. Dedicated benchmark environments, preregistered objectives, noise/uncertainty policy, and
   evidence retention.
7. Required check names and trusted sources, merge-queue behavior, CODEOWNERS, exception schema,
   maximum exception lifetime, and policy-change approval.

Numeric thresholds should be frozen from the accepted qualification objectives and measured
baselines, not copied from generic industry percentages. Once frozen, they may tighten through
normal review; weakening after a failure requires the documented superseding decision and
preserved negative evidence.
