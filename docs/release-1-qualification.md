# Positron Release 1 Qualification

This document is the binding Release Scope Ledger and Qualification
Matrix for Positron Release 1. ADR-0074 governs changes to it.

## 1. Status Model

Every required capability-and-target pair is a Qualification Cell with a
stable gate ID and one state:

- `Specified`: contract, target, owner role, executable gate design, and
  required evidence are defined.
- `Implemented`: candidate implementation and gate machinery exist.
- `Qualified`: the exact release candidate artifact passed the complete
  gate on the named target and its immutable evidence is retained.

No umbrella row may be marked `Qualified` from a subset of its child
cells. A failed or unsupported required child blocks Release 1.

The architecture records every gate template below as specified. M0
must resolve selectors such as maintained Kubernetes minors, named
S3-compatible products, producer versions, registries, filesystems, and
StorageClasses into an exact versioned Qualification Target Registry.
Each expanded cell starts `Specified`; no unresolved selector can be
marked `Implemented` or `Qualified`. Implementation work must not mark a
cell `Implemented` until its test entry point exists, or `Qualified`
until retained evidence verifies the candidate Release Manifest digest.

## 2. Scope Ledger

### 2.1 Required in Release 1

- Standalone, single-process, single-node database.
- Native Log and Trace Signal Stores.
- OTLP Logs and Traces over gRPC and HTTP.
- Loki Push and Loki OTLP log-path ingestion.
- Native typed pipeline, bounded read-only SQL, search, live tail,
  resumable results, durable export, trace structure, and explicit
  log/trace correlation.
- First-party Grafana data source.
- Generated Rust, TypeScript, Python, Go, Java/JVM, and .NET SDKs.
- Mandatory native encryption at rest and the complete approved key
  hierarchy, provider, rotation, recovery, and purge contracts.
- API-key identity, tenant isolation and lifecycle, no impersonation,
  governance audit, Ingest Policy, dynamic-schema bounds, query and
  resource governance.
- Catalog, durability, recovery, verification, quarantine, maintenance,
  process lifecycle, and graceful shutdown.
- Verified backup and restore with every required repository adapter.
- Native, OCI, Nix, package, Compose, Helm, and Kubernetes operator
  Distribution Surfaces.
- Operational telemetry, dashboards, alerts, runbooks, doctor, support
  bundle, release verification, and security response.

### 2.2 Explicitly Follow-On

- Profile and Metric Signal Stores and their Receiver Adapters.
- Native replication, high availability, failover, and clustering.
- SSO, OIDC, SAML, SCIM, certificate-to-principal mapping, and custom
  RBAC.
- A FIPS validation claim.
- Continuous PITR, selective restore, legal hold, and arbitrary
  record-level or predicate deletion.
- Object storage, raw block, or primary multi-writer storage as the
  Primary Data Volume.
- LogQL, TraceQL, and PromQL compatibility.
- Native Windows and FreeBSD distributions.

### 2.3 Required Artifacts and Runtime Independence

An artifact can be required to ship and qualify without becoming a
runtime dependency of the database. The Positron Operator, Grafana data
source, generated SDKs, Compose example, Helm chart, packages, and Nix
surfaces are release-blocking artifacts, but an operator may run the
standalone native or OCI database without deploying any of those
integrations. Conversely, “optional to deploy” never permits a required
artifact or its Qualification Cells to be omitted from Release 1.

## 3. Non-Waivable Gates

The following gates cannot be waived, reclassified, or accepted through
documented exception:

- no loss of acknowledged Store Blocks
- no unauthenticated or corrupt telemetry returned as valid
- mandatory authenticated encryption for all managed persistent data
- no plaintext key material or prohibited secrets in artifacts,
  diagnostics, logs, status, or support bundles
- tenant isolation and authoritative Tenant Attribution
- no system-administrator tenant impersonation
- atomic publication of governance-sensitive state and audit evidence
- bounded admission and no unbounded queue, task, cursor, lease, or
  maintenance backlog
- verified backup key recovery and complete restore into fresh storage
- managed-scope Tenant Purge correctness
- signed artifact and Release Manifest authenticity

Changing one of these requires a superseding fundamental ADR and a new
major release scope; it cannot unblock Release 1.

## 4. Qualification Matrix

Each gate below expands into one cell per listed target. Evidence must
identify the individual target; aggregate success is insufficient.

Owner roles are functional accountabilities, not named individuals. One
role owns each gate's definition, execution, evidence, and status; other
roles may contribute without splitting release accountability.

| Owner role | Gate IDs |
|---|---|
| Release Engineering | `Q-BUILD-001`, `Q-DIST-001`, `Q-DIST-002`, `Q-DIST-003`, `Q-SUPPLY-001` |
| Public API and SDK | `Q-API-001`, `Q-SDK-001`, `Q-COMPAT-001` |
| Ingest Interoperability | `Q-RX-001`, `Q-RX-002`, `Q-RX-003`, `Q-RX-004` |
| Log Store | `Q-LOG-001`, `Q-TAIL-001` |
| Trace Store | `Q-TRACE-001` |
| Query and Integrations | `Q-QUERY-001`, `Q-QUERY-002`, `Q-GRAFANA-001` |
| Identity and Governance | `Q-AUTH-001`, `Q-TENANT-001`, `Q-AUDIT-001`, `Q-POLICY-001` |
| Storage Kernel | `Q-SCHEMA-001`, `Q-RESOURCE-001`, `Q-STORAGE-001`, `Q-CATALOG-001`, `Q-CRASH-001`, `Q-INTEGRITY-001`, `Q-TIME-001`, `Q-MAINT-001` |
| Security and Key Management | `Q-KEY-001`, `Q-KEY-002`, `Q-CRYPTO-001`, `Q-LISTENER-001`, `Q-SECURITY-001` |
| Recovery and Lifecycle | `Q-BACKUP-001`, `Q-BACKUP-002`, `Q-UPGRADE-001`, `Q-CONFIG-001`, `Q-PROCESS-001` |
| Diagnostics and Operations | `Q-DIAG-001`, `Q-DIAG-002`, `Q-OPS-001` |
| Kubernetes Platform | `Q-K8S-001`, `Q-K8S-002`, `Q-K8S-003` |
| Performance Qualification | `Q-PERF-001`, `Q-SOAK-001` |

| Gate | Area | Required targets | Release-blocking proof |
|---|---|---|---|
| `Q-BUILD-001` | Rust build | Linux `x86_64`, Linux `aarch64`, macOS Apple Silicon, macOS Intel | Locked clean build, tests, binary identity, SBOM, provenance |
| `Q-DIST-001` | Native archives | Every required Linux and macOS target | Install, initialize, ingest, query, restart, verify, backup, restore, uninstall |
| `Q-DIST-002` | OS packages | Debian/Ubuntu, Fedora/RHEL-compatible, Homebrew, Nix package, NixOS module | Native service lifecycle, paths, permissions, upgrade, removal with retained data |
| `Q-DIST-003` | Containers | OCI `linux/amd64`, OCI `linux/arm64`, Docker, Compose | Non-root arbitrary UID, read-only root, volumes, claim, health, drain, recovery |
| `Q-API-001` | Public API | gRPC, HTTP/JSON, OpenAPI | Generated parity, v1 compatibility, stable errors, Capability Statement |
| `Q-SDK-001` | SDK release set | Rust, TypeScript, Python, Go, Java/JVM, .NET | Generate, package, publish candidate, live conformance, schema digest equality |
| `Q-RX-001` | OTLP Logs | gRPC/Protobuf, HTTP/Protobuf, HTTP/JSON; uncompressed and gzip | Native semantic fixture round trip, partial success, bounds, auth, policy |
| `Q-RX-002` | OTLP Traces | gRPC/Protobuf, HTTP/Protobuf, HTTP/JSON; uncompressed and gzip | Span observation, conflict, trace summary, malformed and partial behavior |
| `Q-RX-003` | Loki | Push path and Loki OTLP log path | Labels, metadata, bodies, tenant alias conflict, retry behavior |
| `Q-RX-004` | Producers | pinned OpenTelemetry SDKs/Collectors, Alloy, Beyla, E-Navigator, Tempo-target clients | Real end-to-end delivery with preserved supported semantics |
| `Q-LOG-001` | Log Store | scalar and complex attributes, full text, structured predicates, JSON/logfmt parsing | Native value and namespace fidelity across active, sealed, compacted data |
| `Q-TRACE-001` | Trace Store | incremental traces, late spans, duplicate and conflicting observations | Stable consolidation, quiescence, structural incompleteness, correlation |
| `Q-QUERY-001` | Query | pipeline and bounded SQL | Typed-plan parity, total bounds, cancellation, complete/incomplete status |
| `Q-QUERY-002` | Result delivery | pagination, reconnect, restart, export | Stable snapshot, cumulative budgets, repeat detection, Result Digest |
| `Q-TAIL-001` | Live tail | history bridge, live follow, lag, expiry | No handoff gap, at-least-once cursor behavior, bounded consumer |
| `Q-GRAFANA-001` | Grafana | search, tail, trace lookup, service relationships, log-to-trace | Tenant-bound data source against candidate server |
| `Q-AUTH-001` | Identity | ingest, query, tenant-admin, system-admin scopes | Hash-only storage, rotation, revocation, non-enumeration, no impersonation |
| `Q-TENANT-001` | Tenant lifecycle | Active, ReadOnly, Suspended, Purging, Purged | Drain, access, retention, non-reuse, restore tombstones |
| `Q-AUDIT-001` | Governance audit | every security-sensitive mutation | Joint catalog/audit commit, failure closed, chain and checkpoint verification |
| `Q-POLICY-001` | Ingest Policy | accept, reject, remove, redact, truncate | Policy provenance, intrinsic protection, prospective-only behavior, no leaks |
| `Q-SCHEMA-001` | Dynamic values | all supported types, duplicate keys, conflicts, overflow | No coercion or loss, bounded catalog/index state, explicit query semantics |
| `Q-RESOURCE-001` | Resource Governor | memory, CPU, I/O, disk, queues, descriptors | Reservations, fairness, pressure states, protected Recovery Reserve |
| `Q-STORAGE-001` | Primary storage | every published filesystem, Docker volume, and Kubernetes StorageClass target | Capability probe, durability, locking, crash, full disk, reattach |
| `Q-CATALOG-001` | Catalog | every transaction persistence boundary | Complete predecessor or successor only; audit binding; no mixed generation |
| `Q-CRASH-001` | Active segments | every frame and frontier boundary | Acknowledged-data recovery, safe post-frontier truncation, nonce safety |
| `Q-INTEGRITY-001` | Integrity | startup verification, online/offline verify, scrub, quarantine, abandonment | Never return corrupt data; correct degrade/fence and evidence |
| `Q-TIME-001` | Time | malformed source time, NTP slew/step, restart regression, timezone/DST | Query provenance, ingest retention, `ClockUncertain` safety |
| `Q-KEY-001` | Local key custody | bootstrap, hardened key file, X25519 Recovery Bundle | Fresh init, warnings, independent recovery, wrong/missing key failure |
| `Q-KEY-002` | External key providers | AWS KMS, GCP KMS, Azure Key Vault/Managed HSM, Vault Transit, OpenBao Transit, KMIP 2.1 | Workload identity, exact key pinning, outage, rotation, migration, recovery |
| `Q-CRYPTO-001` | Crypto Backend | every required architecture and persistent object kind | Known-answer and cross-platform vectors, nonce/context binding, zeroization |
| `Q-BACKUP-001` | Backup repositories | local, AWS S3, each named S3-compatible target, GCS, Azure Blob | Identity, CAS, multipart, checksums, interruption, throttle, purge compatibility |
| `Q-BACKUP-002` | Backup/restore | local and every external repository target | Online verified snapshot, incremental reuse, empty-target restore, query validation |
| `Q-UPGRADE-001` | Upgrade | patch, minor, format-neutral, format-changing, failure at each phase | Signed preflight, drain, snapshot, COW publish, rollback/restore semantics |
| `Q-CONFIG-001` | Configuration | native, Docker, Nix, Kubernetes | Same schema, precedence, redaction, reload atomicity, migration, drift |
| `Q-LISTENER-001` | Listeners | control, operations, API, OTLP gRPC/HTTP, Loki | TLS, auth, bounds, proxy trust, abuse, reload, drain |
| `Q-PROCESS-001` | Process lifecycle | native, systemd, Docker, Kubernetes | Startup phase, readiness, graceful record, second signal, forced recovery |
| `Q-MAINT-001` | Maintenance | every task class and conflict class | Reservations, checkpoints, pause expiry, crash resume, eventual progress |
| `Q-DIAG-001` | Diagnostics | online, offline, degraded, fenced, key-unavailable | Read-only doctor, stable findings, no mutation |
| `Q-DIAG-002` | Support bundle | encrypted and explicit plaintext modes | Canary exclusion, pseudonymization, bounds, manifest and signature status |
| `Q-K8S-001` | Kubernetes versions | every upstream-maintained minor at release time on `amd64` and `arm64` | Install, reconcile, upgrade, backup, restore, failure and restricted policy matrix |
| `Q-K8S-002` | Kubernetes distributions | upstream, EKS, GKE, AKS, OpenShift, k3s | Exact supported patch and StorageClass evidence |
| `Q-K8S-003` | Operator | two replicas, scoped and cluster-wide RBAC, CRD `v1beta1` | Lease failover, SSA ownership, drift, finalizers, retain/delete, operand N/N-1 |
| `Q-COMPAT-001` | Compatibility | old client/new server, new client/old server, config, CRD, storage, backup | Compatibility Manifest matches tested paths and refusals |
| `Q-SUPPLY-001` | Supply chain | every required artifact and registry | Reproducible payload, signatures, offline verify, SBOM, provenance, revocation |
| `Q-SECURITY-001` | Security | auth, crypto, parsing, network, filesystem, provider, operator boundaries | Threat tests, fuzz/property/sanitizer evidence, canary secrets, advisory scan |
| `Q-OPS-001` | Operational telemetry | native and operator processes | Bounded labels, dashboards, alerts, runbooks, health derivation, self-export guard |
| `Q-PERF-001` | Performance | local, constrained-container, scale-up reference profiles | Preregistered throughput, latency, RSS, I/O, amplification, recovery gates |
| `Q-SOAK-001` | Soak | mixed logs/traces, query, tail, maintenance, backup, faults | Bounded resources and backlog for the preregistered duration |

## 5. Evidence Contract

Every gate attempt retains machine-readable Qualification Evidence with:

- gate and target identity
- state and pass/fail result
- Release Manifest and artifact digests
- Qualification Target Registry and gate-definition digests
- accountable owner role
- source and toolchain identity
- operating system, architecture, kernel, runtime, cloud/provider, and
  storage identity
- redacted Effective Configuration digest
- fixture, dataset, generator, workload, and fault-schedule digests
- exact harness and command identity
- start/end times and duration
- raw measurements and declared units
- logs, metrics, traces, and verification reports allowed by the
  diagnostic security contract
- failure classification and retained negative evidence
- verifier identity and signature where configured

Evidence paths use:

`qualification/evidence/<release>/<gate>/<target>/<attempt>/`

Passing and failing attempts are retained. A later pass does not erase a
previous failure; the Release Manifest names the qualifying attempt and
any superseded evidence.

## 6. Performance Preregistration

Before the first release-candidate optimization, `Q-PERF-001` and
`Q-SOAK-001` must freeze:

- exact reference machine or cloud-instance identities
- CPU topology, memory, storage, filesystem, kernel, and container limits
- dataset generator and seed
- Log/Trace mix, value distributions, cardinality, compression, and
  retention
- ingest batch and concurrency patterns
- query suite, selectivity, concurrency, tails, and export workload
- maintenance, backup, rotation, and fault schedule
- warm-up, sample, and soak durations
- throughput floors
- p50, p95, and p99 latency ceilings
- RSS, allocator, file-descriptor, task, queue, and cache ceilings
- write, space, compaction, and backup amplification ceilings
- recovery, readiness, drain, backup, restore, and upgrade-time ceilings
- permitted error rates and explicit availability calculation

The preregistration is versioned and committed before candidate results
are collected. A gate definition cannot be relaxed after observing a
failure without a superseding decision that preserves the failed result
and explains the changed objective.

## 7. Vertical Implementation Milestones

### M0 — Contract and Harness

Entry: ADR-0074 accepted.

Exit:

- Rust workspace and module boundaries exist.
- Canonical Protobuf API and generation are reproducible.
- Configuration/schema generation and stable error taxonomy exist.
- Qualification Target Registry resolves every dynamic target selector.
- Qualification gate registry and evidence format validate.
- Adversarial fixtures cover protocol, persistence, crypto, and resource
  boundaries.

### M1 — Encrypted Kernel Vertical Slice

Exit:

- Local key bootstrap and encryption work end-to-end.
- Immutable catalog, active segment, durability frontier, recovery, and
  Resource Governor pass crash tests.
- Minimal OTLP Log input becomes natively stored and queryable.
- Acknowledged-data preservation is proved before feature expansion.

### M2 — Complete Logs

Exit:

- OTLP and Loki log receivers qualify.
- Log value model, policy, schema bounds, indexing, search, query, tail,
  retention, and compaction qualify on native artifacts.

### M3 — Complete Traces and Correlation

Exit:

- OTLP trace receivers qualify.
- Span observations, conflicts, trace summaries, quiescence, structural
  query, service relationships, and log/trace correlation qualify.

### M4 — Governance and Lifecycle

Exit:

- Tenant and principal lifecycle, audit, no impersonation, quotas,
  policies, durable operations, configuration, maintenance, integrity,
  clock safety, process lifecycle, doctor, and support bundles qualify.

### M5 — Recovery and Distribution Surfaces

Exit:

- External Key Providers and Backup Repositories qualify.
- Backup, restore, key migration, purge, and upgrade qualify.
- Native archives/packages, OCI, Compose, Nix, Helm, operator,
  Kubernetes, Grafana, and SDK artifacts pass their functional matrices.

### M6 — Release Qualification

Exit:

- Every required Qualification Cell is `Qualified`.
- Performance and soak preregistrations are unchanged or superseded with
  preserved negative evidence.
- All required registry artifacts share the Release Manifest identity.
- No non-waivable gate or unresolved release-blocking security finding
  remains.
- Independent artifact verification reproduces required payloads and
  validates signatures offline.

## 8. Scope Change Procedure

A Release 1 scope change requires a superseding ADR that lists:

- added, removed, or reclassified Scope Ledger entries
- affected gate IDs and targets
- architecture and compatibility consequences
- security, durability, recovery, and operational consequences
- implementation and qualification cost
- schedule impact and displaced work
- evidence needed to prove the replacement

Until that ADR is accepted and this document changes in the same commit,
the existing Qualification Matrix remains binding.
