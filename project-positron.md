# Project Positron

> Unified single-process observability database written in Rust.

> **Note:** This is the Release 1 product vision and architecture baseline.
> Implementation is in progress.

------------------------------------------------------------------------

# 1. Vision

Project Positron is a next-generation observability database designed
around a simple principle:

> **One binary. One process. One storage kernel. Every observability
> signal.**

Unlike traditional observability stacks that combine multiple
independent systems (logs, metrics, traces, profiles, search engines,
object stores, coordinators, queues, etc.), Positron aims to provide a
unified database kernel capable of storing and querying every
OpenTelemetry signal efficiently.

Core goals include:

-   Extremely low overhead
-   High ingestion throughput
-   Excellent full-text search
-   Native structured search
-   Columnar execution
-   Scale-up first
-   Optional clustering
-   Automatic workload-aware optimization
-   Standards-native telemetry interoperability
-   Rust-first implementation
-   Database-grade local installation and operation

------------------------------------------------------------------------

# 2. Philosophy

Positron is **not** intended to be a PostgreSQL replacement.

It is **not** intended to become another Elasticsearch clone.

Instead it is an observability-native database whose physical
design is optimized around append-only telemetry.

Positron is a standalone application and storage backend. Alloy,
Tempo, Loki, Pyroscope, Beyla, E-Navigator, or another collector or
backend is never required for Positron to operate. Compatibility lives
at versioned receiver boundaries; accepted telemetry is decoded into
Positron's native signal model and physical stores rather than retained
as an opaque vendor payload.

Ingest compatibility, query-language compatibility, dashboard
compatibility, and storage-format compatibility are separate claims and
must be tested and documented independently. The current receiver
research and staged matrix live in
`docs/research/telemetry-ingest-compatibility.md`.

The vocabulary in `CONTEXT.md` and accepted ADRs are binding design
constraints. Receiver adapters and optional integrations must reject
incompatible input rather than weaken tenant isolation, durability,
typing, bounded resources, native storage, or query semantics. Changing
a fundamental requires an explicit superseding ADR.

The Positron application is implemented entirely in Rust. The server,
storage kernel, signal stores, receiver adapters, query engine,
governance and lifecycle subsystems, and CLI ship without a Go, Java,
Node.js, or other language runtime. Other languages are allowed only for
external integration artifacts whose host platforms require them,
including minimal Grafana frontend code and SDKs generated from the
canonical public API definition. Such artifacts cannot own Positron
domain, storage, query-planning, policy, or durability logic. Any
reusable component that can reasonably be implemented in Rust remains
Rust.

Core principles:

-   immutable storage
-   append-only ingestion
-   specialized physical layouts
-   unified kernel
-   minimal dependencies
-   predictable latency
-   zero-copy execution whenever possible

------------------------------------------------------------------------

# 3. Non Goals

-   OLTP database
-   General relational database
-   Arbitrary ACID transactions
-   Arbitrary UPDATE-heavy workloads
-   Generic JSON database

------------------------------------------------------------------------

## 3.1 Release 1 Identity and Authorization

Release 1 authenticates principals with built-in API keys. Initialization
creates one system-administrator credential. Interactive initialization
may display its secret once; non-interactive initialization exposes it
through an owner-only one-time Bootstrap Claim. Only salted key hashes
are persisted after the claim material is destroyed.

Tenant principals receive fixed ingest, query, or tenant-administration
scopes. System administration is separate and cannot be inherited
through tenant administration. Every request resolves to exactly one
principal and tenant.

Keys may overlap during rotation and may be revoked immediately. The CLI
supports creation, listing, rotation, revocation, and scope inspection
without redisplaying secret material. Authentication and administrative
activities produce immutable governance audit records.

Governance audit records live in a kernel-owned append-only store,
separate from tenant telemetry and the future user-ingested audit signal.
Records contain ingest time, principal, applicable tenant, action,
target, outcome, request ID, and non-secret metadata. Secrets, raw API
keys, and sensitive request bodies are never recorded.

Security-relevant administrative mutations are acknowledged only after
their catalog change and audit record durably commit. If auditing is
unavailable, mutations fail closed. Authentication failures are recorded
when possible, but an auditing failure can never turn rejected
authentication into success.

Tenant administrators may read their tenant's audit subset; system
administrators may read all records. Tenant purge does not erase
governance history, and only system policy controls audit retention.
Records are hash-chained and periodic checkpoints are signed by the
Instance Integrity Key. This detects offline corruption and rollback
against a trusted checkpoint without claiming protection from a
compromised authorized process or an independently exported old copy.
The CLI can filter, verify, and export audit history.

Release 1 does not include passwords, browser login, SSO, OIDC, SAML,
SCIM, or customizable RBAC. Deployments may place an authenticating proxy
in front of Positron; native identity federation is follow-on work.

------------------------------------------------------------------------

## 3.2 Transport Security

Positron implements TLS natively in Rust for OTLP, Loki Push, Query API,
SDK, and administrative listeners. TLS 1.2 and 1.3 are supported.
Without TLS, listeners bind only to loopback or an explicitly configured
Unix socket by default.

Operators may explicitly enable non-loopback plaintext per listener.
This opt-out remains operationally ready but produces a governance audit
record, persistent health warning, and configuration warning. Plaintext
is never selected as an automatic fallback.

Certificates reload without restart, and an invalid replacement leaves
the previous valid identity active. Optional mTLS validates peers, while
API keys remain the Release 1 principal and scope identity. Direct
certificate-to-principal mapping is follow-on work.

Forwarded identity and tenant headers are trusted only from configured
proxy addresses, and API-key tenancy remains authoritative. Secrets,
private keys, and authorization headers are redacted from logs,
diagnostics, and audit metadata. SDKs verify certificates by default and
require an explicit plaintext or insecure-verification option.

------------------------------------------------------------------------

## 3.3 Deployment and Distribution

Positron is installed and operated like a standalone database. Release 1
must run directly from its native `positron` executable, from an OCI
container image, and through a supported Nix package. Docker,
Kubernetes, Nix, Alloy, Grafana, and external collectors are optional
Distribution Surfaces or integrations, never runtime prerequisites.
“Optional” here means that a database deployment need not install or
run the integration. Every Distribution Surface and integration named
as required by the Release 1 scope must still ship as a Release 1
artifact.

The same Rust application, configuration model, public APIs, storage
format, security defaults, and lifecycle commands apply across every
surface. The single binary provides server and administrative CLI
commands, including initialization, foreground serving, status,
verification, backup, restore, key management, and tenant lifecycle.

The Release 1 distribution matrix is:

-   native Linux `x86_64` and `aarch64` archives
-   native macOS Apple Silicon and Intel archives
-   Debian and Ubuntu packages
-   Fedora and RHEL-compatible packages
-   Homebrew formula and service integration
-   Nix flake with package, development shell, checks, and NixOS module
-   signed multi-architecture OCI image for `linux/amd64` and
    `linux/arm64`
-   Docker Compose quickstart
-   Helm chart for a standalone Kubernetes StatefulSet

Native Windows and FreeBSD support follow Release 1. Windows users may
run the Release 1 image through Docker or use WSL.

Docker is the primary portable runtime, not an optional afterthought.
The same OCI image runs under Docker, Docker Compose, and Kubernetes.
It contains the server and complete CLI, runs as a non-root arbitrary
UID in the foreground, supports an immutable root filesystem, writes
only to explicit data, configuration, temporary, and key mounts, emits
structured logs to standard output and error, honors cgroup CPU and
memory limits, exposes liveness and readiness health, and drains and
durably closes on `SIGTERM`.

Default Docker and Helm examples persist data and local-key material in
separate volumes. The image includes current CA roots but no shell,
package manager, language runtime, or debug tooling. Every image is
signed and published with checksums, an SBOM, and provenance.

The image entrypoint is the Rust binary itself, and its default command
is `positron serve --init-if-empty`. Container paths are:

-   `/var/lib/positron` for durable database data
-   `/var/lib/positron-secrets` for local key and bootstrap material
-   `/etc/positron` for configuration
-   `/run/positron` for disposable runtime state

Truly empty data and secrets mounts initialize transactionally, create
the default tenant and mandatory encryption hierarchy, and start
serving. Initialization resumes only a provably incomplete
initialization and never treats corrupt or inconsistent state as empty.
Existing data with absent or mismatched keys, and existing local key
material without its matching instance, fail closed.

Non-interactive initialization never prints the initial
system-administrator API key to container logs. It writes claim material
owner-only in the secrets mount. `positron bootstrap claim`, invoked
through Docker, Compose, or Kubernetes execution, returns the secret
once and atomically destroys the recoverable claim. Helm may instead
initialize from an operator-supplied Kubernetes Secret.

Integration tests cover install, initialize, ingest, query, restart,
backup, restore, key-management, and upgrade behavior for every
Distribution Surface. One signed release manifest binds all artifacts
to the same version and source commit.

------------------------------------------------------------------------

## 3.4 Kubernetes Operator

Release 1 includes a deployment-optional Positron Operator implemented
in Rust and shipped inside the standard OCI image. `positron operator`
runs the Kubernetes controller
and `positron serve` runs the database. There is no separate operator
executable, instance-manager binary, or required sidecar, and Positron
remains fully operable without Kubernetes.

Release 1 defines:

-   `PositronCluster`
-   `PositronBackup`
-   `PositronScheduledBackup`

The Positron Operator reconciles Kubernetes-native workloads, services,
storage, configuration, credentials, network policy, disruption policy,
TLS, Key Providers, backup, restore, fencing, hibernation, upgrades, and
status. `PositronCluster` may bootstrap a new database or restore a
verified Backup Snapshot.

`PositronCluster.spec.instances` is fixed to `1` in Release 1, and the
operator rejects higher values rather than presenting multiple
standalone pods as high availability. Removing a resource retains PVCs,
Backup Snapshots, and external key resources by default. Future
clustered releases extend the same resource model with replication,
leader placement, switchover, failover, and Virtual Shard movement.

The operator uses the same public administration APIs and lifecycle
contracts as the CLI. It never implements storage, durability, query,
or signal semantics in the Kubernetes controller.

Each Positron release supports every upstream-maintained Kubernetes
minor version at release time and records exact tested patch versions in
its Kubernetes Conformance Matrix. Release 1 tests both `amd64` and
`arm64` across upstream Kubernetes plus current EKS, GKE, AKS,
OpenShift, and k3s environments. Unsupported combinations are explicit;
compatibility is never described as best effort.

The operator uses stable Kubernetes APIs without requiring optional
feature gates. CRDs use `apiextensions.k8s.io/v1`, structural OpenAPI
schemas, defaults, CEL validation, status subresources, printer columns,
and explicit unknown-field pruning. Release 1 serves `v1beta1`; later
representations coexist through conversion and storage-version
migration before an older version is retired.

Resource status uses standard conditions with `observedGeneration`,
reason, message, and transition time. Reconciliation is idempotent,
watch-driven, bounded, and jittered, and it uses server-side apply with
explicit field ownership. Two operator replicas coordinate through a
stable `coordination.k8s.io/v1` Lease while the Release 1 database
remains one instance.

The operator supports cluster-wide or explicitly scoped multi-namespace
installation with generated least-privilege RBAC and never requires
`cluster-admin`. Bounded finalizers protect only operations that must
finish, with retain as the default deletion policy. Admission webhooks
are avoided when schema or CEL can enforce an invariant; conversion
webhooks are added only when multiple API representations require them.

Operator and database pods conform to the Restricted Pod Security
Standard: non-root execution, read-only root filesystem,
`RuntimeDefault` seccomp, no privilege escalation, and all capabilities
dropped.

Integration tests cover installation, reconciliation, drift repair,
operator leader failover, API outage, eviction, node drain, PVC detach
and reattach, Key Provider outage, backup and restore, certificate
rotation, operand and operator upgrade, CRD migration, uninstall with
retention, and restricted-namespace execution.

Operator and database images are independently pinned by immutable
digest. Operator version N manages database versions N and N-1 so the
controller may upgrade first. Database upgrades are declarative and
manual by default; an explicitly configured signed release channel may
automate patch upgrades, while minor and persistent-format changes
always require an intentional specification change.

Upgrade preflight verifies artifact signatures, the supported version
path, CRD compatibility, Key Provider and recovery readiness, disk
headroom, storage semantics, and absence of conflicting lifecycle work.
An upgrade without a format change gracefully replaces the pod and may
automatically restore the previous image on failure.

A persistent-format upgrade reports its service interruption and:

1.  stops admission and drains committed work
2.  seals active segments
3.  creates and verifies a Quiescent Upgrade Snapshot
4.  performs a copy-on-write migration
5.  atomically publishes the new format

Failure before publication resumes the old version unchanged. Failure
after publication never launches an incompatible old binary; rollback
restores the Quiescent Upgrade Snapshot into fresh storage. Because no
writes are accepted after that snapshot, rollback loses no acknowledged
data. Status exposes preflight, expected downtime, migration progress,
rollback availability, and the terminal outcome.

`PositronBackup` is an immutable one-shot request for one configured
Backup Repository. The operator invokes the running database through
its authenticated administration API and never mounts a live PVC into a
second Positron process. Status records conditions, start and completion
time, manifest digest, logical and transferred bytes, incremental reuse,
key-recovery readiness, and verification outcome.

A backup becomes `Completed` only after Positron verifies application
consistency, signatures, Repository Key Registry state, and required key
recovery. `PositronScheduledBackup` creates a visible
`PositronBackup` for every execution and defines timezone, schedule,
missed-start deadline, retention, and `Forbid` concurrency by default.
No backup work is hidden inside the controller.

Deleting a Kubernetes backup resource retains repository data by
default. Remote deletion requires an explicit policy and Governance
Audit Record. Repository authentication uses workload identity or
referenced Kubernetes Secrets whose values never appear in status or
Events.

Restore is bootstrap-only: the operator creates a new
`PositronCluster` and fresh PVC from a verified Backup Snapshot.
In-place overwrite, merge restore, and non-empty targets are rejected.
Purge Tombstones and the current Repository Key Registry apply before
readiness. Release 1 does not present CSI VolumeSnapshots as Positron
backups because a volume snapshot alone cannot prove application,
key-registry, and purge consistency.

Operator, database, or Kubernetes API interruption resumes status
reconciliation without duplicating a completed backup.

`PositronCluster.spec.lifecycle.mode` supports `Running`, `Fenced`, and
`Hibernated`. Fencing rejects ingestion, queries, tails, and
administrative mutations; drains work; durably flushes committed state;
seals active segments; and releases mutable storage ownership. The pod
remains alive only for health and authenticated local inspection and
repair.

The operator automatically fences ambiguous volume ownership,
instance-or-key mismatch, unsafe upgrade state, and irreconcilable
storage identity. Unfencing requires an intentional specification
change and successful storage, key, format, and ownership preflight.

Hibernation first reaches the same durable fenced state, then scales the
StatefulSet to zero while retaining PVCs, keys, Services, backups, and
resource status. Scheduled backups pause visibly. Resume neither
auto-initializes storage nor adopts mismatched material.

Deleting `PositronCluster` defaults to `Retain`: runtime resources are
removed while PVCs, repository data, and external keys remain.
Destructive deletion requires an explicit policy bound to the cluster
UID, backup and key checks, and Governance Audit Records. Finalizers
protect only active lifecycle transitions, expose actionable blocked
conditions, and never delete an external KMS key. Kubernetes Events
carry non-secret transitions and reasons; durable governance detail
remains in Positron.

------------------------------------------------------------------------

## 3.5 Operational Observability

Release 1 emits Operational Telemetry independently of the follow-on
native Metrics Signal Store. The database and Positron Operator expose
bounded Prometheus/OpenMetrics endpoints.

Database metrics cover process health, ingestion, rejection, durability,
segment lifecycle, compaction, retention, query budgets, live-tail lag,
encryption, Key Providers, backups, restores, and lifecycle state.
Operator metrics cover reconciliation latency and errors, retries,
leader state, resource conditions, upgrades, backups, fencing, and
drift.

Labels never contain trace IDs, span IDs, attribute values, API-key
identity, or unbounded tenant identity. Authenticated administration
APIs provide tenant-specific detail without creating high-cardinality
metric series.

Non-interactive logs are structured JSON; attached terminals receive
concise human-readable output. Internal events use stable names,
severity, component, request identity, and redacted tenant and key
references without secrets or telemetry bodies.

Optional internal traces export through OTLP only to an explicitly
configured external destination. Self-export to the same Positron
instance is rejected by default to prevent a telemetry feedback loop.

One internal Health State drives `/health/live`, `/health/ready`,
authenticated degraded detail, Kubernetes conditions, and non-secret
Events. Liveness reports process viability; readiness reports safe
traffic admission.

Release 1 ships operational Grafana dashboards, Prometheus alert rules,
Kubernetes `ServiceMonitor` examples, and actionable runbooks.
Operational telemetry is scraped or exported and is never silently
stored as tenant signal data.

------------------------------------------------------------------------

## 3.6 Configuration Contract

Every Distribution Surface consumes the same versioned Configuration
Contract derived from Positron's Rust configuration types. TOML is the
canonical human-authored file format. Release artifacts generate JSON
Schema, reference documentation, example configuration, and operator
validation from the same definitions rather than maintaining separate
Docker, Nix, Helm, or Kubernetes configuration models.

Configuration sources have deterministic precedence:

1.  compiled defaults
2.  the selected TOML configuration file
3.  environment variables named as `POSITRON__SECTION__FIELD`
4.  explicit command-line overrides

Environment and command-line overrides support non-secret settings
only. Secret-bearing settings contain typed references to protected
files, workload identity, external Key Providers, or Kubernetes
Secrets; they never contain literal secret values. Diagnostics preserve
the source of each setting while redacting secret material.
Provider-native credential discovery, such as an external cloud SDK's
standard environment or workload-identity chain, belongs to that
adapter's authentication boundary. It is not a `POSITRON__` secret
override, is never copied into the Effective Configuration, and is
reported only as redacted provider-authentication provenance.

Unknown fields, invalid types, unsupported versions, and unsafe setting
combinations are errors. Positron does not silently ignore or coerce
configuration. Deprecated fields produce a stable warning naming their
replacement and removal release.

`positron config validate` checks syntax and semantics without starting
the database. `positron config explain` describes fields and their
mutability. `positron config effective --redacted` renders the complete
Effective Configuration and its sources, and `positron config diff`
compares two configurations or a proposed configuration with the
running instance.

Every field declares exactly one Configuration Mutability class:

-   live-reloadable
-   drain-and-reload
-   restart-required
-   immutable after initialization

Reload may be requested through `SIGHUP`, the authenticated
administration API, or the Positron Operator. Positron parses and
validates a complete candidate snapshot before applying it. An invalid
candidate leaves the previous Effective Configuration active. A
drain-and-reload candidate enters bounded drain behavior before atomic
publication; restart-required changes remain pending and visible rather
than being partially applied. Successful and rejected administrative
configuration changes produce Governance Audit Records.

Instance identity, storage format, encryption identity, and initialized
durable paths are immutable after initialization. Changing them requires
an explicit migration or restore workflow rather than a configuration
override.

For an operator-managed deployment, `PositronCluster.spec` and its
referenced Kubernetes Secrets are the desired configuration. The
operator renders the canonical TOML representation, records its digest
in status, and detects Configuration Drift. Direct environment or
command-line overrides that bypass the custom resource are rejected.
The operator reconciles non-security drift and fences the instance when
drift affects immutable identity, encryption, storage ownership, or
safe lifecycle. Native, Docker, Nix, and Kubernetes installations
therefore expose one schema and one set of validation semantics.

------------------------------------------------------------------------

## 3.7 Resource Governance

The Storage Kernel owns one Resource Governor for ingestion, queries,
tails, compaction, retention, backup, restore, encryption, and
administrative work. Signal Stores report costs and consume grants but
cannot bypass admission or create private unbounded queues.

Global ceilings honor detected process and cgroup CPU and memory limits,
filesystem capacity, file-descriptor limits, and explicit operator
limits. Operator limits may conservatively lower detected capacity but
cannot make unavailable capacity admissible. Tenant quotas nest beneath
global ceilings and cannot reserve more than the system can safely
provide.

Before beginning bounded work, a component acquires a Resource
Reservation for its worst-case or conservatively estimated memory,
queue slots, and required disk headroom. Runtime accounting corrects
estimation error and cancels interruptible work before it violates a
hard ceiling. Already-admitted durability work retains the capacity
needed to finish and cannot be cancelled merely to admit newer work.

Scheduling preserves this priority order:

1.  durability completion and recovery
2.  security, fencing, purge, repair, and lifecycle administration
3.  ingestion
4.  interactive queries and live tails
5.  ordinary compaction, optimization, and backup

Priority does not permit starvation. Weighted-fair scheduling applies
within a class and across tenants, and maintenance receives bounded
progress guarantees. CPU-heavy operators use cooperative work units and
cancellation rather than monopolizing executor threads.

A Recovery Reserve is unavailable to ordinary workloads and protects
durability completion, retention, emergency compaction, purge, repair,
fencing, and safe shutdown. Disk Pressure State controls admission:

-   `Healthy` admits work within ordinary budgets.
-   `SoftPressure` throttles lower-priority work, accelerates eligible
    reclamation, and warns before safety headroom is consumed.
-   `HardPressure` rejects new ingestion and disk-growing maintenance
    while preserving bounded query, deletion, purge, repair, backup
    export, fencing, and shutdown paths that remain safe.

Compaction cannot consume its input segments or publish output unless
the reservation covers peak copy-on-write amplification. Retention and
emergency compaction draw from their protected reserve so reaching
pressure cannot itself prevent reclamation. Positron never relies on a
filesystem `ENOSPC` result as normal admission control.

Queues are bounded at every receiver and execution boundary. Capacity
rejections use stable typed errors, distinguish retryable overload from
permanent policy rejection, provide retry guidance when meaningful, and
preserve Partial Ingest Result semantics. Streamed queries and tails
terminate explicitly rather than silently truncating output.

Quota and system-limit changes follow Configuration Mutability, produce
Governance Audit Records, and cannot revoke capacity already committed
to durability work. Resource decisions expose bounded Operational
Telemetry for utilization, reservations, throttling, rejections,
pressure transitions, queue delay, fairness, and reserve consumption
without unbounded tenant labels.

The Positron Operator configures Kubernetes requests and limits
consistently with the database ceilings, but the database independently
observes its actual cgroup and storage environment. Kubernetes
scheduling or limits are never treated as a substitute for native
admission control.

------------------------------------------------------------------------

## 3.8 Primary Storage

Release 1 stores live database state on one Primary Data Volume exposed
through a database-safe filesystem. Native local filesystems, Docker
volumes, and filesystem-mode Kubernetes PVCs are Distribution Surfaces
for that same contract; they do not select different storage engines.

The Primary Data Volume contains active and sealed segments, catalogs,
kernel metadata, compaction output, recovery state, and persistent-format
upgrade staging. Temporary output that will be atomically published is
created within the same filesystem as its destination. Publication never
depends on cross-filesystem rename.

The durability contract requires:

-   durable synchronization of file contents and required parent
    directories
-   atomic same-filesystem rename for catalog and manifest publication
-   safe truncation and recovery of incomplete active-segment tails
-   stable reopen and read-after-synchronization behavior
-   reliable process-lifetime exclusive locking
-   correct error propagation for exhausted or read-only storage

Before recovery, Positron runs a bounded, non-destructive Storage
Capability Probe in a dedicated probe area and acquires a Storage
Ownership Lock. The probe exercises the required operations rather than
trusting a filesystem type string. Failure keeps data APIs closed and
reports the exact missing capability. No configuration flag may weaken
the storage semantics behind an Ingest Acknowledgment.

The lock is held by the operating system for the server process
lifetime; stale file existence is not treated as ownership. A second
writer fails before recovery. Kubernetes fencing, StatefulSet identity,
and volume access modes add coordination but never replace native
duplicate-writer prevention.

S3-compatible and other object storage is a Backup Repository only in
Release 1. Positron does not use object storage as an active segment or
catalog filesystem. Raw block devices and primary multi-writer shared
storage are follow-on capabilities.

A network filesystem or network-backed PVC is supported only when its
provider, product version, mount contract, and Kubernetes StorageClass
combination is supported in the release's storage section of the
Kubernetes Conformance Matrix. Passing a local capability probe is
necessary but not sufficient for a published crash-durability claim.
Unknown combinations are unsupported rather than silently advertised
as durable.

The Local Root Key File remains on a separate secrets root and must
independently satisfy its stricter ownership, permission, link, and
durable-publication contract. It is never placed inside the Primary Data
Volume merely because the data is encrypted.

Integration and fuzz tests cover abrupt process and node termination,
torn active-segment tails, failed synchronization, hard disk pressure,
remount, Docker volume restart, PVC detach and reattach, and
concurrent-writer attempts. Each supported storage combination must
recover every acknowledged Store Block or fail closed.

------------------------------------------------------------------------

## 3.9 Integrity Verification and Corruption Response

Positron verifies storage integrity continuously without making every
restart depend on a full scan of all telemetry. Startup validates the
catalog-generation chain, reachable manifests, key-envelope bindings,
instance and storage ownership, and the recoverable active-segment tail.
It records and authenticates a Durability Frontier for every active
segment.

Recovery may truncate an incomplete frame strictly after the Durability
Frontier. Authentication failure, structural inconsistency, or missing
bytes at or before that frontier means acknowledged durability can no
longer be proven and the instance enters Fenced state. Recovery never
uses current file length alone as evidence of acknowledged state.

A bounded Integrity Scrub walks every reachable immutable segment,
authenticates each Encrypted Frame, and validates block boundaries,
indexes, metadata, catalog references, and logical object checksums.
Scrubbing uses Resource Reservations, yields to foreground work, stores
durable progress, and eventually revisits all reachable data. Retention
and compaction cannot erase evidence for a discovered failure before it
is durably recorded.

`positron verify` supports:

-   online verification against a stable catalog generation without
    blocking ordinary safe traffic
-   deeper offline verification with exclusive storage ownership
-   resumable bounded execution
-   a machine-readable Verification Report containing scope, catalog
    generation, examined objects and bytes, omissions, findings, and
    terminal completion status

Verification never reports success for an incomplete scope. Secrets and
telemetry bodies are absent from reports.

An integrity failure in an otherwise isolated immutable segment creates
a Quarantined Segment. Positron removes it from ordinary reads without
claiming it was repaired, preserves its files and evidence, marks Health
State degraded, and reports the affected tenant, Signal Store, and
event- and ingest-time ranges through authenticated administration
surfaces. Unaffected ingestion and reads may continue only while
catalogs, keys, storage ownership, and every relevant Durability
Frontier remain trustworthy.

A query whose Query Snapshot requires quarantined data terminates with
an explicitly incomplete status and the affected range. It may return
already-produced valid batches but can never label the result complete
or silently substitute missing data. Corrupt or unauthenticated records
are never decoded and returned as telemetry.

Catalog-chain corruption, instance-identity ambiguity, Key Envelope
mismatch, unreliable storage ownership, or damage at or before a
Durability Frontier fences the complete instance. Local inspection,
verification, backup evidence export, and repair commands remain
available under the Fenced lifecycle contract.

Release 1 has no replica from which to infer missing bytes and therefore
performs no automatic data repair. The supported recovery path restores
a verified Backup Snapshot into fresh storage. If no recoverable copy
exists, a system administrator may perform Segment Abandonment only
through an explicit data-loss confirmation. The operation is
irreversible, produces a Governance Audit Record and durable integrity
record, names the lost tenant, signal, and time range, and never rewrites
the quarantined bytes into apparently valid data.

Future replicated releases may retrieve an immutable object from a
verified peer only when its complete object identity, size, checksums,
encryption context, and catalog reference match. That repair uses the
same quarantine and evidence model rather than creating a second
integrity contract.

Scrub age and progress, verification outcomes, quarantine state,
integrity failures, abandonment, and fencing reasons are exposed through
authenticated CLI and administration APIs, Health State, Governance
Audit Records, and bounded Operational Telemetry.

------------------------------------------------------------------------

## 3.10 Time and Clock Safety

Producer clocks are untrusted input. Positron preserves every Event Time
and signal-defined observed time exactly as received, including missing,
zero, out-of-range, skewed, or contradictory values. Validation
annotations describe their usability without rewriting the source
fields.

Every accepted record also receives an Ingest Time from the Storage
Kernel. Commit positions, not timestamps, define durable record order
and resume positions.

Each signal defines a provenance-bearing Query Time:

-   a log uses a valid source timestamp, otherwise a valid observed
    timestamp, otherwise its Ingest Time
-   a span uses a valid start timestamp, otherwise its Ingest Time

The stored record exposes which source supplied Query Time and why a
fallback occurred. Queries use Query Time by default and may explicitly
select Event Time or Ingest Time. A contradictory span, including an end
before its start, remains stored and searchable but is marked invalid
for duration-dependent computation and structural analysis never
fabricates a corrected duration.

Extreme but representable producer timestamps remain queryable through
bounded outlier structures. They cannot force unbounded partitions,
expand ordinary indexes, alter compaction buckets, or extend another
record's retention. Invalid values remain accessible through explicit
quality predicates.

Retention, quota age, and physical reclamation use Ingest Time only.
Producer time can neither retain telemetry indefinitely nor cause its
premature removal.

The Storage Kernel maintains a persisted, non-decreasing Lifecycle
Clock for retention, expiry, scheduled deletion, and other destructive
time-driven work. Within a running process it advances from monotonic
elapsed time and safely reconciles with UTC wall time. Restart compares
the new wall clock with the durable anchor before advancing lifecycle
state.

A wall-clock change beyond the configured safe reconciliation bound
enters `ClockUncertain`. Ingestion may continue from the safe Lifecycle
Clock anchor and records expose that condition, but retention,
scheduled destructive deletion, and other lifecycle actions that would
irreversibly interpret uncertain wall time pause. Security checks,
certificate validation, and monotonic Key Cache Leases retain their own
fail-closed time contracts. Queries by source time remain available.

Health State, Governance Audit Records, the administration API, CLI,
and Positron Operator conditions expose the observed offset, safe
anchor, paused actions, and remediation. The state clears automatically
only when clock recovery is unambiguous; accepting a discontinuity
requires explicit system-administrator action and a durable audit
record.

Request deadlines, execution budgets, cache leases, scheduling
intervals, and elapsed-duration measurements use monotonic clocks.
Calendar schedules retain explicit UTC offsets or IANA timezone names
and do not reinterpret already-recorded instants after timezone or
daylight-saving changes.

Unit, integration, and fuzz tests cover missing and contradictory
telemetry times, extreme source values, NTP slew and step, backward
restart, large forward jumps, timezone and daylight-saving changes, and
recovery from `ClockUncertain`.

------------------------------------------------------------------------

## 3.11 Compatibility and Versioning

Every Positron release publishes a machine-readable Compatibility
Manifest. Product, public API, query language, configuration, receiver,
Kubernetes CRD, operator-to-database, persistent storage, and backup
compatibility are independent claims in that manifest. A shared product
version or green compilation result cannot substitute for a tested
claim.

Positron product releases follow semantic versioning. A patch release
may fix behavior within an existing contract but cannot require a
persistent-format migration or break documented configuration, API,
query, SDK, or operational semantics. Minor releases may add compatible
capabilities and may require an intentional format migration under the
upgrade contract. Breaking public behavior requires a new major
contract.

Public API packages and native query languages carry explicit major
versions. Within `v1`, fields, methods, operators, result states, and
stable error codes evolve additively. An older valid `v1` client remains
supported by a newer `v1` server. Deprecation within a major version
documents a replacement but does not silently remove the old wire
contract.

Every server exposes an unauthenticated non-secret version summary and
an authenticated full Capability Statement. The statement includes:

-   product version and source identity
-   supported API packages and Schema Digest
-   supported native query-language versions
-   receiver protocols and feature gates
-   readable and writable persistent and backup Format Epochs
-   operator and CRD compatibility where applicable

Generated SDKs negotiate capabilities before using a feature introduced
after the baseline `v1` contract. A new SDK talking to an older server
returns stable `UNSUPPORTED_FEATURE` detail locally instead of sending a
request whose required semantics cannot be honored. Capability caching
is bounded and invalidated when server identity or version changes.

Configuration files contain an explicit schema version. A server reads
its current and immediately preceding minor configuration schema.
`positron config migrate` validates and writes a separate current-schema
candidate with a semantic diff; it never silently rewrites the
operator's source file. Skipping versions is allowed only when the
published Migration Graph contains that edge.

Persistent Format Epochs are independent of product versions. Each
binary declares the epochs it may read, write, and migrate. Until a
fenced copy-on-write migration atomically publishes a new epoch, the old
binary remains capable of opening the Primary Data Volume. After
publication, an older binary refuses to open a newer writable epoch
and exposes no override. Downgrade therefore means restore or an
explicitly published reverse migration, never hopeful startup.

Backup manifests declare their Format Epoch, minimum reader, feature
requirements, encryption context, and source product version. Restore
preflight follows the release's Migration Graph and rejects snapshots
from unknown or newer unsupported epochs before writing a target.

Receiver Adapter support is declared by pinned producer, protocol, and
version entries in the Ingest Compatibility matrix. API compatibility
does not imply OTLP, Loki, Tempo, Alloy, Beyla, E-Navigator, or other
producer conformance. Kubernetes CRD conversion and the operator N/N−1
database window likewise remain independently versioned and tested.

Integration tests cover old-client/new-server and new-client/old-server
behavior, stable errors and completion states, configuration migration,
backup restore, storage upgrade, downgrade refusal, CRD conversion,
operator skew, and every published receiver target.

------------------------------------------------------------------------

## 3.12 Tenant Lifecycle

Every Tenant has an immutable random Tenant ID, an immutable unique
Tenant Slug, and a mutable display name. Tenant ID is authoritative for
authentication, authorization, segments, encryption, quotas, audit,
cursors, backups, and destructive operations. Slugs are human-facing
locators and display names are labels; neither may silently redirect an
operation to a different Tenant ID.

Initialization creates the `default` Tenant through the same
transactional administration path used after startup. It has no
storage, authorization, encryption, retention, or quota bypass.

Tenant Lifecycle State is a durable state machine:

-   `Active` admits scoped ingest, query, tail, and administration.
-   `ReadOnly` rejects new ingestion while preserving bounded query,
    tail, and tenant administration.
-   `Suspended` rejects tenant ingest, query, and tail traffic while
    preserving system-administrator inspection and recovery.
-   `Purging` is the irreversible in-progress Tenant Purge state.
-   `Purged` is terminal and retains only non-reusable identity,
    Purge Tombstones, and Governance Audit Records.

Moving from `Active` to `ReadOnly` stops admission and drains already
admitted ingestion before publishing the state. Moving to `Suspended`
stops admission, drains committed ingestion, and cancels or drains
queries and tails according to their existing bounded contracts.
`Active`, `ReadOnly`, and `Suspended` transitions are reversible after
policy, key, quota, and storage preflight. Entering `Purging` is one-way.

Retention and physical reclamation continue in `ReadOnly` and
`Suspended`. Release 1 does not infer a legal hold from suspension;
holding data beyond its configured policy requires a future explicit,
audited legal-hold design.

Tenant creation atomically commits Tenant ID, slug, display name,
initial Signal Store retention, quotas, Tenant KEK, lifecycle state,
and Governance Audit Record. A failed transaction exposes no partial
tenant. The administrative operation accepts an idempotency key so a
retry cannot create a second tenant.

Tenant-bound Principals and API Keys cannot move between tenants.
Changing ownership means creating a replacement principal in the target
tenant and revoking the old credential through the ordinary rotation
workflow.

Quota reductions do not delete telemetry. When current usage exceeds a
new growth limit, the Resource Governor rejects additional growth until
retention or administration restores compliance. A retention reduction
first produces an impact preview covering affected Signal Stores, time
ranges, approximate bytes, and earliest reclamation; applying it
requires explicit confirmation bound to that preview.

Lifecycle, display-name, policy, quota, and retention mutations are
idempotent catalog operations. Their acknowledgment follows the
fail-closed governance contract: state and its redacted Governance Audit
Record commit together. Destructive operations require Tenant ID even
when a slug is supplied for operator confirmation.

Tenant IDs and slugs remain reserved after purge and restore applies
their Purge Tombstones before exposing any catalog state. A new tenant
can never inherit old API keys, encrypted data, cursors, audit history,
or backup reachability through identity reuse.

------------------------------------------------------------------------

## 3.13 Tenant Attribution and Impersonation

Every public data request performs Tenant Attribution before decoding
telemetry, planning a query, or acquiring a Resource Reservation. HTTP
uses `Authorization: Bearer <Positron API key>` and gRPC uses equivalent
authorization metadata. Successful authentication resolves exactly one
Principal and Scope and, for tenant-scoped work, exactly one Tenant ID.

Receiver payloads and compatibility hints are not authority. OTLP
resource or record attributes, Loki labels, URL parameters, request
bodies, and vendor fields cannot select or change a tenant.
`X-Scope-OrgID` or another supported protocol hint may be absent; when
present it must exactly match an External Tenant Alias bound to the
authenticated Tenant ID. A mismatch is rejected before any record in
the request commits.

External Tenant Aliases are protocol-specific, unique, immutable
bindings created through audited tenant administration. They exist only
to validate producer configuration and never replace Tenant ID. An
alias bound to a Purged Tenant is reserved permanently.

One request, stream, and Admission Group can belong to only one Tenant
ID. A receiver detecting mixed or nested tenant claims rejects the
request as a permanent validation failure rather than splitting it
across security boundaries.

A system-administrator Principal controls instance and tenant
administration but is not a tenant Principal. It cannot ingest as,
query as, tail as, or impersonate a tenant. Release 1 provides no
federated cross-tenant telemetry query. A system administrator who needs
data-plane access creates or rotates an explicit tenant-bound Principal
under the normal audited workflow.

The Positron Data Source and other automation use tenant-bound query
Principals. Each configured data source therefore has one Tenant
Attribution; selecting a different data source changes credentials
rather than supplying an arbitrary tenant header.

A configured trusted proxy must still authenticate with a Positron API
Key. Forwarded user or service identity may become Proxy Actor Context
in redacted Governance Audit Records, but it cannot expand Scope,
replace Principal, select Tenant ID, or suppress the proxy's own
identity. Forwarded headers from any unconfigured address are ignored or
rejected according to listener policy.

mTLS validates the network peer and protects transport. Release 1 does
not map a certificate subject, SAN, or issuer to a Principal or Tenant
ID.

Authentication and attribution failures use constant-shape,
non-enumerating responses. They do not reveal whether an API key,
Tenant ID, Tenant Slug, External Tenant Alias, or lifecycle state
exists. Detailed redacted reasons are available only through bounded
Governance Audit Records and Operational Telemetry.

Receiver conformance exercises absent and conflicting compatibility
headers, forged payload attributes, mixed batches, trusted and
untrusted proxy headers, revoked and wrong-scope keys, system keys,
suspended and purged tenants, and every supported HTTP and gRPC
transport. No successful fixture may attribute one accepted record to a
tenant other than the authenticated key's Tenant ID.

------------------------------------------------------------------------

## 3.14 Retry-Safe Administration

Every mutating public administration method accepts an Administrative
Idempotency Key. The server binds it to the authenticated Principal,
operation type, and digest of the canonical validated request. Retrying
the same binding returns the existing operation or terminal result
without executing the mutation twice. Reusing the key with different
content returns stable `IDEMPOTENCY_CONFLICT` detail and performs no
work.

Mutable administrative resources expose a Resource Generation. Policy,
quota, retention, configuration, lifecycle, alias, and credential
mutations carry an expected-generation precondition. A stale
precondition returns the current generation and a redacted semantic diff
rather than overwriting concurrent state.

Backup, restore, Tenant Purge, key rotation or migration, verification,
persistent-format migration, and upgrade are Durable Operations. The
initial request durably creates an Operation ID before asynchronous work
starts. State is one of:

-   `Pending`
-   `Running`
-   `Succeeded`
-   `Failed`
-   `Cancelled`

Operation status exposes its type, target identity, creator, accepted
generation, current phase, bounded progress, creation and update times,
terminal error code, safe retry guidance, cancellation availability,
and applicable Irreversible Boundary. Secret values and telemetry
contents never appear in operation state.

Cancellation is operation-specific and cooperative. Before its
Irreversible Boundary, cancellation restores or retains the documented
pre-operation state. At or after that boundary, Positron rejects
cancellation or performs the operation's documented forward recovery;
it never reports a rollback that did not occur. Each destructive
operation presents its boundary during preflight before execution.

Disconnect or deadline expiry changes only the caller's knowledge, not
the operation outcome. Clients treat it as unknown and resolve by
Administrative Idempotency Key or Operation ID. The API never maps a
transport timeout to a fabricated failed state.

Active operation records do not expire. Completed records remain
queryable under a documented system-governance retention policy, and
responses expose the earliest lookup expiry. Expiring an idempotency
index never removes its Governance Audit Records, domain tombstones, or
other safeguards against repeating a destructive transition.

Creation and every state transition durably commit with a redacted
Governance Audit Record. If that record cannot commit, the transition
does not publish. Operation history therefore remains distinct from,
but verifiable against, the governance history.

The CLI exposes consistent `--wait` behavior, progress display, and
stable `--output json` for every Durable Operation. Generated SDKs offer
create-or-resolve, get, wait, and cancel helpers over the same API.

The Positron Operator derives deterministic idempotency keys from
Kubernetes resource UID, observed generation, and operation type.
Reconciliation after process, network, or Kubernetes API interruption
reattaches to the existing operation.

Administrative idempotency does not alter the telemetry delivery
contract. Ingestion remains explicitly at least once and may preserve
duplicate observations after an ambiguous producer retry.

------------------------------------------------------------------------

## 3.15 Pre-Persistence Ingest Policy

Each Tenant owns a versioned declarative Ingest Policy beneath optional
stricter system-wide ceilings. The default policy accepts all telemetry
that satisfies the supported native signal and resource contracts. It
does not silently drop, truncate, coerce, hash, or redact fields.

Rules may match the Signal Store, Receiver Adapter, resource,
instrumentation-scope, or record attribute path and type, service
identity, log severity, or bounded body predicate. Rule evaluation is
deterministic, ordered, and limited by a compiled maximum rule count,
nesting depth, input bytes, and evaluation steps. Pattern matching uses
bounded Rust implementations without backtracking or user code.

Release 1 actions are:

-   accept the record
-   reject the record with a permanent policy result
-   remove a matched non-intrinsic field and attach a typed Redaction
    Marker
-   replace a matched non-intrinsic value with a typed Redaction Marker
-   truncate a matched non-intrinsic value to an explicit byte or
    element limit while marking the result as truncated

A policy cannot rewrite Tenant ID, Event Time, Ingest Time, Query Time
provenance, trace ID, span ID, commit position, encryption context, or
another Intrinsic Field that defines identity, durability, or
correlation. It may reject a complete record containing unacceptable
intrinsic data.

The ingest pipeline order is:

1.  bounded transport read and decompression
2.  authentication and Tenant Attribution
3.  structural protocol decoding
4.  Ingest Policy evaluation
5.  native semantic validation and Resource Reservation
6.  Store Block encoding, encryption, durable commit, and
    acknowledgment

Transport and structural failures occur before policy because Positron
cannot safely evaluate an unbounded or undecodable payload. Policy
transformations become native values before indexing and persistence;
the unredacted matched values are not written to Positron storage,
Operational Telemetry, Governance Audit Records, or error details.

Every admitted request snapshots one policy generation. Records already
being evaluated finish under that snapshot when a new policy atomically
activates. Every resulting Store Block carries Policy Provenance with
the exact policy version and digest; transformed records additionally
identify stable applied rule IDs and typed transformation markers.

Receiver responses distinguish permanent policy rejection, permanent
validation failure, and retryable capacity failure while preserving
Admission Group and Partial Ingest Result semantics. A protocol that
cannot express partial success follows its already-documented whole
request response behavior without rolling committed groups back.

`positron policy validate` compiles and bounds a candidate. `test`
evaluates fixtures without mutation, `diff` describes semantic rule
changes, and `explain` reports deterministic matching and actions with
secret output redacted. Policy changes require Resource Generation and
Administrative Idempotency Key preconditions and atomically commit with
Governance Audit Records.

Policy changes affect only telemetry admitted after their activation.
Release 1 performs no retroactive rewrite or arbitrary record deletion;
previously persisted content leaves managed live and backup scope only
through Retention Policy or whole-Tenant Purge. Activation therefore
requires an explicit warning when a new rule is intended to remediate
data that may already exist.

Operational Telemetry exposes bounded counts, latency, rejection class,
and stable rule ID, but never matched values or telemetry bodies.
Published Ingest Compatibility conformance uses the default preserving
policy; documentation states when an explicitly configured policy
intentionally changes producer semantics.

Release 1 executes only built-in Rust policy operators. Arbitrary
scripts, regular-expression engines with unbounded backtracking, WASM,
webhooks, and synchronous external processors are excluded.

------------------------------------------------------------------------

## 3.16 Dynamic Schema and Value Limits

The native value model preserves every supported OTLP value kind:
null or absent, boolean, signed integer, floating point, string, bytes,
array, and ordered key/value list. Receiver Adapters map source values
into this model without converting values to strings or collapsing
numeric kinds.

Resource, instrumentation-scope, and record attributes occupy distinct
namespaces. A dynamic attribute whose text matches an Intrinsic Field
remains in its source namespace and cannot shadow or replace the
intrinsic value.

The same attribute path may carry different types across records.
Positron stores typed variants and requires typed query behavior;
`"42"`, integer `42`, and floating-point `42.0` are not equal through
implicit coercion.

Repeated instances of one key within a single attribute collection form
an Attribute Occurrence Set. Positron preserves their source order and
typed values instead of selecting first- or last-write-wins. Query
operators address one occurrence by index or evaluate explicit `any` or
`all` semantics. Projecting the path returns the occurrence set, so
duplicate behavior cannot differ between filtering and output.

One Value Limit Profile bounds:

-   compressed and decompressed request bytes
-   records and aggregate attributes per request
-   encoded and decoded record size
-   log body and individual value size
-   attributes per namespace
-   key and path length
-   nesting depth
-   array and key/value-list length

System ceilings are compiled or configured within documented
safe maxima and cannot be raised by a Tenant. Tenant policy may lower
them. Bounded transport and decompression limits apply before structural
decode; semantic limits apply after Ingest Policy so an explicit
pre-persistence rule may remove, redact, or truncate otherwise rejected
content.

Exceeding an effective limit permanently rejects the affected record or
request according to what can be decoded safely. Positron never
silently truncates, drops, flattens, or coerces input. Receiver results
name the stable limit class and actual versus allowed magnitude without
echoing the offending value.

Each Tenant has a bounded Tenant Schema Catalog containing frequently
observed and queried paths, namespaces, typed variants, conflict counts,
and Attribute Promotion state. Catalog admission and automatic indexing
consume explicit per-tenant entry, memory, and persistent-byte budgets.
No tenant-controlled path becomes global planner state.

Valid attributes beyond catalog or index budgets enter Schema Overflow.
Their complete key, namespace, and typed value remain in the record's
generic representation and are queryable through an explicit path, but
they do not allocate catalog entries, statistics, dictionaries, or
automatic indexes. Queries over overflow data remain subject to Query
Budget and report reduced pruning.

Schema discovery returns bounded top paths, observed typed variants,
conflicts, promotion state, budget consumption, overflow record and byte
counts, and sampled path digests. It never enumerates an unbounded
attacker-controlled keyspace. Tenant administrators may request a
bounded paginated scan as a Durable Operation under an explicit budget.

Attribute Promotion consumes a per-tenant index budget, records its
reason and evidence, and remains a reversible physical optimization.
Demotion or budget exhaustion cannot change names, types, occurrence
semantics, or query results.

The CLI and administration API expose the effective Value Limit Profile,
catalog pressure, typed conflicts, bounded top paths, Schema Overflow,
and promotion decisions. Operational Telemetry reports bounded aggregate
counts without attribute names as metric labels.

Receiver conformance covers deeply nested values, mixed numeric kinds,
bytes, duplicate keys, cross-record type changes, high-cardinality path
names, compression expansion, every limit boundary, and policy-before-
limit behavior.

------------------------------------------------------------------------

## 3.17 Resumable Query Results and Exports

Every query response starts with a header containing the typed result
schema, Query Snapshot identity, deterministic ordering, effective
Query Budget, and initial Snapshot Lease and Query Cursor information.
It then emits bounded Result Batches and exactly one terminal status.

Search results default to Query Time followed by Commit Position and
signal-specific intrinsic tie-breakers. Explicit ordering must be total
for cursor pagination. A plan without a deterministic total order may
stream within one connection but is rejected when the caller requests
pagination, resume, or durable export.

Pagination uses an opaque authenticated Query Cursor and never a numeric
offset. The cursor binds:

-   Tenant ID and required Scope
-   API and query-language version
-   logical-plan and canonical-parameter digest
-   Query Snapshot catalog generation and per-store commit bounds
-   deterministic ordering and last emitted key
-   cumulative Query Budget consumption
-   Snapshot Lease identity and expiry
-   cursor-key epoch

Cursor contents are not an authorization credential. Every resume
reauthenticates a tenant query Principal, rechecks Tenant Lifecycle
State, verifies the cursor, and enforces current security policy without
allowing it to change the bound query.

A Snapshot Lease is a bounded persistent Resource Reservation that pins
the immutable segments and catalog generations needed by a resumable
query. Leases consume tenant counts, bytes, and lifetime quota, survive
process restart, and have a Release 1 hard maximum TTL of one hour
(3,600 seconds). Making that ceiling configurable is not a Release 1
configuration surface. This follows the existing one-hour hard lease
precedent for bounded key custody in ADR-0037. Compaction
and Retention Policy may logically replace data but cannot physically
reclaim a leased object until release or expiry. A lease never postpones
Tenant Purge.

Query Budget accounting is cumulative across pages, reconnects, and
server restarts. A caller cannot reset scanned bytes, output, compute
time, or traversal limits by requesting another cursor. Current stricter
security or resource ceilings may stop further execution, but they
cannot produce a result from a different snapshot.

Each Result Batch has a deterministic sequence number and content
digest. Its continuation cursor points after that complete batch. A
disconnect can make delivery of the last batch ambiguous, so resume is
at least once at the batch boundary; any repeated batch keeps the same
snapshot, sequence, and digest. CLI and Generated SDK helpers discard
verified repeats and reject a sequence whose digest changes.

Resume never skips an unambiguously pending batch and never moves to a
newer Query Snapshot. Cursor tampering, expiry, loss of required Scope,
Tenant suspension or purge, quarantine of required data, exhausted
budget, or unavailable leased state yields a stable explicit terminal
reason rather than silently restarting.

The terminal status is `Complete` only after every admitted operator and
Result Batch finishes. It otherwise names budget exhaustion,
cancellation, snapshot expiry, integrity failure, unavailable data,
authorization change, or internal failure as explicitly incomplete.
Terminal statistics include records and bytes emitted, records and
bytes scanned, pruning, cumulative budget, elapsed execution, resume
count, repeated-batch count, and Result Digest.

The Result Digest covers the logical sequence of batch digests once,
excluding transport retries. It lets an export consumer prove that
deduplication produced the same complete ordered result.

Large durable exports create a Durable Operation using the same Query
Snapshot, Snapshot Lease, Result Batch, budget, and completion model.
Output is written incrementally to an explicitly configured protected
destination with a signed manifest, batch digests, Result Digest, and
terminal state. Export never holds an unlimited connection or receives
an unlimited lease.

Release conformance interrupts every batch boundary, restarts the
process, rotates cursor keys, exercises cursor tampering and expiry,
races retention and compaction, quarantines required data, revokes
credentials, changes resource ceilings, and verifies cumulative budgets
and final Result Digests.

------------------------------------------------------------------------

## 3.18 Process Lifecycle and Graceful Shutdown

One Process Phase state machine governs native service management,
Docker, systemd, Kubernetes, and operator status:

-   `Starting`
-   `Recovering`
-   `Serving`
-   `Draining`
-   `Fenced`
-   `Stopping`

`Starting` parses and validates the complete Configuration Contract,
initializes local runtime facilities, and binds only the Control
Listener and Operations Listener. They expose non-secret startup state
and authenticated safe diagnostics under their separate contracts but
accept no telemetry, ordinary query, or mutating network administration
before readiness.

`Recovering` acquires the Storage Ownership Lock, runs the Storage
Capability Probe, verifies instance and key identity, opens Key
Providers, recovers active tails against Durability Frontiers, validates
catalog reachability, and initializes the Resource Governor. Data
listeners become ready only after every required step succeeds.

Syntactically or semantically invalid configuration exits nonzero before
storage mutation. Recoverable external dependency outages, including a
temporarily unavailable external Key Provider, keep the health process
alive and not-ready under bounded jittered retry. Instance, key,
ownership, or integrity ambiguity enters `Fenced` with only the
previously approved inspection and recovery surfaces.

`Serving` admits traffic according to Health State and tenant, resource,
and security policy. Liveness means the process event loop and critical
workers can still make progress. A dependency outage, `ClockUncertain`,
hard disk pressure, or another ordinary degraded/not-ready condition
does not by itself fail liveness and create a restart loop.

The first `SIGTERM` or interactive interrupt atomically begins a Drain:

1.  enter `Draining` and fail readiness
2.  stop new ingestion, query, tail, export, and mutating
    administration admission
3.  complete already-admitted ingestion using its retained Resource
    Reservations
4.  drain queries and exports within their existing budgets
5.  send tails a terminal status and newest safe Tail Cursor
6.  seal active segments and publish final Durability Frontiers and
    catalog state
7.  checkpoint pending governance evidence
8.  write a Graceful Shutdown Record
9.  zeroize cached keys, release the Storage Ownership Lock, and exit
    successfully

Shutdown does not extend an operation's Query Budget or create
unbounded waiting. A Durable Operation that can safely resume persists
its phase and stops at its documented boundary; another operation
either finishes within the drain budget or reports why graceful
shutdown remains blocked.

The configured shutdown deadline is visible through configuration
explanation and diagnostics. Docker, Compose, systemd, Helm, and
operator-generated Kubernetes settings must provide at least that grace
interval plus a documented safety margin. Inconsistent grace
configuration is rejected by generated deployment tooling and surfaced
as degraded for externally managed deployments.

A second termination signal requests immediate crash-safe exit. Positron
stops attempting graceful publication and exits nonzero without claiming
a Graceful Shutdown Record. Unacknowledged in-flight work may be absent
after recovery, while every acknowledged Store Block remains protected
by its already-published Durability Frontier.

If an orchestrator sends an uncatchable kill or the deadline expires,
the next start performs ordinary crash recovery. Receipt of `SIGTERM`,
container exit, or pod termination is never interpreted as evidence that
Drain completed.

`SIGHUP` requests only a transactional configuration reload under the
Configuration Mutability contract. It does not restart listeners,
rotate unrelated keys, compact, or initiate shutdown as an implicit
side effect.

Health endpoints, CLI status, systemd readiness notification, container
health checks, Kubernetes conditions and Events, and process exit codes
all derive from Process Phase and Health State. No Distribution Surface
maintains a competing lifecycle interpretation.

Integration and fuzz tests exercise startup and Drain under normal load,
disk pressure, corrupt tails, Key Provider outage, configuration reload,
long query, active tail, and Durable Operation. They verify readiness
transitions, terminal results, exit status, recovery, and
acknowledged-data preservation.

------------------------------------------------------------------------

## 3.19 Multi-Provider Backup Repositories

Release 1 implements one Rust Repository Adapter boundary with supported
providers for:

-   local filesystem
-   AWS S3
-   explicitly supported S3-compatible products
-   Google Cloud Storage
-   Azure Blob Storage

A Repository Conformance Target names the provider, product or managed
service, API behavior, deployment context or region where relevant, and
tested version. Positron never converts an S3 protocol resemblance,
emulator result, or successful upload into an unsupported compatibility
claim.

Every writable Repository Adapter must provide:

-   immutable put-if-absent object creation
-   authoritative object metadata and size lookup
-   bounded ranged reads
-   end-to-end checksum verification
-   resumable or multipart upload with abandoned-upload cleanup
-   conditional compare-and-swap publication of the registry head
-   explicit, observable deletion
-   bounded retry classification and throttling feedback

A provider without reliable conditional publication cannot host a
writable Repository Key Registry. Positron uses direct metadata,
conditional requests, and content identities for correctness and does
not require list results to be immediately consistent.

`positron repository init` creates an immutable Repository Identity in
an explicitly selected empty prefix. The identity binds repository ID,
instance authorization, format, provider kind, prefix, and integrity-key
fingerprint. Positron refuses to initialize or silently adopt a
non-empty foreign prefix. Attaching an existing Positron repository
requires explicit identity verification and never rewrites its owner.

Credentials use provider-native workload identity, standard credential
chains, or protected file and Kubernetes Secret references. Secret
values are absent from the Configuration Contract, Backup Snapshots,
Repository Key Registry, Kubernetes status and Events, Operational
Telemetry, Governance Audit Records, and diagnostics.

All external provider transport uses verified TLS with no insecure
opt-out. Positron encrypts and authenticates every backup object before
upload under the existing encryption and envelope contracts.
Provider-side encryption, customer-managed bucket keys, or storage
service controls are additional defense and never replace native
encryption or key recovery.

Repository Immutability Policy, object versioning, retention, legal
hold, and WORM state are detected where provider APIs expose them and
reported during initialization, verification, backup, and purge
preflight. If provider controls keep a reachable Tenant KEK envelope,
Tenant Purge remains visibly pending rather than claiming cryptographic
completion.

Uncoordinated provider lifecycle expiration or mutation is unsupported.
External policies may retain objects longer than Positron but cannot
delete or rewrite objects still reachable from the registry and snapshot
manifests. `repository doctor` identifies observable lifecycle conflicts
without claiming it can discover every out-of-band provider policy.

The CLI provides:

-   `positron repository init`
-   `positron repository verify`
-   `positron repository doctor`
-   `positron repository status`

These commands validate Repository Identity, required permissions,
conditional publication, checksum and range behavior, resumable upload
recovery, credential and Key Provider access, registry integrity,
immutability, and purge compatibility. Tests use dedicated probe objects
and never delete unknown contents.

Repository operations use Resource Reservations and Durable Operations.
Concurrent snapshots share immutable checksum-addressed objects while
Registry Generations serialize through compare-and-swap. Interrupted
uploads and publications resume idempotently without making an
incomplete snapshot current.

Release claims require real-provider tests for initialization,
concurrent publication, interrupted and partial upload, throttling,
credential rotation, stale list results, checksums, range restore,
registry recovery, Backup Envelope Overlay, retention, deletion, Tenant
Purge, and complete restore. Emulator tests may accelerate development
but cannot replace the named provider target.

Repository Adapters remain backup infrastructure only. They never expose
object storage as Release 1 active segments, catalogs, or a Primary Data
Volume.

------------------------------------------------------------------------

## 3.20 Catalog and Control-Plane Transactions

Release 1 catalog state is a graph of immutable encrypted Catalog
Objects rather than a mutable database file. A Catalog Generation names
its predecessor hash, instance identity, Format Epoch, root objects,
tenant and system manifests, Envelope Catalog state, Durable Operations,
Snapshot Leases, configuration and policy generations, governance-audit
frontier, and complete reachable-object digest.

One Storage Kernel Catalog Writer serializes catalog mutations in
Release 1. Readers pin immutable Catalog Generations and do not block
the writer while traversing an older generation. Resource Generation
preconditions are checked again inside the serialized transaction
before new state is prepared.

Telemetry ingestion does not execute a Catalog Transaction for every
Store Block. Active-segment append, Durability Frontier publication, and
Commit Position assignment retain their dedicated bounded fast path.
Catalog publication occurs for segment creation and sealing, manifest
replacement, and other lifecycle transitions rather than each record.

A Catalog Transaction commits in this order:

1.  build and encrypt every new immutable Catalog Object
2.  write each object into a transaction-owned staging area
3.  durably synchronize object contents and required directories
4.  reserve the next governance-audit chain position and durably write
    any required Prepared Audit Entry
5.  create an encrypted Catalog Commit Record binding the new root,
    predecessor, transaction ID, prepared audit frontier, and
    object-set digest
6.  synchronize the commit record
7.  atomically rename a small authenticated commit marker into the
    published generation directory
8.  durably synchronize that directory

The published commit marker contains only bootstrap routing needed to
identify and authenticate the encrypted Catalog Commit Record. Its
durable atomic publication is the single visibility point. The
transaction is acknowledged only after the directory synchronization
completes.

A Prepared Audit Entry is not a Governance Audit Record visible to
readers until the Catalog Commit Record that references it publishes.
The Governance Audit Store has one logical append sequencer. A Catalog
Transaction reserves its predecessor and next position; later audit
entries cannot chain through that position until the transaction
publishes or abandons it. Bounded callers may wait, while best-effort
authentication-failure recording may be dropped with an aggregate
counter rather than changing the rejected authentication outcome.

If catalog publication fails, the previous catalog and governance
frontiers remain current, the reserved position is released, and its
transaction-owned Prepared Audit Entry remains unreachable evidence.
Later audit entries continue from the prior committed hash. Recovery
never truncates an unrelated committed audit record or allows a chain to
reference an invisible entry.

Governance-sensitive tenant, principal, policy, quota, retention,
configuration, key, repository, and lifecycle mutations cannot publish
without their bound audit entry. Catalog state and governance evidence
therefore become visible through one commit point rather than through
best-effort coordination between stores.

Segment sealing, compaction, retention, quarantine, Segment
Abandonment, key rotation, Tenant Purge, Durable Operation progress,
Snapshot Lease state, backup snapshot capture, and graceful shutdown
use the same Catalog Transaction protocol where they change
control-plane reachability.

Recovery enumerates published commit markers and selects the highest
Catalog Generation whose complete predecessor chain, commit record,
audit frontier, object-set digest, key context, and referenced objects
verify. A torn marker is unpublished and falls back to its predecessor.
A fully published generation with missing or unauthenticated reachable
state is integrity corruption and enters `Fenced`; recovery never
combines objects from different generations to invent a plausible root.

Old Catalog Generations and Catalog Objects remain reachable while
required by a Query Snapshot, Snapshot Lease, backup capture,
verification, migration, or recovery window. Reference-driven garbage
collection removes only objects unreachable from every protected root,
uses Resource Reservations, and records orphan and reclamation evidence.
Tenant Purge follows its stronger envelope-removal rules and is not
delayed by an ordinary Snapshot Lease.

The CLI provides authenticated online `positron catalog inspect` and
`positron catalog verify`, plus exclusive offline `positron catalog
recover`. Recovery tooling lists valid generations, failures, orphans,
audit frontiers, and projected data loss before any change. It may
publish an existing fully verified generation only through explicit
system-administrator confirmation and Governance Audit evidence; it
never synthesizes missing Catalog Objects or auto-selects a lossy root.

The Catalog Writer implements a logical commit interface independent of
local file publication. A future clustered release can order the same
transactions through metadata consensus while preserving Catalog
Objects, manifests, Signal Store boundaries, audit binding, and reader
snapshots.

Integration and fuzz tests crash and remount the process across object,
audit, commit-record, rename, and directory-synchronization boundaries.
Every recovery must expose either the complete predecessor or the
complete successor generation, never mixed state or a governance
mutation without its audit record.

------------------------------------------------------------------------

## 3.21 Listener Topology and Connection Protection

Release 1 defines six independently configurable listener roles:

-   `control` is the Control Listener.
-   `operations` is the Operations Listener.
-   `api` serves native query, streaming, SDK, tenant administration,
    and system administration over HTTP/1.1 and HTTP/2.
-   `otlp-grpc` receives OTLP logs and traces over gRPC.
-   `otlp-http` receives OTLP logs and traces over HTTP.
-   `loki-push` receives the supported Loki Push surface.

The Control Listener is an owner-only Unix socket, located at
`/run/positron/control.sock` in the container contract. It supports
Bootstrap Claim, startup progress, safe diagnostics, fenced inspection,
and explicit local recovery. Filesystem ownership and permissions gate
the bootstrap-only surface; other privileged commands additionally use
ordinary system-administrator authorization when the identity subsystem
is available. The socket cannot be mapped to TCP, forwarded by the
server, or used for tenant data traffic.

The Operations Listener exposes only minimal non-secret live and ready
responses, redacted product identity, and Prometheus/OpenMetrics. It
binds loopback by default. A non-loopback metrics endpoint requires
mTLS, an authenticated API key with sufficient system scope, or an
explicit unauthenticated-metrics configuration. That explicit choice is
visible in Health State and configuration diagnostics. Full Capability
Statements, verification detail, tenant status, errors, and diagnostics
remain authenticated administration surfaces.

For this metrics-only case, mTLS is an explicit listener peer allowlist,
not certificate-to-Principal mapping. It grants no query, ingest, or
administration Scope and does not change the Release 1 API-key identity
contract.

The conventional defaults for OTLP are TCP `4317` for gRPC and `4318`
for HTTP. Other default ports and all bind addresses are declared in the
generated configuration reference rather than inferred from container
port publication. Every network listener defaults to loopback unless a
Distribution Surface intentionally renders a different binding.

Each listener has a separate Network Listener Profile covering:

-   bind addresses and protocol versions
-   certificate and trust stores
-   TLS and optional mTLS policy
-   Plaintext Opt-Out
-   proxy CIDRs and fixed forwarded-header hop count
-   connection and TLS-handshake concurrency
-   request headers, compressed bytes, decompressed bytes, and expansion
    ratio
-   HTTP/2 streams, flow-control windows, and frame behavior
-   gRPC message, keepalive, and ping limits
-   idle, header, body, request, and drain deadlines

Network data listeners do not bind a non-loopback address without a
valid TLS identity unless that exact listener has an explicit Plaintext
Opt-Out. Failure to load or validate a replacement certificate leaves
the previous listener active. Kubernetes examples reference certificate
Secrets and integrate with cert-manager issuance and rotation; Positron
does not claim or silently create a publicly trusted certificate.

Only the minimal liveness and readiness responses may be unauthenticated
without additional configuration. Ingestion, query, tail, export,
administration, full capabilities, metrics under a protected profile,
and diagnostics require authentication and applicable Scope.

CORS, browser cookies, implicit credential forwarding, and wildcard
origins are disabled by default. Enabling specific CORS origins is an
explicit API-listener setting and never enables cookie authentication.

Connection Admission runs before API-key parsing and Tenant Attribution.
It uses bounded per-address and global reservations for accepted sockets,
TLS handshakes, headers, bodies, decompression, HTTP/2 streams and
windows, gRPC messages, keepalive, ping frequency, and idle lifetime.
Once authentication succeeds, Principal and Tenant limits account for
subsequent work without releasing global reservations prematurely.

Resource exhaustion rejects or closes work with protocol-correct stable
overload behavior. The operating-system listen backlog is not considered
admission control, and slow or half-open clients cannot hold an
unbounded task, buffer, timer, or file descriptor.

Forwarded identity and address headers are considered only when the
immediate peer belongs to an exact configured proxy CIDR and the
listener's fixed hop policy validates. Otherwise they are ignored or
rejected according to profile. Release 1 provides no PROXY protocol,
dynamic proxy discovery, or trust based on a forwarded header itself.
Proxy Actor Context remains non-authoritative under Tenant Attribution.

A live-reloadable Network Listener Profile is parsed, bound, and
cryptographically validated as a complete replacement before
publication. The previous listener stops admission only after the new
one is ready, then drains existing connections under its old bounded
policy. Bind conflict or invalid policy leaves the old listener active.

The Positron Operator renders profiles, certificate references, Network
Policies, Services, probes, and ServiceMonitor authentication
consistently. Kubernetes NetworkPolicy and ingress controls supplement
but do not replace Connection Admission.

Integration and fuzz tests cover slow headers and bodies, idle
exhaustion, TLS handshake floods, invalid and rotated certificates,
HTTP/2 stream and window abuse, gRPC keepalive and ping abuse,
compressed expansion, oversized messages, proxy spoofing, port
conflict, replacement failure, and graceful listener drain.

------------------------------------------------------------------------

## 3.22 Maintenance Coordination

One Storage Kernel Maintenance Coordinator owns Release 1 background
work. Signal Stores and kernel subsystems submit typed Maintenance Tasks
and cannot create private schedulers, unbounded queues, or unaccounted
background loops.

Maintenance Task classes include:

-   active-segment rolling and sealing
-   compaction and index construction
-   retention publication and physical reclamation
-   catalog and orphan reclamation
-   Integrity Scrub and quarantine follow-up
-   Tenant Schema Catalog statistics, promotion, and demotion
-   governance-audit checkpoints
-   key rewrap, envelope verification, and migration
-   Backup Repository verification and cleanup
-   Backup Snapshot and durable export work
-   Snapshot Lease and completed-operation expiry

Each task has a stable identity, task class, Tenant ID or system scope,
Signal Store and Virtual Shard where applicable, immutable input object
identities, Resource Generation and catalog preconditions, priority,
estimated Resource Reservations, checkpointed progress, and terminal
outcome. Retrying the same identity attaches to or resumes the existing
work.

The coordinator maintains an explicit conflict graph. Tasks whose input,
output, envelope, manifest, or tenant lifecycle effects conflict cannot
run concurrently. Immutable input remains reachable until one
successful task atomically publishes output through a Catalog
Transaction. A failed or cancelled task leaves no partially current
state.

Every task reserves memory, CPU work, I/O concurrency, queue capacity,
and peak copy-on-write disk headroom through the Resource Governor.
Durability, recovery, lifecycle safety, foreground ingestion, query,
and maintenance priorities retain their accepted ordering and Recovery
Reserve. Maintenance cannot bypass hard pressure because it labels
itself internal.

Scheduling is weighted-fair across Tenants, Signal Stores, and Virtual
Shards. Task-class priority cannot starve a tenant indefinitely, and
ordinary foreground load cannot prevent bounded maintenance progress
until disk pressure becomes unavoidable. Backlog age and explicit
progress SLOs determine starvation rather than queue position alone.

Urgent work is event-driven by segment thresholds, disk pressure,
quarantine, purge state, lease expiry, key state, and catalog
reachability. Periodic scrub, verification, backup, audit checkpoint,
and optimization work uses the Lifecycle Clock with deterministic
per-instance jitter to prevent synchronized fleet load.

`ClockUncertain` pauses age-derived retention eligibility and scheduled
destructive work. It does not stop authentication of existing objects,
safe compaction, integrity response, or reclamation whose eligibility
was already durably established without the uncertain clock.

A Maintenance Window may defer optional compaction optimization,
promotion, demotion, repository verification, scheduled backup, and
durable export. It cannot disable durability completion, crash recovery,
integrity response, Tenant Purge progress, retention obligations,
security rotation deadlines, or emergency reclamation.

A Maintenance Pause applies only to declared deferrable task classes,
requires Administrative Idempotency Key and Resource Generation
preconditions, carries an explicit bounded expiry, and produces
Governance Audit Records. Status continuously reports deferred work,
capacity risk, retention or recovery implications, and the time at which
automatic resume occurs. Release 1 provides no indefinite global pause.

Long tasks publish bounded progress checkpoints through Catalog
Transactions and resume after process restart without rereading all
completed input. Copy-on-write outputs that never publish remain orphan
evidence and become eligible for reference-driven reclamation only after
verification proves them unreachable.

The Positron Operator observes Maintenance Coordinator status and may
request native Durable Operations. It never mounts storage to compact,
delete, verify, rotate, or rewrite data itself. Kubernetes CronJobs are
not correctness machinery for database maintenance.

The CLI and administration API provide:

-   `positron maintenance status`
-   `positron maintenance explain`
-   `positron maintenance run`
-   `positron maintenance pause`
-   `positron maintenance resume`

They expose task identity and class, bounded scope, current phase,
backlog age, reservations, conflict owner, blocked precondition,
estimated amplification, expected foreground impact, checkpoint,
terminal outcome, and safe operator actions.

Health State and Operational Telemetry expose bounded task counts,
backlog age, queue delay, progress, reservation pressure, starvation,
failure classes, and SLO violations. Metrics do not place Tenant IDs,
segment identities, keys, or attribute paths in labels; authenticated
status provides that detail.

Integration tests run each task class concurrently with representative
ingest, query, tail, backup, and administration load. They add disk
pressure, `ClockUncertain`, dependency outage, repeated task failure,
crashes at checkpoints and publication boundaries, conflicts, pauses,
and restarts. Fuzz tests exercise scheduler inputs and state
transitions.

------------------------------------------------------------------------

## 3.23 Diagnostics, Offline Inspection, and Support Bundles

`positron doctor` is a bounded read-only diagnostic workflow. Online
mode uses authenticated administration APIs or the owner-only Control
Listener. Offline mode requires the server to be stopped and acquires
the Storage Ownership Lock before inspecting the Primary Data Volume.

A Doctor Report covers:

-   Configuration Contract validity and effective redacted sources
-   Primary Data Volume capabilities, ownership, pressure, and
    headroom
-   instance, encryption, Key Provider, key-envelope, and recovery
    readiness
-   Catalog Generation chains, Durability Frontiers, manifests,
    quarantine, and scrub state
-   Resource Governor reservations, queues, fairness, and Recovery
    Reserve
-   Maintenance Coordinator backlog, conflicts, checkpoints, and
    pauses
-   Durable Operations and Snapshot Leases
-   Network Listener Profiles, certificates, proxy trust, and drain
    state
-   Backup Snapshot and Backup Repository identity, verification, and
    purge compatibility
-   Process Phase and Health State derivation

Doctor performs no mutation, truncation, catalog publication, repair,
unfencing, key rotation, deletion, or provider change. It produces
stable finding codes, evidence scope, severity, and safe next commands.
Repair and recovery stay in separate workflows with impact preview,
Administrative Idempotency Key, Resource Generation preconditions,
explicit confirmation, Irreversible Boundaries, and Governance Audit
Records.

`positron support bundle create` emits a versioned bounded Support
Bundle with a manifest and checksum for every member. Its default
allowlist includes:

-   redacted Effective Configuration and Compatibility Manifest
-   product, API, schema, build, and Format Epoch identities
-   Health State and a bounded Operational Telemetry snapshot
-   recent already-redacted structured operational logs
-   non-content catalog topology and verification summaries
-   bounded resource, maintenance, operation, listener, backup, and
    repository status
-   filesystem and operating-environment characteristics needed to
    evaluate the supported contract
-   Doctor Report and sanitized Crash Records

A Support Bundle never contains tenant telemetry records or bodies,
query results, API-key secrets or hashes, TLS private keys, Root KEKs,
Tenant KEKs, Segment DEKs, unwrapped key material, Local Root Key Files,
Recovery Bundles, provider credentials, authorization headers, secret
environment values, Kubernetes Secret values, raw process memory, or
core dumps.

Tenant IDs, external aliases, network addresses, hostnames, usernames,
filesystem paths, repository coordinates, and provider identifiers are
pseudonymized by default with an ephemeral per-bundle keyed mapping.
Equal values remain correlatable within that bundle but not across
bundles. A system administrator may explicitly retain named identifier
classes; the choice is listed prominently in the Redaction Report.

Bundle inclusion and redaction are generated from typed schema
classifications and a closed allowlist. Unknown fields are excluded.
Free-form regex substitution is defense in depth and never the primary
secrecy control. The Redaction Report identifies policy version,
included data classes, excluded classes, retained identifiers,
pseudonymization, byte and time limits, declared truncation, encryption,
and signature state.

Generation obtains Resource Reservations and enforces hard elapsed-time,
input-log-window, file-count, and archive-byte bounds. If a permitted
source exceeds a bound, the bundle contains a deterministic truncated
summary and declares the omission; it never silently claims completeness.

A Support Bundle may be encrypted as an age v1 artifact to one or more
native X25519 recipients. Plain archive output requires an explicit
`--allow-plaintext-bundle` option, atomic owner-only file creation, and
a persistent security warning in the Redaction Report. Passphrases,
SSH recipients, and external plugins are not accepted implicitly.
The bundle is an explicit operator export outside Positron-managed
database persistence. Its plaintext escape hatch therefore does not
create a plaintext mode for segments, catalogs, audit, backups, staging,
temporary database state, or any other managed persistent object.

When the Instance Integrity Key is available, it signs the bundle
manifest and the manifest binds every member checksum and Redaction
Report. A Fenced instance whose required key is unavailable may still
create a checksum-protected bundle, but its unsigned reason is explicit
and cannot be presented as authenticated instance evidence.

Panic handling writes only a bounded sanitized Crash Record with product
and build identity, Process Phase, stable component and finding code,
safe backtrace identity, and applicable catalog and operation
generations. Positron never enables OS core dumps or memory capture
automatically because memory may contain telemetry, credentials, and
unwrapped keys.

Runtime diagnostic-level changes follow Configuration Mutability,
Resource Generation, and Governance Audit contracts. No logging level
permits secrets, authorization values, telemetry bodies, query results,
or plaintext key material.

The complete doctor and bundle implementation ships in the standard
Rust binary and minimal OCI image. Operators use it directly, through
`docker exec`, or through `kubectl exec`; no shell, package install,
debug container, sidecar, or separate language runtime is required.

Release tests seed unique canary credentials, key material, telemetry,
identifiers, paths, proxy metadata, provider errors, and panic inputs
through every subsystem. Online, offline, startup, degraded, Fenced,
key-unavailable, truncated, encrypted, and explicitly plaintext bundle
tests fail if prohibited bytes or undeclared identifier classes appear.

------------------------------------------------------------------------

## 3.24 Supply Chain, Signing, and Security Response

Every release has one signed machine-readable Release Manifest. It binds:

-   product version, source commit, source archive, and build identity
-   API version, Schema Digest, generated definitions, and SDK Release
    Set
-   Compatibility Manifest, Migration Graph, and Format Epochs
-   every binary, archive, OS package, OCI index and image, Nix output,
    Helm chart, Grafana plugin, SDK package, and documentation artifact
-   checksums, target platform, toolchain, generator, and dependency
    inputs
-   SPDX and CycloneDX SBOM identities
-   build and publication provenance
-   license notices and dependency policy result
-   conformance, test, fault, security, and reproducibility evidence
-   registry location, immutable identity, and publication state

The Release Manifest is the root of a completed release. A Git tag,
registry tag, package version, or successful CI workflow alone is not
release authority.

Builds use pinned Rust, linker, platform, Protobuf, OpenAPI, SDK,
frontend, package, and documentation toolchains; committed lockfiles;
locked dependency resolution; isolated CI; and captured source inputs.
A build cannot silently resolve a newer dependency or generator than the
manifest declares.

Linux binaries, the unsigned OCI filesystem payload, generated API
artifacts, and Generated SDK source packages are Reproducible Payloads.
Independent builders must recreate their functional bytes from declared
inputs. Platform code signing, macOS notarization, registry metadata,
timestamps, and transparency proofs are recorded as separate wrapping
layers so their expected nondeterminism cannot excuse drift in the
payload.

Every applicable artifact has cryptographic checksums, SPDX and
CycloneDX SBOMs, license notices, build provenance, and the strongest
native registry signature or trusted-publishing evidence available.
OCI artifacts use immutable digests and transparency-backed signatures.
Docker, Compose, Helm, operator, and upgrade examples use digests as
authority rather than mutable tags.

`positron release verify` validates a downloaded or installed artifact
against the Release Manifest: signature chain, Project Trust Root,
revocation state, checksum, target platform, product and API identity,
Schema Digest, Compatibility Manifest, and applicable transparency
inclusion proof. Verification can run offline using explicitly installed
trust and bundled proofs; it never silently fetches a new trust root.

Signing identities have documented online and offline custody,
separation of duties, rotation, expiry, and incident procedures.
Successor keys are cross-signed by an authorized predecessor or the
Project Trust Root where possible. Revocations and emergency trust
updates are signed, versioned, published independently of ordinary
release channels, and tested in native, OCI, Nix, package, Helm, and
operator verification paths.

Rust crates deny `unsafe` by default. A module requiring unsafe code is
explicitly isolated and reviewed with documented safety invariants,
call-site constraints, ownership, and targeted tests. Persistence,
cryptography, parser, decompression, network framing, and foreign-
interface boundaries receive applicable fuzz tests with regression
corpora.

Product behavior is covered by comprehensive unit tests, integration
tests, and fuzz tests. Integration tests include interoperability,
compatibility, crash and remount, corruption, backup and restore,
migration, Kubernetes, network abuse, resource pressure, security, and
supported-target behavior.

Publication may resume idempotently after a registry failure, but the
version remains incomplete and unannounced until every required
Distribution Surface, Grafana plugin, and Generated SDK exists under the
exact manifest identity. Publication never increments versions merely
to recover from partial registry completion.

Native installations do not self-update in Release 1. They may fetch or
receive metadata for a signed available version and run `release
verify`, but installation remains an explicit operator action.
Operator-driven automatic updates remain opt-in and patch-only, use
immutable signed digests, and obey the approved preflight, Drain,
Quiescent Upgrade Snapshot, migration, and rollback rules.

The repository publishes `SECURITY.md` with private reporting,
encryption for sensitive reports, disclosure coordination, severity
triage, supported versions, and time-bounded remediation targets. The
Security Support Window covers the current and immediately preceding
minor release; operators outside it receive explicit unsupported status
and a signed upgrade path rather than unverified patch promises.

Advisories identify affected versions and artifacts, exploitability,
mitigation, fixed releases, format or key implications, and whether
rotation, revocation, restore, or purge action is required. CVE or
ecosystem advisory publication follows the relevant coordinated process.

A compromised registry, artifact, dependency, CI identity, or signing
key can be revoked without authorizing an unsigned, unknown, or
format-incompatible binary. Revocation causes upgrade preflight and
`release verify` to fail closed while preserving explicit offline
recovery procedures for already stored data.

------------------------------------------------------------------------

## 3.25 Release 1 Scope

Release 1 includes:

-   standalone single-node Log and Trace Signal Stores
-   OTLP gRPC and HTTP plus Loki Push Receiver Adapters
-   native pipeline and bounded SQL query, search, tail, resumable
    result, export, trace structure, and cross-signal correlation
-   first-party Grafana data source and the complete SDK Release Set
-   all accepted encryption, key provider, tenancy, authorization,
    no-impersonation, policy, audit, lifecycle, resource, integrity,
    maintenance, backup, restore, operator, distribution, diagnostic,
    and compatibility contracts
-   every provider, platform, architecture, Kubernetes target, and
    artifact explicitly named as Release 1 in an accepted ADR

The following remain outside Release 1:

-   Metric and Profile Signal Stores
-   native replication, high availability, failover, and clustering
-   SSO, OIDC, SAML, SCIM, certificate-to-principal mapping, and
    customizable RBAC
-   a FIPS validation claim or FIPS Cryptographic Profile
-   continuous point-in-time recovery, selective restore, legal hold,
    and arbitrary record deletion
-   object storage, raw block, or primary multi-writer shared storage as
    a Primary Data Volume
-   LogQL, TraceQL, and PromQL compatibility claims
-   native Windows and FreeBSD distributions

Adding or removing a required Release 1 capability requires a
superseding ADR that explains the product and compatibility impact.
Issue priority or implementation convenience cannot silently change
scope.

Rust code is formatted with rustfmt and linted with Clippy. Every product
change has comprehensive unit tests. Cross-module, public-interface,
persistence, provider, compatibility, recovery, and deployment behavior
has integration tests. Applicable parsers, protocols, storage inputs,
recovery paths, and state machines have fuzz tests.

Implementation proceeds through product milestones:

1.  core runtime and encrypted storage kernel
2.  Log Store ingestion, storage, query, and operations
3.  Trace Store and cross-signal workflows
4.  governance, lifecycle, integrity, maintenance, backup, and recovery
5.  distributions, operator, Kubernetes, Grafana, and SDKs

Follow-on metrics, profiles, and clustering preserve explicit
interfaces and invariants in Release 1 without adding speculative
runtime machinery.

------------------------------------------------------------------------

# 4. Signals

Release 1 signals:

1.  Logs
2.  Traces

Follow-on signals:

1.  Profiles
2.  Metrics

Future signal families:

-   events
-   audit
-   eBPF
-   network flows
-   security events

Each signal receives its own optimized signal store while sharing the
storage kernel:

-   active-segment durability
-   catalog
-   scheduler
-   query engine
-   segment lifecycle
-   a replication-ready commit and placement boundary; the replication
    runtime is follow-on
-   authentication
-   multi-tenancy

Release 1 Receiver Adapters:

-   OTLP Logs and Traces over gRPC
-   OTLP Logs and Traces over HTTP with Protobuf or JSON
-   uncompressed and gzip OTLP requests
-   Loki Push at `/loki/api/v1/push`
-   Loki's `/otlp/v1/logs` path for OTLP logs

Named Release 1 conformance targets include OpenTelemetry SDKs and
Collectors, Alloy OTLP pipelines, Beyla traces, E-Navigator traces, and
clients that would otherwise send OTLP traces to Tempo.

The follow-on Metric Store adds OTLP Metrics and Prometheus Remote Write.
The follow-on Profile Store adds versioned OTLP Profiles and Pyroscope
Push or pprof receiver adapters. Development-status profile contracts
are pinned and tested by exact revision.

Receiver adapters decode accepted telemetry into Positron's native
logical signal model. Ingest compatibility does not imply compatibility
with vendor query APIs, dashboards, internal blocks, chunks, or storage
files. Every named compatibility claim requires a pinned real producer
and version in the conformance suite.

------------------------------------------------------------------------

# 5. Architecture

High-level pipeline:

Ingress → Admission Control → Signal Routing → Per-core Signal Writers →
Store Blocks → Active Segment → Sealed Segments → Query Engine

The database remains a **single multithreaded Rust process**.

An ingest request is not a transaction across signals or virtual shards.
Admission groups records by tenant, signal store, and virtual shard.
Each group reserves bounded memory, storage, and replication capacity
before encoding when those resources exist in the deployment mode, and
each store block commits atomically. Release 1 standalone admission has
no replication reservation or quorum path.

Committed groups are not rolled back when another group fails. Partial
results distinguish accepted records from retryable capacity failures,
future replicated-mode quorum failures, and permanent validation
failures. Overload produces explicit backpressure rather than an
unbounded queue.

Delivery is at least once. A timeout followed by retry may create
duplicates; version 1 does not promise distributed request atomicity,
exactly-once ingestion, or global deduplication.

------------------------------------------------------------------------

# 6. Storage Model

The storage kernel manages immutable, single-tenant, single-signal
segments.

Each segment has a common kernel envelope containing:

-   identity
-   tenant
-   virtual shard
-   signal type
-   event-time range
-   ingest-time range
-   size
-   checksums
-   payload references

The owning signal store defines the internal blocks, indexes, statistics,
and encodings. A segment never mixes tenants or signals.

Fixed ingest-time retention buckets bound compaction. Only sealed
segments from the same tenant, signal store, and retention bucket may be
compacted together; active segments are never inputs. This prevents
compaction from extending older telemetry's retention lifetime.

Compaction may change store blocks, indexes, encodings, and physical
ordering but must preserve the exact logical telemetry. Publication
atomically swaps input segments for output segments in the manifest.
Existing query snapshots may continue using the inputs until
reclamation is safe, and a failed compaction leaves the published
manifest unchanged.

Tenant identity is a storage-kernel invariant. Every ingest and query is
scoped to one authenticated tenant, and identifiers such as `trace_id`
are resolved within that tenant. Retention, quotas, deletion, and
encryption policies operate independently per tenant. Normal data
queries cannot cross tenant boundaries.

Standalone deployments use an explicit default tenant.

Retention is configured per tenant and signal store. It atomically
removes whole sealed segments from the manifest once their complete time
range has expired according to ingest time. New query snapshots stop
seeing removed segments immediately; physical reclamation waits for
existing snapshots to release them.

Telemetry retains its original Event Time without correction. Each
signal derives the default Query Time through the provenance-bearing
fallback contract in section 3.10, and callers may explicitly select
Event Time or Ingest Time. The Storage Kernel assigns Ingest Time when
it accepts telemetry; retention and physical lifecycle use that clock.
Segment envelopes record ranges needed for each supported temporal axis.
Signal Stores isolate extreme producer times through bounded outlier
structures, but Positron never silently rewrites the source value.

Version 1 also supports whole-tenant purge. The operation first moves
the tenant to a `PURGING` lifecycle state, blocks new ingest, query, and
tail operations, cancels or drains existing work, rolls active segments,
removes the tenant's live manifests, and evicts its cached keys.

The Storage Kernel then removes every tenant KEK envelope from the live
Envelope Catalog and from the Repository Key Registry of every
registered Backup Repository. Each repository receives a signed Purge
Tombstone, and restore must apply repository tombstones before making
any tenant visible. Once Positron verifies that no managed live or
backup envelope can recover the tenant KEK, it destroys remaining key
material and reports the purge complete.

If any registered repository is unavailable, immutable, or retains a
reachable historical envelope version, the purge remains visibly
pending and cannot report success. Positron cannot revoke unregistered,
exported, or offline copies outside its managed repositories and reports
that boundary explicitly.

Governance audit history retains only the tenant identifier, purge
authorization and scope, timestamps, state transitions, and completion
proof under system audit retention; it retains no tenant telemetry.
Version 1 does not support deleting individual records, identifiers,
attribute matches, or arbitrary time slices. Targeted deletion requires
a future rewrite or record-tombstone design.

------------------------------------------------------------------------

# 7. Memory Model

Three independent representation roles:

1.  Signal-specific mutable ingest state
2.  Immutable execution batches
3.  Compressed store blocks

No representation attempts to optimize every workload simultaneously.

------------------------------------------------------------------------

# 8. Custom Column Engine

Positron intentionally builds its own in-memory column engine instead of
relying internally on Apache Arrow.

Reasons:

-   observability-specific types
-   lower overhead
-   tighter storage integration
-   specialized string handling
-   specialized dictionaries
-   custom compression
-   better ownership model

Arrow compatibility remains available through adapters.

------------------------------------------------------------------------

# 9. Search

Search is divided into:

-   segment pruning
-   row-group pruning
-   bitmap indexes
-   inverted text indexes
-   predicate execution
-   late materialization

Regex queries are accelerated using literal extraction plus candidate
verification.

------------------------------------------------------------------------

# 10. Logs

Native OTLP log model.

Intrinsic columns:

-   timestamp
-   severity
-   trace_id
-   span_id
-   service
-   resource
-   scope
-   body

Dynamic attributes are promoted automatically based on workload.

The Loki Push adapter maps source timestamps to event time, log lines to
native body strings, stream labels to string stream attributes, and
structured metadata to record attributes. Valid trace and span
identifiers additionally populate intrinsic correlation fields while
their source values remain preserved. No heuristic severity, service, or
field extraction occurs.

API-key tenancy is authoritative. `X-Scope-OrgID` may be absent or match
the authenticated tenant; a mismatch is rejected. Request, record,
label, and key/value sizes are bounded before allocation-heavy decoding.

Loki Push success is returned only when every record commits. If some
admission groups commit and another fails, the request returns an error;
retry may duplicate committed records because Loki Push cannot express
Positron's partial result. Successful groups are never rolled back.

Intrinsic fields have fixed signal-defined names and types. Dynamic
attributes preserve their original OTLP value types and remain in
separate resource, instrumentation-scope, and record namespaces.
Missing, empty, zero, and false values are distinct, and queries perform
no silent cross-type coercion.

Attribute promotion is purely physical. It may add a column, dictionary,
bitmap, or index but cannot change the attribute's logical identity,
type, or query results. Queries fall back to the generic attribute
representation in unpromoted segments, and promotion may be reversed
without losing access to historical data.

Version 1 guarantees full predicate and index support for scalar
attributes. Complex arrays and maps are preserved but do not receive
that full guarantee.

------------------------------------------------------------------------

# 11. Traces

Native span storage.

A trace is the tenant-scoped collection of committed spans sharing one
`trace_id`; it is not an atomic ingest object. Every committed span is
queryable immediately, even when its root or parent has not arrived.
Seeing a root span does not prove completion.

Committed append-only deltas maintain trace summaries, and compaction
materializes them. After a configurable ingest-time quiet period, a
trace becomes quiescent rather than complete. A late span reopens the
trace and appends another summary delta.

Trace-by-ID returns every retained span visible in its query snapshot and
reports first-seen and last-seen times, span count, quiescence,
missing-parent count, and possible retention or query-budget truncation.
Critical-path and service-relationship results are marked incomplete
when required spans are missing.

Every accepted span is stored as an immutable span observation. A logical
span groups observations by tenant, `trace_id`, and `span_id`.
Semantically identical retries appear once in normal results with an
observation count; equality uses the decoded native signal model rather
than raw Protobuf bytes or ingest time.

Disagreeing observations remain available as variants and mark the
logical span conflicted. Structural operators deterministically use the
earliest committed observation, expose the conflict, and mark analysis
incomplete. Diagnostic expansion returns every observation and commit
position. Admission, storage, and quota accounting count every received
observation.

Optimizations include:

-   trace summaries
-   span tables
-   event tables
-   link tables
-   trace indexes
-   structural operators

------------------------------------------------------------------------

# 12. Profiles

Follow-on architecture only. Release 1 contains no Profile Signal Store,
profile receiver, profile query surface, or advertised profile
capability. The boundaries below reserve the intended specialized store
without adding speculative runtime machinery.

Dedicated profile engine.

Interned stack tries.

Dictionary-based functions.

Trace correlation.

Flamegraph execution.

------------------------------------------------------------------------

# 13. Metrics

Follow-on architecture only. Release 1 Operational Telemetry does not
create a tenant Metrics Signal Store, metrics receiver, metrics query
surface, or advertised metrics capability. The boundaries below reserve
the intended specialized store without adding speculative runtime
machinery.

Dedicated time-series engine.

Series dictionary.

Compressed chunks.

Exemplars.

PromQL-compatible execution (future).

------------------------------------------------------------------------

# 14. Query Engine

Native execution engine.

Queries scan committed store blocks from both active and sealed segments.
Segment sealing is not a visibility boundary.

Each query captures the committed high-water mark of every involved
signal store when it begins. Cross-signal queries do not claim a
transactionally atomic snapshot across signal stores.

In the first clustered release, HA queries are served by leaders.
Followers provide replication and failover rather than read scaling.

Release 1 query surfaces:

-   native HTTP and streaming Query API
-   CLI using the same public API
-   first-party Grafana data-source plugin

The Grafana data source supports log search, live tailing, trace search,
trace-by-ID, service relationships, and log-to-trace navigation. Positron
does not impersonate Loki or Tempo query, administration, ruler,
deletion, storage, or internal APIs.

LogQL and TraceQL may become independently conformance-tested parser
frontends in later releases. PromQL belongs with the follow-on Metric
Store. Until a frontend's conformance suite passes, Positron does not
call it compatible.

Release 1's primary language is a typed native pipeline over an explicit
Logs, Spans, or Traces source. Every query has a bounded time range over
an explicit temporal axis and defaults to Query Time. Operators cover
structured filtering, full-text search, projection, sorting, limiting,
grouping, aggregation, JSON and logfmt parsing, explicit casts, trace
structure, critical-path traversal, and service relationships.

Log full-text search is a case-sensitive substring predicate over string
bodies. Regular-expression search uses a bounded finite-automaton matcher;
patterns have explicit size, nesting, and compiled-program limits, and
unsupported or over-limit patterns are rejected before execution. Both
search forms remain subject to the query's cumulative CPU, memory, decoded
record, scan, output, wall-time, and cancellation budgets.

Cross-signal correlation is explicit and tenant-scoped through identities
such as `trace_id` and `span_id`. Release 1 has no arbitrary joins.

A documented read-only SQL subset supports `SELECT`, `WHERE`, `GROUP BY`,
`ORDER BY`, aggregates, and `LIMIT`. It has no DDL, DML, transactions,
arbitrary joins, stored procedures, or PostgreSQL compatibility claim.

Both languages compile into the same typed logical plan and return
equivalent results for equivalent operations. Resource admission rejects
unbounded or excessively expensive plans before execution.

Every tenant has a query budget beneath system-wide ceilings. Budgets
bound lookback range, scanned bytes, decoded records, result rows and
bytes, memory, CPU and wall time, concurrency, and trace-traversal
breadth. Planning estimates cost from segment metadata and reserves
concurrency and memory before admission; runtime counters enforce limits
when estimates are wrong.

Query work runs below ingestion and durability work in scheduler
priority. Tenants receive weighted-fair scheduling. Cancellation,
disconnect, deadline expiry, and budget exhaustion propagate through all
operators and promptly release reservations.

Streamed results terminate with an explicit complete marker or an
incomplete error. Responses report execution statistics, including data
scanned, pruning effectiveness, elapsed time, and the limiting budget.
Clients and tenant administrators may lower limits but cannot exceed
system policy.

Live tail emits only committed logs. A subscription atomically captures
per-shard commit positions, optionally executes a bounded historical
query to that boundary, and then follows new commits without a handoff
gap.

An opaque authenticated tail cursor carries the commit-position vector
and is bound to its tenant and filter. Resume is at least once:
duplicates are possible, while gaps and cursor expiry are explicit.
Retention or compaction may expire required history.

Subscription memory, output rate, and idle lifetime are bounded by the
tenant's query budget. A lagging consumer is disconnected with a
`consumer_lagged` error and the newest safe cursor rather than causing
unbounded buffering or silent drops. Live tail is not a durable queue or
an exactly-once stream.

## 14.1 Public API and SDKs

The sole hand-edited public API definition is the versioned Protobuf
package under `api/positron/v1`. It defines query, live streaming,
governance, tenant administration, health, and backup-control services.

The Rust server and CLI use generated Rust types and service interfaces.
gRPC is the canonical transport. HTTP and JSON routes, OpenAPI
documentation, and publishable SDK wire clients are generated from the
same definition and are never maintained as parallel sources.

Every derived artifact embeds its API version and schema digest. Rustfmt,
Clippy, and integration tests protect API changes. Version 1 allows
additive compatible changes only; breaking changes require a new
versioned API package.

Upstream OTLP definitions remain separately pinned external contracts.
Generated Positron SDKs cover query, streaming, administration, and
lifecycle operations rather than inventing another telemetry
instrumentation API. Public API messages are not Store Block formats.

Release 1 publishes generated Rust, TypeScript, Python, Go, Java/JVM,
and .NET SDKs to their standard registries. The server and required SDKs
share one release version, API version, and schema digest. Generator
tools and configuration are pinned, and generated wire code is never
edited manually.

Each SDK must compile, package, and pass the same live conformance suite
against the candidate Rust server. A signed release-set manifest lists
the server, SDK packages, checksums, schema digest, generator versions,
and registry status.

Registry publication is not transactional. If one required publication
fails, the release remains incomplete and resumes at the same version;
the server release is not announced complete until the complete set is
available. Handwritten documentation and examples may not define API
behavior absent from the generated contract. Additional language SDKs
follow the same process in later releases.

------------------------------------------------------------------------

# 15. Replication

Release 1 ships no replication runtime, consensus, quorum path, replica
role, failover, or replicated configuration. It is standalone and
single-node; only replication-ready identities and commit boundaries
remain in its formats and interfaces.

Follow-on HA:

one leader and two followers per virtual shard

Follow-on cluster:

virtual shards

A virtual shard is the smallest unit of placement, leadership, quorum
replication, failover, and migration. It belongs to one tenant but may
contain separate segments from any of that tenant's signal stores. Every
store block and segment belongs to exactly one virtual shard.

All signal stores use the tenant's shared shard map. Each store derives a
stable routing key, preferring a shared correlation identity such as
`trace_id` when one exists and otherwise using a signal-native identity.
Colocation improves cross-signal locality but is never required for
query correctness.

Standalone mode maps all virtual shards to the local process. Queries
that span virtual shards use scatter/gather.

Replication operates on checksummed segment blocks through the common
kernel envelope. Block encoding remains signal-store-specific.

In HA mode, only the shard leader compacts. Followers receive the
resulting physical store blocks instead of independently producing
potentially different layouts.

Two of three replicas are required to elect a leader and acknowledge
writes. Losing one replica preserves service after any necessary
election; during a partition, only the majority side may serve traffic.
Minority replicas reject writes and do not serve stale reads in the
first clustered release. Positron never silently downgrades quorum
durability.

Acknowledged store blocks survive any single-node failure. An
unacknowledged active-segment tail may be truncated during recovery.
Quorum loss makes the virtual shard unavailable rather than
inconsistent. Forced single-replica disaster recovery is an explicit
offline operator action with a possible-data-loss warning, not an
automatic availability feature.

The architecture does not promise a recovery-time objective before
benchmarks and operational testing establish one.

------------------------------------------------------------------------

# 16. Clustering

This section is follow-on architecture only. Release 1 starts no
metadata-consensus group, accepts no multi-node membership, and
advertises no clustering capability.

Embedded metadata consensus.

Metadata consensus owns membership, the virtual-shard map, and
assignment epochs. Telemetry does not flow through metadata consensus.

In the first clustered release, a tenant receives a fixed set of stable
virtual-shard IDs at creation. Deployments provision more virtual shards
than nodes, and scale-out reassigns whole shards rather than splitting or
merging live routing keyspaces. A genuinely hot individual shard is an
explicit first-clustered-release limitation.

Shard migration keeps the current leader serving while destination
learners copy verified sealed segments and catch up on committed active
segment blocks. Consensus then changes replica membership and may
transfer leadership. Every assignment change increments an epoch that
fences stale leaders, writers, and routes. Source data is reclaimed only
after the membership change and older query snapshots release it.

Single binary.

No external ZooKeeper or etcd required.

Scale-up first.

Scale-out second.

------------------------------------------------------------------------

# 17. Performance Goals

Performance goals guide the product implementation:

Implementation techniques may include:

-   near-zero steady-state per-record allocation
-   bounded write and space amplification
-   SIMD-friendly execution
-   late materialization
-   immutable snapshots
-   per-core ownership

Representative integration tests should protect observable performance
characteristics when stable assertions are practical. Positron has no
separate performance or soak validation process.

------------------------------------------------------------------------

# 18. Adaptive Storage

One major innovation:

The database continuously learns query patterns.

Compaction may:

-   promote attributes
-   build indexes
-   change encodings
-   reorder columns
-   remove unused indexes

Automatically.

Adaptive choices never weaken tenant isolation, durability, retention,
attribute typing, or query semantics.

------------------------------------------------------------------------

# 19. Crash Safety

Signal stores encode telemetry into canonical, checksummed store blocks.

The storage kernel appends store blocks directly to an active segment.

In standalone mode, acknowledgment occurs only after the store blocks
are durably flushed to the local active segment.

In three-replica HA mode, acknowledgment occurs only after a two-replica
majority has durably appended the store blocks.

Release 1 has no memory-only or asynchronous unsafe acknowledgment mode,
and the first clustered release retains that rule. The deployment mode
determines durability; requests and tenants cannot weaken it.

Sealing atomically publishes the same bytes as a sealed segment
without copying or re-encoding them.

Crash recovery validates the active segment and truncates an incomplete
tail. A recovered encrypted active segment is then sealed and never
appended again; new writes use a new segment and DEK so an interrupted
frame's nonce cannot be reused. There is no separate WAL or journal
representation.

------------------------------------------------------------------------

## 19.1 Backup and Restore

Release 1 creates online, application-consistent full-instance backup
snapshots. Snapshot creation briefly rolls active segments, captures one
manifest and catalog generation, then allows ingestion to continue.
Immutable files are copied incrementally by checksum through a supported
Repository Adapter for local filesystem, AWS S3, named S3-compatible
products, Google Cloud Storage, or Azure Blob Storage.

Backups include tenant definitions, policies, API-key hashes, manifests,
signal-store data, and governance audit history. External secret files
and TLS private keys, root KEKs, provider credentials, and Recovery
Bundles are excluded. Segment reclamation cannot remove files still
needed by an in-progress snapshot.

Each Backup Repository has a Repository Key Registry separate from
immutable snapshot ciphertext. It contains the reachable Key Envelopes,
Backup Envelope Overlays, and tenant Purge Tombstones that govern
whether a snapshot can be decrypted and restored.

Backup manifests, Backup Envelope Overlays, Purge Tombstones, and each
Registry Generation are signed by the Instance Integrity Key. Registry
generations name their predecessor hash and publish a new head through
compare-and-swap. Restore verifies the complete chain and refuses to
publish a non-head or internally inconsistent generation.

The CLI supports backup creation, listing, verification, and restore.
Verification checks every manifest reference, checksum, format version,
required catalog object, key-provider reference, and key fingerprint.
Restore targets an empty offline instance, applies repository Purge
Tombstones, and publishes only after complete verification.

On Kubernetes, `PositronBackup` and `PositronScheduledBackup` expose
these same operations declaratively through the Positron Operator; their
status is derived from the database's durable backup operation rather
than Kubernetes Job or volume-snapshot completion.

An instance using an automatically bootstrapped local root key cannot
create a backup until `positron keys recovery create` has produced a
separately stored Recovery Bundle and `positron keys recovery verify`
has authenticated it against the instance fingerprint. Startup retains
its key-custody warning until that verification succeeds.

For an external KMS or HSM, backup readiness verifies provider access
and records the immutable provider and key identity. Root keys remain
non-exportable and recovery uses the provider's native replication,
backup, or disaster-recovery controls rather than a Positron export.

Release 1 does not merge a backup into a running instance and does not
promise continuous point-in-time, individual-record, or selective-tenant
recovery. Restore acceptance tests query restored data and verify
authentication, retention policy, and audit-history continuity.

------------------------------------------------------------------------

## 19.2 Encryption at Rest

Release 1 includes native authenticated encryption at rest for all
Positron-managed persistent data, including segment payloads and indexes,
catalog and manifest metadata, governance audit history, and backup
snapshots. The storage kernel owns the encryption envelope so signal
stores keep their native layouts without owning key-provider logic.

Positron uses envelope encryption. A provider-owned root KEK, which is
never stored in Positron data or backup repositories, wraps system and
tenant KEKs. Each tenant KEK wraps randomly generated per-segment DEKs.
Provider identity, key identity, and key version are recorded with each
wrapped key so data remains portable across supported key rotations.

Release 1 ships both a protected local key-file provider and external
key providers behind one Rust interface. Provider credentials are
external secrets and are not copied into Positron data or backups.
Startup and restore fail closed when a required provider or key is
unavailable or incorrect.

Encryption is mandatory for every Release 1 instance and has no
plaintext-at-rest opt-out. On the first start of a fresh empty instance,
if the operator supplied neither a provider nor key material, Positron
creates a cryptographically random local root KEK with an exclusive
atomic write and owner-only permissions. It never prints the key.

The Local Root Key File lives in a dedicated platform security
directory outside data, temporary, and backup roots. User installations
use the platform configuration directory, system packages use an
administrator-owned Positron secrets directory, and containers should
mount it as a separate persistent secret volume.

Creation refuses symbolic links and uses exclusive, no-follow,
owner-only file creation followed by durable synchronization of both
the file and its parent directory. Startup requires a regular,
single-link file with expected ownership, permissions, version, and
fingerprint and reopens it without following links. Filesystems that
cannot enforce these controls cannot use the local provider.

The versioned file contains local-provider identity, key ID, creation
metadata, integrity checksum, and the 256-bit root KEK. The key cannot
be encrypted without introducing another root secret. There is no
insecure-permissions override.

An automatically bootstrapped local key produces an explicit warning
on every startup describing its custody and recovery limitations and
recommending an external provider. Positron also records the bootstrap
as soon as the governance audit store is available.

The generated local root key is never copied into a Backup Snapshot.
The CLI can export it only as a separately stored, authenticated
encrypted Recovery Bundle for one or more operator-supplied recovery
recipients. Verification proves that the bundle matches the instance
fingerprint without changing the active key.

The Recovery Bundle uses the interoperable `age-encryption.org/v1`
container. Its inner payload is a deterministic, versioned Protobuf
message containing the instance identity, root key, provider metadata,
creation time, and integrity-key fingerprints. Positron signs the
payload with the Instance Integrity Key before encryption.

A bundle supports one or more native age X25519 Recovery Recipients; any
listed recipient may recover it. Interactive age scrypt passphrase
protection is available as a fallback. Passphrases are never accepted
through command arguments, environment variables, configuration, or
logs.

Release 1 does not accept SSH recipients, external age plugins, or
threshold secret sharing. Recipient rotation creates and verifies a
replacement bundle before the previous bundle may be retired.
`positron keys recovery inspect` exposes only non-secret format,
recipient, instance, and fingerprint metadata.

Automatic generation is never a recovery path. If initialized data
exists but its local key is missing or invalid, or if a configured
external provider is unavailable, Positron fails closed and never
generates a replacement or falls back to another provider.

The Release 1 provider set is:

-   protected local key file
-   AWS KMS
-   Google Cloud KMS
-   Azure Key Vault and Managed HSM
-   HashiCorp Vault Transit
-   OpenBao Transit
-   KMIP 2.1

External root keys are pre-provisioned by operators. Positron may resolve
an operator-supplied alias during initialization, but it persists the
immutable, version-pinned Provider Key URI. It may verify that key,
wrap and unwrap Positron KEKs, rewrap envelopes, and migrate to another
pre-provisioned key. Release 1 never creates, enables, disables,
schedules deletion of, or destroys an external root key.

Provider authentication uses native renewable workload identity:

-   AWS standard credential chain and workload roles
-   Google Application Default Credentials and Workload Identity
-   Azure managed identity or workload identity
-   Vault and OpenBao renewable machine tokens obtained through
    Kubernetes or JWT authentication, or a protected token file
-   KMIP mutually authenticated TLS

Positron configuration stores only non-secret selectors and protected
credential-file references. A provider's native credential chain may
consume environment or file credentials, but Positron never persists,
returns, or logs their values. Every external Key Provider connection
requires verified TLS and has no insecure opt-out.

Initialization performs a temporary, context-bound wrap and unwrap probe
that verifies the exact Provider Key URI and required least-privilege
capabilities. Probe key material is zeroized and never persisted.

Every wrapped key uses a deterministic, versioned Protobuf Wrapped Key
Payload. It contains the key bytes, instance identity, key kind,
immutable key ID and epoch, tenant or system scope, and SHA-256 Envelope
Context digest. Local root and tenant KEKs protect these payloads with
AES-256-KWP. External providers use their native wrap or encrypt
operation and their native encryption context when available.

The plaintext Key Envelope contains only its format version, provider
type, immutable Provider Key URI, wrapping algorithm, child-key
identity and epoch, context digest, and opaque ciphertext. These fields
are routing hints and remain untrusted until they exactly match the
unwrapped payload. Embedded context is always checked even when the
provider separately authenticates context.

A wrong scope, substitution, or context mismatch fails closed as
`KEY_ENVELOPE_CONTEXT_MISMATCH`, marks storage unhealthy, and produces a
Governance Audit Record. Temporary plaintext payloads and unwrapped keys
are zeroized immediately after use.

All Release 1 cryptography passes through one internal Rust Crypto
Backend for authenticated encryption, key wrapping, hashing, signatures,
secure random generation, and zeroization. Cryptographic dependencies
are pinned, and releases publish their cryptographic inventory, SBOM,
known-answer results, cross-platform test-vector results, and
vulnerability-response policy.

Release 1 does not claim FIPS 140-3 validation. Approved algorithm names
alone are not treated as module or deployment certification. Stored
algorithm identifiers and the Crypto Backend boundary preserve a future
Cryptographic Profile using a validated module and compatible recovery
and signature constructions. That profile requires its own supported
operating environments and truthful certification status.

Every provider passes the same wrap, unwrap, verification, outage,
rotation, and wrong-key conformance suite. Vault and OpenBao are
separate conformance targets even when their adapters share protocol
code. Release 1 has no generic executable or arbitrary-webhook key
provider.

External Key Providers are not called on the per-frame ingest or query
path. Unwrapped system and tenant KEKs exist only in a bounded,
zeroizing process-memory cache, with memory locking where supported.
The Key Cache Lease defaults to 15 minutes, may be configured down to
zero, and has a hard maximum of one hour.

During a provider outage, operations whose required KEKs have valid
leases may continue until those leases expire. An uncached or expired
key produces a retryable `KEY_PROVIDER_UNAVAILABLE` result for the
affected tenant; Positron never falls back to another provider or to
plaintext. Provider failure marks health degraded, and expiry of the
system KEK makes the instance not-ready.

Startup and restore always perform live provider verification; key
caches are never persisted. Rotation, revocation, credential reload,
and administrative cache purge evict affected keys immediately when
performed through Positron. A provider-side change for which Positron
receives no notification takes effect no later than the current lease's
expiry.

Persistent content is encoded as independently addressable encrypted
frames using AES-256-GCM. Each segment has a random 256-bit DEK. Every
frame under that DEK receives an immutable sequence number used to
derive a unique 96-bit nonce. Store Blocks, indexes, statistics, and
segment metadata are separate frames so queries retain random access.

Frame associated data binds the tenant, signal store, virtual shard,
segment, payload kind, sequence number, and storage-format version.
Checksums cover ciphertext for corruption checks that do not require a
key; the AEAD tag is authoritative for authenticity. The only plaintext
segment bootstrap fields are the magic, format version, algorithm
identifier, opaque key reference, and Key Envelope required to locate
and unwrap the segment DEK.

Catalog, manifest, governance-audit, and backup metadata use the same
framed construction with independent system-object DEKs. The format
records an algorithm identifier for migration, but Release 1 has no
operator-selectable alternative data cipher.

Initialization also creates an Ed25519 Instance Integrity Key. Its
private key is wrapped under the system KEK; only its public key and
fingerprint are bootstrap metadata. Local Recovery Bundles pin the
instance and integrity-key fingerprints, while external-provider
recovery binds them through authenticated provider context.

Integrity-key rotation cross-signs the successor and retains the public
verification history. Signed registry chains detect corruption and
ordinary rollback but cannot prevent restoration of an independently
exported old repository copy outside Positron's managed scope.

Every KEK has immutable Key Epochs and may temporarily retain multiple
valid Key Envelopes. Root-key rotation and cross-provider migration use
the same online, resumable rewrap workflow. Tenant-key rotation makes a
new epoch active for new segment DEKs and rolls existing active
segments before new writes continue under that epoch.

The Envelope Catalog adds new envelopes for existing DEKs without
changing encrypted frames. Old and new envelopes coexist during the
migration, and each copy-on-write catalog publication is idempotent and
crash-safe. Failure preserves the last committed active epoch and
restart resumes outstanding rewrap work.

Rotation cannot complete or authorize retirement of an old key until
every live object and retained Backup Snapshot has a verified envelope
under the new epoch. Immutable backup data is not rewritten; a signed
Backup Envelope Overlay adds the new recovery path. Progress,
verification, completion, and attempted premature retirement are
Governance Audit Records.

The CLI provides initialization, provider health checks, key
verification, rotation, provider migration, and recovery checks.

Encryption at rest is a Release 1 acceptance requirement, not a
follow-on capability. Its cryptographic envelope, recovery behavior,
and enablement policy are specified separately.

------------------------------------------------------------------------

# 20. ADRs

The authoritative product decision records are the accepted files under
`docs/adr/`. `CONTEXT.md` supplies their binding ubiquitous language.

Later ADRs refine or supersede older decisions where they say so. The
history remains in the older file; this architecture document reflects
the newest accepted contract. Adding an inline second ADR numbering
scheme here is prohibited because it previously drifted from the
authoritative files.

------------------------------------------------------------------------

# 21. Roadmap

Release 1 follows the five product milestones in section 3.25.

Release 1 delivers the complete standalone logs-and-traces database,
security and governance model, lifecycle and recovery tooling,
Distribution Surfaces and integrations required by the accepted product
ADRs.

Follow-on releases add:

-   Profile Signal Store and its Receiver Adapters
-   Metric Signal Store, OTLP Metrics, and Prometheus Remote Write
-   three-replica HA and clustering under sections 15 and 16
-   a FIPS Cryptographic Profile
-   only those deferred capabilities promoted by later ADRs

Metrics, profiles, and clustering influence Release 1 boundaries and
formats without adding speculative runtime implementations.

------------------------------------------------------------------------

# 22. Long-Term Vision

Project Positron should become the observability equivalent of
PostgreSQL:

One executable.

One deployment.

One storage kernel.

One unified database for logs, traces, metrics, and profiles.

The defining research areas are:

-   adaptive physical storage
-   unified observability kernel
-   workload-driven indexing
-   one-write ingestion
-   native cross-signal execution
-   low-overhead architecture
-   custom column engine
-   scale-up-first systems design
