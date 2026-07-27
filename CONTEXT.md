# Positron

Positron is an observability database that stores and queries multiple telemetry signals through one shared kernel while preserving signal-specific physical designs.

## Language

**Storage Kernel**:
The shared database foundation that coordinates every signal store, including durability, metadata, lifecycle, replication, and query infrastructure.
_Avoid_: Storage engine, unified storage engine

**Signal Store**:
The signal-specific physical storage model for one kind of telemetry, optimized for that signal's structure and access patterns.
_Avoid_: Signal engine, physical storage engine

**Tenant**:
The authenticated ownership and isolation boundary for telemetry, policies, resource usage, and identifier resolution.
_Avoid_: Account, namespace, organization

**Tenant ID**:
The immutable random identity used by authorization, storage, encryption, audit, cursors, backup, and destructive tenant operations.
_Avoid_: Tenant Slug, display name, API-key prefix

**Tenant Slug**:
The immutable unique human-facing locator assigned at tenant creation and never reused, while Tenant ID remains authoritative.
_Avoid_: mutable display name, Tenant ID, Kubernetes namespace

**Tenant Lifecycle State**:
The durable state controlling tenant traffic and reversibility: Active, ReadOnly, Suspended, Purging, or Purged.
_Avoid_: API-key status, instance Fenced state, billing status

**Tenant ReadOnly**:
The reversible tenant state that rejects new ingestion while permitting bounded query, tail, and tenant administration over retained data.
_Avoid_: immutable storage, Suspended, Fenced

**Tenant Suspended**:
The reversible tenant state that rejects ingest, query, and tail traffic while preserving data and system-administrator recovery access.
_Avoid_: Tenant Purge, Hibernated, disabled API key

**Tenant Attribution**:
The authentication-time binding of one request to exactly one Principal, Scope, and Tenant ID before payload decoding or resource admission.
_Avoid_: tenant header routing, payload attribute, system-administrator impersonation

**External Tenant Alias**:
An immutable protocol-specific value uniquely bound to one Tenant ID solely to validate compatibility hints such as Loki's `X-Scope-OrgID`.
_Avoid_: Tenant ID, Tenant Slug, tenant selector

**Proxy Actor Context**:
Redacted identity metadata asserted by a configured trusted proxy for governance evidence without changing the Positron Principal, Scope, or Tenant Attribution.
_Avoid_: forwarded authorization, impersonation, tenant routing

**Principal**:
An authenticated identity acting through one API key with explicit system or tenant scopes.
_Avoid_: User, account

**API Key**:
A secret credential shown once at creation and persisted only as a salted hash, used to authenticate a principal.
_Avoid_: Password, session token

**Scope**:
A fixed authorization capability granted to a principal: ingest, query, tenant administration, or system administration.
_Avoid_: Custom role, permission string

**Governance Audit Record**:
An immutable security history entry for authentication and administrative activity, distinct from user-ingested audit telemetry.
_Avoid_: Audit signal, application log

**Governance Audit Store**:
The kernel-owned, append-only security history that durably records governance audit records independently of tenant telemetry lifecycle.
_Avoid_: Audit signal store, tenant log store

**Administrative Idempotency Key**:
A caller-supplied identifier bound to one Principal, operation type, and canonical request digest so a retry resolves the original administrative outcome.
_Avoid_: request ID, telemetry deduplication key, resource name

**Resource Generation**:
The durable monotonically increasing version of mutable administrative state used as an expected-generation precondition against lost updates.
_Avoid_: Assignment Epoch, configuration version, product version

**Durable Operation**:
The persisted state machine and stable Operation ID for a potentially long-running administrative action whose outcome must survive caller, process, or operator retries.
_Avoid_: background task, Kubernetes Job, request timeout

**Irreversible Boundary**:
The named Durable Operation phase after which cancellation cannot restore the exact pre-operation state and recovery must follow the operation-specific contract.
_Avoid_: error point, commit of every progress update, process shutdown

**Receiver Adapter**:
A versioned protocol boundary that converts a supported external telemetry request into Positron's native signal model.
_Avoid_: Compatibility mode, vendor store

**Ingest Compatibility**:
A conformance-tested guarantee that a named producer and protocol version can deliver telemetry to a receiver adapter without losing supported signal semantics.
_Avoid_: Backend compatibility, format resemblance

**Ingest Policy**:
A tenant-scoped versioned declarative program that accepts, rejects, or explicitly transforms telemetry before indexing, persistence, encryption, and acknowledgment.
_Avoid_: retention policy, query filter, external processor

**Policy Provenance**:
The immutable policy version, digest, and applied-rule evidence attached to accepted storage output so a transformation can be attributed to the exact Ingest Policy.
_Avoid_: current policy, receiver version, governance log alone

**Redaction Marker**:
A typed value proving that an Ingest Policy intentionally removed or replaced source content, distinct from a producer-supplied string that merely looks redacted.
_Avoid_: empty value, silent deletion, log masking

**Attribute Occurrence Set**:
The ordered typed values carried by repeated instances of one attribute key within the same namespace and record, preserved without last-write-wins collapse.
_Avoid_: duplicate error, coerced array, overwritten attribute

**Tenant Schema Catalog**:
The bounded tenant-owned summary of observed attribute paths, namespaces, types, query use, conflicts, and promotion state used for planning and governance.
_Avoid_: global schema, stored telemetry, SQL catalog

**Schema Overflow**:
The generic non-indexed representation for valid dynamic attributes that exceed Tenant Schema Catalog or automatic-index budgets while remaining explicitly queryable.
_Avoid_: dropped field, rejected record, unknown column

**Value Limit Profile**:
The effective hard-system and tenant-lowered bounds for transport expansion, record size, attribute count, nesting, arrays, keys, bodies, and individual values.
_Avoid_: Ingest Policy, storage quota, query budget

**Conformance Target**:
A pinned producer, protocol, and version combination used to prove an interoperability claim with real end-to-end fixtures.
_Avoid_: Best-effort compatibility, latest

**Positron Query API**:
The authoritative public HTTP and streaming interface for native log, trace, and cross-signal queries.
_Avoid_: Loki API, Tempo API

**API Definition**:
The sole hand-edited, versioned Protobuf contract from which Positron's public services, HTTP routes, documentation, and SDK wire clients are generated.
_Avoid_: OpenAPI source, server struct, storage schema

**Schema Digest**:
The content identity of one canonical API definition embedded into generated artifacts and release metadata.
_Avoid_: Package version, server commit

**Generated SDK**:
A publishable language package whose wire client and data types are reproducibly produced from one API definition.
_Avoid_: Handwritten client, telemetry instrumentation SDK

**SDK Release Set**:
The server and required generated SDK packages that share one release version, API version, and schema digest and are announced only after every required registry publication succeeds.
_Avoid_: Best-effort SDK release, independently versioned clients

**Release Manifest**:
The signed machine-readable root binding one Positron version to its source, Compatibility Manifest, schemas, artifacts, checksums, toolchains, SBOMs, provenance, evidence, and registry publication state.
_Avoid_: changelog, Git tag, OCI index

**Project Trust Root**:
The explicitly installed offline-verifiable public identity used to authenticate Release Manifests and authorized signing-key rotations or revocations.
_Avoid_: registry TLS certificate, Instance Integrity Key, package checksum

**Reproducible Payload**:
The unsigned functional artifact bytes that independent builders must recreate from the Release Manifest inputs before platform signing, notarization, or registry wrapping.
_Avoid_: identical timestamped signature, CI success, source archive alone

**Security Support Window**:
The published product-version range eligible for coordinated advisories and security fixes, covering the current and immediately previous minor in Release 1.
_Avoid_: API compatibility lifetime, operator skew, best-effort patching

**Release Scope Ledger**:
The binding inventory of capabilities required in Release 1 and those explicitly deferred, changed only through a superseding ADR with stated cost and schedule impact.
_Avoid_: roadmap wish list, issue backlog, marketing checklist

**Qualification Matrix**:
The release-blocking set of supported targets and executable gates mapping every required capability to ownership and retained evidence.
_Avoid_: test suite count, CI dashboard, best-effort compatibility list

**Qualification Cell**:
One independently reportable capability-and-target pair whose state is Specified, Implemented, or Qualified and whose failure cannot be hidden by another passing target.
_Avoid_: umbrella feature status, test case alone, platform assumption

**Qualification Target Registry**:
The versioned exact expansion of every selector in the Qualification Matrix into provider, product, version, architecture, platform, registry, and deployment target identities before implementation claims begin.
_Avoid_: current-latest alias, test environment inventory, post-failure target selection

**Qualification Evidence**:
The immutable machine-readable results, environment identity, inputs, artifact digests, logs, metrics, and failure details proving one Qualification Cell's outcome.
_Avoid_: verbal sign-off, screenshot alone, mutable CI link

**Compatibility Manifest**:
The machine-readable release artifact that declares product, API, query, configuration, receiver, CRD, storage-format, backup-format, operator, and migration compatibility as separate tested claims.
_Avoid_: changelog, semantic-version assumption, compatibility marketing

**Capability Statement**:
The runtime response identifying one server's product version, API packages, Schema Digest, query versions, receiver protocols, feature gates, and readable and writable formats.
_Avoid_: release notes, SDK version, health response

**Format Epoch**:
An independently versioned persistent representation with an explicit set of binaries that may read it, write it, or migrate it.
_Avoid_: product version, API version, segment generation

**Migration Graph**:
The release-published directed paths by which configuration, Primary Data Volume, or Backup Snapshot formats can be transformed without assuming unsupported intermediate compatibility.
_Avoid_: automatic upgrade, downgrade compatibility, release ordering

**Plaintext Opt-Out**:
An explicit per-listener operator configuration that permits non-loopback plaintext transport while preserving visible security warnings and audit evidence.
_Avoid_: TLS fallback, development auto-detection

**Control Listener**:
The owner-only local Unix socket for bootstrap claim, startup diagnostics, fenced inspection, and explicit local recovery that can never bind remotely.
_Avoid_: administration network API, Operations Listener, unauthenticated backdoor

**Operations Listener**:
The separately bound minimal surface for non-secret liveness, readiness, redacted version, and bounded Operational Telemetry scraping.
_Avoid_: Control Listener, tenant query API, full diagnostics

**Network Listener Profile**:
The complete per-listener bind, protocol, TLS, mTLS, proxy trust, authentication, connection, stream, request, and timeout policy.
_Avoid_: global port setting, ingress configuration, firewall rule

**Connection Admission**:
The pre-authentication Resource Governor layer that bounds address, handshake, headers, bodies, decompression, streams, flow control, keepalive, and idle use before tenant quotas are available.
_Avoid_: Tenant Attribution, operating-system backlog alone, application query admission

**Maintenance Coordinator**:
The Storage Kernel scheduler that admits, orders, conflicts, checkpoints, and observes all background lifecycle and optimization work under the Resource Governor.
_Avoid_: cron, Signal Store background thread, Kubernetes operator loop

**Maintenance Task**:
An idempotent typed work item with stable identity, scope, immutable inputs, preconditions, priority, resource estimate, progress, and terminal outcome.
_Avoid_: untracked async task, Durable Operation request, executor future

**Maintenance Window**:
A configured Lifecycle Clock interval that may defer optional optimization and backup tasks without delaying correctness, integrity, purge, retention, or emergency work.
_Avoid_: downtime, legal hold, global scheduler pause

**Maintenance Pause**:
An audited expiring deferral of explicitly deferrable Maintenance Task classes with visible backlog and risk.
_Avoid_: indefinite disable, retention hold, Process Phase

**Encryption at Rest**:
Storage-kernel protection that keeps Positron-managed persistent data and backups confidential and tamper-evident when storage media or backup repositories are read outside an authorized running instance.
_Avoid_: TLS, filesystem permissions, checksum

**Key Provider**:
A configured local or external authority that wraps and unwraps Positron key-encryption keys without coupling stored data to one vendor.
_Avoid_: Secret store, encryption algorithm, credential file

**Root KEK**:
The provider-owned root key-encryption key that wraps Positron's tenant and system KEKs and is never stored in Positron data or backup repositories.
_Avoid_: Data key, API key, TLS key

**Provider Key URI**:
The immutable, version-pinned identity of a pre-provisioned external Root KEK used in Key Envelopes and provider verification.
_Avoid_: Mutable key alias, provider endpoint, credential reference

**Tenant KEK**:
A tenant-scoped key-encryption key, stored only in wrapped form, that wraps the data-encryption keys for that tenant's segments.
_Avoid_: Root key, segment key

**Segment DEK**:
A randomly generated data-encryption key used for one segment and stored only in wrapped form.
_Avoid_: Tenant key, shared data key

**Key Envelope**:
The persisted provider identity, opaque key reference, wrapped key material, and version metadata needed to recover a Positron key without storing its wrapping key or provider credentials.
_Avoid_: Key file, plaintext key, provider credential

**Wrapped Key Payload**:
The deterministic versioned Protobuf plaintext containing key material and its authoritative instance, kind, identity, epoch, scope, and context digest before a Key Provider or KEK wraps it.
_Avoid_: Key Envelope, API message, plaintext key file

**Envelope Context**:
The canonical instance, key, scope, and purpose binding whose SHA-256 digest must match both a Key Envelope and its decrypted Wrapped Key Payload.
_Avoid_: provider credential, request context, frame associated data

**Crypto Backend**:
The sole internal Rust boundary for authenticated encryption, key wrapping, hashing, signatures, secure random generation, and key zeroization.
_Avoid_: Key Provider, cipher configuration, cryptographic profile claim

**Cryptographic Profile**:
A release-qualified combination of Crypto Backend, algorithms, operating environments, build inputs, and compliance evidence.
_Avoid_: runtime cipher preference, algorithm identifier, marketing claim

**Key Bootstrap**:
The one-time creation of a protected local Root KEK for a fresh empty instance when the operator supplied neither a Key Provider nor key material.
_Avoid_: Key fallback, missing-key recovery, key rotation

**Local Root Key File**:
The versioned owner-only file holding an automatically generated local Root KEK in a dedicated security directory outside Positron data, temporary, and backup roots.
_Avoid_: Recovery Bundle, configuration file, encrypted data file

**Recovery Bundle**:
A separately stored age v1 artifact containing a signed, versioned recovery payload that lets an authorized X25519 recipient or interactive passphrase holder restore an automatically generated local Root KEK and verify its instance fingerprint.
_Avoid_: Backup Snapshot, plaintext key export, provider credential backup

**Recovery Recipient**:
A native age X25519 public identity authorized to decrypt a Recovery Bundle.
_Avoid_: Positron Principal, SSH key, Key Provider

**Key Cache Lease**:
The bounded interval during which an unwrapped system or Tenant KEK may remain usable in protected process memory without revalidation by its Key Provider.
_Avoid_: Key lifetime, retention period, persisted key cache

**Key Epoch**:
An immutable generation of KEK material and its provider binding, used actively for new envelopes or retained read-only while older envelopes remain reachable.
_Avoid_: Key Cache Lease, software release, mutable key version

**Envelope Catalog**:
Copy-on-write Storage Kernel metadata that maps encrypted-object identities to one or more valid Key Envelopes independently of immutable encrypted frames.
_Avoid_: Segment index, key provider, plaintext key store

**Catalog Object**:
An immutable encrypted Storage Kernel metadata object addressed by authenticated identity and reachable through a Catalog Generation.
_Avoid_: mutable catalog page, Store Block, Repository Key Registry object

**Catalog Generation**:
A complete immutable catalog root that names its predecessor, Format Epoch, manifests, control-plane objects, governance frontier, and object-set digest.
_Avoid_: Resource Generation, segment generation, Query Snapshot

**Catalog Writer**:
The single Release 1 Storage Kernel authority that serializes and publishes Catalog Transactions while readers pin immutable generations.
_Avoid_: metadata service, Signal Store writer, future consensus group

**Prepared Audit Entry**:
A durably written immutable governance entry with a reserved audit-chain position that becomes visible only when its binding Catalog Commit Record publishes.
_Avoid_: Governance Audit Record, best-effort log, orphaned visible audit

**Catalog Commit Record**:
The immutable transaction record binding a new Catalog Generation to its predecessor, object-set digest, transaction identity, and prepared governance frontier before atomic publication.
_Avoid_: WAL record, mutable current pointer, segment manifest

**Backup Envelope Overlay**:
A signed append-only backup artifact that adds a verified Key Envelope for an existing snapshot without modifying its immutable encrypted data.
_Avoid_: Rewritten backup, incremental data backup, Recovery Bundle

**Repository Key Registry**:
The managed backup-repository control plane that stores reachable Key Envelopes, Backup Envelope Overlays, and Purge Tombstones separately from immutable snapshot ciphertext.
_Avoid_: Backup Snapshot, Envelope Catalog, external Key Provider

**Purge Tombstone**:
A signed repository-level record that makes a purged tenant unrestorable from every snapshot managed by that repository.
_Avoid_: record tombstone, retention marker, physical data overwrite

**Instance Integrity Key**:
The Ed25519 signing identity whose wrapped private key authenticates Positron backup control state and governance-audit checkpoints across key rotations.
_Avoid_: Root KEK, TLS identity, API signing key

**Registry Generation**:
A signed Repository Key Registry state that names its predecessor hash and becomes current through a compare-and-swap head update.
_Avoid_: Backup Snapshot, catalog generation, mutable registry file

**Encrypted Frame**:
An independently checksummed and AEAD-protected persistent extent that can be authenticated and decrypted without reading the complete storage object.
_Avoid_: Store Block, compressed block, TLS record

**Distribution Surface**:
A supported way to install and run the same standalone Positron application and storage format, such as a native executable, OCI image, or Nix package.
_Avoid_: separate edition, client SDK, deployment dependency

**Container Contract**:
The release-blocking behavior that makes one signed multi-architecture OCI image run identically under Docker, Docker Compose, and Kubernetes with explicit persistence, security, health, and shutdown semantics.
_Avoid_: Docker-only edition, Helm behavior, development container

**Configuration Contract**:
The versioned, generated, and distribution-independent rules that define Positron settings, sources, precedence, validation, secrecy, mutability, and reload behavior.
_Avoid_: Docker configuration, Helm values contract, environment-variable API

**Effective Configuration**:
The complete redacted configuration snapshot produced from compiled defaults, a TOML file, environment overrides, and command-line overrides after schema and semantic validation.
_Avoid_: raw config file, environment dump, Kubernetes manifest

**Configuration Mutability**:
The declared lifecycle class of one setting: live-reloadable, drain-and-reload, restart-required, or immutable after initialization.
_Avoid_: best-effort reload, dynamic by default

**Configuration Drift**:
A difference between the operator-rendered desired configuration and the observed effective configuration of an operator-managed Positron instance.
_Avoid_: resource status change, manual hotfix, version skew

**Resource Governor**:
The Storage Kernel authority that admits, schedules, throttles, and rejects work against global ceilings and tenant quotas while protecting durability and recovery capacity.
_Avoid_: query limiter, operating-system OOM handling, Kubernetes resource limit

**Resource Reservation**:
A bounded capacity grant acquired before work begins for the memory, queue slots, and disk headroom that the admitted operation can require.
_Avoid_: usage estimate, unbounded allocation, billing quota

**Recovery Reserve**:
Capacity unavailable to ordinary workloads and retained for durability completion, retention, emergency compaction, purge, repair, fencing, and safe shutdown.
_Avoid_: unused capacity, query reserve, overcommit

**Disk Pressure State**:
The healthy, soft-pressure, or hard-pressure storage condition derived from usable capacity and required Recovery Reserve, with explicit admission behavior for each state.
_Avoid_: disk-full error, filesystem utilization metric

**Primary Data Volume**:
The single filesystem volume that owns one Release 1 instance's live segments, catalogs, compaction output, and upgrade staging under database-safe persistence semantics.
_Avoid_: Backup Repository, object store, multi-writer volume

**Storage Capability Probe**:
The startup verification that a Primary Data Volume provides the synchronization, atomic publication, truncation, reopen, and locking behavior required by Positron's durability contract.
_Avoid_: filesystem-name check, benchmark, durability opt-out

**Storage Ownership Lock**:
The process-lifetime exclusive claim that prevents two Positron server processes from opening one Primary Data Volume for mutation.
_Avoid_: Kubernetes Lease, leader election, lock file existence

**Durability Frontier**:
The authenticated active-segment position through which Positron has acknowledged committed Store Blocks and before which recovery may never silently truncate or discard bytes.
_Avoid_: file length, sealed position, replication lag

**Integrity Scrub**:
A bounded background traversal that authenticates every reachable Encrypted Frame and validates immutable segment indexes, metadata, and catalog references.
_Avoid_: compaction, startup recovery, backup verification

**Quarantined Segment**:
An immutable segment excluded from normal reads after an integrity failure while its identity, tenant, signal, time range, and evidence remain visible for diagnosis and recovery.
_Avoid_: deleted segment, retention candidate, repaired segment

**Verification Report**:
A machine-readable, signed-or-checksummed account of the scope, catalog generation, objects examined, integrity findings, omissions, and completion status of one verification run.
_Avoid_: health endpoint, log output, backup manifest

**Doctor Report**:
A bounded read-only online or offline diagnostic assessment of configuration, storage, keys, catalogs, resources, operations, maintenance, listeners, backup, and repository readiness.
_Avoid_: repair plan, Support Bundle, health response

**Support Bundle**:
A versioned bounded diagnostic archive built from an explicit allowlist, with pseudonymized deployment metadata, checksummed contents, a redaction report, and optional recipient encryption.
_Avoid_: telemetry export, core dump, backup snapshot

**Redaction Report**:
The Support Bundle manifest section that identifies included data classes, pseudonymization, exclusions, declared truncation, encryption, signature status, and redaction-policy version.
_Avoid_: proof no bug exists, Ingest Policy, log-scrubbing regex

**Crash Record**:
A bounded sanitized process-failure record containing diagnostic identity and non-secret failure context without raw memory, telemetry bodies, or key material.
_Avoid_: core dump, panic payload echo, Support Bundle

**Segment Abandonment**:
An explicit system-administrator decision that removes an unrecoverable Quarantined Segment from the live catalog while durably recording its identity and known data-loss range.
_Avoid_: automatic repair, retention, silent deletion

**Bootstrap Claim**:
The owner-only, one-time retrieval of an initial system-administrator API key created by non-interactive instance initialization and atomically destroyed when claimed.
_Avoid_: API-key lookup, persistent credential file, container log output

**Positron Operator**:
The deployment-optional but Release-1-required Rust Kubernetes controller, executed as `positron operator` from the standard OCI image, that reconciles declarative Positron resources without becoming a runtime dependency of the database.
_Avoid_: required control plane, sidecar, separate operator binary

**PositronCluster**:
The Kubernetes custom resource describing the desired lifecycle, security, storage, networking, backup, restore, and version state of a Positron database deployment.
_Avoid_: Release 1 HA claim, Kubernetes cluster, Storage Kernel cluster

**PositronBackup**:
An immutable Kubernetes request and status record for one application-verified Backup Snapshot of a PositronCluster.
_Avoid_: Kubernetes Job completion, CSI snapshot, repository object

**PositronScheduledBackup**:
A Kubernetes schedule that creates visible PositronBackup resources under explicit timezone, concurrency, deadline, and retention policy.
_Avoid_: hidden CronJob, database retention, continuous archive

**Kubernetes Conformance Matrix**:
The release-specific evidence identifying every supported Kubernetes patch version, architecture, distribution, storage class, upgrade path, and exercised failure scenario.
_Avoid_: best-effort support, Helm lint result, latest Kubernetes

**Quiescent Upgrade Snapshot**:
A verified Backup Snapshot created after admission stops and committed work drains, providing a no-acknowledged-data-loss recovery point for a persistent-format upgrade.
_Avoid_: periodic backup, online backup, rollback image

**Fenced**:
A durable Positron lifecycle state in which data and mutation APIs are closed, committed work is flushed, active segments are sealed, and mutable storage ownership is released while local inspection remains available.
_Avoid_: not-ready pod, paused reconciliation, network isolation

**Hibernated**:
A Kubernetes lifecycle state reached only after fencing, in which database pods are scaled to zero while storage, keys, Services, backups, and declarative status are retained.
_Avoid_: shutdown, deletion, scale-to-zero data loss

**Operational Telemetry**:
Bounded metrics, structured logs, health state, and optional traces emitted by Positron about its own operation without becoming user-ingested signal data.
_Avoid_: Metrics Signal Store, tenant telemetry, governance audit

**Health State**:
The authoritative internal assessment from which process liveness, traffic readiness, degraded dependency detail, and Kubernetes conditions are derived.
_Avoid_: HTTP status alone, pod phase, log severity

**Process Phase**:
The runtime state controlling listener and shutdown behavior: Starting, Recovering, Serving, Draining, Fenced, or Stopping.
_Avoid_: Health State, Tenant Lifecycle State, Kubernetes pod phase

**Drain**:
The bounded transition that closes admission, completes admitted durability work, terminates reads explicitly, seals active state, and prepares a crash-safe process stop.
_Avoid_: sleep before exit, Fenced state, connection close

**Graceful Shutdown Record**:
The durable proof that a Drain published final frontiers and catalog state, checkpointed governance, and released mutable ownership before successful process exit.
_Avoid_: process exit code alone, SIGTERM receipt, pod termination

**Positron Data Source**:
The first-party Grafana data-source plugin that translates Grafana exploration workflows into Positron Query API requests.
_Avoid_: Loki data source, Tempo data source, compatibility proxy

**Pipeline Query**:
A typed, time-bounded native query over an explicit log, span, or trace source, composed from Positron operators.
_Avoid_: LogQL query, TraceQL query, shell pipeline

**Correlation**:
A tenant-scoped traversal between related telemetry through explicit identities such as trace ID and span ID.
_Avoid_: Arbitrary join, inferred relationship

**Span**:
A committed trace operation identified within a tenant by its trace ID and span ID, independently visible even when related spans have not arrived.
_Avoid_: Trace row, completed operation

**Span Observation**:
An immutable accepted representation of one received span payload before logical consolidation by trace ID and span ID.
_Avoid_: Logical span, duplicate row

**Conflicted Span**:
A logical span whose observations share an identity but disagree semantically, preserving every variant rather than choosing one silently.
_Avoid_: Updated span, last-write-wins span

**Trace**:
The tenant-scoped collection of committed spans sharing one trace ID, observed incrementally rather than ingested atomically.
_Avoid_: Trace batch, completed trace

**Trace Summary**:
The incrementally derived structural and statistical view of a trace, maintained through committed deltas.
_Avoid_: Authoritative completion record

**Quiescent Trace**:
A trace for which no new span has arrived during the configured ingest-time quiet period.
_Avoid_: Complete trace, closed trace

**Logical Plan**:
The typed internal representation shared by pipeline and SQL queries while retaining signal-specific operators.
_Avoid_: Universal signal schema, query string

**Query Budget**:
The tenant-specific execution limits under system ceilings that bound query lookback, scanned and decoded data, output, memory, compute time, concurrency, and traversal breadth.
_Avoid_: Timeout, best-effort limit

**Complete Result**:
A query result whose terminal status confirms that every admitted operator finished within its budget.
_Avoid_: Partial stream, truncated success

**Result Batch**:
A bounded typed query-output unit with a deterministic sequence number and content digest within one Query Snapshot.
_Avoid_: network chunk, page offset, untyped row buffer

**Query Cursor**:
An opaque authenticated continuation bound to a Tenant ID, logical query, deterministic order, Query Snapshot, cumulative Query Budget, and expiry.
_Avoid_: Tail Cursor, numeric offset, reusable page number

**Snapshot Lease**:
A bounded persistent reservation that keeps the immutable objects required by a resumable Query Snapshot reachable until explicit release or expiry.
_Avoid_: database transaction, backup retention, unbounded segment pin

**Result Digest**:
The terminal digest over the ordered logical Result Batches used with batch sequence and content digests to detect duplicate, missing, or changed output.
_Avoid_: Query Cursor signature, file checksum, query-plan hash

**Commit Position**:
A monotonically ordered logical position for committed store blocks within one virtual shard.
_Avoid_: File offset, event time

**Tail Cursor**:
An opaque, authenticated, tenant-and-filter-bound vector of virtual-shard commit positions used to resume a live tail.
_Avoid_: Durable queue offset, exactly-once cursor

**Backup Snapshot**:
An application-consistent manifest and catalog generation whose referenced immutable files can be copied incrementally and restored as one full Positron instance.
_Avoid_: File copy, point-in-time recovery

**Backup Repository**:
A qualified local filesystem, AWS S3, named S3-compatible, Google Cloud Storage, or Azure Blob destination that stores verified snapshots, immutable checksum-addressed objects, and its Repository Key Registry.
_Avoid_: Primary storage, live replica

**Repository Adapter**:
The Rust boundary that implements one qualified backup provider's immutable-object, range-read, checksum, resumable-upload, compare-and-swap, identity, and deletion semantics.
_Avoid_: Primary Data Volume backend, generic object-store claim, provider credential

**Repository Identity**:
The immutable Positron-owned repository and prefix identity that prevents a Backup Repository from silently adopting or colliding with foreign contents.
_Avoid_: bucket name, endpoint URL, instance display name

**Repository Conformance Target**:
A pinned provider, product or service, API behavior, deployment context, and tested version for which Positron proves the complete Backup Repository contract.
_Avoid_: S3-compatible, cloud-supported, emulator-only claim

**Repository Immutability Policy**:
Provider-enforced versioning, retention, legal-hold, or WORM behavior that may protect backup objects while also preventing Positron from completing deletion or Tenant Purge.
_Avoid_: Positron Retention Policy, backup schedule, encryption

**Virtual Shard**:
The tenant-owned unit of placement, leadership, quorum replication, failover, and migration, containing separate segments from any of that tenant's signal stores.
_Avoid_: Partition, physical shard, signal shard

**Routing Key**:
The stable signal-derived identity used to assign telemetry to a tenant's virtual shard, preferring a shared correlation identity when one exists.
_Avoid_: Primary key, segment key

**Intrinsic Field**:
A signal-defined field with a stable logical name and type.
_Avoid_: Promoted attribute, inferred column

**Attribute**:
A dynamically named telemetry value that preserves its original type and belongs to a resource, instrumentation-scope, or record namespace.
_Avoid_: Dynamic column, untyped field

**Stream Attribute**:
A string attribute shared by a group of log records received together through a stream-oriented protocol.
_Avoid_: Resource attribute, Loki label

**Attribute Promotion**:
A reversible physical optimization that accelerates an attribute without changing its logical name, namespace, type, or query behavior.
_Avoid_: Schema promotion, type inference

**Shard Migration**:
The online transfer of a whole virtual shard to a new replica assignment without changing the shard's routing keyspace.
_Avoid_: Resharding, shard split

**Assignment Epoch**:
The monotonically increasing version of a virtual shard's replica assignment, used to fence stale leaders, writers, and routing information.
_Avoid_: Schema version, segment generation

**Segment**:
An ordered container of store blocks belonging to exactly one tenant, virtual shard, and signal store, managed by the storage kernel as one lifecycle unit.
_Avoid_: Mixed-tenant segment, mixed-signal segment, universal segment format

**Store Block**:
The canonical, checksummed physical payload produced by a signal store for persistence, recovery, and replication.
_Avoid_: Microblock, journal record

**Active Segment**:
The appendable segment receiving durable store blocks for one signal store.
_Avoid_: Active journal, journal segment

**Sealed Segment**:
An immutable segment whose existing store blocks can be published without copying or re-encoding.
_Avoid_: Finalized journal

**Ingest Acknowledgment**:
Confirmation that an accepted store block has satisfied the durability guarantee of the current deployment mode.
_Avoid_: Receipt acknowledgment, buffered acknowledgment

**Local Durability**:
The standalone guarantee that an acknowledged store block has been durably flushed to the node's active segment.
_Avoid_: Best-effort durability

**Quorum Durability**:
The high-availability guarantee that an acknowledged store block has been durably appended by a majority of its three replicas.
_Avoid_: Leader-only durability

**Committed Store Block**:
A store block that has satisfied the deployment's durability guarantee and is therefore visible to queries.
_Avoid_: Flushed block, sealed block

**Admission Group**:
The records from one ingest request that share a tenant, signal store, and virtual shard and reserve capacity and commit independently.
_Avoid_: Transaction, atomic batch

**Partial Ingest Result**:
An ingest outcome that distinguishes committed records from retryable and permanently rejected records without rolling successful admission groups back.
_Avoid_: Transaction rollback, global batch failure

**Query Snapshot**:
A stable query view bounded by each involved signal store's committed position when the query begins.
_Avoid_: Global transaction snapshot

**Retention Policy**:
The tenant-and-signal-specific duration after which whole sealed segments become eligible for logical removal and later physical reclamation.
_Avoid_: Record TTL, deletion policy

**Tenant Purge**:
A managed-scope irreversible operation that blocks a tenant, removes its live data, eliminates every reachable Tenant KEK envelope from the instance and registered backup repositories, and destroys the remaining key material.
_Avoid_: Record deletion, filtered deletion

**Purged Tenant**:
The terminal tenant state retaining only a non-reusable Tenant ID and Tenant Slug, signed Purge Tombstones, and governance evidence.
_Avoid_: deleted account, Suspended tenant, reusable name

**Event Time**:
The original producer time carried by telemetry and preserved without correction or fallback.
_Avoid_: Query Time, Ingest Time, corrected timestamp

**Ingest Time**:
The time assigned by the storage kernel when telemetry is accepted, used to govern retention and physical lifecycle.
_Avoid_: Event time, source time

**Query Time**:
The provenance-bearing temporal value used by default for search: valid source time, then signal-defined observed time, then Ingest Time.
_Avoid_: rewritten Event Time, retention time, commit order

**Lifecycle Clock**:
The persisted, non-decreasing Storage Kernel clock that governs retention, expiry, and scheduled destructive lifecycle work independently of untrusted producer timestamps.
_Avoid_: system wall clock, monotonic process timer, Event Time

**Clock-Uncertain State**:
The degraded state entered when wall-clock movement cannot be safely reconciled with the persisted Lifecycle Clock, pausing destructive time-driven work until recovery or audited acceptance.
_Avoid_: timezone mismatch, producer clock skew, process deadline

**Retention Bucket**:
A fixed ingest-time interval that bounds which sealed segments may be compacted together without extending older telemetry's retention lifetime.
_Avoid_: Compaction window, event-time bucket

**Compaction**:
An atomic replacement of sealed segments from one tenant, signal store, and retention bucket with logically equivalent sealed segments whose physical design may differ.
_Avoid_: In-place rewrite, active-segment compaction
