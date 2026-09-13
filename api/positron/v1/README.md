# Canonical Positron v1 API source

`positron.proto` is the hand-edited versioned public contract required by
ADR-0028. The committed Rust v1 types, HTTP/JSON route map, OpenAPI document,
Schema Digest, reference documentation, and validation fixtures are part of
the same product surface and must change together.

`positron-api/build.rs` generates Protobuf messages, fixed enums, and the Rust
`ApiKeyServiceClient`, `TenantQuotaServiceClient`, `TenantServiceClient`, `TenantAliasServiceClient`, `TenantLifecycleServiceClient`, `TenantRetentionServiceClient`,
`PolicyPreviewServiceClient`, `PolicyTestServiceClient`, `PolicyDiffServiceClient`,
`PolicyExplainServiceClient`, and `PolicyActivateServiceClient` directly from this schema using locked `prost-build 0.14.3` and
`protoc-bin-vendored 3.2.0`. Ordinary Cargo builds regenerate the output in
`OUT_DIR`; no globally installed compiler is required. API-key HTTP clients
and the runtime service use those generated messages and client through the
bounded JSON adapter named by the canonical HTTP mapping. The API listener
serves HTTP/JSON; generated Protobuf bindings are available as wire types,
while a gRPC administration listener is not exposed.
The build also derives the embedded Schema Digest from the exact Protobuf
source bytes; contract tests compare it with the committed map, OpenAPI,
fixtures, and digest artifact so stale public artifacts fail the tests.

The foundation exposes capability negotiation: it reports the
canonical v1 package and Schema Digest or refuses an incompatible major with a
stable code, retry class, completion state, and non-secret source. It does not
introduce SDK publication or a deferred product capability.

`ApiKeyService.Manage` is served by the authenticated `api` listener at
`POST /v1/api-keys:manage`. The body is limited to 1024 bytes; responses are
limited to 64 KiB. JSON uses snake_case action and scope names. Unknown fields,
duplicate fields, malformed identifiers, and action-inapplicable fields are
rejected. Authorization is `Bearer` metadata. `target_tenant` is an optional
control-plane target for an API-key lifecycle action selected by a System
Administration principal;
it never chooses or impersonates data-plane authority. Only System
Administration may manage keys.

Create requires `scope`, `expected_generation`, and `idempotency_key`, with an
optional `expires_at_unix_seconds` measured against the persisted Lifecycle
Clock. It may name `target_tenant` to provision a tenant-bound principal for
that immutable Tenant ID; otherwise it retains the authenticated legacy
administrative create behavior. Rotate and revoke require `principal`, `expected_generation`, and
`idempotency_key`; list and scope_inspect may also name `target_tenant`, while
scope_inspect requires `principal`.
Identifiers use canonical lowercase UUID text. List returns only redacted
descriptors. A create or rotate retry returns the original principal without a
secret; a lost first secret requires a new rotation. HTTP failures use stable
codes `authentication_rejected` (401), `invalid_request` (400),
`stale_generation` or `idempotency_conflict` (409), `key_unavailable` (404), and
`administration_unavailable` (503).

`TenantRetentionService` is served by the authenticated `api` listener at
`POST /v1/tenant-retention:preview` and
`POST /v1/tenant-retention:update`. A tenant-administration credential may
operate only on its own active or read-only tenant. Preview returns pages of at
most 64 redacted scope impacts, with an opaque Catalog-snapshot continuation;
the confirmation digest still covers the full canonical impact. A reduction
update carries that digest, expected retention generation, and idempotency key.
Authentication completes before body decoding. The
schema-derived `TenantRetentionServiceClient` and `positron tenant retention
preview|update` CLI use the protected-stdin credential and TLS-default
transport contract shared by the administration clients.

`TenantService` is served by the authenticated `api` listener for explicit
System Administration requests: `POST /v1/tenants:create`,
`POST /v1/tenants:inspect`, `POST /v1/tenants:list`, and
`POST /v1/tenants:update-display-name`. All requests authenticate before the
bounded body is decoded. Create receives an immutable tenant ID, canonical slug,
display name, retention period, positive resource limits, and idempotency key;
inspect returns one redacted tenant descriptor. List returns fixed pages of up to
48 descriptors and an opaque Catalog-snapshot continuation; a stale continuation
must restart enumeration rather than mixing descriptor snapshots. The display-name update
uses a nonzero display generation and idempotency key. The schema-derived
`TenantServiceClient` and `positron tenant create|inspect|list|update-display-name`
CLI use protected-stdin credentials and TLS by default; plaintext requires the
explicit `--allow-plaintext` opt-out.

`TenantAliasService.Bind` is served at `POST /v1/tenant-aliases:bind` for a
System Administration bearer. It records an immutable compatibility assertion
for an explicit tenant and returns only a redacted receipt. The schema-derived
`TenantAliasServiceClient` and `positron tenant alias bind` CLI use
protected-stdin credentials and TLS by default; plaintext requires the explicit
`--allow-plaintext` opt-out.

The native CLI invokes this API using `positron key create|list|rotate|revoke|scope-inspect`.
TLS is the default: pass `--endpoint ADDRESS:PORT --server-name DNS_OR_IP --trust-file CA_PEM
--credential-stdin`; the server name is verified against the presented certificate and the CA
reference is read only for that connection. `--allow-plaintext` is an explicit opt-out and cannot
be combined with a trust reference. Supply the bearer through a pipe from a secret manager. Terminal input is refused to prevent echo. Secrets
are never accepted in arguments or environment variables. Mutations require
`--expected-generation N --idempotency-key UUID`; create also requires
`--scope ingest|query|tenant-administration` and accepts optional
`--target-tenant UUID`; the same target is accepted for list, rotate, revoke,
and scope-inspect, while rotate/revoke/scope-inspect require `--principal UUID`.
`--expires-at N` is optional for create. A new
secret is emitted once to stdout; protect that output as credential material.
Public plaintext requires the server's configuration-file-only
`listener.api_transport = "plaintext"` opt-out and the client's explicit
`--allow-plaintext`; it is never an automatic TLS fallback. This sends bearer
credentials and API data without transport encryption. Positron emits the
non-secret configuration warning, remains ready with a persistent health
warning, and records the selected profile once in the governance audit chain.

The client preserves only published failures: `invalid_request`, `authentication_rejected`,
`stale_generation`, `idempotency_conflict`, `key_unavailable`, and
`administration_unavailable`. Malformed,
oversized, or status-mismatched error responses are a bounded transport failure and do not echo
their body.

`PolicyService.Validate` is served by the authenticated `api` listener at
`POST /v1/policies:validate`. A Tenant Administration bearer authenticates before
the bounded 64 KiB candidate is decoded; a System Administration credential cannot
impersonate a tenant through this endpoint. Validation compiles a prospective
candidate in memory and returns only its generation, digest, and rule count. It
never activates a policy, writes a catalog generation, or reveals rules, literals,
or telemetry values. The native CLI is `positron policy validate --policy-file PATH`
with the same protected stdin credential and TLS defaults as the other
administration clients. Its closed failures are `invalid_request` (400),
`authentication_rejected` (401), and `administration_unavailable` (503).

The native Policy CLI uses the checked public clients. Every command requires
`--endpoint IP:PORT` and `--credential-stdin`; TLS requires `--server-name`
and `--trust-file`, while `--allow-plaintext` is the sole plaintext opt-out.
It reads caller-selected files only to the published request bounds:

- `positron policy validate --policy-file PATH`
- `positron policy test --policy-file PATH --candidate-file PATH`
- `positron policy diff --before-policy-file PATH --after-policy-file PATH`
- `positron policy explain --policy-file PATH --candidate-file PATH`
- `positron policy activate --policy-file PATH --expected-generation N --idempotency-key UUID`

Its output contains only published generations, digests, counts, semantic
categories, accepted or rejected outcome, bounded redacted explanations, and
audit position. It never prints credentials, file contents, rule identifiers,
predicate literals, fixture values, or remote error bodies.

`PolicyService.Activate` is served by the same authenticated `api` listener at
`POST /v1/policies:activate`. A Tenant Administration bearer authenticates
before the bounded candidate is decoded. The request carries the expected policy
generation and a canonical Administrative Idempotency Key. A successful request
durably publishes the candidate's required successor generation with governance
evidence; an exact retry returns the original receipt after later changes or
reopen. A stale generation reports only the current generation and a semantic
category, and changed content under an existing key is an idempotency conflict.
The operation is prospective: it does not rewrite existing telemetry.

`PolicyService.Test` is served by the same authenticated `api` listener at
`POST /v1/policies:test`. A Tenant Administration bearer authenticates before
the bounded prospective policy and fixture are decoded. It evaluates the
fixture only in memory and returns the policy generation, digest, accepted
outcome, and applied-rule count; it never activates the candidate or returns
fixture values, rule identifiers, predicate literals, or telemetry values. The
served route's closed
failures are `invalid_request` (400), `authentication_rejected` (401), and
`administration_unavailable` (503).

`PolicyService.Explain` is served by the same authenticated `api` listener at
`POST /v1/policies:explain`. A Tenant Administration bearer authenticates before
the bounded prospective policy and fixture are decoded. It evaluates only in
memory and returns the policy generation, digest, accepted or rejected outcome,
and a bounded explanation containing only semantic action evidence. It never
activates a policy or returns rule identifiers, predicate literals, or fixture
values. Its closed failures are `invalid_request` (400),
`authentication_rejected` (401), and `administration_unavailable` (503).

`TenantQuotaService.Update` is served by the authenticated `api` listener at
`POST /v1/tenant-quotas:update`. A Tenant Administration bearer may mutate only its
attributed control-plane tenant; `tenant` never provides data-plane attribution. The request
contains an expected resource generation, idempotency key, positive weight, and eleven positive
named resource limits: `memory_bytes`, `queue_slots`, `task_slots`, `buffer_cache_bytes`,
`batch_items`, `lease_slots`, `retry_slots`, `io_permits`, `cpu_work_units`,
`file_descriptors`, and `disk_headroom_bytes`. A successful update returns the published
successor `resource_generation`. Replaying the same valid idempotency binding returns that
successor without restoring obsolete live quota state.

The quota CLI is `positron tenant quota update` and uses the same protected stdin credential and
TLS defaults as `positron key`. It requires all eleven named limits, `--tenant`,
`--expected-generation`, and `--idempotency-key`; plaintext needs explicit `--allow-plaintext`.
Quota failures are `invalid_request` (400), `authentication_rejected` (401),
`stale_generation` or `idempotency_conflict` (409), and `administration_unavailable` (503).

`TenantLifecycleService.Transition` is served by the authenticated `api`
listener at `POST /v1/tenant-lifecycle:transition`. A System Administration
bearer authenticates before the 1024-byte request body is decoded. The request
names its immutable target tenant, lifecycle target, expected lifecycle
generation, and idempotency key. An exact retry returns the original committed
transition and audit metadata; stale requests expose only the current lifecycle
generation and one bounded redacted semantic difference. Direct `Purged`
completion is unavailable until its separately authorized cryptographic purge
completion has succeeded. The native CLI is `positron tenant lifecycle
transition --tenant UUID --target active|read-only|suspended|purging|purged
--expected-generation N --idempotency-key UUID`, with the same protected stdin
credential and TLS-default transport contract as the other administration
commands. Its closed failures are `invalid_request` (400),
`authentication_rejected` (401), `tenant_unavailable` (404),
`stale_generation`, `idempotency_conflict`, `invalid_transition`, or
`purge_completion_unavailable` (409), and `administration_unavailable` (503).
A stale-generation body also carries the current nonzero `resource_generation` and a bounded,
redacted `semantic_diff`, so a caller can recover without receiving quota values or credentials.

`TenantAliasService.Bind` is served by the authenticated `api` listener at
`POST /v1/tenant-aliases:bind`. A System Administration bearer authenticates
before the 1024-byte body is decoded. The request names an explicit immutable
tenant, one bounded protocol-specific `external_alias`, its expected alias
generation, and an idempotency key. The alias is a compatibility assertion for
data-plane requests only after the credential has already attributed one
tenant; it never selects routing or authority. A successful first bind returns
only the target tenant, successor alias generation, and redacted audit
position/time. The alias text, credential, and request digest stay out of the
receipt. Exact retries return the original receipt, while an alias cannot be
rebound, unbound, or reused by another tenant, including after purge. Closed
failures are `invalid_request` (400), `authentication_rejected` (401),
`tenant_unavailable` (404), `stale_generation`, `idempotency_conflict`,
`alias_already_bound`, or `alias_conflict` (409), and
`administration_unavailable` (503).
