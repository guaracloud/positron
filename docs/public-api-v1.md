# Positron v1 public interface

The canonical public contract is `api/positron/v1/positron.proto`. Its
committed Rust types, gRPC and HTTP/JSON mappings, OpenAPI description, Schema
Digest, JSON Schema, reference documentation, and validation fixtures form one
product surface and change together.

The native `api` listener exposes capability negotiation and authenticated
API-key lifecycle management, tenant registry and profile administration, tenant quota updates,
tenant lifecycle transitions, immutable tenant-alias binding, and policy validation,
testing, diff, explanation, and activation. The native administrative CLI uses the
available client-backed subset of that listener with
verified TLS by default: its configured server name and protected CA reference bind the HTTPS
authority separately from the dial address. Plaintext requires the explicit listener and CLI
opt-out. Bearer metadata comes from a non-terminal stdin pipe. It accepts no credential
argument or environment variable. See [the canonical API reference](../api/positron/v1/README.md)
for the create, list, rotate, revoke, and scope-inspect request contract, generation
preconditions, idempotency semantics, failure codes, and one-time secret output.
A create retry that completes an authenticated pre-marker preparation returns the
original principal with no secret; it never reconstructs or redisplays the original secret.
Its stable lifecycle failures distinguish authentication, stale generation, idempotency conflict,
unavailable key, and unavailable administration; malformed remote errors remain redacted transport
failures.

`TenantRetentionService` serves preview and confirmed-update requests through
the authenticated native `api` listener at
`POST /v1/tenant-retention:preview` and
`POST /v1/tenant-retention:update`. Checked wire types preserve only
generation-pinned, redacted impact evidence and an opaque preview confirmation
digest. A tenant-administration credential is bound to its own active or
read-only tenant, and authentication completes before the bounded body is
decoded. The schema-derived `TenantRetentionServiceClient` and
`positron tenant retention preview|update` CLI use the configured endpoint,
protected-stdin credential, and TLS-default transport contract shared by the
administration clients.
Public plaintext requires the server's configuration-file-only
`listener.api_transport = "plaintext"` opt-out and the client's explicit
`--allow-plaintext`; it is never an automatic TLS fallback. This sends bearer
credentials and API data without transport encryption. Positron emits the
non-secret configuration warning, remains ready with a persistent health
warning, and records the selected profile once in the governance audit chain.
SDK publication and a public query transport remain unavailable.

## Compatibility and capability behavior

The v1 package evolves additively. An older v1 capability request that omits
the additive `capability` field means `canonical_public_interface`, so old and
current clients receive the same typed statement and Schema Digest.
Unsupported API majors are refused before work begins.

| Capability | Availability | Meaning |
| --- | --- | --- |
| `canonical_public_interface` | `implemented` | The v1 negotiation and mapping boundary is available. |
| `release_one_query` | `unavailable` | Query behavior is in Release 1 scope but is not implemented yet. |
| `metrics` | `unsupported` | Metrics are outside Release 1 scope. |
| Any capability request on another API major | `version_incompatible` | The server cannot interpret that API package. |

Every statement carries an explicit deprecation state. The current v1 surface
is `current`.

## Bounds and failures

gRPC protobuf and HTTP/JSON capability request bodies are limited to 64 bytes.
Decoding rejects malformed bodies, duplicate fields, unknown fields, unknown
capability values, and oversized bodies. Client encoding allocates at most one
heap buffer, reserves that buffer once at the 64-byte body limit, and performs
no I/O.

Public failures contain only a stable code, safe closed detail, retry class,
completion state, and source. Caller text is never reflected. Input failures
are rejected before work and require input correction; unsupported,
unavailable, and version-incompatible requests are non-retryable for the same
deployed artifact.

Recovery is to correct malformed input, remove unknown fields, stay within the
published bound, or select an API major and capability reported by the target.
Read-only capability negotiation writes no durable state. Authenticated API-key lifecycle
mutations publish one Catalog generation and the matching redacted Governance Audit record.
An API-key lifecycle action may carry `target_tenant`, an explicit administrative
Tenant ID selected only by a System Administration principal. It provisions,
inspects, rotates, or revokes a tenant-bound principal through the ordinary
lifecycle and never supplies data-plane attribution or system-administrator
impersonation.

## Tenant quota updates

`POST /v1/tenant-quotas:update` updates one tenant's durable quota resource through a
Tenant Administration bearer. The `tenant` value is an explicit control-plane target and must
equal the bearer-attributed tenant; it cannot select data-plane attribution. The direct mutation
requires a nonzero expected resource generation, an Administrative Idempotency Key, a positive
weight, and eleven positive named limits: `memory_bytes`, `queue_slots`, `task_slots`,
`buffer_cache_bytes`, `batch_items`, `lease_slots`, `retry_slots`, `io_permits`,
`cpu_work_units`, `file_descriptors`, and `disk_headroom_bytes`. Success returns the published
successor `resource_generation`; the same idempotency binding replays that successor without a
second mutation.

The operation uses stable `invalid_request` (400), `authentication_rejected` (401),
`stale_generation` or `idempotency_conflict` (409), and `administration_unavailable` (503)
responses. A stale-generation response includes the current `resource_generation` and a bounded
redacted `semantic_diff`. The diff identifies a quota-resource change without exposing quota
values or credentials. The native command is `positron tenant quota update`; it supplies its
bearer on protected stdin and uses TLS unless explicitly passed `--allow-plaintext`.

## Tenant lifecycle transitions

`POST /v1/tenant-lifecycle:transition` performs one System Administration
transition for an explicit immutable Tenant ID. Authentication completes before
the bounded request body is decoded. The transition carries a nonzero expected
lifecycle generation and Administrative Idempotency Key; identical retries
return the committed transition and audit metadata even after a later lifecycle
successor. Stale requests return only the current lifecycle generation and one
bounded redacted semantic difference. The endpoint does not expose tenant
identity, credentials, or request values in failures.

The allowed targets are `active`, `read_only`, `suspended`, `purging`, and
`purged`. `purging` is irreversible, while direct `purged` completion is
unavailable until the separately authorized cryptographic purge-completion
operation has established its proof. Stable failures are `invalid_request`
(400), `authentication_rejected` (401), `tenant_unavailable` (404),
`stale_generation`, `idempotency_conflict`, `invalid_transition`, or
`purge_completion_unavailable` (409), and `administration_unavailable` (503).

The native command is `positron tenant lifecycle transition`; it requires
`--tenant`, `--target`, `--expected-generation`, and `--idempotency-key`. The
bearer arrives only on protected stdin. TLS is the default and plaintext needs
the explicit `--allow-plaintext` opt-out.

## Tenant registry and profile administration

System Administration requests can create, inspect, list, and update the display
name of explicit tenant registry entries through `POST /v1/tenants:create`,
`POST /v1/tenants:inspect`, `POST /v1/tenants:list`, and
`POST /v1/tenants:update-display-name`. Authentication completes before the
bounded request body is decoded. Create requires the immutable tenant ID,
canonical slug, display name, retention period, positive weight, all eleven
positive resource limits, and an idempotency key. Inspect and list return only
redacted durable descriptors: tenant ID, slug, display name, retention and
display generations, and lifecycle state.

The display-name update requires a nonzero expected display generation and an
idempotency key. Exact retries replay the original receipt; a stale request
returns only the current display generation and a bounded redacted semantic
difference. Stable failures are `invalid_request` (400),
`authentication_rejected` (401), `tenant_unavailable` (404) for inspection,
`tenant_conflict`, `stale_display_generation`, or `idempotency_conflict` (409),
and `administration_unavailable` (503). The schema-derived `TenantServiceClient`
and `positron tenant create|inspect|list|update-display-name` CLI require
`--endpoint` and `--credential-stdin`; TLS also requires `--server-name` and
`--trust-file`, while plaintext requires the explicit `--allow-plaintext`
opt-out.

## Immutable tenant aliases

`POST /v1/tenant-aliases:bind` records one immutable protocol compatibility
alias for an explicit tenant under a System Administration bearer. Authentication
finishes before the bounded 1024-byte body is decoded. The alias does not select
a tenant for routing, identity, or authorization: a data-plane credential first
attributes its immutable tenant, then an optional protocol hint must equal that
tenant's bound alias. System administrators retain no data-plane authority.

The request contains `tenant`, `external_alias`, a nonzero expected alias
generation, and an idempotency key. The first bind publishes successor generation
2; an exact retry returns its original redacted audit receipt. An alias can never
be rebound, unbound, or reused by another tenant, including after the original
tenant is purged. The receipt contains target tenant, alias generation, audit
position, and audit time only. It never returns the alias, request digest, or
credentials. The schema-derived `TenantAliasServiceClient` and `positron tenant
alias bind` CLI require `--endpoint` and `--credential-stdin`; TLS also requires
`--server-name` and `--trust-file`, while plaintext requires the explicit
`--allow-plaintext` opt-out. Stable failures are `invalid_request` (400),
`authentication_rejected` (401), `tenant_unavailable` (404),
`stale_generation`, `idempotency_conflict`, `alias_already_bound`, or
`alias_conflict` (409), and `administration_unavailable` (503).

## Policy validation

`POST /v1/policies:validate` accepts one bounded 64 KiB `policy_json` candidate
under a Tenant Administration bearer. Authentication completes before body decoding
and always resolves the caller's tenant; the request has no tenant selector and a
System Administration principal cannot use it to impersonate tenant authority.
Validation compiles the candidate prospectively and returns only the nonzero
`policy_generation`, 64-character `policy_digest`, and bounded `rule_count`. It
does not activate the candidate, write catalog or governance state, or return rule
identifiers, predicate literals, or telemetry values.

The native command is `positron policy validate --policy-file PATH`. The file stays
out of command-line arguments, the bearer arrives through protected stdin, and TLS
is the default unless `--allow-plaintext` is explicit. Its stable failures are
`invalid_request` (400), `authentication_rejected` (401), and
`administration_unavailable` (503).

## Policy CLI

The native policy commands use the checked public clients and require
`--endpoint IP:PORT` plus `--credential-stdin`. TLS requires both
`--server-name NAME` and `--trust-file PATH`; `--allow-plaintext` is the only
plaintext opt-out. Policy and fixture inputs are caller-selected files read
only to their published request bounds.

- `positron policy validate --policy-file PATH`
- `positron policy test --policy-file PATH --candidate-file PATH`
- `positron policy diff --before-policy-file PATH --after-policy-file PATH`
- `positron policy explain --policy-file PATH --candidate-file PATH`
- `positron policy activate --policy-file PATH --expected-generation N --idempotency-key UUID`

Validate prints generation, digest, and rule count. Test prints generation,
digest, accepted outcome, and applied-rule count. Diff prints before/after
generations and digests plus the published semantic categories. Explain prints
generation, digest, outcome, and the bounded redacted semantic explanation.
Activate prints successor generation, digest, and audit position. The CLI
never prints credential text, file contents, rule identifiers, predicate
literals, fixture values, or remote error bodies.

## Policy activation

`POST /v1/policies:activate` accepts a bounded prospective `policy_json`, its
nonzero expected generation, and a canonical Administrative Idempotency Key under
a Tenant Administration bearer. Authentication completes before decoding the
candidate. The candidate must carry the expected successor generation. On success
the service returns only the successor resource generation, policy digest, and
governance audit position. Exact retries return that original durable receipt,
including after later policy updates and reopen. A stale request returns the
current generation and `policy generation changed`; changed content under an
existing idempotency key returns `idempotency_conflict`. Activation is prospective
and does not rewrite retained telemetry.

## Policy explanation

`POST /v1/policies:explain` accepts one bounded 64 KiB prospective
`policy_json` and `candidate_json` fixture under a Tenant Administration bearer.
Authentication completes before either body is decoded. It returns only the
nonzero policy generation, 64-character digest, accepted or rejected outcome,
and a bounded semantic explanation. The explanation never exposes rule
identifiers, predicate literals, action values, or fixture values. The operation
does not activate the candidate or write catalog or governance state. Its stable
failures are `invalid_request` (400), `authentication_rejected` (401), and
`administration_unavailable` (503).

## Policy fixture testing

`POST /v1/policies:test` accepts one bounded 64 KiB request containing a
prospective `policy_json` and a `candidate_json` fixture under a Tenant
Administration bearer. Authentication completes before either body is decoded.
The service evaluates only in memory and returns the nonzero policy generation,
64-character digest, accepted outcome, and bounded applied-rule count. It does
not activate the candidate, write catalog or governance state, or return rule
identifiers, predicate literals, fixture values, or telemetry values.

The served route's stable failures are `invalid_request` (400), `authentication_rejected` (401), and
`administration_unavailable` (503).

## Policy diff

`POST /v1/policies:diff` accepts bounded `before_policy_json` and
`after_policy_json` candidates under a Tenant Administration bearer. Authentication
completes before either candidate is decoded. The service compares both candidates
only in memory and returns their nonzero generations, 64-character digests, and a
bounded sequence of semantic categories. Categories identify generation, rule
addition or removal, predicate, and action changes without returning rule
identifiers, predicate literals, action values, or any telemetry values. It does
not activate either candidate or write catalog or governance state. Its stable
failures are `invalid_request` (400), `authentication_rejected` (401), and
`administration_unavailable` (503).
