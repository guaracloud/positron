# Canonical Positron v1 API source

`positron.proto` is the hand-edited versioned public contract required by
ADR-0028. The committed Rust v1 types, HTTP/JSON route map, OpenAPI document,
Schema Digest, reference documentation, and validation fixtures are part of
the same product surface and must change together.

`positron-api/build.rs` generates Protobuf messages, fixed enums, and the Rust
`ApiKeyServiceClient` directly from this schema using locked `prost-build 0.14.3` and
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
rejected. Authorization is `Bearer` metadata; no request field may choose a
tenant or impersonate one. Only System Administration may manage keys.

Create requires `scope`, `expected_generation`, and `idempotency_key`, with an
optional `expires_at_unix_seconds` measured against the persisted Lifecycle
Clock. Rotate and revoke require `principal`, `expected_generation`, and
`idempotency_key`. List has no other fields; scope_inspect requires `principal`.
Identifiers use canonical lowercase UUID text. List returns only redacted
descriptors. A create or rotate retry returns the original principal without a
secret; a lost first secret requires a new rotation. HTTP failures use stable
codes `authentication_rejected` (401), `invalid_request` (400),
`stale_generation` or `idempotency_conflict` (409), `key_unavailable` (404), and
`administration_unavailable` (503).

The native CLI invokes this API using `positron key create|list|rotate|revoke|scope-inspect`.
Pass `--endpoint 127.0.0.1:PORT --credential-stdin`; supply the bearer through a
pipe from a secret manager. Terminal input is refused to prevent echo. Secrets
are never accepted in arguments or environment variables. Mutations require
`--expected-generation N --idempotency-key UUID`; create also requires
`--scope ingest|query|tenant-administration`, while rotate/revoke/scope-inspect
require `--principal UUID`. `--expires-at N` is optional for create. A new
secret is emitted once to stdout; protect that output as credential material.
