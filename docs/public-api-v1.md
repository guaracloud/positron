# Positron v1 public-interface candidate

The canonical hand-edited contract is
`api/positron/v1/positron.proto`. `cargo xtask generate` parses that bounded
source and the Rust-owned Configuration Contract, then deterministically
produces the Rust contract, gRPC and HTTP/JSON mappings, OpenAPI description,
generated client request surface, SHA-256 Schema Digest, JSON Schema, and
reference documentation plus bounded API and configuration validation
fixtures. `cargo xtask verify-generation` rejects checked generated output
that is not byte-identical to that regeneration. Generated files are not
edited directly.

This milestone exposes an in-memory contract and generated transport mapping;
it does not start a listener, publish an SDK, or implement query execution.
Those remain separately activated and qualified work.

## Compatibility and capability behavior

The v1 package evolves additively. An older v1 capability request that omits
the additive `capability` field means `canonical_public_interface`, so old and
current clients receive the same typed statement and Schema Digest.
Unsupported API majors are refused before work begins.

The capability statement reports concrete current truth:

| Capability | Availability | Meaning |
| --- | --- | --- |
| `canonical_public_interface` | `implemented` | The generated v1 negotiation and mapping boundary is available. |
| `release_one_query` | `unavailable` | Query behavior is in Release 1 scope but has not been activated by this milestone. |
| `metrics` | `unsupported` | Metrics are explicitly outside Release 1 scope. |
| Any capability request on another API major | `version_incompatible` | The server cannot interpret that API package. |

Every statement also carries an explicit deprecation state. The current v1
surface is `current`; no v1 behavior is deprecated by this milestone.

## Bounds and failures

Generated gRPC protobuf and HTTP/JSON capability request bodies are limited to
64 bytes. Decoding rejects malformed bodies, duplicate fields, unknown fields,
unknown capability values, and oversized bodies. Client encoding allocates at
most one heap buffer, reserves that buffer once at the 64-byte body limit, and
performs no I/O. Because the generated request contains only two bounded
`uint32` values, every typed request is provably smaller than that limit and
client encoding is infallible. HTTP/JSON encoding writes directly into the
reserved buffer: decimal conversion uses a 10-byte stack scratch area, with
zero intermediate heap-body bytes and zero completed-body copies. Oversized
and malformed outcomes apply only when decoding untrusted transport bodies.

Public failures contain only a stable code, safe closed detail, retry class,
completion state, and source. Caller text is never reflected. Input failures
are rejected before work and require input correction; unsupported,
unavailable, and version-incompatible capability requests are non-retryable
for the same deployed artifact.

Recovery is to correct malformed input, remove unknown fields, stay within the
published bound, or select an API major and capability reported by the target.
There is no migration or persistent-state recovery for this milestone because
the public-interface candidate writes no durable state.

## Release status

This behavior may be recorded as an implemented candidate after its exact
revision passes the required engineering gates. It is not a `Qualified`
Release 1 compatibility claim, published SDK, deployment, or release. Those
states require their separately authorized exact-artifact evidence.
