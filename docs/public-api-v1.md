# Positron v1 public interface

The canonical public contract is `api/positron/v1/positron.proto`. Its
committed Rust types, gRPC and HTTP/JSON mappings, OpenAPI description, Schema
Digest, JSON Schema, reference documentation, and validation fixtures form one
product surface and change together.

This surface exposes capability negotiation. It does not yet start a listener,
publish an SDK, or implement query execution.

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
This interface writes no durable state.
