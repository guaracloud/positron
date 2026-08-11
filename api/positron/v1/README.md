# Canonical Positron v1 API source

`positron.proto` is the hand-edited versioned public contract required by
ADR-0028. The committed Rust v1 types, HTTP/JSON route map, OpenAPI document,
Schema Digest, reference documentation, and validation fixtures are part of
the same product surface and must change together.

The current foundation exposes capability negotiation: it reports the
canonical v1 package and Schema Digest or refuses an incompatible major with a
stable code, retry class, completion state, and non-secret source. It does not
introduce SDK publication, a listener, persistence behavior, or a deferred
product capability.
