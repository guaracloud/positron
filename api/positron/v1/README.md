# Canonical Positron v1 API source

`positron.proto` is the sole hand-edited versioned public contract required by
ADR-0028. Run `cargo xtask generate-api` to regenerate the Rust v1 types,
HTTP/JSON route map, OpenAPI document, and SHA-256 Schema Digest. Generated
files in this directory and `crates/positron-api/src/generated.rs` are never
edited by hand.

The foundation exposes only capability negotiation: it reports the canonical
v1 package and Schema Digest or explicitly refuses an incompatible major with
a stable code, retry class, completion state, and non-secret source. It does
not introduce SDK publication, a listener, a persistence format, or any
deferred product capability.
