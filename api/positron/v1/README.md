# Canonical Positron v1 API source

`positron.proto` is the sole hand-edited versioned public contract required by
ADR-0028. Run `cargo xtask generate` to regenerate the Rust v1 types,
HTTP/JSON route map, OpenAPI document, SHA-256 Schema Digest, and the
cross-transport validation fixtures plus the schema, reference, and validation
fixtures owned by the Rust Configuration Contract. Run `cargo xtask
verify-generation` to reject checked-output drift. Generated files in this
directory and `crates/positron-api/src/generated.rs` are never edited by hand.

The generator is the locked `xtask` workspace tool. Its Rust and Cargo tool
versions are recorded in `qualification/engineering/toolchains.tsv`, and its
dependencies are pinned by `Cargo.lock`.

The foundation exposes only capability negotiation: it reports the canonical
v1 package and Schema Digest or explicitly refuses an incompatible major with
a stable code, retry class, completion state, and non-secret source. It does
not introduce SDK publication, a listener, a persistence format, or any
deferred product capability.
