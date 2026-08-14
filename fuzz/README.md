# Fuzz tests

Add fuzz targets with the untrusted-input or stateful product boundary they
exercise. Applicable targets include parsers, protocol decoders, public request
bodies, persistent formats, recovery inputs, cryptographic envelopes, and
state-machine transitions.

Keep useful seed inputs and promote every fixed crash to the regression corpus.
Run a target with:

```console
cargo +nightly fuzz run <target>
```

Dynamic schema discovery, whole-root overflow, typed duplicate selection, and
checkpoint round trips share one bounded production-API target:

```console
cargo +nightly fuzz run schema_discovery_query
```

The repository's production toolchain remains pinned; `cargo-fuzz` uses an
installed nightly toolchain only for sanitizer instrumentation.

Current storage target:

```console
cargo +nightly fuzz run primary_data_volume_stateful
```

Current authenticated-frame target:

```console
cargo +nightly fuzz run encrypted_frame_open
```

Current Local Root Key File parser target:

```console
cargo +nightly fuzz run local_root_key_file
```

This target accepts only a bounded structured mutation program, never raw or
hex-encoded Local Root Key File bytes. The first byte is the `V` baseline
selector. Each remaining command is exactly three bytes: opcode, bounded index
or size, and value. The opcodes are `W` for overwrite, `X` for XOR, `T` for
truncate, `A` for append, `R` for resize, `C` for checksum recomputation, and
`N` for the no-op used by text corpus seeds. Append is limited to 16 bytes and
the candidate is limited to 150 bytes. Inputs are limited to 64 bytes and
incomplete or unknown commands are rejected.

The harness synthesizes the published known-answer file internally into
zeroizing custody before interpreting commands. Corpus entries and any
libFuzzer crash or reproducer artifacts therefore contain only selectors,
opcodes, indices, sizes, and mutation values; they must never contain a complete
134-byte Local Root Key File, its 268-character hexadecimal representation, or
Root KEK material.

Current Resource Governor state-machine target:

```console
cargo +nightly fuzz run resource_governor_stateful
```

This harness executes a bounded program of ordinary, tenant-attributed recovery,
and system recovery reservations; drop/cancel; resize; disk-pressure observation;
shutdown; and recovery-safe completion. It retains at most eight handles and
checks conservation, fixed pool accounting, capacity observations, bounded
reason telemetry, reserve consumption, lifecycle counts, and final drainage
after every transition.

Current Catalog Generation state-machine target:

```console
cargo +nightly fuzz run catalog_generation_stateful
```

This harness uses the real Primary Data Volume and the Catalog's deterministic
file-operation fault seam. It publishes one bounded governance-sensitive
proposal at every object, audit, commit, marker, rename, and directory-sync
boundary, then reopens storage and asserts complete predecessor-or-successor
catalog and audit visibility.
