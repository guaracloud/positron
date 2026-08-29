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

The bounded ingest-policy target compiles adversarial rule programs and drives
them through authenticated OTLP decoding, admission grouping, schema ownership,
and durable ingest:

```console
cargo +nightly fuzz run ingest_policy --sanitizer none -- -runs=1000
```

The repository's production toolchain remains pinned; `cargo-fuzz` uses an
installed nightly toolchain only for sanitizer instrumentation.

Current storage target:

```console
cargo +nightly fuzz run primary_data_volume_stateful
```

The active-segment state-machine target also exercises bounded snapshot-lease
creation, marked resume/repeat, usage recording, release, expiry, and reopen
recovery alongside append and persisted-corruption transitions:

```console
cargo +nightly fuzz run active_segment_ledger_stateful --sanitizer none -- -runs=1000
```

The bounded query matcher target exercises substring matching, the static
regex automaton, and conservative text-pruning candidate extraction:

```console
cargo +nightly fuzz run query_search_matcher
```

The bounded SQL target feeds arbitrary bytes through a bounded lossy UTF-8
conversion, parses raw SQL candidates, and checks deterministic failure
classification. It also generates equivalent bounded SQL and native-pipeline
queries from the same escaped body literal and asserts that both frontends
produce the same typed plan or stable failure class:

```console
cargo +nightly fuzz run query_sql
```

The authenticated cursor boundary target checks bounded cursor ownership,
lossless round trips, and truncation rejection. The current 4545-byte cursor
encoding is the only resumable wire. The legacy 341-byte and v3 373-byte
authenticated encodings are recognized only to return the stable invalid-cursor
result; their numeric-offset semantics are rejected. All other lengths are
rejected before any resume state is constructed:

```console
cargo +nightly fuzz run query_cursor --sanitizer none -- -runs=1000
```

The live-tail cursor target checks bounded shard-frontier decoding,
authentication, duplicate-shard rejection, and truncation handling:

```console
cargo +nightly fuzz run tail_cursor --sanitizer none -- -runs=1000
```

The live-tail state-machine target drives bounded multi-shard poll,
acknowledgement, resume, cancellation, disconnect, drop, and cleanup sequences:

```console
cargo +nightly fuzz run tail_state_machine --sanitizer none -- -runs=1000
```

The persistent snapshot-lease target exercises the production PSLEASE1 v1
through v4 codec, including marker and physical-usage fields, checked lengths,
unknown tags, truncation, and overflow mutations:

```console
cargo +nightly fuzz run snapshot_lease_record --sanitizer none -- -runs=1000
```

The physical query-search target builds bounded authenticated Store Blocks and
schema text coverage, then exercises identity/digest validation, conservative
candidate pruning, fallback, and decoding through the production scan path.
It asserts that a matching body is never pruned.  A nonmatching body may still
decode because trigrams are only pruning evidence; exact substring and regex
verification is covered by `query_search_matcher` and the query execution
post-filter:

```console
cargo +nightly fuzz run query_search_physical --sanitizer none -- -runs=1000
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
