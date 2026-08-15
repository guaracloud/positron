# Log Store Block Format v2

This document remains the byte-level authority for native Log Store Block
version 2. Version 2 extends, and does not reinterpret, the version 1 format in
[`log-store-block-format-v1.md`](log-store-block-format-v1.md). Readers retain
the complete version 1 contract. Current writers emit version 2; current
readers continue to accept versions 1 and 2.

The block envelope is unchanged except that its version field is `2`. All
version 1 bounds, byte order, rejection rules, record ordering, body encoding,
policy provenance, and scan behavior remain authoritative unless explicitly
extended below. Unknown versions and tags still fail closed.

Ingest Policy transformations use only the existing native value grammar:
removed values are absent, redacted values are native nulls, and truncated
values retain their bounded native prefix. Existing policy provenance stores
the activated policy generation, canonical content digest, and only the stable
IDs of rules whose actions applied. Audit and query code reconstruct the exact
actions from that immutable activated policy and provenance; no policy-only
value tag exists in this format.

## Record metadata extension

Version 2 inserts native Log metadata after observed time and before Ingest
Time. The fields are encoded in this order:

| Field | Encoding |
| --- | --- |
| severity number | signed big-endian `i32` |
| severity text | `u32 length || UTF-8 bytes` |
| event name | `u32 length || UTF-8 bytes` |
| trace ID | presence `0`, or `1 || 16 bytes` |
| span ID | presence `0`, or `1 || 8 bytes` |
| flags | big-endian `u32` |
| dropped attribute count | big-endian `u32` |
| resource dropped attribute count | big-endian `u32` |
| resource schema URL | `u32 length || UTF-8 bytes` |
| scope name | `u32 length || UTF-8 bytes` |
| scope version | `u32 length || UTF-8 bytes` |
| scope dropped attribute count | big-endian `u32` |
| scope schema URL | `u32 length || UTF-8 bytes` |

All strings participate in the version 1 record-byte bound. Presence tags
other than `0` and `1`, truncation, invalid UTF-8, and bound violations are
malformed blocks. A version 1 record has no bytes at this position and decodes
to explicit empty metadata.

## Stream attribute namespace

Version 2 extends the attribute namespace tag table with:

| Tag | Namespace |
| ---: | --- |
| `4` | stream |

Tags `1` through `3` keep their exact version 1 meanings. Tag `4` is invalid in
a version 1 block and cannot be silently reinterpreted by a new reader. The
version 2 format uses tag `4` only for the native Stream Attribute namespace.

## Schema Catalog and overflow

The Log Store owns a bounded Tenant Schema Catalog separately from Store Block
payloads. Its immutable Catalog Object uses the ASCII magic `PSCHEMA1` and
version `1`, followed by the tenant identity, entry/memory/persistent-byte/
index-byte budgets, overflow record and byte counters, and deterministic
namespace-qualified path entries. Each entry preserves observed typed
variants, observation and conflict counts, query-use count, promotion state,
index bytes, and canonical bounded per-block typed dictionaries. A bounded
`REPLAY1` trailer records one canonical authenticated replay frontier per
shard. The allocation-free reader preflight accounts catalog entries, physical
index paths, and frontier vector storage before construction. Each physical
dictionary is keyed by the exact Store Block identity and authenticated payload
digest, and its paths and type masks must match promoted catalog members. A
query may prune only when all of those facts match; missing, stale,
unreachable, replacement, or demoted coverage falls back to the authoritative
v2 value and reports reduced pruning. These sidecars do not add a Store Block
tag or version. The object is
content-addressed and published only through
the Storage Kernel Catalog Writer with the generation precondition and typed
governance evidence required by ADR-0069. It is rebuildable optimization state,
published only after bootstrap replay before Serving or during graceful
shutdown after ingest drains. A process crash leaves version 2 blocks as the
authoritative replay source and does not require a new block version or tag.

Discovery spends bounded work and admits an entry only when every applicable
catalog and index budget remains available. A valid attribute that cannot be
admitted is encoded with the existing physical representation tag `2` as
Schema Overflow. Its namespace, key, ordered occurrences, and complete native
values remain unchanged; overflow updates only bounded evidence and never
allocates catalog, statistics, dictionary, or automatic-index state. Generic
and overflow records therefore have identical logical scan and typed-query
semantics, while overflow scans report reduced pruning. Promoted scalar paths
carry a canonical typed-variant dictionary whose entry, per-block
identity/digest framing, path, and type-mask bytes all consume the same checked
index and persistent budgets. Observation or governed query-use evidence may
promote a path; removing query evidence or reconciling unreachable blocks
removes the corresponding physical coverage without altering logical state.
Dictionary budget exhaustion overflows the complete attribute root atomically.
Verified coverage can reject an impossible type before value traversal; exact
value comparison, ordered nested duplicates, and explicit `index`, `any`, and
`all` selection still use the source-of-truth record values with no coercion.
This format defines the bounded immutable discovery snapshot, not a public
administration operation or pagination authority. Tenant-administrator
exposure is owned by tickets #69 through #71 and uses the recoverable Durable
Operation authority from ticket #73; no schema-local cursor or operation record
is stored in `PSCHEMA1`.
