# Log Store Block Format v1

This document is the byte-level authority for the minimal M1 native Log Store
Block. The Log Signal Store prepares these canonical bytes; the Storage Kernel
wraps them in the authenticated Store Block record defined by
[`active-segment-format-v1.md`](active-segment-format-v1.md). The kernel remains
the sole owner of checksumming, encryption, durability, physical segment
scope, and publication.

All integers are big-endian. Readers reject unknown versions and tags,
truncation, trailing bytes, invalid UTF-8, invalid native time annotations,
zero records, and any declared bound that exceeds the limits below before
allocating or observing a logical record.

## Block envelope

| Bytes | Field | Value |
| ---: | --- | --- |
| 8 | magic | ASCII `PLOGBL01` |
| 2 | version | `1` |
| 16 | Tenant ID | exact nonzero physical tenant |
| 2 | record count | `1..=1024` |
| variable | records | record layout below |

The embedded Tenant ID is defense in depth. A scan first requires an
authenticated kernel snapshot whose physical scope is the same tenant and
`Logs`; the decoder then requires the embedded ID to agree. Trace snapshots
and another tenant's snapshots never reach Log decoding.

## Record

| Bytes | Field | Encoding |
| ---: | --- | --- |
| 1 | Event Time quality | `1` usable, `2` missing, `3` zero, `4` outlier, `5` contradictory |
| 0 or 8 | Event Time | absent only for quality `2`; otherwise exact signed Unix nanoseconds |
| 1 | observed-time presence | `0` absent, `1` present |
| 0 or 9 | observed time | quality tag plus exact signed Unix nanoseconds |
| 8 | Ingest Time | exact signed Unix nanoseconds assigned by the Storage Kernel |
| 1 | body presence | `0` absent, `1` present |
| variable | body | one native value when present |
| 2 | attribute-set count | `0..=1024` |
| variable | attribute sets | ordered layout below |
| 8 | policy generation | nonzero |
| 32 | policy digest | nonzero exact digest |
| 2 | applied-rule count | `0..=64` |
| variable | applied rule IDs | each `u32 length || UTF-8 bytes`, `1..=256` bytes |

Missing and present-empty bodies are different encodings. Retention and
physical lifecycle use the stored Ingest Time; source Event and observed time
remain exact query inputs and cannot change lifecycle age.

## Attribute occurrence set

| Bytes | Field | Encoding |
| ---: | --- | --- |
| 1 | physical representation | `1` generic, `2` Schema Overflow |
| 1 | namespace | `1` resource, `2` instrumentation scope, `3` record |
| variable | key | `u32 length || UTF-8 bytes`, `1..=65536` bytes |
| 2 | occurrence count | `1..=1024` |
| variable | values | native values in source order |

Repeated keys and values remain ordered. Generic and Schema Overflow are
physical placements with the same logical equality and scan result; the
overflow marker remains observable as bounded evidence. M1 defines no
promoted or demoted representation.

## Native value

| Tag | Value | Payload |
| ---: | --- | --- |
| `0` | null | none |
| `1` | boolean | one byte, `0` or `1` |
| `2` | signed integer | exact `i64` |
| `3` | floating point | exact IEEE 754 `u64` bits |
| `4` | string | `u32 length || UTF-8 bytes` |
| `5` | bytes | `u32 length || opaque bytes` |
| `6` | array | `u16 count || ordered native values` |
| `7` | key/value list | `u16 count || (u32 key length || UTF-8 key || native value)*` |

Individual strings, bytes, and keys are at most 65,536 bytes. Arrays and
key/value lists contain at most 1,024 entries and nest at most 16 levels.
Duplicate key/value-list keys remain ordered. Numeric and textual kinds are
never coerced.

## Scan and deferred behavior

M1 scan is a logical full scan over authenticated committed blocks from one
bounded kernel snapshot. The caller supplies a nonzero result limit of at most
1,024 records; reaching it with remaining records returns an explicitly
incomplete result. Active, recovered, sealed, and sealed-plus-active ledger
states expose the same logical order.

Complete scalar indexing, full-text search, pruning, retention execution,
compaction, Attribute Promotion, and demotion remain M2 work. M1 introduces no
placeholder index, alternate durable representation, or Signal Store-owned
durability authority.
