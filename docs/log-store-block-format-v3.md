# Log Store Block Format v3

This document is the byte-level authority for the marker-bearing native Log
Store Block. Version 3 extends [`log-store-block-format-v2.md`](log-store-block-format-v2.md)
without changing its envelope, record field order, metadata extension, stream
namespace, policy provenance, bounds, or scan order. Log Store writers emit
version 3 for all new blocks. Readers retain versions 1 and 2 and reject the
marker value tag in those versions; version 3 readers accept native tags
`0..=7` plus marker tag `8`.

The block envelope remains `PLOGBL01 || version:u16 || tenant[16] ||
record_count:u16 || records`, with version `3` and the v2 record layout. Every
native value position in a v3 record uses the grammar below: the body, every
attribute occurrence, and every recursively nested array or key/value-list
value. Version 1 and version 2 bytes are never reinterpreted as version 3.

## Native value grammar

Tags `0..=7` retain the exact v1/v2 meanings from
[`log-store-block-format-v1.md`](log-store-block-format-v1.md): null, boolean,
signed integer, floating-point bits, string, bytes, array, and ordered
key/value list. Tag `8` is reserved for a policy transformation marker and is
invalid in v1 and v2.

The tag-8 payload is:

```text
tag:8 || action:u8 || original_kind:u8 [|| sanitized_value]
```

The action values are:

| Value | Action | Valid original kind | Payload |
| ---: | --- | --- | --- |
| `0` | Removed | any native kind `0..=7` | none |
| `1` | Redacted | any native kind `0..=7` | none |
| `2` | TruncatedBytes | String `4` or Bytes `5` | one ordinary same-kind value |
| `3` | TruncatedElements | Array `6` or key/value list `7` | one ordinary same-kind value |

`original_kind` uses the existing native-kind tags `0..=7`; `8` and unknown
values are invalid. Removed and Redacted are exactly three bytes and retain no
source payload. A truncation marker is three marker bytes followed by exactly
one ordinary encoded child whose effective native kind equals
`original_kind`. A child that is itself a marker or truncation wrapper, an
action/kind pair outside the table, a mismatched child kind, or trailing marker
payload is malformed. Marker leaves contained inside an Array or key/value-list
sanitized child are valid; the immediate wrapped child remains an ordinary
same-kind root value, while marker leaves nested within that retained collection
preserve their own policy evidence.

All marker metadata and retained collection slots participate in the existing
bounded record, value, decoded-memory, and reservation accounting. A
payload-free marker contributes zero semantic decoded payload bytes; a
truncation marker contributes the sanitized child's semantic decoded bytes.
The source path, occurrence or array slot, duplicate order and count, and
marker leaf remain visible through existing internal projections. Payload-free
Removed and Redacted marker leaves have no descendants. No removed or redacted
source bytes, value, length, hash, or rendering is retained. Truncation exposes
only the sanitized same-kind native child and its action evidence.

Ordinary scalar, Null, native-kind, and original-kind predicates never match a
marker. `any` and `all` treat a marker as nonmatching, while `index` retains
the occurrence ordinal. Truncation uses normal same-kind typed comparison and
projection over its sanitized child. Marker-only paths do not infer schema
scalar types or scalar dictionaries; unsafe physical coverage falls back to
the authoritative generic scan. This value extension does not change
`PSCHEMA1`'s format version or add a public query syntax or endpoint.

## Compatibility

The v1 and v2 Log Store contracts remain readable and retain native tags
`0..=7` with their prior meanings. Version 3 is the only writer format for
marker-bearing blocks. Unknown versions and tags, malformed action/kind pairs,
invalid UTF-8, truncation, bound violations, and trailing bytes fail closed.
The marker is an internal policy result, not a producer value or a null
sentinel; only the shared Ingest Policy transition may create one.
