# Log Store Block Format v2

This document is the byte-level authority for the current native Log Store
Block. Version 2 extends, and does not reinterpret, the version 1 format in
[`log-store-block-format-v1.md`](log-store-block-format-v1.md). Readers retain
the complete version 1 contract; writers emit version 2.

The block envelope is unchanged except that its version field is `2`. All
version 1 bounds, byte order, rejection rules, record ordering, body encoding,
policy provenance, and scan behavior remain authoritative unless explicitly
extended below. Unknown versions and tags still fail closed.

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
version 2 writer uses tag `4` only for the native Stream Attribute namespace.
