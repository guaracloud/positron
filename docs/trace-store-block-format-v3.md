# Trace Store Block Format v3

This document is the byte-level authority for the marker-bearing native Trace
Store Block. Version 3 extends the historical v1/v2 contract in
[`trace-store-block-format-v1.md`](trace-store-block-format-v1.md). It keeps
the envelope, observation fields, version-2 native OTLP detail section,
policy-provenance placement, bounds, and scan order unchanged. Trace Store
writers emit version 3 for all new blocks. Readers retain v1 and v2 and reject
the marker value tag in those versions; version 3 readers accept native tags
`0..=7` plus marker tag `8`.

The block envelope remains `PTRCBL01 || version:u16 || tenant[16] ||
observation_count:u16 || observations`, with version `3`. Version 3 retains
the v2 detail section before policy provenance. Every native value position in
a v3 observation uses the grammar below: Resource, Instrumentation Scope, and
Record/Span attribute occurrences, plus typed occurrences in span events and
links, recursively through arrays and ordered key/value lists. The Log-only
Stream namespace remains invalid for Trace Store blocks.

## Source time encoding

Start, end, and detail-event source times retain the historical quality-byte
encoding. Tags `1..=5` mean usable, missing, zero, outlier, and contradictory;
tags other than `2` are followed by the exact signed `i64` Unix-nanoseconds
value. Version 3 additionally defines tag `6` as an exact unsigned `u64`
source timestamp greater than `i64::MAX`; it is followed by that eight-byte
value and has `Outlier` quality with no usable native instant. Query Time falls
back to Ingest Time for this representation while the original source value
remains available to durable reads. Historical v1/v2 readers and bytes retain
their prior time meanings and reject tag `6` as malformed; no old field is
reinterpreted.

## Native value grammar

Tags `0..=7` retain the exact v1/v2 meanings: null, boolean, signed integer,
floating-point bits, string, bytes, array, and ordered key/value list. Tag `8`
is reserved for a policy transformation marker and is invalid in v1 and v2.

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

`original_kind` uses native-kind tags `0..=7`; `8` and unknown values are
invalid. Removed and Redacted are exactly three bytes and retain no source
payload. A truncation marker is three marker bytes followed by exactly one
ordinary encoded child whose effective native kind equals `original_kind`. A
child that is itself a marker or truncation wrapper, an action/kind pair
outside the table, a mismatched child kind, or trailing marker payload is
malformed. Marker leaves contained inside an Array or key/value-list sanitized
child are valid; the immediate wrapped child remains an ordinary same-kind
root value, while marker leaves nested within that retained collection preserve
their own policy evidence.

All marker metadata and retained collection slots participate in the existing
bounded block, observation, decoded-memory, and reservation accounting. A
payload-free marker contributes zero semantic decoded payload bytes; a
truncation marker contributes the sanitized child's semantic decoded bytes.
Source paths, occurrence or array slots, duplicate order and count, and marker
leaves remain visible through existing internal projections. Payload-free
Removed and Redacted marker leaves have no descendants. No removed or redacted
source bytes, value, length, hash, or rendering is retained. Truncation exposes
only the sanitized same-kind native child and its action evidence.

Ordinary scalar, Null, native-kind, and original-kind predicates never match a
marker. `any` and `all` treat a marker as nonmatching, while `index` retains
the occurrence ordinal. Truncation uses normal same-kind typed comparison and
projection over its sanitized child. Marker-only paths do not infer schema
scalar types or scalar dictionaries; any unsafe coverage falls back to the
authoritative scan. This value extension does not alter the v1/v2 Trace Store
fields or add a public query syntax or endpoint.

## Compatibility

The v1 and v2 Trace Store contracts remain readable and retain native tags
`0..=7` with their prior meanings. Version 3 is the only writer format for
marker-bearing blocks. Unknown versions and tags, malformed action/kind pairs,
invalid UTF-8, truncation, bound violations, and trailing bytes fail closed.
The marker is an internal policy result, not a producer value or a null
sentinel; only the shared Ingest Policy transition may create one.
