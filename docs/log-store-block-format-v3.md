# Log Store Block Format v3

This document is the byte-level authority for the current native Log Store
Block. Version 3 extends, and does not reinterpret, version 2 in
[`log-store-block-format-v2.md`](log-store-block-format-v2.md). The block
envelope is unchanged except that its version field is `3`. Current writers
emit version 3. Current readers accept versions 1, 2, and 3; readers that do
not recognize version 3 reject it at the version field before observing a
logical record.

All version 1 and version 2 bounds, byte order, record ordering, metadata,
Stream Attribute namespace, policy provenance, and scan behavior remain
authoritative unless explicitly extended below. Unknown versions and tags,
truncation, trailing bytes, and bound violations fail closed.

## Policy transformation evidence

Version 3 extends the native value tag table with typed Ingest Policy evidence:

| Tag | Value | Payload |
| ---: | --- | --- |
| `8` | removed | none |
| `9` | redacted | none |
| `10` | truncated | one retained native value |

The removed and redacted values contain no producer content. They are typed
values rather than strings, nulls, or omitted bytes, so a scan cannot confuse
policy evidence with producer data. A truncated value retains the prefix and
native kind produced by policy. Its nested native value uses the same tag
table and consumes one level of the 16-level nesting budget. Recursive or
malformed wrappers beyond that budget are rejected.

Tags `0` through `7` keep their exact version 1 meanings. Tags `8` through
`10` are invalid in version 1 and version 2 blocks. A writer never uses a
version 3 tag while claiming an older version.

## Deterministic policy provenance

The policy provenance fields keep the version 1 encoding and bounds. For every
accepted record, the writer stores exactly one nonzero policy generation, its
nonzero 32-byte digest, and the source-ordered IDs of rules whose action
actually applied. A terminal Accept is applied and recorded. A terminal Reject
does not produce a stored record. Rules that did not match, transformations
that did not change their target, and rules after a terminal action are not
recorded.

Policy evidence and provenance are part of the canonical Store Block bytes and
therefore remain covered by the Storage Kernel checksum, encryption,
durability, replay, and physical-scope checks. Reopen and recovery do not
re-evaluate policy or reconstruct provenance from current configuration.
