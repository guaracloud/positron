# Active Segment and Durability Frontier Format v1

This document is the Release 1 byte-level authority for the files written by
the Storage Kernel Active Segment Ledger. The Catalog publishes segment
lifecycle metadata; these files carry canonical Signal Store blocks and their
authenticated local durability bound.

All integers are unsigned big-endian. Readers reject unknown versions,
trailing frontier bytes, invalid tags, impossible positions, duplicate active
metadata, symlinks, hard links, and non-regular files.

## Paths and identity

Each segment has a random nonzero 128-bit `segment_id`. Files are rooted below
the owned Primary Data Volume and opened relative to retained directories:

- `segments/active/<segment_id hex>.segment`
- `segments/active/<segment_id hex>.frontier`
- `segments/sealed/<segment_id hex>.segment`
- `segments/sealed/<segment_id hex>.frontier`

The immutable physical scope is `(tenant_id, signal_kind, virtual_shard_id)`.
One Catalog object records the scope, segment identity, lifecycle state, and
base Commit Position. At most one object per scope may be active. Catalog
Generations are the lifecycle authority; the header state records creation and
is not rewritten while sealing.

## Catalog segment metadata

| Bytes | Field | Value or limit |
| ---: | --- | --- |
| 8 | magic | ASCII `PSEGMET1` |
| 2 | version | `1` |
| 1 | state | `1` active, `2` sealed |
| 16 | tenant ID | nonzero domain identity |
| 1 | signal | `1` logs, `2` traces |
| 4 | virtual shard ID | valid nonzero shard |
| 16 | segment ID | random, nonzero |
| 8 | base Commit Position | predecessor frontier |

The encoding is exactly 56 bytes. Objects without this magic belong to another
Catalog authority and are ignored. Matching magic with invalid length,
version, or fields fails closed.

## Segment header

The segment starts with:

| Bytes | Field | Value or limit |
| ---: | --- | --- |
| 8 | magic | ASCII `PSEGACT1` |
| 2 | version | `1` |
| 64 | metadata | the encoding above |
| 4 | wrapped-key length | `1..=256` |
| variable | wrapped segment DEK | authenticated AES-KWP envelope |

Each physical segment receives a fresh 256-bit data-encryption key. The
caller-provided protection key wraps that DEK; it is not used for frame
encryption. The wrapped-key context binds the Positron instance, key kind,
segment object and key epoch, segment scope, tenant, signal, shard, and format
epoch. A wrong protection key or substituted context fails authentication.

The header is written once, synchronized, then made reachable by synchronizing
the active directory. A partial header is never usable.

## Store Block records

Immediately after the header, each canonical Store Block is encoded as:

| Bytes | Field | Value or limit |
| ---: | --- | --- |
| 4 | encrypted-frame length | at most 1,048,960 |
| variable | encrypted frame | existing encrypted-frame format |

Plaintext blocks are nonempty and at most 1,048,576 bytes. Frame context binds
the segment object, `StoreBlock` purpose, format and key epochs, and zero-based
sequence. Commit Position is `base_position + sequence + 1`. This sole ledger
authority owns allocation. Recovery never appends to the predecessor: it seals
it and creates a fresh successor with a fresh DEK, preventing nonce reuse.

Appending the same canonical Store Block is idempotent within the retained
ledger: it returns the existing position and does not append a duplicate.

## Durability Frontier

The frontier is a fixed 82-byte authenticated object:

| Bytes | Field | Value or limit |
| ---: | --- | --- |
| 8 | magic | ASCII `PFRONT01` |
| 2 | version | `1` |
| 16 | segment ID | matches path and header |
| 8 | durable segment bytes | header through last acknowledged frame |
| 8 | next sequence | acknowledged frame count |
| 8 | Commit Position | base plus next sequence |
| 32 | authenticator | HMAC under segment DEK over prior fields |

Acknowledgment is permitted only after this order completes:

1. write the complete length-prefixed encrypted frame;
2. synchronize the segment file;
3. write and synchronize a new temporary frontier;
4. rename it over the published frontier;
5. synchronize the frontier directory.

The receipt contains segment ID, Commit Position, and frontier authenticator.
Failure before mutation is retryable. Failure after segment mutation requires
reopen. Failure after frontier rename but before directory synchronization is
commit-ambiguous: no receipt is returned and reopen determines whether the
authenticated frontier became reachable.

## Recovery

Recovery authenticates the frontier before verifying the bounded segment
prefix it names. Every record length, sequence-derived context, encrypted-frame
tag, and Commit Position must agree.

- Missing or truncated bytes at or before the frontier are corruption.
- Authentication failure, including wrong-key recovery, fails closed.
- Bytes after the frontier are unacknowledged and may be truncated only while
  the Catalog still names the segment active.
- Sealed segments must match their frontier exactly.
- A crash between segment and frontier renames is reconciled by locating and
  authenticating the files independently, then completing the seal.
- A crash after physical seal but before Catalog publication is reconciled
  from the predecessor Catalog Generation and atomically republished with its
  fresh active successor.

Recovery and append require Resource Governor reservations. Cancellation is
observed before admission; admitted durability work runs to a typed terminal
outcome. Any post-write append failure poisons the live ledger so no retry can
reuse an AEAD sequence before recovery creates a fresh segment and DEK.

## Sealing

Sealing moves the unchanged segment and frontier from `active` to `sealed`,
synchronizes both directories, and publishes sealed Catalog metadata. It does
not copy, decrypt, re-encrypt, or rewrite acknowledged bytes. Every rename and
publication edge is idempotently recoverable.

## Bounds

- Store Block plaintext: 1,048,576 bytes.
- Encrypted frame: 1,048,960 bytes.
- Wrapped DEK: 256 bytes.
- Recovered blocks: 1,024, with at most 1,048,576 retained plaintext bytes.
- Catalog segment metadata inherits the Catalog's 1,024-object bound.
- Recovery memory and descriptor claims are explicit Resource Governor inputs;
  there is no unbounded scan or hidden retry loop.
