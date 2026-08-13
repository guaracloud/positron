# Active Segment and Durability Frontier Format v2

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

Format v2 replaces the rejected plaintext-metadata v1 bootstrap. The segment
starts with only the fields needed to select the format and recover the DEK:

| Bytes | Field | Value or limit |
| ---: | --- | --- |
| 8 | magic | ASCII `PSEGACT2` |
| 2 | version | `1` |
| 2 | frame algorithm | `1`, AES-256-GCM |
| 2 | wrapping algorithm | `1`, AES-256-KWP |
| 16 | provider key reference | opaque, nonzero |
| 8 | provider key epoch | nonzero |
| 4 | wrapped-key length | `1..=256` |
| variable | wrapped segment DEK | authenticated AES-KWP envelope |
| 4 | encrypted-metadata-frame length | `1..=256` |
| variable | encrypted segment metadata | AES-256-GCM frame over the exact 56-byte Catalog encoding above |

Each physical segment receives a fresh 256-bit data-encryption key. The
caller-provided protection key wraps that DEK; it is not used for frame
encryption. The opaque provider reference and epoch must match the supplied
recovery capability before unwrap. The wrapped-key context binds the Positron instance, key kind,
segment object and key epoch, segment scope, tenant, signal, shard, and format
epoch. The encrypted metadata independently binds scope, segment identity,
creation lifecycle, and base Commit Position. A wrong protection key,
substituted route, or substituted context fails authentication.

The header is written once, synchronized, then made reachable by synchronizing
the active directory. A partial header is never usable.

## Store Block records

Immediately after the header, each canonical Store Block is encoded as:

| Bytes | Field | Value or limit |
| ---: | --- | --- |
| 4 | encrypted-frame length | at most 1,048,960 |
| variable | encrypted frame | existing encrypted-frame format; plaintext is the 16-byte stable Store Block identity followed by canonical block bytes |

Plaintext blocks are nonempty and at most 1,048,576 bytes. Frame context binds
the segment object, `StoreBlock` purpose, format and key epochs, and the
one-based frame sequence reserved after metadata sequence zero. Commit Position
is `base_position + frame_sequence`. This sole ledger
authority owns allocation. Recovery never appends to the predecessor: it seals
it and creates a fresh successor with a fresh DEK, preventing nonce reuse.

Retrying the same stable Store Block identity with the same canonical bytes is
idempotent within the retained ledger. Reusing an identity with different
bytes fails closed. Equal canonical bytes under distinct identities are
legitimate separate appends.

## Durability Frontier

Format v2 encrypts frontier metadata as one independent frame:

| Bytes | Field | Value or limit |
| ---: | --- | --- |
| 8 | magic | ASCII `PFRONT02` |
| 2 | version | `1` |
| 2 | frame algorithm | `1`, AES-256-GCM |
| 4 | encrypted-frame length | at most 512 |
| variable | encrypted frontier frame | plaintext is `durable_bytes:u64 || next_sequence:u64 || commit_position:u64` |

The frontier frame purpose is `DurabilityFrontier`; its nonce sequence is
`u64::MAX - encrypted_next_sequence`, disjoint from metadata and Store Block
sequences. Recovery tries only the bounded Release 1 sequence
domain and requires the authenticated plaintext to agree with the successful
sequence. No segment identity, Commit Position, or sequence is plaintext in
the frontier artifact. The receipt authenticator is an HMAC of the complete
encoded encrypted frontier and is not persisted as additional plaintext.

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

## Migration policy

There is no released v1 data contract to migrate. Readers explicitly refuse
the old `PSEGACT1` and `PFRONT01` plaintext-metadata formats as unsupported;
they do not guess, partially import, or silently rewrite them. A future
released-format migration requires an accepted ADR and an explicit bounded
migration path.

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
