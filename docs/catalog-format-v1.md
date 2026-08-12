# Catalog durable format v1

This document is the canonical durable-format authority for the Release 1 Catalog implementation.
ADR-0069 remains the product decision; this file fixes the byte layouts, bounds, refusal rules,
and crash behavior implemented by `positron-kernel`.

## Layout and bounds

The Primary Data Volume contains descriptor-relative `catalog/objects`,
`catalog/governance-audit`, `catalog/commits`, `catalog/generations`, and `catalog/staging`
directories. Symlinks, non-regular files, hard-linked files, cross-device directories, empty
artifacts, and files beyond their type-specific maximum are refused.

A Catalog Proposal contains 1 through 1,024 distinct content-addressed objects, each at most
1,048,576 plaintext bytes and at most 16,777,216 plaintext bytes in total. An audit intent is 1
through 65,536 bytes. Retained encrypted commit and audit artifacts plus authenticated generation
markers share one 16,777,216-byte recoverability budget. At most 65,536 committed generations and
65,536 generation-directory entries are accepted; their names share an 8,388,608-byte scan budget.
Publication refuses a successor before artifact I/O if it would exceed either retained-history
bound. Recovery applies the identical limits while walking the chain; each individual read is
separately bounded and the reserved recovery claim covers the canonical worst case.

## Encrypted system-object envelope

Object, audit, and commit files use artifact format v3:

`magic[8] || version:u16 || kind:u8 || provider:u16 || wrapping-algorithm:u16 || provider-key-ref[16] || root-key-epoch:u64 || child-key-id[32] || child-key-epoch:u64 || envelope-context-sha256[32] || AES-256-KWP(Wrapped Key Payload)[136] || encrypted-frame-v1`

Every artifact has a fresh independent random 256-bit DEK. All entropy, SHA-256, HMAC-SHA-256,
AES-256-KWP, and AES-256-GCM operations pass through the single internal Crypto Backend. The
envelope context binds the instance, artifact kind, immutable content identity, child-key identity
and epoch, system scope and purpose, and Format Epoch. The wrapped plaintext is a deterministic,
versioned Protobuf Wrapped Key Payload containing the DEK and the same authoritative instance,
key kind, child-key ID and epoch, system scope, and context digest.
The plaintext routing fields must match the configured provider key reference and root-key epoch,
and the recomputed context digest must match before unwrap. The encrypted frame additionally binds
the kernel system-object kind, immutable object identity, DEK epoch 1, Format Epoch, purpose, and
frame sequence. Wrong context, provider reference, root epoch, envelope, frame checksum, or AEAD tag
fails closed. Root-key rotation unwraps, verifies, and rewraps only the 247-byte key-envelope header; encrypted
frame bytes remain unchanged.

The authenticated generation marker is exactly 82 bytes:

`magic[8] || version:u16 || generation-number:u64 || generation-id[32] || HMAC-SHA256[32]`

Its MAC uses the Catalog system key and a marker domain separator. A marker is published only under
the canonical pathname derived from the authenticated number and generation ID. A genuinely short
marker is an unpublished torn write. A complete marker with bad magic, unsupported version,
sentinel identity, bad MAC, trailing data, or mismatched pathname fences recovery.

## Publication, retry, and recovery

Catalog open first reserves the fixed worst-case recovery claim from the Resource Governor's
protected Repair pool. Commit reserves one joint Durability Completion claim for object, audit,
commit, marker, memory, item, I/O, descriptor, and disk costs before allocation or I/O. Admission
refusal is typed and releases no partial ownership. Reservations release on success, failure, retry,
and drop.

Publication writes and synchronizes immutable encrypted objects, then optional governance audit,
then the commit record, and finally renames and synchronizes the authenticated marker. Existing
artifacts are never acknowledged because a pathname exists: each is opened descriptor-relatively,
bounded, authenticated against its exact expected identity and context, synchronized as a named
file, and followed by its directory durability barrier on every retry. A retry after marker rename
revalidates and resynchronizes the complete generation before acknowledging it.

Recovery bounds the complete directory enumeration before classifying entries, verifies markers,
walks the exact predecessor chain, authenticates every retained commit/audit record, verifies audit
and transaction chains, and loads objects only for the latest committed generation. An absent or
only genuinely torn marker falls back to the last complete predecessor. Any published-artifact
corruption, unsupported complete format, ambiguity, substitution, or authentication failure fails
closed; no partially reconstructed generation becomes current.

## Compatibility and fault matrix

Artifact v3, frame v1, commit/audit codec v1, and marker v1 are the only accepted formats. A complete
unknown artifact or marker version is `UnsupportedFormat`; truncation and structural corruption are
`IntegrityCorruption`; key/context/tag failures are `AuthenticationFailed`; exhausted governor or
recoverability bounds are explicit admission/limit failures. Pre-marker write, file-sync, rename,
and directory-sync faults recover only the predecessor. A post-marker-rename directory-sync fault
recovers the complete successor but remains acknowledgement-ambiguous until a retry repeats all
durability barriers.
