# Durable export output format v1

The Storage Kernel owns the complete durable export payload surface. Query and
Governance receive an opaque output identity and typed receipts; they never
receive a Primary Data Volume path, directory handle, encryption key, frame,
or mutable output-file capability.

## Binding and bounds

One fixed-size `POSEXP04` Catalog Object binds an output identity to the
accepted durable Operation ID, Tenant ID, configured destination identity,
request digest, Query Snapshot identity/generation/frontier, Snapshot Lease
identity, and lease start/expiry. The output identity is domain-derived from
that accepted Operation ID alone. A caller idempotency key therefore recovers
the same operation and output, while a distinct accepted operation gets a
distinct output even when its query and destination are identical.
It also records only the next sequence, retained protected-byte total, last Query
Result Batch digest, an optional terminal-evidence digest, and an optional
terminal-manifest digest. The descriptor contains no batch payload,
continuation cursor, terminal evidence, or terminal manifest bytes. `POSEXP03`
descriptors remain readable as pre-terminal-evidence records; they cannot infer
a terminal outcome from an absent cursor.

Before the descriptor becomes visible, the Kernel synchronizes one separately
encrypted `initial` artifact containing the complete original binding and the
authenticated Query Cursor that starts its snapshot. It uses a distinct Export
Output frame context and the same 8,192-byte cursor ceiling. Recovery addresses
this artifact by the accepted Operation ID, authenticates its Tenant,
destination, and request-digest binding, rejects expiry or tampering, and then
publishes the original descriptor. It never derives a replacement snapshot,
lease, cursor, or output identity from a later clock or Catalog generation.
An exact creation retry accepts only the same binding and cursor. This keeps an
interrupted first-batch export resumable against its original snapshot after
the Catalog advances without placing cursor bytes in the fixed descriptor.

The binding rejects sentinel identities and leases longer than the Release 1
hard 3,600-second ceiling. Each output permits at most 1,024 batches, one
1,048,576-byte canonical batch, one 8,192-byte opaque continuation cursor,
and 1,073,741,824 protected bytes. Batch append reserves tenant
`InteractiveQueryTail` memory, task, I/O, file-descriptor, and disk-headroom
capacity before Query serializes, reads, decrypts, or mutates the output. The
reservation covers canonical bytes and one bounded encrypted/plaintext record
scan; ordinary append uses descriptor-retained payload length and reads only a
possible one-record unpublished tail. Reopen and read paths stream-authenticate
every record with the same bounded working set.

## Payload layout and publication

Payload lives at the kernel-private descriptor-relative location
`exports/<output-identity-hex>/payload`. Every lookup opens components with
no-follow directory descriptors and validates the payload is a single-linked
regular file. This location is an implementation-owned layout, never an API
or configuration value.

The payload is append-only. Each record is `u32 encrypted_length || encrypted
artifact`. The encrypted plaintext is:

```text
POEXBAT1 || sequence:u64 || result_batch_digest:[u8;32] ||
continuation_cursor_length:u16 || canonical_batch_length:u32 ||
continuation_cursor || canonical_batch
```

Each artifact is an independently authenticated encrypted frame using the
Export Output system-object kind. Its envelope and frame context bind the
output identity and expected sequence; a substituted, truncated, malformed,
or wrong-key record fails closed before the bytes are returned.

For a first append, the Kernel writes the length and encrypted record, syncs
the payload, then publishes the fixed successor Catalog descriptor. A crash
after payload sync but before descriptor publication leaves at most one extra
fully authenticated record. Reopening scans and authenticates every record;
retrying that sequence with identical digest, canonical bytes, and opaque
cursor publishes that record's fixed successor descriptor and returns its
original receipt exactly once. Until then, the committed checkpoint remains
the descriptor's `next_sequence - 1` record; an empty descriptor has no
checkpoint even when the first record is an orphan. A changed replay fails
with an idempotency conflict. A descriptor that claims data absent from the
payload, or whose recorded last digest differs from the authenticated record, is
integrity corruption.

The result-batch and continuation cursor bytes remain encrypted in the payload
object. The Catalog remains bounded progress metadata and does not rewrite
prior output batches when a successor is published.

Before publishing a final Result Batch descriptor, Query supplies one bounded
opaque terminal-evidence record containing its exact Complete or Incomplete
truth, Result Digest, cumulative Query Budget, and resume statistics. Kernel
encrypts and synchronizes it at the sibling
`exports/<output-identity-hex>/terminal`, then publishes its digest with that
final batch descriptor. An empty export uses the same artifact and descriptor
publication without a batch. The artifact is Query-owned: Kernel only bounds,
protects, and binds it. A restart reads evidence only when the descriptor names
its digest, reconstructs the signed manifest without re-executing the Query
Snapshot, and then performs the normal idempotent terminal operation
transition. An orphaned terminal artifact is never terminal truth.

## Terminal manifest

Query creates the bounded terminal-manifest bytes and authenticates its own
wire contract. The Kernel persists those opaque bytes at the sibling
`exports/<output-identity-hex>/manifest` as one independently authenticated
Export Output artifact. Its plaintext is `POEXMAN1 || manifest_length:u32 ||
manifest`, and its frame context binds the output identity. A `write_manifest`
accepts at most 42,496 bytes, creates the sibling once, syncs it, then publishes
only its SHA-256 digest in the descriptor. Exact ambiguous retries succeed;
different bytes are an idempotency conflict. `read_manifest` returns bytes only
after the digest-bearing descriptor was published and verifies both the frame
and digest, so an orphan from an interrupted write is never treated as a
terminal result.

The kernel-owned `ExportManifestSigner` opens the existing wrapped Instance
Integrity Key into an export-only, domain-separated Ed25519 signing capability.
It signs at most 42,496 canonical manifest bytes under
`positron-query-export-manifest-signature-v1`. Verification always takes an
externally pinned `BootstrapIntegrityIdentity` from the accepted governance
key history. The identity carried in a receipt is checked against that expected
key and fingerprint; it never self-authorizes a manifest. The signer reuses the
existing IKI custody and rotation history and neither exposes its seed nor
broadens `AuditCheckpointSigner` into a generic signing capability.

`cargo fuzz run export_output_record` exercises the bounded descriptor, initial
preparation, and plaintext-record decoders. `encrypted_frame_open` independently exercises the
shared protected-frame parser and authentication boundary used by every output
record.
