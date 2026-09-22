# Sign durable Query export manifests with the Instance Integrity Key

Durable Query export manifests are signed with a narrow, domain-separated
Ed25519 capability opened by kernel key custody from the wrapped Instance
Integrity Key. The capability signs only the canonical bounded export-manifest
payload, which binds the tenant-protected output identity, destination,
request digest, Query Snapshot, ordered batch digests, terminal status, and
Result Digest. It does not reuse the Governance Audit checkpoint signer or
create a generic application signing API.

Verification requires a caller-supplied, bootstrap-pinned Instance Integrity
identity (public key and fingerprint), rather than trusting a public key
embedded in an export. Existing authorized integrity-key rotation history
continues to determine valid successor identities, and rewrapping the same
key preserves its identity. The signed manifest is encrypted in the
kernel-owned output alongside bounded append-only batches; a MAC may protect
internal custody metadata but does not replace the signature.

This extends ADR-0040 for the specific durable Query export artifact and
extends ADR-0066's signed-export requirement. It adds no new key store,
rotation history, audit authority, or public key distribution mechanism.
