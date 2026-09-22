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
embedded in an export. Release 1's durable-export verifier pins the current
authenticated Catalog Governance identity and rejects an unknown predecessor
or any arbitrary embedded identity. Rewrapping the same key preserves that
identity and supports ordinary restart verification. ADR-0040 continues to
require authorized integrity-key rotation history for its control-state
artifacts; accepting historical integrity identities for query-export
verification remains a full-release integration requirement once canonical
Governance exposes that history to this verifier. The signed manifest is encrypted in the
kernel-owned output alongside bounded append-only batches; a MAC may protect
internal custody metadata but does not replace the signature.

This extends ADR-0040 for the specific durable Query export artifact and
extends ADR-0066's signed-export requirement. It adds no new key store,
rotation history, audit authority, or public key distribution mechanism.
