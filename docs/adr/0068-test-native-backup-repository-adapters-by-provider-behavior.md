# Test native Backup Repository adapters by provider behavior

Release 1 implements Rust Repository Adapters for local filesystem, AWS S3,
explicitly supported S3-compatible products, Google Cloud Storage, and Azure
Blob Storage. Each Repository target names the exact service or product and
tested context. Writable providers must support immutable put-if-absent
objects, authoritative metadata, bounded range reads, checksums, resumable
upload, conditional registry-head compare-and-swap, observable deletion, and
bounded retry classification; listing is never a correctness primitive.
Initialization writes an immutable Repository Identity only into an explicitly
empty prefix and attaching existing contents requires exact verification.
Credentials use native identity or protected references, all external
transport requires verified TLS, and Positron encrypts before upload. Provider
versioning, retention, legal hold, and WORM are surfaced because retained key
envelopes keep Tenant Purge pending, while uncoordinated lifecycle deletion is
unsupported. Integration and fuzz tests cover provider failure and recovery
behavior. Repository Adapters remain backup-only and never become Release 1
primary storage.
