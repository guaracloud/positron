# Temporary engineering exceptions

Non-waivable gates have no exception path.

An eligible exception is a new
`EXC-<year>-<sequence>.toml` file containing exactly these scalar keys:

```toml
schema_version = "1"
id = "EXC-2026-0001"
invariant = "DOC-04"
gate = "EG-DOCS"
scope = "exact/path"
artifact_or_target = "not-applicable"
failure_digest = "sha256:..."
evidence_digest = "sha256:..."
rationale = "Specific technical reason"
risk = "Specific bounded risk"
compensating_control = "Exact control"
compensating_evidence = "sha256:..."
owner = "Accountable role"
independent_approver = "Independent role"
tracking_issue = "https://github.com/guaracloud/positron/issues/..."
created_at = "2026-07-27T00:00:00Z"
expires_at = "2026-08-10T00:00:00Z"
removal_condition = "Exact condition"
signature = "verified-signature-identity"
```

The runner rejects missing or extra keys, wildcards, repository-wide scope,
post-hoc creation, author self-approval, unknown identities, non-waivable gates,
scope expansion, expiry beyond 14 days, or an expired record. It reports an
accepted exception as `exceptional`, never `passed`.

There is no editable renewal. A successor uses a new identity and the stricter
seven-day approvals in `docs/engineering/quality-gates.md`.
