# Engineering gate registries

These registries are authoritative inputs to `cargo xtask quality`.

Tab-separated registries use UTF-8, one header row, no quoted fields, no
embedded tabs, and `|` for a list within a field. Lines beginning with `#` are
comments. The runner rejects missing fields, duplicate identities, unknown
references, drift from the binding standards, and application behavior inside
a scaffold-only scope.

| Registry | Purpose |
| --- | --- |
| `gates.tsv` | Gate stages, coordinator, budgets, exception class, activation, and runner |
| `invariants.tsv` | Exactly one gate and accountable owner for every engineering invariant |
| `owners.tsv` | Functional owner roles and bootstrap CODEOWNER identity |
| `toolchains.tsv` | Exact production and detector tool identities |
| `scopes.tsv` | Module state, semantic owner, and risk-gate activation |
| `artifact-scopes.tsv` | Non-Rust artifact roots held scaffold-only until their gates activate |
| `architecture-edges.tsv` | Complete allowed internal crate-edge set |
| `thresholds.tsv` | Measured ratchets and intentionally unresolved M0 baselines |
| `dependencies.tsv` | Mandatory review for each direct third-party dependency |
| `unsafe-allowlist.tsv` | Approved owned-unsafe boundaries; empty by default |
| `temporary-work.tsv` | Owner, issue, and expiry for temporary markers; empty by default |

The initial scaffold policy record is
`policy-changes/M0-INITIAL.json`. Later policy changes require their own
immutable record and old/new evidence; editing the initial record is invalid.
