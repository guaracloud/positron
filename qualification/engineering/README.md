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
| `scopes.tsv` | Module state, semantic owner, risk-gate activation, and atomic application-activation ledger |
| `artifact-scopes.tsv` | Non-Rust artifact roots held scaffold-only until their gates activate |
| `architecture-edges.tsv` | Complete allowed internal crate-edge set and its activation identity |
| `thresholds.tsv` | Measured ratchets, their evidence, and intentionally unresolved M0 baselines |
| `dependencies.tsv` | Mandatory review for each direct third-party dependency |
| `unsafe-allowlist.tsv` | Approved owned-unsafe boundaries; empty by default |
| `temporary-work.tsv` | Owner, issue, and expiry for temporary markers; empty by default |

The initial scaffold policy record is
`policy-changes/M0-INITIAL.json`. Later policy changes require their own
immutable record and old/new evidence; editing the initial record is invalid.

## Application activation ledger

An active application scope must declare one atomic ledger: its activation
identity and complete scope set, exact allowed edges, selected risk gates,
public test command, measured coverage and mutation baseline identities,
dependency review, and immutable contract-evidence record. Scaffold application
rows must leave every ledger field as `-`; tooling may not claim those fields.

`architecture-edges.tsv` records the same activation identity for every edge.
`thresholds.tsv` records a `measured-baseline` value and evidence path before
an activation can refer to it. This keeps a scope transition, its detector
baseline, and its policy record auditable as one change rather than as a
partially enabled state.
