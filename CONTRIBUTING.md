# Contributing to Positron

Positron uses evidence-gated development. A review opinion supplements the
automated contracts; it never replaces a missing or failed gate.

## Prerequisites

- the exact stable Rust toolchain and targets in `rust-toolchain.toml`
- every PR-stage tool and exact version in
  `qualification/engineering/toolchains.tsv`
- Git

Run:

```console
cargo xtask setup
cargo xtask quality
```

`setup` configures this checkout to use `.githooks/`. It does not change global
Git configuration. The pre-commit hook runs the bounded fast profile; the
pre-push hook runs the complete PR profile. Hooks are convenience feedback.
Protected-branch CI is authoritative.

## Change discipline

Before editing code:

1. identify the semantic owner in `docs/application-design.md`;
2. identify every affected invariant and Qualification Cell;
3. decide whether the change alters caller knowledge, ownership, a durable
   format, compatibility, a non-waivable invariant, or Release 1 scope;
4. if it does, land the accepted superseding ADR and all corresponding
   contract, test, migration, and gate changes together; and
5. write the lowest-interface positive, boundary, negative, and adversarial
   tests that prove the behavior.

Application crates begin in a machine-enforced scaffold-only state. Activating
one requires an owner, explicit allowed dependency edges, risk gates, test
entry points, measured coverage and mutation baselines, and any required threat
model or format/API decision. The gate runner rejects application behavior in
an unactivated crate.

API schemas, integrations, generated SDKs, distribution surfaces, fuzz targets,
and model tests have the same protection through
`qualification/engineering/artifact-scopes.tsv`. Executable or product source
outside every registered scope fails the architecture gate.

## Dependencies

New dependencies are exceptional, not routine. Before adding one:

- record its necessity, owner, exact source and version, minimal feature set,
  license, maintenance and security assessment, and removal condition in
  `qualification/engineering/dependencies.tsv`;
- update `deny.toml` and Cargo Vet policy without weakening existing policy;
- use exact manifest versions and regenerate `Cargo.lock` intentionally; and
- run `cargo xtask quality`.

Wire, provider, SDK, and persistence types may not leak across their owning
module interfaces merely to avoid defining an invariant-bearing native type.

## Gate and policy changes

Gate, tool, threshold, corpus, target, fixture, workflow, owner, CODEOWNERS,
hook, and baseline changes are policy changes. They require a record under
`qualification/engineering/policy-changes/` describing detection gained and
lost, migration, old/new dual-run evidence, and approvals. A gate may not be
weakened in the same change to make a behavior change pass.

Temporary exceptions use the exact schema documented in
`qualification/engineering/exceptions/README.md`. Non-waivable properties,
evidence integrity, secret disclosure, and known correctness, durability,
isolation, safety, security, or authenticity failures have no exception path.

## Completion

A change is ready for review only when:

- formatting, compiler, Clippy, rustdoc, tests, architecture, dependency,
  policy, and secret gates pass;
- every selected dynamic gate has retained evidence;
- the worktree contains no generated drift or unexplained temporary marker;
- failures and negative evidence remain visible; and
- the pull request explains contracts, risks, tests, and operational impact.

Commit, push, publication, qualification, and release are separate actions.
Perform only the actions explicitly authorized for the task.
