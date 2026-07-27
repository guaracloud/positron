# Instructions for AI agents

These instructions apply to the entire repository.

## Authority and boundaries

Read, in order, the relevant parts of:

1. `project-positron.md`
2. `CONTEXT.md`
3. accepted files under `docs/adr/`
4. `docs/release-1-qualification.md`
5. `docs/application-design.md`
6. `docs/engineering/standards.md`
7. `docs/engineering/quality-gates.md`

Do not reinterpret a stronger contract through a weaker document. Do not code
the application while its crate remains `scaffold` in
`qualification/engineering/scopes.tsv`. The scaffold gate intentionally
rejects hidden behavior, speculative feature flags, placeholder APIs, and
disabled deferred signals or clustering.

Non-Rust product surfaces are independently locked in
`qualification/engineering/artifact-scopes.tsv`. Do not place code, schemas,
generators, scripts, SDK sources, fuzz targets, models, integration code, or
distribution behavior outside a registered and activated scope.

## Required workflow

- Preserve one semantic owner and the acyclic crate graph in
  `qualification/engineering/architecture-edges.tsv`.
- Use Rust 2024, resolver 3, the exact pinned toolchain, locked resolution, and
  inherited workspace lints.
- Add no dependency without the complete review record required by
  `CONTRIBUTING.md`.
- Add no unsafe code outside a separately approved, allowlisted boundary with
  its safety case and required detector evidence.
- Do not use panics, unwrap/expect, unchecked indexing, ignored results,
  string-driven control flow, detached tasks, unbounded queues, ambient
  authority, or hidden best-effort behavior in production paths.
- Keep generated files generated. Never edit generated output by hand.
- Begin reproducible defect fixes with a failing regression test. Test returned
  outcomes or externally readable behavior, not private implementation shape.
- Run `cargo xtask quality`. Do not substitute ad hoc commands for the
  authoritative runner.

## Policy protection

Never weaken, skip, delete, rename, path-filter, or silently reclassify a gate,
lint, test, threshold, target, corpus, fixture, hook, workflow, owner, or
evidence field to make a change pass. Policy changes require the committed
record and approvals described in `CONTRIBUTING.md`. A timeout, cancellation,
missing tool, stale result, retry-to-green, or ignored test is a failure.

Do not fabricate `Qualified` or merge-eligible evidence. Local and dirty-tree
evidence is diagnostic only. Do not erase a failed attempt after a later pass.

Commit, push, pull request, tag, publish, deploy, and release actions each
require explicit user authorization.
