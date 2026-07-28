# Positron

Positron is an observability database for native Logs and Traces. This
repository is currently an **engineering scaffold only**: its Rust application
crates intentionally contain no product behavior.

The frozen product contract lives in [project-positron.md](project-positron.md),
the binding language in [CONTEXT.md](CONTEXT.md), the accepted decisions in
[docs/adr](docs/adr), and the whole-application shape in
[docs/application-design.md](docs/application-design.md). Engineering changes
must satisfy [the standards](docs/engineering/standards.md) through
[the quality gates](docs/engineering/quality-gates.md).

## Start here

1. Install the exact `pr` profile tools listed in
   `qualification/engineering/toolchains.tsv`.
2. Run `cargo xtask setup` once to install the repository-managed Git hooks.
3. Run `cargo xtask quality` before requesting review.

The quality runner produces local evidence under `target/quality/evidence/`.
Local evidence is deliberately marked ineligible for merge; trusted CI evidence
is bound to the pull-request or merge-group revision.

The normal development path is intentionally lightweight: pre-commit runs
fast structural checks, while pre-push and pull-request CI run the host build,
formatting, lints, tests, docs, current-tree secret scan, dependency policy,
and advisory scan. Cross-target builds, coverage, full-history secret scans,
and Cargo Vet run in the scheduled extended profile rather than on every push.

## Scaffold boundary

The foundational domain, API, and configuration boundaries are active but
still contain no product behavior. Every other application crate remains
registered as `scaffold` in `qualification/engineering/scopes.tsv`. The
architecture gate permits only crate documentation, inherited policy, and the
empty composition-root entry point for a scaffold scope. Before product
behavior is added, the owning change must activate the exact module scope,
register its risks and test entry points, and satisfy the mapped gates. Editing
a marker cannot silently bypass that transition.

The API, Grafana integration, SDK, deployment, fuzz, and model roots are
likewise locked by `qualification/engineering/artifact-scopes.tsv`; code placed
outside a registered scope is rejected.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the complete workflow.
