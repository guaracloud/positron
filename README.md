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

1. Install the exact tool versions listed in
   `qualification/engineering/toolchains.tsv`.
2. Run `cargo xtask setup` once to install the repository-managed Git hooks.
3. Run `cargo xtask quality` before requesting review.

The quality runner produces local evidence under `target/quality/evidence/`.
Local evidence is deliberately marked ineligible for merge; trusted CI evidence
is bound to the pull-request or merge-group revision.

## Scaffold boundary

Every application crate is registered as `scaffold` in
`qualification/engineering/scopes.tsv`. The architecture gate permits only
crate documentation, inherited policy, and the empty composition-root entry
point while that state remains active. Before product behavior is added, the
owning change must activate the exact module scope, freeze its measured
thresholds, register its risks and test entry points, and satisfy the mapped
gates. Editing a marker cannot silently bypass that transition.

The API, Grafana integration, SDK, deployment, fuzz, and model roots are
likewise locked by `qualification/engineering/artifact-scopes.tsv`; code placed
outside a registered scope is rejected.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the complete workflow.
