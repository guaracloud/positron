# Contributing to Positron

Positron keeps its development loop deliberately small: implement product
behavior, format it, lint it, test it, and review it.

## Source of truth

Read the relevant parts of:

1. `project-positron.md`
2. `CONTEXT.md`
3. accepted product decisions under `docs/adr/`
4. `docs/application-design.md`

If a change alters an accepted product decision, update or supersede the
relevant ADR with the code.

## Development checks

All Rust code is formatted with rustfmt and linted with Clippy:

```console
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
```

Every product change includes:

- comprehensive unit tests for the behavior owned by the changed module;
- integration tests for cross-module, public-interface, persistence, provider,
  and end-to-end behavior affected by the change; and
- fuzz tests for applicable untrusted-input, parser, protocol, storage,
  recovery, and state-machine boundaries.

Run the relevant focused tests while working, then the workspace tests:

```console
cargo test --locked --workspace --lib
cargo test --locked --workspace --tests
```

Run each applicable fuzz target from `fuzz/` with `cargo fuzz run <target>`.
Fuzzing is expected where the change introduces or alters a fuzzable boundary.
There is no numeric coverage threshold or repository-specific validation
runner beyond formatting, linting, unit tests, integration tests, and fuzz
tests.

Defect fixes begin with a failing regression test. Tests should assert returned
outcomes or externally readable behavior rather than private implementation
shape.

## Dependencies

Add a dependency only when it directly supports the product and the standard
library or an existing dependency is insufficient. Use minimal features and
update `Cargo.lock` with the manifest change.

## Pull requests

Explain the product outcome and the unit, integration, and fuzz tests that
cover it. Formatting, Clippy, and applicable tests must pass. Commit, push,
publish, deploy, and release are separate actions and must be explicitly
authorized.
