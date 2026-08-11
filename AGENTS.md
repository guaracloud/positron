# Instructions for AI agents

These instructions apply to the entire repository.

## Product

Read, in order, the relevant parts of:

1. `project-positron.md`
2. `CONTEXT.md`
3. accepted product decisions under `docs/adr/`
4. `docs/application-design.md`

Deliver only the Positron product described by those sources. Implement the
smallest complete change that satisfies the product contract; avoid speculative
abstractions, duplicate authorities, placeholder surfaces, and unrelated
tooling. Update or supersede an ADR when changing an accepted decision.

## Engineering

- Meet a production-grade software-engineering bar: correctness, security,
  clarity, maintainability, predictable performance, and explicit failures.
- Use safe, idiomatic Rust with clear ownership, small typed interfaces, bounded
  resources, an acyclic crate graph, and minimal dependencies. Do not panic,
  unwrap, index unchecked, or ignore results in product paths.
- Use Rust 2024, resolver 3, the pinned toolchain, locked resolution, rustfmt,
  and warning-free Clippy. Keep derived public artifacts synchronized with
  their canonical source.

## Tests

- Fully cover changed behavior and meaningful failure paths with focused unit
  tests. Begin reproducible defect fixes with a failing regression test.
- Add integration tests for affected cross-module and externally observable
  behavior.
- Add fuzz tests for applicable untrusted-input, protocol, storage, recovery,
  and state-machine boundaries.
- Test public outcomes, not private implementation shape.
- Workspace production-Rust line coverage across unit and integration tests
  must remain at least 95%. Production code must not be excluded merely to pass
  the threshold.

Run the relevant focused tests and these direct checks:

```console
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo llvm-cov --locked --workspace --lib --bins --tests --all-features --fail-under-lines 95
cargo test --locked --workspace --tests
```
Run applicable fuzz targets with `cargo fuzz run <target>`. Do not introduce a custom validation runner, evidence system, or parallel governance framework.