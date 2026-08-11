# Instructions for AI agents

These instructions apply to the entire repository.

## Product authority

Read, in order, the relevant parts of:

1. `project-positron.md`
2. `CONTEXT.md`
3. accepted product decisions under `docs/adr/`
4. `docs/application-design.md`

Keep work focused on code and documentation that directly produce the Positron
product described by those sources.

## Development policy

- Preserve clear semantic ownership and an acyclic crate graph.
- Use Rust 2024, resolver 3, the pinned toolchain, and locked dependency
  resolution.
- Keep generated or derived public-interface artifacts synchronized with their
  canonical product source.
- Format Rust code with rustfmt and keep it free of Clippy warnings.
- Begin reproducible defect fixes with a failing regression test.
- Give changed product behavior comprehensive unit-test coverage.
- Add integration tests for affected cross-module and externally observable
  behavior.
- Add fuzz tests for applicable untrusted-input, protocol, storage, recovery,
  and state-machine boundaries.
- Test returned outcomes or externally readable behavior, not private
  implementation shape.

Run the relevant focused tests and then:

```console
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --lib
cargo test --locked --workspace --tests
```

Commit, push, pull request, tag, publish, deploy, and release actions each
require explicit user authorization.
