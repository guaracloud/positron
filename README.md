# Positron

Positron is an observability database for native Logs and Traces.

The product vision lives in [project-positron.md](project-positron.md), the
binding vocabulary in [CONTEXT.md](CONTEXT.md), the accepted product decisions
in [docs/adr](docs/adr), and the application shape in
[docs/application-design.md](docs/application-design.md).

## Develop

Use the pinned Rust toolchain from `rust-toolchain.toml`.

```console
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --lib
cargo test --locked --workspace --tests
```

Keep Rust code formatted and free of Clippy warnings. Product changes must
include comprehensive unit tests. Cross-module and externally observable
behavior belongs in integration tests. Parsers, protocol decoders, persistence
boundaries, and other untrusted or stateful inputs use fuzz tests where
applicable.

That is the complete repository policy. See
[CONTRIBUTING.md](CONTRIBUTING.md) for details.
