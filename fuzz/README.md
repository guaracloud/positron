# Fuzz tests

Add fuzz targets with the untrusted-input or stateful product boundary they
exercise. Applicable targets include parsers, protocol decoders, public request
bodies, persistent formats, recovery inputs, cryptographic envelopes, and
state-machine transitions.

Keep useful seed inputs and promote every fixed crash to the regression corpus.
Run a target with:

```console
cargo +nightly fuzz run <target>
```

The repository's production toolchain remains pinned; `cargo-fuzz` uses an
installed nightly toolchain only for sanitizer instrumentation.

Current storage target:

```console
cargo +nightly fuzz run primary_data_volume_stateful
```

Current authenticated-frame target:

```console
cargo +nightly fuzz run encrypted_frame_open
```
