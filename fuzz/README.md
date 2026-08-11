# Fuzz tests

Add fuzz targets with the untrusted-input or stateful product boundary they
exercise. Applicable targets include parsers, protocol decoders, public request
bodies, persistent formats, recovery inputs, cryptographic envelopes, and
state-machine transitions.

Keep useful seed inputs and promote every fixed crash to the regression corpus.
Run a target with:

```console
cargo fuzz run <target>
```
