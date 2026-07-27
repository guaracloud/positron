# Model and concurrency-test scaffold

This directory is reserved for small reference state machines and Loom models
of publication, ownership, leases, cancellation, retry, shutdown, and other
interleaving-sensitive protocols.

A model is introduced with the concrete protocol and must name its abstraction
limits, state-space bound, schedule/seed retention, and corresponding
production interface. A green model is detector evidence, not proof of every
production execution.
