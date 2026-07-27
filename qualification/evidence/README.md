# Qualification evidence

Release qualification attempts use:

`qualification/evidence/<release>/<gate>/<target>/<attempt>/`

Passing, failing, inconclusive, and exceptional attempts are immutable. A
later pass does not overwrite a failure. Evidence is ingested by the approved
retention workflow and bound to the exact source, artifact, target, toolchain,
configuration, fixture, workload, and fault-schedule digests.

Developer runs do not write here. `cargo xtask quality` writes diagnostic
engineering evidence under ignored `target/quality/evidence/`.
