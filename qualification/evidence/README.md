# Qualification evidence

Release qualification attempts use:

`qualification/evidence/<release>/<gate>/<target>/<attempt>/`

Passing, failing, inconclusive, and exceptional attempts are immutable. A
later pass does not overwrite a failure. Evidence is ingested by the approved
retention workflow and bound to the exact source, artifact, target, toolchain,
configuration, fixture, workload, and fault-schedule digests.

Developer runs do not write here. `cargo xtask quality` writes diagnostic
engineering evidence under ignored `target/quality/evidence/`. Each local
attempt path is create-new: a collision, stale trusted-CI revision, or trusted
CI retry fails closed and must not replace an earlier result.
