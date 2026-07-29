# Qualification evidence

Release qualification attempts use:

`qualification/evidence/<release>/<gate>/<target>/<attempt>/`

Passing, failing, inconclusive, and exceptional attempts are immutable. A
later pass does not overwrite a failure. Evidence is ingested by the approved
retention workflow and bound to the exact source, artifact, target, toolchain,
configuration, fixture, workload, and fault-schedule digests.

Developer runs do not write here. `cargo xtask quality` writes diagnostic
engineering evidence under ignored `target/quality/evidence/`. Schema version
2 records exact or explicitly non-applicable Release Manifest, artifact,
target, environment, toolchain, configuration, fixture, corpus, seed, fault
schedule, command, report, owner, verifier, approval, and exception identities.

Each local attempt path is create-new. A collision preserves the original
bytes and retains a distinct failed record in one of 16 deterministic,
atomically claimed collision slots. A stale trusted-CI revision or a missing or
retried trusted-CI attempt also retains a failed aggregator verdict. None may
replace an earlier result.
