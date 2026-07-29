# Qualification evidence

Release qualification attempts use:

`qualification/evidence/<release>/<gate>/<target>/<attempt>/`

Passing, failing, inconclusive, and exceptional attempts are immutable. A
later pass does not overwrite a failure. Evidence is ingested by the approved
retention workflow and bound to the exact source, artifact, target, toolchain,
configuration, fixture, workload, and fault-schedule digests.

Developer runs do not write here. `cargo xtask quality` writes diagnostic
engineering evidence under ignored `target/quality/evidence/`. Schema version
3 records exact or explicitly non-applicable Release Manifest, artifact,
target, environment, toolchain, configuration, fixture, corpus, seed, fault
schedule, command, report, owner, verifier, approval, and exception identities.
Every selected gate retains an immutable bounded JSON raw report below
`target/quality/evidence-reports/<attempt>/<gate>.json`. The evidence record
binds its exact relative path, SHA-256, byte length, content type, verdict, and
structured invocation. The invocation records the registered internal runner,
ordered arguments, workspace-root identity, environment digest, timeout,
memory declaration, activation, exception class, and every controlled child
program, resolved tool path, ordered arguments, input identity, and bounded
stdout/stderr verdict. Captured streams are limited to 128 KiB each and one
gate report is limited to 8 MiB. Not-selected gates retain an explicit
`gate-not-selected` applicability instead of creating a report.

Each local attempt candidate is selected with create-new reservation. Candidate
collisions discovered while selecting the canonical or numbered identities
advance through 16 deterministic, atomically claimed collision slots. When all
16 slots are occupied, the invocation create-news one reserved
`<attempt>-collision-exhausted.json` failure bound to the canonical attempt and
the complete occupied-slot set. If that reserved record already exists, it is
treated as the previously retained exhaustion state and is never overwritten.
For each selected candidate, the runner durably reserves its recovery record
before atomically create-new claiming the primary path. If that primary claim
loses a race, the immutable candidate-specific recovery record remains the
authoritative failed verdict; neither path is overwritten and selection does
not advance to another slot. A stale trusted-CI revision or a missing or
retried trusted-CI attempt also retains a failed aggregator verdict. None may
replace an earlier result.
