# Fuzzing scaffold

Fuzz targets are added only with the untrusted boundary they exercise. Each
target must have an owner, finite PR/extended/release budgets, committed seed
corpus, crash retention, minimized regression promotion, and an oracle that
does not disable authentication or validation through `cfg(fuzzing)`.

No application boundary exists yet, so the scaffold contains no vacuous fuzz
target.
