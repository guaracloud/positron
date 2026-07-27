# Qualification

This tree contains the machine-readable engineering and Release 1
qualification control plane. It does not contain application behavior.

- `engineering/` defines invariant mappings, owners, tools, scopes,
  architecture, thresholds, dependency reviews, exceptions, and evidence.
- `targets/` records static targets and the dynamic selectors that must be
  resolved before a Qualification Cell can move beyond `Specified`.
- `fixtures/` reserves adversarial fixture ownership and synthetic-data rules.
- `evidence/` documents immutable evidence retention. Local runs write only to
  ignored `target/quality/evidence/`.

Passing engineering checks does not mark a Release 1 Qualification Cell
`Implemented` or `Qualified`.
