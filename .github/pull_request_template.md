## Contract and ownership

- Semantic owner:
- Affected invariant IDs:
- Affected Qualification Cell IDs and targets:
- ADR/design impact:

## Behavior and risk

- Intended externally observable outcome:
- Boundaries and failure modes:
- Security, durability, isolation, resource, and compatibility impact:
- Rollback or recovery behavior:

## Evidence

- Positive, boundary, negative, and adversarial tests:
- Property/model/fuzz/fault/detector coverage:
- Exact `cargo xtask quality` attempt:
- Performance evidence or reason not selected:
- Retained negative or inconclusive evidence:

## Policy checklist

- [ ] No gate, threshold, target, tool, fixture, corpus, workflow, owner, or
      baseline was weakened to make this change pass.
- [ ] Generated outputs were produced by their pinned generator and a clean
      regeneration is byte-identical.
- [ ] New dependencies have complete review records and minimal features.
- [ ] Temporary markers and exceptions have an owner, issue, expiry, and
      removal condition.
- [ ] No production secret, tenant data, credential, or key material appears
      in code, fixtures, logs, evidence, or artifacts.
