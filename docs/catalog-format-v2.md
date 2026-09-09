# Catalog durable format v2

Epoch 2 uses the existing authenticated Catalog commit, marker, and artifact codecs with `format_epoch = 2`. Object artifact names and encryption context bind that epoch. Readers accept only Epochs 1 and 2; writers preserve the authenticated basis epoch for ordinary Catalog successors. An Epoch-1 binary rejects a complete Epoch-2 commit during recovery before it loads objects or starts listeners.

The only supported transition is `1 -> 2`. It copies the full bounded object set into Epoch-2 artifacts, writes a redacted `POSFMT01` audit intent bound to the administrator and idempotency key, and publishes the successor marker only after data admission is drained. A pre-marker failure leaves the Epoch-1 predecessor current; an acknowledged Epoch-2 marker has no downgrade route.

Epoch-1 governance state retains its exact authenticated legacy tenant-key envelope route after transition. It is never re-derived as a fallback for a missing or corrupt provisioned envelope. Provisioned tenant envelopes and the plural registry are Epoch-2-only state; missing or corrupt provisioned state fails closed.

Compatibility metadata for this implementation is: readable `{1,2}`, writable `{1,2}` only when preserving the authenticated basis, migration graph `{1 -> 2}`, and no reverse edge. This document does not claim a generic upgrade operation, release manifest tooling, or a completed plural-serving surface.
