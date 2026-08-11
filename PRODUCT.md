# Positron — project website

- register: brand (design IS the product; marketing surface for an OSS database)
- audience: SREs, platform engineers, database engineers evaluating an observability database
- voice: precise · engineered · matter-of-fact (a machined instrument, not a sales page)

## What this site is

The public GitHub Pages site for Positron, an observability database for
native Logs and Traces by Guara Cloud. Two pages:

- `index.html` — the product landing page. States what Positron is. No
  superlatives, no benchmarks, no fabricated metrics; declarative facts from
  the product vision only.
- `architecture.html` — the Release 1 architecture, rendered from
  `project-positron.md`, `docs/application-design.md`, and the accepted
  product ADRs.

## Constraints

- Static only; served by GitHub Pages from the `gh-pages` branch. No build
  step, no framework.
- Content must state only what the product vision defines. Never invent
  numbers, benchmarks, version strings, or availability claims.
- The logo is a placeholder SVG; the final mark will replace
  `assets/logo.svg` (same viewBox) later.

## Family identity (fixed)

Guara Cloud house style shared with purple-wolf and e-navigator:

- Fonts: Afacad Flux (display), Atkinson Hyperlegible (body), Recursive Mono
  (code) via Google Fonts.
- OKLCH tokens, 4pt spacing scale, one committed accent hue per product.
- Taken hues: purple-wolf 302 (purple), e-navigator 194 (teal) + 146 (green).
- Positron's lane: positron blue (hue 262) primary + trace rose (hue 342)
  secondary — the log stream and the trace stream. Deep indigo dark panels
  (the cloud-chamber field) are Positron's signature evolution of the family
  style.
