# Positron site — design system

## Scene

An engineer reads this at a desk mid-investigation, deciding whether Positron
deserves a proof-of-concept. Ambient office light. The page must read like the
engineering it describes: exact, bounded, quiet — with one signature physical
image: the cloud chamber. A positron is only visible by the trail it leaves;
telemetry is the trail a system leaves. The site draws that trail.

## Color strategy

Committed (family style evolved). Light body surfaces tinted toward hue 262;
deep indigo panels carry the hero and every diagram, so diagrams read as
instrument panels. Two signal hues with fixed meaning everywhere:

| Token | Value | Meaning |
| --- | --- | --- |
| `--positron` | `oklch(46% 0.17 262)` | logs, primary actions, links |
| `--positron-bright` | `oklch(72% 0.14 262)` | logs on dark |
| `--trace` | `oklch(54% 0.17 342)` | traces, secondary signal |
| `--trace-bright` | `oklch(74% 0.13 342)` | traces on dark |
| `--verify` | `oklch(50% 0.115 166)` | evidence, qualification, green |
| `--warn` | `oklch(55% 0.12 76)` | fenced / caution states |
| `--deep` | `oklch(16% 0.03 268)` | dark field (hero, diagrams) |
| `--surface` | `oklch(98% 0.008 262)` | body |
| `--ink` | `oklch(19% 0.028 265)` | body text |

Hue meaning never drifts: blue = logs, rose = traces, green = evidence.

## Type

- Display: Afacad Flux 500/600/700, fluid clamp scale, ratio ≥1.25,
  h1 max 4.5rem, letter-spacing ≥ -0.02em.
- Body: Atkinson Hyperlegible 400/700, 1.0625rem/1.65, measure ≤ 68ch.
- Code/labels: Recursive Mono 500/600. Mono is legitimate here — the product
  is a database; CLI and protocol names are real content, not costume.

## Motion

- Signature: the hero cloud chamber (canvas). Particle pairs curl in opposite
  arcs (blue/rose) and decay; slow, sparse, physical. Static SVG fallback for
  `prefers-reduced-motion` and no-JS.
- Diagrams: edges carry flowing dashes (CSS `stroke-dashoffset`); paused under
  reduced motion.
- Reveals: content is visible by default; JS adds `data-reveal` transforms
  only when IntersectionObserver confirms support. Ease: `--ease-out`
  `cubic-bezier(0.22, 1, 0.36, 1)`. Entrances 500–700ms, feedback ≤150ms.

## Bans honored

No gradient text, no side-stripe borders, no glassmorphism-by-default, no
hero-metric template, no identical icon-card grids, no eyebrow kicker
scaffolding, no fabricated numbers. Numbered steps appear only on real
sequences (canonical flows, milestones).
