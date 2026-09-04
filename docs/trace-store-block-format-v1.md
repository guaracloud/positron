# Trace Store Block v1 and v2

Trace Store Blocks are the Trace Store's canonical authenticated payload. The
Storage Kernel owns the surrounding segment envelope, tenant/signal/shard
scope, commit position, digest, encryption, and durability. A block never
contains more than one tenant or signal.

The payload is big-endian and has no padding:

| Field | Encoding |
| --- | --- |
| magic | `PTRCBL01` (8 bytes) |
| version | unsigned 16-bit (`1` or `2`) |
| tenant ID | 16 bytes |
| observation count | unsigned 16-bit, `1..=1024` |
| observations | repeated v1 observation records |

Version 1 observations contain:

1. trace ID (16 bytes), span ID (8 bytes), and a parent-present byte followed
   by the parent span ID when present;
2. span-kind and sampling-decision tags;
3. start and end `EventTime` values, each encoded as a quality byte followed by
   an i64 only when the quality is not `Missing`;
4. a u32-length UTF-8 name;
5. a u16 attribute count followed by namespace-tagged attribute occurrence
   sets. Keys are u32-length UTF-8 strings and each set has a u16 occurrence
   count followed by the native typed value encoding;
6. policy provenance: generation (u64), digest (32 bytes), and applied rule
   identities;
7. the kernel-assigned ingest time as an i64.

Version 2 retains every version 1 field and adds the bounded native OTLP
detail section before policy provenance: span trace state and complete flags;
status code and message; span dropped-attribute, dropped-event, and
dropped-link counts; resource dropped-attribute count and schema URL;
instrumentation-scope name, version, dropped-attribute count, and schema URL;
ordered events (timestamp, name, dropped-attribute count, and typed
occurrence sets); and ordered links (trace ID, span ID, trace state, flags,
dropped-attribute count, and typed occurrence sets). Version 2 writers are
canonical for new observations. Readers retain version 1 compatibility and
default only fields that version 1 could not contain to explicit empty,
zero, or `UNSET` values; they never infer producer detail.

Trace attributes are limited to the Resource, Instrumentation Scope, and
Record/Span namespaces. The Log-only Stream namespace is not a valid Trace
Store value and its wire tag is rejected.

Native values use tags for null, boolean, signed integer, floating-point bits,
string, bytes, array, and ordered key/value list. The decoder applies the
Release 1 value limits before allocating nested values. Names, attribute keys,
and nested map keys accept `1..=65536` UTF-8 bytes; each namespace accepts at
most 1,024 total occurrences across all of its sets. An allocation-free
recursive preflight accounts string/bytes payloads, every nested vector and
policy rule, and the validation-transfer peak before scan admission. The
decoder rejects unknown tags, invalid UTF-8, truncated fields, trailing bytes,
and invalid policy provenance.

Every accepted observation remains an immutable physical observation. This
format does not consolidate retries, derive summaries, infer completion, or
materialize structural relationships; those are later Trace Store operations.
Query scans decode authenticated blocks from both the active segment and
sealed segments through a kernel `LedgerSnapshot` and expose an explicit
result bound or scanned-byte incompleteness.
