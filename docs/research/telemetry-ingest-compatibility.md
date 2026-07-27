# Telemetry ingest compatibility

Research snapshot: 2026-07-26.

## Conclusion

Positron should separate **signal compatibility** from **backend API compatibility**.
OTLP can provide the primary native receiver contract, but it does not make
Positron automatically compatible with Loki Push, Prometheus Remote Write, or
Pyroscope Push. Those are separate protocol adapters. Likewise, accepting the
same OTLP traces that Tempo accepts does not make Positron a Tempo query API or
block-format implementation.

Receiver adapters should decode supported protocols into Positron's native
logical signal models. Vendor names and wire formats must not leak into the
storage kernel or signal stores.

## Primary protocol facts

### OpenTelemetry

The current OTLP specification is stable for logs, traces, and metrics, while
profiles remain in development. OTLP defines gRPC and HTTP transports over the
same Protobuf messages. OTLP/HTTP supports binary Protobuf and JSON Protobuf,
uses `/v1/logs` and `/v1/traces` for Release 1 signals, permits gzip, and
defines signal-specific partial-success responses. The default ports are 4317
for gRPC and 4318 for HTTP.

Sources:

- [OTLP specification 1.11.0](https://opentelemetry.io/docs/specs/otlp/)
- [OTLP exporter specification](https://opentelemetry.io/docs/specs/otel/protocol/exporter/)
- [OpenTelemetry signal status](https://opentelemetry.io/docs/specs/status/)

### Grafana Alloy

Alloy's OpenTelemetry exporters can send logs, traces, and metrics over
OTLP/gRPC or OTLP/HTTP. The HTTP exporter supports Protobuf or JSON and defaults
to the standard `/v1/logs`, `/v1/traces`, and `/v1/metrics` paths. This is the
clean compatibility path for Alloy pipelines.

Alloy's `loki.write` and `pyroscope.write` components are different pipelines:
they target Loki and Pyroscope receiver APIs rather than becoming OTLP merely
because they run inside Alloy.

Sources:

- [Alloy OTLP/HTTP exporter](https://grafana.com/docs/alloy/latest/reference/components/otelcol/otelcol.exporter.otlphttp/)
- [Alloy OTLP receiver](https://grafana.com/docs/alloy/latest/reference/components/otelcol/otelcol.receiver.otlp/)
- [Alloy Loki API source and Push compatibility](https://grafana.com/docs/alloy/latest/reference/components/loki/loki.source.api/)
- [Alloy Pyroscope writer](https://grafana.com/docs/alloy/latest/reference/components/pyroscope/pyroscope.write/)

### Grafana Tempo

Tempo is a trace backend and receiver, not a general source that exports its
stored traces to another backend. Its distributor recommends and accepts OTLP
traces over gRPC and HTTP. Applications, Alloy, or an OpenTelemetry Collector
that would send OTLP to Tempo can instead send the same trace model to
Positron.

Tempo's metrics-generator is a separate producer: it derives metrics from
traces and sends them using Prometheus Remote Write. Supporting those generated
metrics therefore requires a Metric Store and a Remote Write receiver, not
additional trace compatibility.

Sources:

- [Tempo distributor](https://grafana.com/docs/tempo/latest/reference-tempo-architecture/components/distributor/)
- [Tempo OpenTelemetry Collector setup](https://grafana.com/docs/tempo/latest/set-up-for-tracing/instrument-send/set-up-collector/otel-collector/)
- [Tempo metrics-generator](https://grafana.com/docs/tempo/latest/metrics-from-traces/metrics-generator/)

### Grafana Loki

Loki exposes two relevant log receivers:

- `POST /otlp/v1/logs` for native OTLP log ingestion.
- `POST /loki/api/v1/push` for the Loki Push protocol, using
  Snappy-compressed Protobuf or its documented JSON representation.

An Alloy OpenTelemetry pipeline can target Positron's standard OTLP endpoint.
An existing `loki.write` pipeline requires a separate Loki Push adapter or a
configuration change. Loki's LogQL query APIs are another independent
compatibility surface.

Sources:

- [Loki HTTP API](https://grafana.com/docs/loki/latest/reference/loki-http-api/)
- [Loki native OTLP versus Loki exporter](https://grafana.com/docs/loki/latest/send-data/otel/native_otlp_vs_loki_exporter/)

### Grafana Pyroscope and OpenTelemetry Profiles

Pyroscope exposes profile-specific ingestion APIs, including its public
PusherService carrying raw pprof profiles. Alloy's `pyroscope.write` targets a
Pyroscope endpoint. OpenTelemetry Profiles also has an OTLP transport, but the
signal remains in development and its wire model can change between revisions.

Positron must therefore version profile receiver adapters and validate them
against pinned real exporters and Pyroscope versions. A generic claim of
"OTLP Profiles compatible" is not sufficient.

Sources:

- [Pyroscope server API](https://grafana.com/docs/pyroscope/latest/reference-server-api/)
- [OpenTelemetry Profiles](https://opentelemetry.io/docs/specs/otel/profiles/)
- [OTLP specification profile status and endpoint](https://opentelemetry.io/docs/specs/otlp/)

### Grafana Beyla

Beyla exports traces and metrics through OpenTelemetry. Its trace exporter
supports OTLP gRPC, HTTP/Protobuf, and HTTP/JSON and follows the standard
per-signal endpoint behavior. Release 1 can accept Beyla traces through the
standard OTLP receiver; Beyla metrics require the follow-on Metric Store.

Sources:

- [Beyla telemetry export configuration](https://grafana.com/docs/beyla/latest/configure/export-data/)
- [Beyla configuration overview](https://grafana.com/docs/beyla/latest/configure/)

### E-Navigator

The current local E-Navigator repository identifies itself as a collector, not
a backend, and routes metrics, traces, and profiles through independent bounded
OTLP/HTTP workers. It does not currently advertise OTLP logs.

Its trace path uses stable OTLP/HTTP Protobuf at `/v1/traces`. Metrics use
`/v1/metrics`. Profiles are deliberately pinned to the development
`v1development` v0.3.0 Protobuf contract at `/v1development/profiles`, with a
real Pyroscope 1.20.3 compatibility smoke required by its ADR.

Sources:

- `../e-navigator/README.md`
- `../e-navigator/documentation/adr/0003-direct-otlp-profiles.md`
- `../e-navigator/documentation/adr/0004-independent-export-pipelines.md`
- `../e-navigator/crates/e-navigator-sinks/src/otlp_http.rs`
- `../e-navigator/crates/e-navigator-sinks/src/otlp_trace_proto.rs`
- `../e-navigator/crates/e-navigator-sinks/src/otlp_metric_proto.rs`
- `../e-navigator/crates/e-navigator-sinks/src/otlp_profile_proto.rs`

## Staged compatibility matrix

| Producer or pipeline | Actual receiver contract | Release 1 Logs + Traces | Follow-on |
| --- | --- | --- | --- |
| OpenTelemetry SDK or Collector | OTLP gRPC or HTTP | Native Logs and Traces | Metrics and versioned Profiles |
| Alloy `otelcol.exporter.*` | OTLP gRPC or HTTP | Native Logs and Traces | Metrics and versioned Profiles |
| Alloy `loki.write` | Loki Push | Native Logs through the required Loki Push adapter | — |
| Tempo-targeted applications or collectors | Usually OTLP traces | Native Traces | Other Tempo receiver protocols only if separately selected |
| Tempo metrics-generator | Prometheus Remote Write | Not a Release 1 signal | Native Metrics plus Remote Write |
| Loki native OTLP pipeline | OTLP logs, commonly under Loki's `/otlp` prefix | Native Logs through the required `/otlp/v1/logs` path | — |
| Loki Push clients | Loki Push | Native Logs through the required Loki Push adapter | — |
| Beyla | OTLP traces and metrics | Native Traces | Native Metrics |
| E-Navigator | OTLP/HTTP metrics, traces, development Profiles | Native Traces | Native Metrics and pinned Profile revisions |
| Alloy `pyroscope.write` or Pyroscope agents | Pyroscope Push / pprof | Not a Release 1 signal | Native Profiles plus Pyroscope adapters |

## Conformance requirements

A compatibility claim should require all of the following:

1. Decode fixtures generated from the upstream protocol definitions.
2. Real exporter-to-Positron integration tests for named compatibility targets.
3. Full-success, partial-success, retryable failure, permanent failure,
   compression, TLS, authentication-header, oversized-request, unknown-field,
   and malformed-payload coverage.
4. Proof that accepted data remains queryable with its resource, scope,
   intrinsic fields, attributes, events, links, severity, trace context, and
   dropped-count semantics intact.
5. A published version matrix for every development-status or vendor-specific
   protocol.
6. Clear separation between ingest compatibility, query-language
   compatibility, dashboard/data-source compatibility, and storage-format
   compatibility.
