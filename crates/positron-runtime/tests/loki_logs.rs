//! Live Loki receiver behavior through the dedicated listener.

#[path = "loki_logs/support.rs"]
mod support;

#[path = "loki_logs/producer.rs"]
mod producer;

#[path = "loki_logs/route_ownership.rs"]
mod route_ownership;

#[path = "loki_logs/authentication.rs"]
mod authentication;

#[path = "loki_logs/compression.rs"]
mod compression;

#[path = "loki_logs/otlp_alias.rs"]
mod otlp_alias;

#[path = "loki_logs/otlp_producer.rs"]
mod otlp_producer;

#[path = "loki_logs/tracing_loki_producer.rs"]
mod tracing_loki_producer;

#[path = "loki_logs/recovery.rs"]
mod recovery;

#[path = "loki_logs/malformed.rs"]
mod malformed;
