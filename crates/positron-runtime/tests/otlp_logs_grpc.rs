//! OTLP Logs gRPC public-boundary integration tests.

#[path = "otlp_logs_grpc/authenticated_export.rs"]
mod authenticated_export;
#[path = "otlp_logs_grpc/authentication.rs"]
mod authentication;
#[path = "otlp_logs_grpc/support.rs"]
mod support;
#[path = "otlp_logs_grpc/transport_bounds.rs"]
mod transport_bounds;
