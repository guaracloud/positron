//! OTLP Logs gRPC public-boundary integration tests.

#[path = "otlp_logs_grpc/admission_groups.rs"]
mod admission_groups;
#[path = "otlp_logs_grpc/authenticated_export.rs"]
mod authenticated_export;
#[path = "otlp_logs_grpc/authentication.rs"]
mod authentication;
#[path = "otlp_logs_grpc/empty_export.rs"]
mod empty_export;
#[path = "otlp_logs_grpc/forced_shutdown.rs"]
mod forced_shutdown;
#[path = "otlp_logs_grpc/malformed_transport.rs"]
mod malformed_transport;
#[path = "otlp_logs_grpc/resource_governance.rs"]
mod resource_governance;
#[path = "otlp_logs_grpc/retry_semantics.rs"]
mod retry_semantics;
#[path = "otlp_logs_grpc/sdk_producer.rs"]
mod sdk_producer;
#[path = "otlp_logs_grpc/structural_amplification.rs"]
mod structural_amplification;
#[path = "otlp_logs_grpc/support.rs"]
mod support;
#[path = "otlp_logs_grpc/transport_bounds.rs"]
mod transport_bounds;
