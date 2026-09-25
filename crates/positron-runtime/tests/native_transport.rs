//! Real loopback transport integration tests.

use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, any_value};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use positron_domain::identity::TenantSlug;
use positron_domain::lifecycle::TenantLifecycleState;
use positron_governance::{
    AdministrativeIdempotencyKey, CompatibilityHints, PresentedCredential, RequestedIntent,
    ResourceGeneration,
};
use positron_kernel::MountQualification;
use positron_query::QueryBudget;
use positron_runtime::{
    ApiTransportProfile, ApplicationRuntime, BootstrapPaths, HostInputs, InitializationMode,
    InstanceBootstrap, NativeBindings, NativeHost, PublicPlaintextApiStartupIntent,
    ServeConfiguration, ShutdownTrigger, TrustedProxy,
};
use prost::Message;

#[path = "native_transport/support.rs"]
mod support;
use support::*;

#[path = "native_transport/http2_api.rs"]
mod http2_api;
#[path = "native_transport/policy_routes.rs"]
mod policy_routes;
#[path = "native_transport/proxy_trust.rs"]
mod proxy_trust;
#[path = "native_transport/socket_admission.rs"]
mod socket_admission;
#[path = "native_transport/tenant_administration.rs"]
mod tenant_administration;
#[path = "native_transport/tls_profiles.rs"]
mod tls_profiles;
#[path = "native_transport/transport.rs"]
mod transport;
