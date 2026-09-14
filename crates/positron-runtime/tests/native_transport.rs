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
    InstanceBootstrap, NativeBindings, NativeHost, ServeConfiguration, ShutdownTrigger,
    TrustedProxy,
};
use prost::Message;

#[path = "native_transport/support.rs"]
mod support;
use support::*;

mod policy_routes;
mod tenant_administration;
mod tls_profiles;
mod transport;
