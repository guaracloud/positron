//! Shared invariant-bearing domain boundary.
//!
//! This crate owns checked values shared by more than one Positron deep module.
//! It contains no I/O, wire decoding, persistence encoding, configuration
//! loading, provider client, or runtime behavior. Canonical text is a native
//! domain representation only; wire and durable serialization stay with their
//! owning adapters.
//!
//! ```compile_fail
//! use positron_domain::value::ValueLimitProfile;
//!
//! // A later validated state has no public unchecked constructor.
//! ValueLimitProfile {};
//! ```

#![forbid(unsafe_code)]

/// Tenant, principal, scope, and attribution values.
pub mod identity;
/// Checked tenant lifecycle transitions.
pub mod lifecycle;
/// Closed typed failures returned by Domain Types.
pub mod outcome;
/// Cluster-compatible shard and committed-position values.
pub mod routing;
/// Exact source, observed, ingest, and selected query times.
pub mod time;
/// Bounded native dynamic attribute values.
pub mod value;
