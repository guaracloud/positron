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
//! // A validated limit profile has no public unchecked constructor.
//! ValueLimitProfile {};
//! ```
//!
//! ```compile_fail
//! use positron_domain::value::ValidatedAttributeValue;
//!
//! // A validated value is produced only by bounded validation.
//! ValidatedAttributeValue {};
//! ```
//!
//! ```compile_fail
//! use positron_domain::value::ValidatedKeyValue;
//!
//! // A validated entry is produced only while validating its owning list.
//! ValidatedKeyValue {};
//! ```
//!
//! ```compile_fail
//! use positron_domain::value::AttributeOccurrenceSet;
//!
//! // A validated occurrence set cannot bypass its candidate transition.
//! AttributeOccurrenceSet {};
//! ```
//!
//! ```compile_fail
//! use positron_domain::identity::TenantAttribution;
//!
//! // Attribution must pass its tenant-scope check.
//! TenantAttribution {};
//! ```
//!
//! ```compile_fail
//! use positron_domain::lifecycle::TenantLifecycle;
//!
//! // Lifecycle state can advance only through checked transitions.
//! TenantLifecycle {};
//! ```
//!
//! ```compile_fail
//! use positron_domain::time::EventTime;
//!
//! // Event Time must retain a validated source-time annotation.
//! EventTime {};
//! ```
//!
//! ```compile_fail
//! use positron_domain::time::ObservedTime;
//!
//! // Observed Time must retain a validated source-time annotation.
//! ObservedTime {};
//! ```
//!
//! ```compile_fail
//! use positron_domain::time::QueryTime;
//!
//! // Query Time is selected only through a signal-specific transition.
//! QueryTime {};
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
