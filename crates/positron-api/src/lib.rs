//! Public-interface foundations for the canonical Positron v1 API.
//!
//! The public source lives exclusively in `api/positron/v1/positron.proto`.
//! Keep this module and its HTTP/JSON, OpenAPI, and Schema Digest artifacts
//! synchronized with that contract.

#![forbid(unsafe_code)]

/// V1 wire and in-memory interface types.
pub mod generated;
