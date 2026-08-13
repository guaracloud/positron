//! Positron process runtime boundaries.
//!
//! The implemented slice owns transactional Instance Bootstrap. Process
//! lifecycle and listeners remain outside this slice.

#![forbid(unsafe_code)]

mod instance_bootstrap;

pub use instance_bootstrap::{
    BootstrapClaim, BootstrapFailure, BootstrapFailureCode, BootstrapPaths, BootstrapState,
    InitializationPlan, InitializedInstance, InstanceBootstrap,
};
