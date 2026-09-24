#![no_main]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use libfuzzer_sys::fuzz_target;
use positron_config::{
    CommandLineOverrides, ConfigurationDiff, ConfigurationInputs, EffectiveConfiguration,
    EnvironmentOverrides, decode_configuration_document, resolve,
};
use positron_runtime::{
    ConfigurationObservation, ConfigurationPublication, ConfigurationPublicationDisposition,
    ConfigurationReloadOutcome, ConfigurationRuntimeFailure, RuntimeConfiguration,
};

const MAX_INPUT_BYTES: usize = 4_096;
const MAX_RELOADS: usize = 32;
const BASE_CONFIGURATION: &str = "schema_version = 1\n";
const LIVE_CONFIGURATION: &str =
    "schema_version = 1\n[diagnostics]\nlog_level = \"debug\"\n";
const RESTART_CONFIGURATION: &str =
    "schema_version = 1\n[runtime]\nshutdown_grace_seconds = 31\n";
const DRAIN_CONFIGURATION: &str =
    "schema_version = 1\n[listener]\noperations_bind_address = \"127.0.0.1:13134\"\n";
const IMMUTABLE_CONFIGURATION: &str =
    "schema_version = 1\n[storage]\ndata_directory = \"/var/lib/positron-other\"\n";

/// Bounded stand-in for the Catalog and Governance Audit publication seam.
///
/// A request receives one successor receipt or a publication failure; it never
/// returns a generation at or below the previous receipt.
struct SyntheticPublication {
    next_generation: AtomicU64,
    unavailable: bool,
}

impl SyntheticPublication {
    const fn available_after(generation: u64) -> Self {
        Self {
            next_generation: AtomicU64::new(generation),
            unavailable: false,
        }
    }

    const fn unavailable_after(generation: u64) -> Self {
        Self {
            next_generation: AtomicU64::new(generation),
            unavailable: true,
        }
    }
}

impl ConfigurationPublication for SyntheticPublication {
    fn publish(
        &self,
        _: &EffectiveConfiguration,
        _: &EffectiveConfiguration,
        _: &ConfigurationDiff,
        _: ConfigurationPublicationDisposition,
    ) -> Result<u64, ConfigurationRuntimeFailure> {
        if self.unavailable {
            return Err(ConfigurationRuntimeFailure::PublicationUnavailable);
        }

        let mut current = self.next_generation.load(Ordering::Acquire);
        loop {
            let next = current
                .checked_add(1)
                .ok_or(ConfigurationRuntimeFailure::PublicationUnavailable)?;
            match self.next_generation.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(next),
                Err(observed) => current = observed,
            }
        }
    }
}

fn resolve_document(document: &str) -> Option<Arc<EffectiveConfiguration>> {
    let environment = EnvironmentOverrides::try_from_pairs([] as [(&str, &str); 0]).ok()?;
    let command_line = CommandLineOverrides::try_from_pairs([] as [(&str, &str); 0]).ok()?;
    let inputs = ConfigurationInputs::try_new(Some(document), environment, command_line).ok()?;
    resolve(inputs).ok().map(Arc::new)
}

fn canonical_configuration(document: &str) -> Arc<EffectiveConfiguration> {
    resolve_document(document)
        .unwrap_or_else(|| panic!("known valid transactional reload fixture must resolve"))
}

fn assert_same_observation(before: &ConfigurationObservation, after: &ConfigurationObservation) {
    assert_eq!(after.generation(), before.generation());
    assert_eq!(after.effective(), before.effective());
    match (before.pending_restart(), after.pending_restart()) {
        (None, None) => {},
        (Some(before), Some(after)) => {
            assert_eq!(after.candidate(), before.candidate());
            assert_eq!(after.diff(), before.diff());
        },
        _ => panic!("rejected reload changed pending restart state"),
    }
}

fn check_outcome(
    runtime: &RuntimeConfiguration,
    before: &ConfigurationObservation,
    candidate: &Arc<EffectiveConfiguration>,
    outcome: ConfigurationReloadOutcome,
) {
    let after = runtime
        .observed()
        .unwrap_or_else(|_| panic!("runtime observation must remain available"));
    assert!(after.generation() >= before.generation());

    match outcome {
        ConfigurationReloadOutcome::NoChange { generation } => {
            assert_eq!(generation, before.generation());
            assert_same_observation(before, &after);
        },
        ConfigurationReloadOutcome::PublishedLive { generation, .. } => {
            assert!(generation > before.generation());
            assert_eq!(after.generation(), generation);
            assert_eq!(after.effective(), candidate);
            assert!(after.pending_restart().is_none());
        },
        ConfigurationReloadOutcome::PendingRestart { generation, .. } => {
            assert!(generation >= before.generation());
            assert_eq!(after.generation(), generation);
            let pending = after
                .pending_restart()
                .unwrap_or_else(|| panic!("restart-required candidate must remain visible"));
            assert_eq!(pending.candidate(), candidate);
        },
        ConfigurationReloadOutcome::RejectedImmutable { .. }
        | ConfigurationReloadOutcome::RequiresDrain { .. } => {
            assert_same_observation(before, &after);
        },
    }
}

fn reload(
    runtime: &RuntimeConfiguration,
    candidate: Arc<EffectiveConfiguration>,
    unavailable: bool,
) {
    let before = runtime
        .observed()
        .unwrap_or_else(|_| panic!("runtime observation must remain available"));
    let publication = if unavailable {
        SyntheticPublication::unavailable_after(before.generation())
    } else {
        SyntheticPublication::available_after(before.generation())
    };

    match runtime.reload_with(Arc::clone(&candidate), &publication) {
        Ok(outcome) => check_outcome(runtime, &before, &candidate, outcome),
        Err(ConfigurationRuntimeFailure::PublicationUnavailable) => {
            let after = runtime
                .observed()
                .unwrap_or_else(|_| panic!("failed publication must keep runtime observable"));
            assert_same_observation(&before, &after);
        },
        Err(ConfigurationRuntimeFailure::Unavailable) => {
            panic!("single-threaded reload must not lose its configuration lock");
        },
    }
}

fn candidate_for(command: u8) -> Arc<EffectiveConfiguration> {
    match command & 3 {
        0 => canonical_configuration(LIVE_CONFIGURATION),
        1 => canonical_configuration(RESTART_CONFIGURATION),
        2 => canonical_configuration(DRAIN_CONFIGURATION),
        _ => canonical_configuration(IMMUTABLE_CONFIGURATION),
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let runtime = RuntimeConfiguration::new(canonical_configuration(BASE_CONFIGURATION));
    let initial = runtime
        .observed()
        .unwrap_or_else(|_| panic!("new runtime configuration must be observable"));

    // Every arbitrary byte sequence first crosses the public configuration
    // decoder and resolver. Invalid documents are rejected before they can
    // reach the runtime; a valid complete candidate uses the same publication
    // and snapshot assertions as the bounded command sequence below.
    match decode_configuration_document(data) {
        Err(_) => assert_same_observation(
            &initial,
            &runtime
                .observed()
                .unwrap_or_else(|_| panic!("rejected input must leave runtime observable")),
        ),
        Ok(document) => match resolve_document(&document) {
            Some(candidate) => reload(
                &runtime,
                candidate,
                data.first().is_some_and(|byte| byte & 0x80 != 0),
            ),
            None => assert_same_observation(
                &initial,
                &runtime
                    .observed()
                    .unwrap_or_else(|_| panic!("rejected input must leave runtime observable")),
            ),
        },
    }

    for command in data.iter().copied().take(MAX_RELOADS) {
        reload(
            &runtime,
            candidate_for(command),
            command & 0x80 != 0,
        );
    }
});
