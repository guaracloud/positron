use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use positron_governance::{
    AdministrativeIdempotencyKey, CompatibilityHints, IngestPolicyAdministration,
    PolicyAdministrationFailureCode, PresentedCredential, RequestedIntent, ResourceGeneration,
};
use positron_ingest::{IngestPolicy, PolicyAction, PolicyPredicate, PolicyRule};
use positron_kernel::Catalog;

use super::super::super::{InitializationPlan, InstanceBootstrap};
use super::super::support::Roots;

#[test]
fn concurrent_catalog_activation_reports_current_resource_generation()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    let initialized = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    drop(initialized);
    let claim = InstanceBootstrap::claim(&paths)?;
    let initialized = InstanceBootstrap::reopen(&paths)?;
    let administrator = initialized.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let catalog = Catalog::open(
        &initialized._authority,
        initialized.instance,
        initialized.key.catalog_secret(initialized.instance)?,
    )?;
    let administration = IngestPolicyAdministration::open(&catalog, initialized.tenant)?;

    for generation in 2_u64..=9 {
        let barrier = Arc::new(Barrier::new(3));
        let outcomes = thread::scope(|scope| {
            let mut handles = Vec::new();
            for (marker, large) in [(0x40_u8, false), (0x80, true)] {
                let barrier = Arc::clone(&barrier);
                let administration = &administration;
                let catalog = &catalog;
                let identity = &initialized.identity;
                let key = AdministrativeIdempotencyKey::new(
                    [marker.wrapping_add(u8::try_from(generation).expect("bounded generation"));
                        16],
                )
                .expect("nonzero key");
                let predicates = if large {
                    vec![
                        PolicyPredicate::body_exact_text("a".repeat(100_000))
                            .expect("bounded predicate"),
                    ]
                } else {
                    Vec::new()
                };
                let policy = IngestPolicy::compile(
                    generation,
                    vec![
                        PolicyRule::new(
                            format!("concurrent-{generation}-{marker}"),
                            predicates,
                            PolicyAction::Accept,
                        )
                        .expect("bounded rule"),
                    ],
                )
                .expect("bounded policy");
                handles.push(scope.spawn(move || {
                    barrier.wait();
                    if !large {
                        thread::sleep(Duration::from_millis(1));
                    }
                    let expected = ResourceGeneration::new(generation - 1)?;
                    for _ in 0..16 {
                        match administration.activate(
                            catalog,
                            identity,
                            administrator,
                            expected,
                            key,
                            policy.clone(),
                        ) {
                            Err(failure)
                                if failure.code()
                                    == PolicyAdministrationFailureCode::PersistenceUnavailable =>
                            {
                                thread::yield_now();
                            },
                            outcome => return outcome,
                        }
                    }
                    administration.activate(catalog, identity, administrator, expected, key, policy)
                }));
            }
            barrier.wait();
            handles
                .into_iter()
                .map(|handle| handle.join().map_err(|_| "activation thread panicked"))
                .collect::<Result<Vec<_>, _>>()
        })?;
        assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
        let stale = outcomes
            .iter()
            .find_map(|outcome| outcome.as_ref().err())
            .ok_or("one activation must lose the generation race")?;
        assert_eq!(
            stale.code(),
            PolicyAdministrationFailureCode::StaleResourceGeneration
        );
        assert_eq!(
            stale.current_generation().map(ResourceGeneration::get),
            Some(generation)
        );
    }
    Ok(())
}
