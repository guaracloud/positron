use std::sync::Barrier;

use super::lifecycle_tests::{claim, governor};
use super::{AdmissionFailureCode, GovernorFailure, ResourceSnapshot, WorkKind};

fn assert_coherent(snapshot: ResourceSnapshot) {
    let sum = (0..AdmissionFailureCode::COUNT)
        .filter_map(AdmissionFailureCode::from_index)
        .map(|reason| {
            assert!(snapshot.throttle_count_for(reason) <= snapshot.rejection_count_for(reason));
            snapshot.rejection_count_for(reason)
        })
        .sum::<u64>();
    assert_eq!(snapshot.rejection_count(), sum);
}

#[test]
fn concurrent_refusals_and_observation_never_publish_partial_telemetry() {
    const PRODUCERS: usize = 4;
    const ATTEMPTS: usize = 64;
    const OBSERVATIONS: usize = 256;

    let (governor, tenant) = governor();
    let saturated = governor
        .reserve(claim(tenant, WorkKind::InteractiveQueryTail, 50))
        .expect("query capacity is available");
    let start = Barrier::new(PRODUCERS + 2);
    let (class_refusals, contentions) = std::thread::scope(|scope| {
        let producers: Vec<_> = (0..PRODUCERS)
            .map(|_| {
                let governor = &governor;
                let start = &start;
                scope.spawn(move || {
                    start.wait();
                    let mut class_refusals = 0_u64;
                    let mut contentions = 0_u64;
                    for _ in 0..ATTEMPTS {
                        let failure = governor
                            .reserve(claim(tenant, WorkKind::InteractiveQueryTail, 1))
                            .expect_err("saturated capacity or concurrent accounting refuses");
                        match failure.code() {
                            AdmissionFailureCode::ClassCapacityUnavailable => {
                                class_refusals += 1;
                            },
                            AdmissionFailureCode::GovernorContended => contentions += 1,
                            code => panic!("unexpected concurrent refusal: {code:?}"),
                        }
                    }
                    (class_refusals, contentions)
                })
            })
            .collect();
        let observer = {
            let governor = &governor;
            let start = &start;
            scope.spawn(move || {
                start.wait();
                for _ in 0..OBSERVATIONS {
                    match governor.inspect() {
                        Ok(snapshot) => assert_coherent(snapshot),
                        Err(GovernorFailure::GovernorContended { .. }) => {},
                        Err(failure) => panic!("unexpected observation failure: {failure}"),
                    }
                }
            })
        };
        start.wait();
        let mut class_refusals = 0_u64;
        let mut contentions = 0_u64;
        for producer in producers {
            let (class_count, contention_count) = producer.join().expect("producer does not panic");
            class_refusals += class_count;
            contentions += contention_count;
        }
        observer.join().expect("observer does not panic");
        (class_refusals, contentions)
    });

    assert_eq!(class_refusals + contentions, (PRODUCERS * ATTEMPTS) as u64);
    let snapshot = governor
        .inspect()
        .expect("final observation is uncontended");
    assert_coherent(snapshot);
    assert_eq!(
        snapshot.rejection_count_for(AdmissionFailureCode::ClassCapacityUnavailable),
        class_refusals
    );
    assert_eq!(
        snapshot.rejection_count_for(AdmissionFailureCode::GovernorContended),
        contentions
    );
    drop(saturated);
}
