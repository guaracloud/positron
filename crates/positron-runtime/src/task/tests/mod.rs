use super::TaskFailure;

#[test]
fn task_failure_diagnostic_is_stable() {
    assert_eq!(
        TaskFailure::JoinUnavailable.to_string(),
        "runtime task failed"
    );
}
