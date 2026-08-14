use super::{OtlpLogsReceiver, ReceiveFailure};

mod group_capacity;
mod metadata_accounting;

#[test]
fn receiver_defaults_and_failures_keep_the_public_contract() {
    assert_eq!(
        OtlpLogsReceiver::default().value_limit_profile,
        OtlpLogsReceiver::new().value_limit_profile
    );
    assert_eq!(
        ReceiveFailure::TransportLimitExceeded.to_string(),
        "OTLP Logs request was rejected"
    );
}
