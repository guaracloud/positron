use super::{OtlpLogsReceiver, ReceiveFailure};

mod group_capacity;
mod json_semantics;
mod metadata_accounting;
mod receiver_identity;
mod zero_identifiers;

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
