use std::error::Error;

use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
use positron_ingest::{AuthenticatedLokiPushRequest, LokiPushReceiver, ReceiveFailure};
use positron_kernel::MountQualification;
use positron_runtime::{BootstrapPaths, InitializationPlan, InstanceBootstrap};

use super::support::{fixture, temporary_roots};

#[test]
fn json_stream_labels_reject_empty_invalid_and_duplicate_names_before_decode()
-> Result<(), Box<dyn Error>> {
    let roots = temporary_roots()?;
    let paths = BootstrapPaths::new(
        &roots.data(),
        &roots.secrets(),
        MountQualification::LocalHost,
    )?;
    InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let fixture = fixture(instance.default_tenant_id())?;
    let ingest_secret = claim.ingest_secret().ok_or("missing credential")?;
    let governor = fixture.authority.governor();

    for stream in [
        r#"{}"#,
        r#"{"1bad":"value"}"#,
        r#"{"bad.name":"value"}"#,
        r#"{"bad:name":"value"}"#,
        r#"{"nonasciié":"value"}"#,
        r#"{"dup":"first","dup":"second"}"#,
    ] {
        let credential = PresentedCredential::parse(ingest_secret)?;
        let context = instance.attribute(
            credential,
            RequestedIntent::Ingest,
            CompatibilityHints::none(),
        )?;
        let body = format!(r#"{{"streams":[{{"stream":{stream},"values":[["1","line"]]}}]}}"#);
        let request = AuthenticatedLokiPushRequest::json(context, governor, body.into_bytes())?;
        assert_eq!(
            LokiPushReceiver::new()
                .decode(request)
                .expect_err("invalid label set must fail"),
            ReceiveFailure::MalformedPayload,
        );
        assert_eq!(governor.inspect()?.outstanding_reservations(), 0);
    }
    for body in [
        br#"{"streams":[],"streams":[]}"#.as_slice(),
        br#"{"streams":[{"stream":{"app":"one"},"stream":{"app":"two"},"values":[]}] }"#.as_slice(),
        br#"{"streams":[{"stream":{"app":"one"},"values":[],"values":[]}] }"#.as_slice(),
    ] {
        let credential = PresentedCredential::parse(ingest_secret)?;
        let context = instance.attribute(
            credential,
            RequestedIntent::Ingest,
            CompatibilityHints::none(),
        )?;
        let request = AuthenticatedLokiPushRequest::json(context, governor, body.to_vec())?;
        assert_eq!(
            LokiPushReceiver::new()
                .decode(request)
                .expect_err("duplicate schema key must fail before serde"),
            ReceiveFailure::MalformedPayload,
        );
        assert_eq!(governor.inspect()?.outstanding_reservations(), 0);
    }
    Ok(())
}
