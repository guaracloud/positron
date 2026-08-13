use std::error::Error;

use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
use positron_ingest::{AuthenticatedOtlpLogsRequest, OtlpLogsReceiver, ReceiveFailure};
use positron_kernel::MountQualification;
use positron_runtime::{BootstrapPaths, InitializationPlan, InstanceBootstrap};

use super::support::temporary_roots;

#[test]
fn bearer_authentication_precedes_malformed_gzip_and_protobuf() -> Result<(), Box<dyn Error>> {
    let roots = temporary_roots()?;
    let data = roots.data();
    let secrets = roots.secrets();
    let paths = BootstrapPaths::new(&data, &secrets, MountQualification::LocalHost)?;
    InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;

    let rejected = instance.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::Ingest,
        CompatibilityHints::none(),
    );
    assert!(rejected.is_err(), "system administrator cannot ingest");

    let invalid_bearer = format!("pos_{}", "00".repeat(32));
    assert!(
        instance
            .attribute(
                PresentedCredential::parse(&invalid_bearer)?,
                RequestedIntent::Ingest,
                CompatibilityHints::none(),
            )
            .is_err(),
        "invalid bearer is rejected before receiver work",
    );
    assert!(
        instance
            .attribute(
                PresentedCredential::parse(claim.ingest_secret().expect("ingest credential"))?,
                RequestedIntent::Ingest,
                CompatibilityHints::external_tenant_alias("other-tenant")?,
            )
            .is_err(),
        "conflicting external alias is rejected before receiver work",
    );

    let authorized = instance.attribute(
        PresentedCredential::parse(claim.ingest_secret().expect("ingest credential"))?,
        RequestedIntent::Ingest,
        CompatibilityHints::none(),
    )?;
    let governor = instance.resource_governor();
    assert_eq!(governor.inspect()?.outstanding_reservations(), 0);
    let request = AuthenticatedOtlpLogsRequest::gzip_protobuf(authorized, governor, vec![1, 2, 3])?;
    assert_eq!(governor.inspect()?.outstanding_reservations(), 1);
    assert_eq!(
        OtlpLogsReceiver::new()
            .decode(request)
            .expect_err("authenticated malformed gzip"),
        ReceiveFailure::MalformedCompression,
    );
    assert_eq!(governor.inspect()?.outstanding_reservations(), 0);
    Ok(())
}
