#![no_main]

use std::cell::OnceCell;
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use libfuzzer_sys::fuzz_target;
use positron_governance::{
    AuthorizedContext, CompatibilityHints, PresentedCredential, RequestedIntent,
};
use positron_ingest::{AuthenticatedLokiPushRequest, LokiPushReceiver};
use positron_kernel::MountQualification;
use positron_runtime::{
    BootstrapPaths, InitializationPlan, InitializedInstance, InstanceBootstrap,
};

const MAXIMUM_INPUT_BYTES: usize = 1_048_577;

thread_local! {
    static FIXTURE: OnceCell<Option<FuzzFixture>> = const { OnceCell::new() };
}

struct FuzzFixture {
    instance: InitializedInstance,
    context: AuthorizedContext,
    _root: FuzzRoot,
}

struct FuzzRoot(PathBuf);

impl FuzzFixture {
    fn establish() -> Option<Self> {
        Self::try_establish().ok()
    }

    fn try_establish() -> Result<Self, Box<dyn Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root =
            std::env::temp_dir().join(format!("positron-loki-fuzz-{}-{nonce}", std::process::id()));
        let data = root.join("data");
        let secrets = root.join("secrets");
        fs::create_dir_all(&data)?;
        fs::create_dir_all(&secrets)?;
        set_owner_only(&secrets)?;
        let paths = BootstrapPaths::new(&data, &secrets, MountQualification::LocalHost)?;
        drop(InstanceBootstrap::initialize(
            &paths,
            InitializationPlan::non_interactive(),
        )?);
        let claim = InstanceBootstrap::claim(&paths)?;
        let instance = InstanceBootstrap::reopen(&paths)?;
        let context = instance.attribute(
            PresentedCredential::parse(claim.ingest_secret().ok_or("missing ingest credential")?)?,
            RequestedIntent::Ingest,
            CompatibilityHints::none(),
        )?;
        Ok(Self {
            instance,
            context,
            _root: FuzzRoot(root),
        })
    }

    fn exercise(&self, selector: u8, body: Vec<u8>) {
        let governor = self.instance.resource_governor();
        let request = match selector % 4 {
            0 => AuthenticatedLokiPushRequest::json(self.context, governor, body),
            1 => AuthenticatedLokiPushRequest::gzip_json(self.context, governor, body),
            2 => AuthenticatedLokiPushRequest::deflate_json(self.context, governor, body),
            _ => AuthenticatedLokiPushRequest::snappy_protobuf(self.context, governor, body),
        };
        if let Ok(request) = request {
            let _ = LokiPushReceiver::new().decode(request);
        }
    }
}

impl Drop for FuzzRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(unix)]
fn set_owner_only(path: &std::path::Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAXIMUM_INPUT_BYTES {
        return;
    }
    let selector = data.first().copied().unwrap_or_default();
    let body = data.get(1..).unwrap_or_default().to_vec();
    FIXTURE.with(|fixture| {
        if let Some(fixture) = fixture.get_or_init(FuzzFixture::establish) {
            fixture.exercise(selector, body);
        }
    });
});
