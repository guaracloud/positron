use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::native_host::otlp_grpc::blocking::BlockingIngestExecutor;

#[test]
fn cancellation_reclaims_the_owned_stalled_worker_within_the_force_bound()
-> Result<(), Box<dyn std::error::Error>> {
    let mut executor =
        BlockingIngestExecutor::start().map_err(|_| "blocking ingest executor did not start")?;
    let (entered_sender, entered_receiver) = mpsc::sync_channel(1);
    executor
        .handle()
        .map_err(|_| "blocking ingest executor handle was unavailable")?
        .stall_for_test(entered_sender)?;
    entered_receiver.recv_timeout(Duration::from_secs(1))?;

    let started = Instant::now();
    assert!(
        executor
            .shutdown_within(Duration::from_millis(100))
            .map_err(|_| "blocking ingest executor shutdown failed")?
    );
    assert!(started.elapsed() < Duration::from_millis(250));
    Ok(())
}
