use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};

use super::*;

mod authentication;
mod backend_and_persistence;
mod rejection_and_bounds;
mod vectors;

use backend_and_persistence::protected_segment_fixture;
