//! Frozen bounded-runner registry parsing and identity.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use crate::concurrency_source_policy::SpawnSiteRegistry;
use crate::error::XtaskError;

const REGISTRY_PATH: &str = "qualification/engineering/concurrency-fixtures.tsv";
const REGISTRY_HEADER: &str = "scenario_id\tgate_id\tspawn_site\tschedule\tseed\tmax_tasks\tqueue_capacity\treservation_capacity\tretry_limit\tshutdown_ms\texpected";
pub(super) const SPAWN_SITE_REGISTRY_PATH: &str =
    "qualification/engineering/concurrency-spawn-sites.tsv";
const SPAWN_SITE_REGISTRY_HEADER: &str = "path\tsymbol\tkind\tid";
const MAXIMUM_REGISTRY_BYTES: usize = 16_384;
const MAXIMUM_SCENARIOS: usize = 8;
const MAXIMUM_FIELD_BYTES: usize = 96;
pub(super) const REGISTERED_SPAWN_SITE: &str = "quality-bounded-worker-v1";
const CONCURRENCY_GATE: &str = "EG-CONCURRENCY";
const RESOURCE_GATE: &str = "EG-RESOURCE";
const MAXIMUM_CHILD_ARGUMENT_BYTES: usize = 32_768;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ScenarioGate {
    Concurrency,
    Resource,
}

impl ScenarioGate {
    pub(super) fn parse(value: &str) -> Result<Self, XtaskError> {
        match value {
            CONCURRENCY_GATE => Ok(Self::Concurrency),
            RESOURCE_GATE => Ok(Self::Resource),
            _ => Err(XtaskError::invalid(
                "bounded runner registry",
                format!("unsupported gate `{value}`"),
            )),
        }
    }

    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Concurrency => CONCURRENCY_GATE,
            Self::Resource => RESOURCE_GATE,
        }
    }
}

#[derive(Debug)]
pub(super) struct Scenario {
    pub(super) id: String,
    pub(super) gate: ScenarioGate,
    pub(super) spawn_site: String,
    pub(super) schedule: String,
    pub(super) seed: String,
    pub(super) max_tasks: usize,
    pub(super) queue_capacity: usize,
    pub(super) reservation_capacity: usize,
    pub(super) retry_limit: usize,
    pub(super) shutdown: Duration,
    pub(super) expected: String,
}

#[derive(Debug)]
pub(crate) struct FrozenBoundedRunnerRegistry {
    bytes: Box<[u8]>,
    spawn_site_bytes: Box<[u8]>,
    scenarios: Vec<Scenario>,
    spawn_sites: SpawnSiteRegistry,
}

impl FrozenBoundedRunnerRegistry {
    pub(crate) fn capture(bytes: Vec<u8>, spawn_site_bytes: Vec<u8>) -> Result<Self, XtaskError> {
        let path = Path::new(REGISTRY_PATH);
        if bytes.len() > MAXIMUM_REGISTRY_BYTES {
            return Err(XtaskError::invalid_path(
                path,
                format!("bounded runner registry exceeds {MAXIMUM_REGISTRY_BYTES} bytes"),
            ));
        }
        if spawn_site_bytes.len() > MAXIMUM_REGISTRY_BYTES {
            return Err(XtaskError::invalid_path(
                Path::new(SPAWN_SITE_REGISTRY_PATH),
                format!("bounded spawn-site registry exceeds {MAXIMUM_REGISTRY_BYTES} bytes"),
            ));
        }
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| XtaskError::invalid_path(path, "bounded runner registry is not UTF-8"))?;
        let mut lines = text.lines();
        let Some(header) = lines.next() else {
            return Err(XtaskError::invalid_path(
                path,
                "bounded runner registry is empty",
            ));
        };
        if header != REGISTRY_HEADER {
            return Err(XtaskError::invalid_path(
                path,
                "bounded runner registry header does not match the registered schema",
            ));
        }
        let mut scenarios = Vec::new();
        for (line_number, line) in lines.enumerate() {
            if scenarios.len() >= MAXIMUM_SCENARIOS {
                return Err(XtaskError::invalid_path(
                    path,
                    format!("bounded runner registry exceeds {MAXIMUM_SCENARIOS} scenarios"),
                ));
            }
            let fields = line.split('\t').collect::<Vec<_>>();
            let [
                id,
                gate,
                spawn_site,
                schedule,
                seed,
                max_tasks,
                queue_capacity,
                reservation_capacity,
                retry_limit,
                shutdown_ms,
                expected,
            ] = fields.as_slice()
            else {
                return Err(XtaskError::invalid_path(
                    path,
                    format!(
                        "bounded runner registry row {} has the wrong field count",
                        line_number + 2
                    ),
                ));
            };
            for value in [
                *id,
                *gate,
                *spawn_site,
                *schedule,
                *seed,
                *max_tasks,
                *queue_capacity,
                *reservation_capacity,
                *retry_limit,
                *shutdown_ms,
                *expected,
            ] {
                if value.is_empty() || value.len() > MAXIMUM_FIELD_BYTES {
                    return Err(XtaskError::invalid_path(
                        path,
                        format!(
                            "bounded runner registry row {} contains an invalid bounded field",
                            line_number + 2
                        ),
                    ));
                }
            }
            let gate = ScenarioGate::parse(gate)?;
            let max_tasks = parse_positive(path, max_tasks, "max_tasks")?;
            let queue_capacity = parse_positive(path, queue_capacity, "queue_capacity")?;
            let reservation_capacity =
                parse_positive(path, reservation_capacity, "reservation_capacity")?;
            let retry_limit = parse_positive(path, retry_limit, "retry_limit")?;
            let shutdown = Duration::from_millis(
                u64::try_from(parse_positive(path, shutdown_ms, "shutdown_ms")?).map_err(|_| {
                    XtaskError::invalid_path(path, "shutdown_ms cannot be represented")
                })?,
            );
            if *spawn_site != REGISTERED_SPAWN_SITE {
                return Err(XtaskError::invalid_path(
                    path,
                    "bounded runner registry denied an unregistered spawn site",
                ));
            }
            scenarios.push(Scenario {
                id: (*id).to_owned(),
                gate,
                spawn_site: (*spawn_site).to_owned(),
                schedule: (*schedule).to_owned(),
                seed: (*seed).to_owned(),
                max_tasks,
                queue_capacity,
                reservation_capacity,
                retry_limit,
                shutdown,
                expected: (*expected).to_owned(),
            });
        }
        if scenarios.len() != 2 {
            return Err(XtaskError::invalid_path(
                path,
                "bounded runner registry must contain exactly one scenario per registered gate",
            ));
        }
        for gate in [ScenarioGate::Concurrency, ScenarioGate::Resource] {
            if scenarios
                .iter()
                .filter(|scenario| scenario.gate == gate)
                .count()
                != 1
            {
                return Err(XtaskError::invalid_path(
                    path,
                    format!("{} must have exactly one registered scenario", gate.label()),
                ));
            }
        }
        let spawn_sites = parse_spawn_site_registry(&spawn_site_bytes)?;
        Ok(Self {
            bytes: bytes.into_boxed_slice(),
            spawn_site_bytes: spawn_site_bytes.into_boxed_slice(),
            scenarios,
            spawn_sites,
        })
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn spawn_site_bytes(&self) -> &[u8] {
        &self.spawn_site_bytes
    }

    pub(super) fn spawn_sites(&self) -> &SpawnSiteRegistry {
        &self.spawn_sites
    }

    pub(super) fn scenario(&self, gate: ScenarioGate) -> Result<&Scenario, XtaskError> {
        self.scenarios
            .iter()
            .find(|scenario| scenario.gate == gate)
            .ok_or_else(|| {
                XtaskError::invalid("bounded runner registry", "registered scenario is missing")
            })
    }

    pub(crate) fn shutdown_bound(&self, gate: &str) -> Result<Duration, XtaskError> {
        Ok(self.scenario(ScenarioGate::parse(gate)?)?.shutdown)
    }
}

pub(super) fn hex_encode(bytes: &[u8]) -> Result<String, XtaskError> {
    let capacity = bytes.len().checked_mul(2).ok_or_else(|| {
        XtaskError::invalid(
            "bounded runner child arguments",
            "hex-encoded field length cannot be represented",
        )
    })?;
    if capacity > MAXIMUM_CHILD_ARGUMENT_BYTES {
        return Err(XtaskError::invalid(
            "bounded runner child arguments",
            "hex-encoded field exceeds its exact maximum",
        ));
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(capacity);
    for byte in bytes {
        encoded.push(char::from(hex_digit(HEX, byte >> 4)?));
        encoded.push(char::from(hex_digit(HEX, byte & 0x0f)?));
    }
    Ok(encoded)
}

fn hex_digit(digits: &[u8; 16], index: u8) -> Result<u8, XtaskError> {
    digits.get(usize::from(index)).copied().ok_or_else(|| {
        XtaskError::invalid(
            "bounded runner child arguments",
            "hex digit index escaped its canonical alphabet",
        )
    })
}

fn parse_positive(path: &Path, value: &str, field: &str) -> Result<usize, XtaskError> {
    value
        .parse::<usize>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| {
            XtaskError::invalid_path(path, format!("{field} must be a positive bounded integer"))
        })
}

fn parse_spawn_site_registry(bytes: &[u8]) -> Result<SpawnSiteRegistry, XtaskError> {
    let path = Path::new(SPAWN_SITE_REGISTRY_PATH);
    let registry = std::str::from_utf8(bytes)
        .map_err(|_| XtaskError::invalid_path(path, "frozen spawn-site registry is not UTF-8"))?;
    let mut rows = registry.lines();
    let Some(header) = rows.next() else {
        return Err(XtaskError::invalid_path(
            path,
            "spawn-site registry is empty",
        ));
    };
    if header != SPAWN_SITE_REGISTRY_HEADER {
        return Err(XtaskError::invalid_path(
            path,
            "spawn-site registry header does not match the registered schema",
        ));
    }
    let mut registered = BTreeMap::new();
    for (offset, row) in rows.enumerate() {
        let fields = row.split('\t').collect::<Vec<_>>();
        let [source, symbol, kind, id] = fields.as_slice() else {
            return Err(XtaskError::invalid_path(
                path,
                format!(
                    "spawn-site registry row {} has the wrong field count",
                    offset + 2
                ),
            ));
        };
        if source.is_empty()
            || symbol.is_empty()
            || id.is_empty()
            || source.len() > MAXIMUM_FIELD_BYTES
            || symbol.len() > MAXIMUM_FIELD_BYTES
            || id.len() > MAXIMUM_FIELD_BYTES
            || !matches!(*kind, "process" | "thread")
        {
            return Err(XtaskError::invalid_path(
                path,
                "spawn-site registry contains an invalid bounded lifecycle owner",
            ));
        }
        if registered
            .insert(
                ((*source).to_owned(), (*symbol).to_owned(), (*id).to_owned()),
                (*kind).to_owned(),
            )
            .is_some()
        {
            return Err(XtaskError::invalid_path(
                path,
                "spawn-site registry contains a duplicate semantic spawn site",
            ));
        }
    }
    if registered.is_empty() {
        return Err(XtaskError::invalid_path(
            path,
            "spawn-site registry contains no registered lifecycle owners",
        ));
    }
    Ok(registered)
}
