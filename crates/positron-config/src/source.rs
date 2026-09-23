use super::*;

fn preflight_toml(file: &str) -> Result<(), ConfigurationFailure> {
    let mut entry_count = 0_usize;
    for raw_line in file.lines() {
        let line = content_before_comment(raw_line)?.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            preflight_table_header(line)?;
            entry_count = entry_count
                .checked_add(1)
                .ok_or_else(|| document_failure(ConfigurationFailureCode::ResourceLimit))?;
            if entry_count > MAX_TOML_ENTRIES {
                return Err(document_failure(ConfigurationFailureCode::ResourceLimit));
            }
            continue;
        }
        let Some(separator) = unquoted_equals(line)? else {
            return Err(document_failure(ConfigurationFailureCode::Malformed));
        };
        let key = line
            .get(..separator)
            .ok_or_else(|| document_failure(ConfigurationFailureCode::Malformed))?
            .trim();
        let value = line
            .get(separator.saturating_add(1)..)
            .ok_or_else(|| document_failure(ConfigurationFailureCode::Malformed))?
            .trim();
        preflight_key(key)?;
        entry_count = entry_count
            .checked_add(1)
            .ok_or_else(|| document_failure(ConfigurationFailureCode::ResourceLimit))?;
        if entry_count > MAX_TOML_ENTRIES {
            return Err(document_failure(ConfigurationFailureCode::ResourceLimit));
        }
        preflight_scalar(value)?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum QuoteState {
    Unquoted,
    Basic,
    BasicEscape,
    Literal,
}

fn content_before_comment(line: &str) -> Result<&str, ConfigurationFailure> {
    let mut state = QuoteState::Unquoted;
    for (index, byte) in line.bytes().enumerate() {
        state = match state {
            QuoteState::BasicEscape => QuoteState::Basic,
            QuoteState::Basic => match byte {
                b'\\' => QuoteState::BasicEscape,
                b'"' => QuoteState::Unquoted,
                _ => QuoteState::Basic,
            },
            QuoteState::Literal => match byte {
                b'\'' => QuoteState::Unquoted,
                _ => QuoteState::Literal,
            },
            QuoteState::Unquoted => match byte {
                b'"' => QuoteState::Basic,
                b'\'' => QuoteState::Literal,
                b'#' => {
                    return line
                        .get(..index)
                        .ok_or_else(|| document_failure(ConfigurationFailureCode::Malformed));
                },
                _ => QuoteState::Unquoted,
            },
        };
    }
    match state {
        QuoteState::Unquoted => Ok(line),
        QuoteState::Basic | QuoteState::BasicEscape | QuoteState::Literal => {
            Err(document_failure(ConfigurationFailureCode::Malformed))
        },
    }
}

fn preflight_table_header(line: &str) -> Result<(), ConfigurationFailure> {
    if line.starts_with("[[") {
        return if line == "[[export.destination]]" {
            Ok(())
        } else {
            Err(document_failure(ConfigurationFailureCode::Malformed))
        };
    }
    if !line.ends_with(']') {
        return Err(document_failure(ConfigurationFailureCode::Malformed));
    }
    let name = line
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .ok_or_else(|| document_failure(ConfigurationFailureCode::Malformed))?
        .trim();
    if name.len() > MAX_KEY_BYTES {
        return Err(document_failure(ConfigurationFailureCode::ResourceLimit));
    }
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err(document_failure(ConfigurationFailureCode::Malformed));
    }
    Ok(())
}

fn unquoted_equals(line: &str) -> Result<Option<usize>, ConfigurationFailure> {
    let mut state = QuoteState::Unquoted;
    for (index, byte) in line.bytes().enumerate() {
        state = match state {
            QuoteState::BasicEscape => QuoteState::Basic,
            QuoteState::Basic => match byte {
                b'\\' => QuoteState::BasicEscape,
                b'"' => QuoteState::Unquoted,
                _ => QuoteState::Basic,
            },
            QuoteState::Literal => match byte {
                b'\'' => QuoteState::Unquoted,
                _ => QuoteState::Literal,
            },
            QuoteState::Unquoted => match byte {
                b'"' => QuoteState::Basic,
                b'\'' => QuoteState::Literal,
                b'=' => return Ok(Some(index)),
                _ => QuoteState::Unquoted,
            },
        };
    }
    match state {
        QuoteState::Unquoted => Ok(None),
        QuoteState::Basic | QuoteState::BasicEscape | QuoteState::Literal => {
            Err(document_failure(ConfigurationFailureCode::Malformed))
        },
    }
}

fn preflight_key(key: &str) -> Result<(), ConfigurationFailure> {
    if key.len() > MAX_KEY_BYTES {
        return Err(document_failure(ConfigurationFailureCode::ResourceLimit));
    }
    if !key
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err(document_failure(ConfigurationFailureCode::Malformed));
    }
    Ok(())
}

fn preflight_scalar(value: &str) -> Result<(), ConfigurationFailure> {
    if value.is_empty() {
        return Err(document_failure(ConfigurationFailureCode::Malformed));
    }
    if value.starts_with('[') {
        return if value.len() <= 512 {
            Ok(())
        } else {
            Err(document_failure(ConfigurationFailureCode::ResourceLimit))
        };
    }
    if value.starts_with('{') {
        return Err(document_failure(ConfigurationFailureCode::Malformed));
    }
    let scalar_bytes = if let Some(inner) = value
        .strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
    {
        if value.starts_with("\"\"\"") {
            return Err(document_failure(ConfigurationFailureCode::Malformed));
        }
        inner.len()
    } else if let Some(inner) = value
        .strip_prefix('\'')
        .and_then(|inner| inner.strip_suffix('\''))
    {
        if value.starts_with("'''") {
            return Err(document_failure(ConfigurationFailureCode::Malformed));
        }
        inner.len()
    } else {
        value.len()
    };
    if scalar_bytes > MAX_VALUE_BYTES {
        return Err(document_failure(ConfigurationFailureCode::ResourceLimit));
    }
    Ok(())
}

const fn document_failure(code: ConfigurationFailureCode) -> ConfigurationFailure {
    ConfigurationFailure::new(code, FailureSource::ConfigurationDocument)
}

fn environment_path(key: &str) -> Option<String> {
    let suffix = key.strip_prefix("POSITRON__")?;
    if suffix.is_empty()
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return None;
    }
    let segments = suffix.split("__").collect::<Vec<_>>();
    if segments.iter().any(|segment| segment.is_empty()) {
        return None;
    }
    Some(
        segments
            .into_iter()
            .map(str::to_ascii_lowercase)
            .collect::<Vec<_>>()
            .join("."),
    )
}

pub(super) fn apply_toml(
    candidate: &mut Candidate,
    file: &str,
) -> Result<(), ConfigurationFailure> {
    preflight_toml(file)?;
    let table = file.parse::<toml::Table>().map_err(|_| {
        ConfigurationFailure::new(
            ConfigurationFailureCode::Malformed,
            FailureSource::ConfigurationDocument,
        )
    })?;

    let Some(schema_version) = table.get("schema_version") else {
        return Err(ConfigurationFailure::new(
            ConfigurationFailureCode::MissingSchemaVersion,
            FailureSource::SchemaVersion,
        ));
    };
    apply_toml_value(candidate, Setting::SchemaVersion, schema_version)?;

    for section in table.keys().filter(|section| *section != "schema_version") {
        if !is_known_toml_section(section) {
            return Err(document_failure(ConfigurationFailureCode::UnknownSetting));
        }
    }

    for (section, value) in &table {
        if section == "schema_version" {
            continue;
        }
        let toml::Value::Table(settings) = value else {
            return Err(document_failure(ConfigurationFailureCode::UnknownSetting));
        };
        if section == "export" {
            apply_export_destinations(candidate, settings)?;
            continue;
        }
        for (key, setting_value) in settings {
            let mut path = String::with_capacity(section.len() + key.len() + 1);
            path.push_str(section);
            path.push('.');
            path.push_str(key);
            let Some(setting) = setting_for_path(&path) else {
                return Err(ConfigurationFailure::new(
                    ConfigurationFailureCode::UnknownSetting,
                    FailureSource::ConfigurationDocument,
                ));
            };
            apply_toml_value(candidate, setting, setting_value)?;
        }
    }
    Ok(())
}

fn is_known_toml_section(section: &str) -> bool {
    if section == "export" {
        return true;
    }
    contract::SETTING_DEFINITIONS
        .iter()
        .filter_map(|definition| definition.path().split_once('.'))
        .any(|(known_section, _)| known_section == section)
}

fn apply_toml_value(
    candidate: &mut Candidate,
    setting: Setting,
    value: &toml::Value,
) -> Result<(), ConfigurationFailure> {
    match (setting_definition(setting).kind(), value) {
        (SettingKind::Integer, toml::Value::Integer(value)) => candidate.apply(
            setting,
            &value.to_string(),
            SettingSource::ConfigurationFile,
        ),
        (SettingKind::String, toml::Value::String(value)) => {
            candidate.apply(setting, value, SettingSource::ConfigurationFile)
        },
        (SettingKind::ExportDestinations, _) => Err(ConfigurationFailure::new(
            ConfigurationFailureCode::Malformed,
            FailureSource::ExportDestinations,
        )),
        _ => Err(ConfigurationFailure::new(
            ConfigurationFailureCode::Malformed,
            FailureSource::ConfigurationDocument,
        )),
    }
}

fn apply_export_destinations(
    candidate: &mut Candidate,
    table: &toml::map::Map<String, toml::Value>,
) -> Result<(), ConfigurationFailure> {
    if table.len() != 1 {
        return Err(document_failure(ConfigurationFailureCode::UnknownSetting));
    }
    let Some(toml::Value::Array(entries)) = table.get("destination") else {
        return Err(document_failure(ConfigurationFailureCode::UnknownSetting));
    };
    let ValueDomain::ExportDestinations(maximum_destinations, maximum_name_bytes, maximum_tenants) =
        setting_definition(Setting::ExportDestinations).domain()
    else {
        return Err(ConfigurationFailure::new(
            ConfigurationFailureCode::Malformed,
            FailureSource::ExportDestinations,
        ));
    };
    if entries.len() > maximum_destinations {
        return Err(ConfigurationFailure::unsupported_value(
            FailureSource::ExportDestinations,
        ));
    }

    let mut destinations = Vec::with_capacity(entries.len());
    for entry in entries {
        let toml::Value::Table(entry) = entry else {
            return Err(ConfigurationFailure::unsupported_value(
                FailureSource::ExportDestinations,
            ));
        };
        let destination = parse_export_destination(entry, maximum_name_bytes, maximum_tenants)?;
        if destinations
            .iter()
            .any(|existing: &ExportDestinationDefinition| {
                existing.name == destination.name || existing.identity == destination.identity
            })
        {
            return Err(ConfigurationFailure::unsupported_value(
                FailureSource::ExportDestinations,
            ));
        }
        destinations.push(destination);
    }
    destinations.sort_unstable_by(|left, right| left.name.cmp(&right.name));
    candidate.apply_export_destinations(destinations)
}

fn parse_export_destination(
    entry: &toml::map::Map<String, toml::Value>,
    maximum_name_bytes: usize,
    maximum_tenants: usize,
) -> Result<ExportDestinationDefinition, ConfigurationFailure> {
    if entry.len() != 3
        || entry
            .keys()
            .any(|key| !matches!(key.as_str(), "name" | "identity" | "allowed_tenants"))
    {
        return Err(document_failure(ConfigurationFailureCode::UnknownSetting));
    }
    let Some(toml::Value::String(name)) = entry.get("name") else {
        return Err(ConfigurationFailure::unsupported_value(
            FailureSource::ExportDestinations,
        ));
    };
    if !valid_export_destination_name(name, maximum_name_bytes) {
        return Err(ConfigurationFailure::unsupported_value(
            FailureSource::ExportDestinations,
        ));
    }
    let Some(toml::Value::String(identity)) = entry.get("identity") else {
        return Err(ConfigurationFailure::unsupported_value(
            FailureSource::ExportDestinations,
        ));
    };
    let identity = parse_export_identity(identity)?;
    let Some(toml::Value::Array(tenant_values)) = entry.get("allowed_tenants") else {
        return Err(ConfigurationFailure::unsupported_value(
            FailureSource::ExportDestinations,
        ));
    };
    if tenant_values.is_empty() || tenant_values.len() > maximum_tenants {
        return Err(ConfigurationFailure::unsupported_value(
            FailureSource::ExportDestinations,
        ));
    }
    let mut allowed_tenants = Vec::with_capacity(tenant_values.len());
    for value in tenant_values {
        let toml::Value::String(value) = value else {
            return Err(ConfigurationFailure::unsupported_value(
                FailureSource::ExportDestinations,
            ));
        };
        let tenant = TenantId::parse_canonical(value).map_err(|_| {
            ConfigurationFailure::unsupported_value(FailureSource::ExportDestinations)
        })?;
        if allowed_tenants.contains(&tenant) {
            return Err(ConfigurationFailure::unsupported_value(
                FailureSource::ExportDestinations,
            ));
        }
        allowed_tenants.push(tenant);
    }
    allowed_tenants.sort_unstable();
    Ok(ExportDestinationDefinition {
        name: name.to_owned(),
        identity,
        allowed_tenants,
    })
}

fn valid_export_destination_name(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn parse_export_identity(value: &str) -> Result<[u8; 16], ConfigurationFailure> {
    if value.len() != 32
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ConfigurationFailure::unsupported_value(
            FailureSource::ExportDestinations,
        ));
    }
    let mut identity = [0_u8; 16];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let [high, low] = *pair else {
            return Err(ConfigurationFailure::unsupported_value(
                FailureSource::ExportDestinations,
            ));
        };
        let high = hexadecimal_nibble(high)?;
        let low = hexadecimal_nibble(low)?;
        let Some(slot) = identity.get_mut(index) else {
            return Err(ConfigurationFailure::unsupported_value(
                FailureSource::ExportDestinations,
            ));
        };
        *slot = (high << 4) | low;
    }
    if identity.iter().all(|byte| *byte == 0) {
        return Err(ConfigurationFailure::unsupported_value(
            FailureSource::ExportDestinations,
        ));
    }
    Ok(identity)
}

fn hexadecimal_nibble(value: u8) -> Result<u8, ConfigurationFailure> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(ConfigurationFailure::unsupported_value(
            FailureSource::ExportDestinations,
        )),
    }
}

pub(super) fn apply_environment(
    candidate: &mut Candidate,
    overrides: &EnvironmentOverrides,
) -> Result<(), ConfigurationFailure> {
    for (key, value) in &overrides.pairs {
        let Some(path) = environment_path(key) else {
            return Err(ConfigurationFailure::new(
                ConfigurationFailureCode::UnknownSetting,
                FailureSource::EnvironmentOverride,
            ));
        };
        let Some(setting) = setting_for_path(&path) else {
            return Err(ConfigurationFailure::new(
                ConfigurationFailureCode::UnknownSetting,
                FailureSource::EnvironmentOverride,
            ));
        };
        candidate.apply(setting, value, SettingSource::Environment)?;
    }
    Ok(())
}

pub(super) fn apply_command_line(
    candidate: &mut Candidate,
    overrides: &CommandLineOverrides,
) -> Result<(), ConfigurationFailure> {
    for (key, value) in &overrides.pairs {
        let Some(setting) = setting_for_path(key) else {
            return Err(ConfigurationFailure::new(
                ConfigurationFailureCode::UnknownSetting,
                FailureSource::CommandLineOverride,
            ));
        };
        candidate.apply(setting, value, SettingSource::CommandLine)?;
    }
    Ok(())
}
