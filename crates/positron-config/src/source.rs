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
        return Err(document_failure(ConfigurationFailureCode::Malformed));
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
    if matches!(value.as_bytes().first(), Some(b'[' | b'{')) {
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
        _ => Err(ConfigurationFailure::new(
            ConfigurationFailureCode::Malformed,
            FailureSource::ConfigurationDocument,
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
