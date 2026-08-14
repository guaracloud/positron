use std::fmt::{Debug, Formatter};

use super::{
    ConfigurationFailure, ConfigurationFailureCode, FailureSource, MAX_CONFIGURATION_BYTES,
    MAX_KEY_BYTES, MAX_OVERRIDE_PAIRS, MAX_VALUE_BYTES,
};

#[derive(Clone, Eq, PartialEq)]
pub struct EnvironmentOverrides {
    pub(crate) pairs: Vec<(String, String)>,
}

impl EnvironmentOverrides {
    pub fn try_from_pairs<K, V>(
        pairs: impl IntoIterator<Item = (K, V)>,
    ) -> Result<Self, ConfigurationFailure>
    where
        K: AsRef<str>,
        V: AsRef<str>,
    {
        collect_pairs(pairs, FailureSource::EnvironmentOverride).map(|pairs| Self { pairs })
    }
}

impl Debug for EnvironmentOverrides {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EnvironmentOverrides")
            .field("pairs", &"<redacted>")
            .field("pair_count", &self.pairs.len())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct CommandLineOverrides {
    pub(crate) pairs: Vec<(String, String)>,
}

impl CommandLineOverrides {
    pub fn try_from_pairs<K, V>(
        pairs: impl IntoIterator<Item = (K, V)>,
    ) -> Result<Self, ConfigurationFailure>
    where
        K: AsRef<str>,
        V: AsRef<str>,
    {
        collect_pairs(pairs, FailureSource::CommandLineOverride).map(|pairs| Self { pairs })
    }
}

impl Debug for CommandLineOverrides {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CommandLineOverrides")
            .field("pairs", &"<redacted>")
            .field("pair_count", &self.pairs.len())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ConfigurationInputs {
    pub(crate) file: Option<String>,
    pub(crate) environment: EnvironmentOverrides,
    pub(crate) command_line: CommandLineOverrides,
}

impl Debug for ConfigurationInputs {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConfigurationInputs")
            .field("file", &self.file.as_ref().map(|_| "<redacted>"))
            .field("environment", &self.environment)
            .field("command_line", &self.command_line)
            .finish()
    }
}

impl ConfigurationInputs {
    pub fn try_new(
        file: Option<&str>,
        environment: EnvironmentOverrides,
        command_line: CommandLineOverrides,
    ) -> Result<Self, ConfigurationFailure> {
        let file = match file {
            Some(value) => {
                if value.len() > MAX_CONFIGURATION_BYTES {
                    return Err(ConfigurationFailure::new(
                        ConfigurationFailureCode::ResourceLimit,
                        FailureSource::ConfigurationDocument,
                    ));
                }
                Some(value.to_owned())
            },
            None => None,
        };
        Ok(Self {
            file,
            environment,
            command_line,
        })
    }
}

fn collect_pairs<K, V>(
    pairs: impl IntoIterator<Item = (K, V)>,
    source: FailureSource,
) -> Result<Vec<(String, String)>, ConfigurationFailure>
where
    K: AsRef<str>,
    V: AsRef<str>,
{
    let mut collected = Vec::with_capacity(MAX_OVERRIDE_PAIRS);
    for (key, value) in pairs {
        let key = key.as_ref();
        let value = value.as_ref();
        if collected.len() == MAX_OVERRIDE_PAIRS
            || key.len() > MAX_KEY_BYTES
            || value.len() > MAX_VALUE_BYTES
        {
            return Err(ConfigurationFailure::new(
                ConfigurationFailureCode::ResourceLimit,
                source,
            ));
        }
        if collected.iter().any(|(existing, _)| existing == key) {
            return Err(ConfigurationFailure::new(
                ConfigurationFailureCode::ConflictingSetting,
                source,
            ));
        }
        collected.push((key.to_owned(), value.to_owned()));
    }
    Ok(collected)
}
