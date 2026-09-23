use std::{
    fmt::{Debug, Formatter},
    fs::File,
    io::Read,
    path::Path,
};

use rustix::fs::{self as unix_fs, Mode, OFlags};

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

/// Failure while assembling canonical configuration inputs from native sources.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigurationInputFailure {
    DocumentUnavailable,
    Configuration(ConfigurationFailure),
}

impl ConfigurationInputs {
    /// Assembles all native sources with canonical precedence and bounded file IO.
    pub fn try_from_sources<EnvironmentKey, EnvironmentValue, CommandLineKey, CommandLineValue>(
        configuration_file: Option<&Path>,
        environment: impl IntoIterator<Item = (EnvironmentKey, EnvironmentValue)>,
        command_line: impl IntoIterator<Item = (CommandLineKey, CommandLineValue)>,
    ) -> Result<Self, ConfigurationInputFailure>
    where
        EnvironmentKey: AsRef<str>,
        EnvironmentValue: AsRef<str>,
        CommandLineKey: AsRef<str>,
        CommandLineValue: AsRef<str>,
    {
        let file = configuration_file
            .map(read_configuration_file)
            .transpose()?;
        let environment = EnvironmentOverrides::try_from_pairs(
            environment
                .into_iter()
                .filter(|(key, _)| key.as_ref().starts_with("POSITRON__")),
        )
        .map_err(Self::configuration_failure)?;
        let command_line = CommandLineOverrides::try_from_pairs(command_line)
            .map_err(Self::configuration_failure)?;
        Self::try_new(file.as_deref(), environment, command_line)
            .map_err(Self::configuration_failure)
    }

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

    const fn configuration_failure(failure: ConfigurationFailure) -> ConfigurationInputFailure {
        ConfigurationInputFailure::Configuration(failure)
    }
}

fn read_configuration_file(path: &Path) -> Result<String, ConfigurationInputFailure> {
    // A path can be replaced after caller-side checks. Opening non-blocking
    // prevents a FIFO or device from turning configuration input into an
    // unbounded wait, and the held descriptor is verified before it is read.
    let file = unix_fs::open(
        path,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|_| ConfigurationInputFailure::DocumentUnavailable)?;
    if !file
        .metadata()
        .map_err(|_| ConfigurationInputFailure::DocumentUnavailable)?
        .file_type()
        .is_file()
    {
        return Err(ConfigurationInputFailure::DocumentUnavailable);
    }
    read_configuration_document(file)
}

fn read_configuration_document(reader: impl Read) -> Result<String, ConfigurationInputFailure> {
    let maximum_bytes = u64::try_from(MAX_CONFIGURATION_BYTES)
        .map_err(|_| ConfigurationInputFailure::DocumentUnavailable)?;
    let mut bytes = Vec::with_capacity(MAX_CONFIGURATION_BYTES + 1);
    reader
        .take(maximum_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ConfigurationInputFailure::DocumentUnavailable)?;
    decode_configuration_document(&bytes)
}

/// Decodes a raw configuration document without lossy UTF-8 replacement.
/// Native-file callers use the same decoder after capped descriptor IO.
pub fn decode_configuration_document(bytes: &[u8]) -> Result<String, ConfigurationInputFailure> {
    if bytes.len() > MAX_CONFIGURATION_BYTES {
        return Err(ConfigurationInputFailure::Configuration(
            ConfigurationFailure::new(
                ConfigurationFailureCode::ResourceLimit,
                FailureSource::ConfigurationDocument,
            ),
        ));
    }
    String::from_utf8(bytes.to_vec()).map_err(|_| {
        ConfigurationInputFailure::Configuration(ConfigurationFailure::new(
            ConfigurationFailureCode::Malformed,
            FailureSource::ConfigurationDocument,
        ))
    })
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

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        io::{self, Read},
        path::Path,
        rc::Rc,
    };

    use super::{
        ConfigurationFailureCode, ConfigurationInputFailure, ConfigurationInputs, FailureSource,
        MAX_CONFIGURATION_BYTES, decode_configuration_document, read_configuration_document,
    };

    struct CountingReader {
        remaining: usize,
        consumed: Rc<Cell<usize>>,
    }

    impl Read for CountingReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let bytes = buffer.len().min(self.remaining);
            buffer[..bytes].fill(b'x');
            self.remaining -= bytes;
            self.consumed.set(self.consumed.get() + bytes);
            Ok(bytes)
        }
    }

    #[test]
    fn configuration_document_reader_stops_after_the_canonical_limit_plus_one() {
        let consumed = Rc::new(Cell::new(0));
        let result = read_configuration_document(CountingReader {
            remaining: MAX_CONFIGURATION_BYTES + 2,
            consumed: Rc::clone(&consumed),
        });

        assert!(matches!(
            result,
            Err(ConfigurationInputFailure::Configuration(failure))
                if failure.code() == ConfigurationFailureCode::ResourceLimit
                    && failure.source() == FailureSource::ConfigurationDocument
        ));
        assert_eq!(consumed.get(), MAX_CONFIGURATION_BYTES + 1);
    }

    #[test]
    fn configuration_document_reader_classifies_invalid_utf8_as_malformed() {
        let result = read_configuration_document(&b"schema_version = 1\n\xff"[..]);

        assert!(matches!(
            result,
            Err(ConfigurationInputFailure::Configuration(failure))
                if failure.code() == ConfigurationFailureCode::Malformed
                    && failure.source() == FailureSource::ConfigurationDocument
        ));
    }

    #[test]
    fn raw_configuration_document_decoder_preserves_byte_failure_classes() {
        let oversized = vec![b'x'; MAX_CONFIGURATION_BYTES + 1];
        let malformed = b"schema_version = 1\n\xff";

        assert!(matches!(
            decode_configuration_document(&oversized),
            Err(ConfigurationInputFailure::Configuration(failure))
                if failure.code() == ConfigurationFailureCode::ResourceLimit
                    && failure.source() == FailureSource::ConfigurationDocument
        ));
        assert!(matches!(
            decode_configuration_document(malformed),
            Err(ConfigurationInputFailure::Configuration(failure))
                if failure.code() == ConfigurationFailureCode::Malformed
                    && failure.source() == FailureSource::ConfigurationDocument
        ));
    }

    #[test]
    fn native_sources_reject_a_non_regular_configuration_path_before_reading() {
        let result = ConfigurationInputs::try_from_sources(
            Some(Path::new("/")),
            [] as [(&str, &str); 0],
            [] as [(&str, &str); 0],
        );

        assert_eq!(result, Err(ConfigurationInputFailure::DocumentUnavailable));
    }
}
