use std::error::Error;
use std::fmt;
use std::io;
use std::path::Path;

#[derive(Debug)]
pub(crate) enum XtaskError {
    Io { action: String, source: io::Error },
    Invalid { subject: String, detail: String },
    Command { command: String, detail: String },
    Timeout { command: String, seconds: u64 },
    Usage(String),
}

impl XtaskError {
    pub(crate) fn io(action: impl Into<String>, source: io::Error) -> Self {
        Self::Io {
            action: action.into(),
            source,
        }
    }

    pub(crate) fn invalid(subject: impl Into<String>, detail: impl Into<String>) -> Self {
        Self::Invalid {
            subject: subject.into(),
            detail: detail.into(),
        }
    }

    pub(crate) fn invalid_path(path: &Path, detail: impl Into<String>) -> Self {
        Self::invalid(path.display().to_string(), detail)
    }

    pub(crate) fn command(command: impl Into<String>, detail: impl Into<String>) -> Self {
        Self::Command {
            command: command.into(),
            detail: detail.into(),
        }
    }

    pub(crate) fn timeout(command: impl Into<String>, seconds: u64) -> Self {
        Self::Timeout {
            command: command.into(),
            seconds,
        }
    }

    pub(crate) fn usage(detail: impl Into<String>) -> Self {
        Self::Usage(detail.into())
    }
}

impl fmt::Display for XtaskError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { action, source } => write!(formatter, "{action}: {source}"),
            Self::Invalid { subject, detail } => {
                write!(formatter, "invalid {subject}: {detail}")
            },
            Self::Command { command, detail } => {
                write!(formatter, "command `{command}` failed: {detail}")
            },
            Self::Timeout { command, seconds } => {
                write!(formatter, "command `{command}` exceeded {seconds} seconds")
            },
            Self::Usage(detail) => formatter.write_str(detail),
        }
    }
}

impl Error for XtaskError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Invalid { .. } | Self::Command { .. } | Self::Timeout { .. } | Self::Usage(_) => {
                None
            },
        }
    }
}
