use std::process::ExitCode;

use positron_config::{
    CommandLineOverrides, ConfigurationFailure, ConfigurationInputs, EnvironmentOverrides,
    SecrecyClass, SettingDefinition, ValueDomain, resolve, setting_definitions, setting_for_path,
};

const EXIT_CONFIGURATION: u8 = 2;

pub(super) fn run(
    arguments: impl Iterator<Item = String>,
    environment: impl IntoIterator<Item = (String, String)>,
) -> ExitCode {
    match execute(arguments, environment) {
        Ok(output) => {
            print!("{output}");
            ExitCode::SUCCESS
        },
        Err(failure) => {
            eprintln!("positron: {}", failure.render());
            ExitCode::from(EXIT_CONFIGURATION)
        },
    }
}

fn execute(
    arguments: impl Iterator<Item = String>,
    environment: impl IntoIterator<Item = (String, String)>,
) -> Result<String, OperatorFailure> {
    match parse(arguments)? {
        Command::Validate(inputs) => {
            let effective = resolve_inputs(inputs, environment)?;
            Ok(format!(
                "status=valid schema_version={} warning_count={}\n",
                effective.schema_version(),
                effective.security_warnings().len()
            ))
        },
        Command::Explain(path) => explain(path.as_deref()),
        Command::Effective(inputs) => Ok(resolve_inputs(inputs, environment)?.redacted_effective()),
        Command::Diff { current, candidate } => {
            let current = resolve_document(&current)?;
            let candidate = resolve_document(&candidate)?;
            let diff = current.semantic_diff(&candidate);
            let mut output = format!(
                "plan={} change_count={}\n",
                diff.plan().as_str(),
                diff.changes().len()
            );
            for change in diff.changes() {
                let before_source = change
                    .before_source()
                    .map_or("unavailable", |source| source.as_str());
                let after_source = change
                    .after_source()
                    .map_or("unavailable", |source| source.as_str());
                output.push_str(&format!(
                    "setting={} before={} before_source={} after={} after_source={} mutability={}\n",
                    change.setting().path(),
                    change.before(),
                    before_source,
                    change.after(),
                    after_source,
                    change.setting().mutability().as_str(),
                ));
            }
            Ok(output)
        },
        Command::Migrate(path) => {
            let effective = resolve_document(&path)?;
            Ok(format!(
                "status=compatible from_schema_version={} to_schema_version={} changed=false\n",
                effective.schema_version(),
                effective.schema_version()
            ))
        },
    }
}

fn resolve_inputs(
    inputs: InputOptions,
    environment: impl IntoIterator<Item = (String, String)>,
) -> Result<positron_config::EffectiveConfiguration, OperatorFailure> {
    let file = inputs
        .config
        .as_deref()
        .map(std::fs::read_to_string)
        .transpose()
        .map_err(|_| OperatorFailure::DocumentUnavailable)?;
    let environment = EnvironmentOverrides::try_from_pairs(
        environment
            .into_iter()
            .filter(|(key, _)| key.starts_with("POSITRON__")),
    )
    .map_err(OperatorFailure::Configuration)?;
    let command_line = CommandLineOverrides::try_from_pairs(inputs.overrides)
        .map_err(OperatorFailure::Configuration)?;
    let inputs = ConfigurationInputs::try_new(file.as_deref(), environment, command_line)
        .map_err(OperatorFailure::Configuration)?;
    resolve(inputs).map_err(OperatorFailure::Configuration)
}

fn resolve_document(
    path: &str,
) -> Result<positron_config::EffectiveConfiguration, OperatorFailure> {
    let document =
        std::fs::read_to_string(path).map_err(|_| OperatorFailure::DocumentUnavailable)?;
    let environment = EnvironmentOverrides::try_from_pairs([] as [(&str, &str); 0])
        .map_err(OperatorFailure::Configuration)?;
    let command_line = CommandLineOverrides::try_from_pairs([] as [(&str, &str); 0])
        .map_err(OperatorFailure::Configuration)?;
    let inputs = ConfigurationInputs::try_new(Some(&document), environment, command_line)
        .map_err(OperatorFailure::Configuration)?;
    resolve(inputs).map_err(OperatorFailure::Configuration)
}

fn explain(path: Option<&str>) -> Result<String, OperatorFailure> {
    let definitions = match path {
        Some(path) => [setting_for_path(path).ok_or(OperatorFailure::UnknownExplainSetting)?]
            .into_iter()
            .map(positron_config::setting_definition)
            .collect::<Vec<_>>(),
        None => setting_definitions().into_iter().collect(),
    };
    let mut output = String::new();
    for (index, definition) in definitions.into_iter().enumerate() {
        if index != 0 {
            output.push('\n');
        }
        render_explanation(&mut output, definition);
    }
    Ok(output)
}

fn render_explanation(output: &mut String, definition: SettingDefinition) {
    let default = if definition.secrecy() == SecrecyClass::SecretBearing {
        "<redacted>"
    } else {
        definition.default_value()
    };
    output.push_str(&format!(
        "setting={} type={} default={} domain={} secrecy={} provenance={} mutability={}\n",
        definition.path(),
        definition.kind().as_str(),
        default,
        domain_description(definition.domain()),
        definition.secrecy().as_str(),
        definition.provenance().as_str(),
        definition.mutability().as_str(),
    ));
}

fn domain_description(domain: ValueDomain) -> String {
    match domain {
        ValueDomain::ExactUnsignedInteger(value) => format!("exact_unsigned_integer:{value}"),
        ValueDomain::StringEnumeration(values) => format!("enum:{}", values.join(",")),
        ValueDomain::UnsignedIntegerRange(minimum, maximum) => {
            format!("unsigned_integer_range:{minimum}..={maximum}")
        },
        ValueDomain::LoopbackSocketAddress(maximum) => {
            format!("loopback_socket_address:max_bytes={maximum}")
        },
        ValueDomain::SocketAddress(maximum) => format!("socket_address:max_bytes={maximum}"),
        ValueDomain::AbsolutePath(maximum) => format!("absolute_path:max_bytes={maximum}"),
        ValueDomain::ProtectedAbsolutePath(maximum) => {
            format!("protected_absolute_path:max_bytes={maximum}")
        },
        ValueDomain::ExportDestinations(maximum, maximum_name_bytes, maximum_tenants) => format!(
            "export_destinations:max_items={maximum},max_name_bytes={maximum_name_bytes},max_tenants={maximum_tenants}"
        ),
    }
}

enum Command {
    Validate(InputOptions),
    Explain(Option<String>),
    Effective(InputOptions),
    Diff { current: String, candidate: String },
    Migrate(String),
}

#[derive(Default)]
struct InputOptions {
    config: Option<String>,
    overrides: Vec<(String, String)>,
}

fn parse(mut arguments: impl Iterator<Item = String>) -> Result<Command, OperatorFailure> {
    match arguments.next().as_deref() {
        Some("validate") => Ok(Command::Validate(parse_inputs(arguments, false)?)),
        Some("explain") => Ok(Command::Explain(parse_explain(arguments)?)),
        Some("effective") => Ok(Command::Effective(parse_effective(arguments)?)),
        Some("diff") => parse_diff(arguments),
        Some("migrate") => parse_migrate(arguments),
        _ => Err(OperatorFailure::Usage),
    }
}

fn parse_inputs(
    mut arguments: impl Iterator<Item = String>,
    require_redacted: bool,
) -> Result<InputOptions, OperatorFailure> {
    let mut inputs = InputOptions::default();
    let mut redacted = false;
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--redacted" if require_redacted && !redacted => redacted = true,
            "--config" if inputs.config.is_none() => {
                inputs.config = Some(arguments.next().ok_or(OperatorFailure::Usage)?);
            },
            "--set" => {
                let value = arguments.next().ok_or(OperatorFailure::Usage)?;
                let (path, value) = value.split_once('=').ok_or(OperatorFailure::Usage)?;
                if path.is_empty() || value.is_empty() {
                    return Err(OperatorFailure::Usage);
                }
                inputs.overrides.push((path.to_owned(), value.to_owned()));
            },
            _ => return Err(OperatorFailure::Usage),
        }
    }
    if require_redacted && !redacted {
        return Err(OperatorFailure::RedactionRequired);
    }
    Ok(inputs)
}

fn parse_effective(
    arguments: impl Iterator<Item = String>,
) -> Result<InputOptions, OperatorFailure> {
    parse_inputs(arguments, true)
}

fn parse_explain(
    mut arguments: impl Iterator<Item = String>,
) -> Result<Option<String>, OperatorFailure> {
    match (arguments.next().as_deref(), arguments.next()) {
        (None, None) => Ok(None),
        (Some("--setting"), Some(path)) if arguments.next().is_none() => Ok(Some(path)),
        _ => Err(OperatorFailure::Usage),
    }
}

fn parse_diff(mut arguments: impl Iterator<Item = String>) -> Result<Command, OperatorFailure> {
    let mut current = None;
    let mut candidate = None;
    while let Some(argument) = arguments.next() {
        let value = arguments.next().ok_or(OperatorFailure::Usage)?;
        match argument.as_str() {
            "--current" if current.is_none() => current = Some(value),
            "--candidate" if candidate.is_none() => candidate = Some(value),
            _ => return Err(OperatorFailure::Usage),
        }
    }
    Ok(Command::Diff {
        current: current.ok_or(OperatorFailure::Usage)?,
        candidate: candidate.ok_or(OperatorFailure::Usage)?,
    })
}

fn parse_migrate(mut arguments: impl Iterator<Item = String>) -> Result<Command, OperatorFailure> {
    match (arguments.next().as_deref(), arguments.next()) {
        (Some("--config"), Some(path)) if arguments.next().is_none() => Ok(Command::Migrate(path)),
        _ => Err(OperatorFailure::Usage),
    }
}

enum OperatorFailure {
    Usage,
    RedactionRequired,
    UnknownExplainSetting,
    DocumentUnavailable,
    Configuration(ConfigurationFailure),
}

impl OperatorFailure {
    fn render(&self) -> String {
        match self {
            Self::Usage => "usage: positron config validate [--config PATH] [--set PATH=VALUE] | explain [--setting PATH] | effective --redacted [--config PATH] [--set PATH=VALUE] | diff --current PATH --candidate PATH | migrate --config PATH".to_owned(),
            Self::RedactionRequired => "effective configuration requires --redacted".to_owned(),
            Self::UnknownExplainSetting => "configuration_rejected code=unknown_setting retry=after_input_correction completion=rejected source=configuration_document".to_owned(),
            Self::DocumentUnavailable => "configuration_rejected code=configuration_document_unavailable retry=after_input_correction completion=rejected source=configuration_document".to_owned(),
            Self::Configuration(failure) => format!(
                "configuration_rejected code={} retry={} completion={} source={}",
                failure.code().as_str(),
                failure.retry_class().as_str(),
                failure.completion_state().as_str(),
                failure.source().as_str(),
            ),
        }
    }
}
