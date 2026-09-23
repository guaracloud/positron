#![no_main]

use libfuzzer_sys::fuzz_target;
use positron_config::{
    CommandLineOverrides, ConfigurationInputs, EnvironmentOverrides, decode_configuration_document,
    resolve,
};

fuzz_target!(|data: &[u8]| {
    if let Ok(document) = decode_configuration_document(data)
    {
        let environment = EnvironmentOverrides::try_from_pairs([] as [(&str, &str); 0]);
        let command_line = CommandLineOverrides::try_from_pairs([] as [(&str, &str); 0]);
        if let (Ok(environment), Ok(command_line)) = (environment, command_line)
            && let Ok(inputs) = ConfigurationInputs::try_new(Some(&document), environment, command_line)
        {
            let _ = resolve(inputs);
        }
    }
});
