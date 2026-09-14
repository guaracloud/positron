use super::operations::{MethodSpec, SERVICES};
use prost::Message;
use std::error::Error;
use std::path::Path;

pub(crate) struct Operation {
    path: String,
    request_limit: usize,
    response_limit: usize,
}

impl Operation {
    pub(crate) fn path(&self) -> &str {
        &self.path
    }

    pub(crate) fn request_limit(&self) -> usize {
        self.request_limit
    }

    pub(crate) fn response_limit(&self) -> usize {
        self.response_limit
    }
}

pub(crate) struct ValidatedOperations {
    operations: Vec<(String, Operation)>,
}

impl ValidatedOperations {
    pub(crate) fn load(
        descriptor_path: &Path,
        mapping_path: &Path,
    ) -> Result<Self, Box<dyn Error>> {
        let descriptor =
            prost_types::FileDescriptorSet::decode(std::fs::read(descriptor_path)?.as_slice())?;
        let mapping: serde_json::Value = serde_json::from_slice(&std::fs::read(mapping_path)?)?;
        let routes = mapping["mappings"]
            .as_array()
            .ok_or("canonical HTTP mapping has no mappings array")?;
        let mut operations = Vec::new();

        for service in SERVICES {
            for method in service.methods {
                validate_descriptor_method(&descriptor, service.name, method)?;
                let rpc = format!("positron.v1.{}/{}", service.name, method.name);
                let route = routes
                    .iter()
                    .find(|route| route["rpc"] == rpc)
                    .ok_or_else(|| format!("{rpc} is missing from canonical HTTP mapping"))?;
                let path = route["path"]
                    .as_str()
                    .filter(|path| path.starts_with('/'))
                    .ok_or_else(|| format!("{rpc} HTTP path is invalid"))?;
                let request_limit = route["max_request_bytes"]
                    .as_u64()
                    .and_then(|limit| usize::try_from(limit).ok())
                    .ok_or_else(|| format!("{rpc} request limit is invalid"))?;
                let response_limit = route["max_response_bytes"]
                    .as_u64()
                    .and_then(|limit| usize::try_from(limit).ok())
                    .ok_or_else(|| format!("{rpc} response limit is invalid"))?;
                operations.push((
                    rpc,
                    Operation {
                        path: path.to_owned(),
                        request_limit,
                        response_limit,
                    },
                ));
            }
        }

        Ok(Self { operations })
    }

    pub(crate) fn operation(&self, rpc: &str) -> Result<&Operation, Box<dyn Error>> {
        self.operations
            .iter()
            .find(|(candidate, _)| candidate == rpc)
            .map(|(_, operation)| operation)
            .ok_or_else(|| format!("{rpc} is not a generated client operation").into())
    }
}

fn validate_descriptor_method(
    descriptor: &prost_types::FileDescriptorSet,
    service_name: &str,
    method: &MethodSpec,
) -> Result<(), Box<dyn Error>> {
    let found = descriptor.file.iter().any(|file| {
        file.package.as_deref() == Some("positron.v1")
            && file.service.iter().any(|service| {
                service.name.as_deref() == Some(service_name)
                    && service.method.iter().any(|candidate| {
                        candidate.name.as_deref() == Some(method.name)
                            && candidate.input_type.as_deref() == Some(method.input)
                            && candidate.output_type.as_deref() == Some(method.output)
                    })
            })
    });
    if found {
        Ok(())
    } else {
        Err(format!(
            "{service_name}/{} is missing from the canonical protobuf descriptor",
            method.name
        )
        .into())
    }
}
