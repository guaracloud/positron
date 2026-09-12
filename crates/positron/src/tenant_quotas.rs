use std::io::{IsTerminal, Read};
use std::net::SocketAddr;
use std::process::ExitCode;

use positron_api::tenant_quotas::{
    TenantQuotaResources, TenantQuotaServiceClient, TenantQuotaServiceClientFailure,
    TenantQuotaTransport, TenantQuotaUpdateRequest,
};
use zeroize::Zeroizing;

pub(super) fn run(arguments: impl Iterator<Item = String>) -> ExitCode {
    match execute(arguments) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("positron: {message}");
            ExitCode::from(2)
        },
    }
}

fn execute(arguments: impl Iterator<Item = String>) -> Result<(), &'static str> {
    let (transport, request) = parse(arguments)?;
    let input = std::io::stdin();
    if input.is_terminal() {
        return Err("credential input must be a pipe; terminal input is refused to prevent echo");
    }
    let mut credential = Zeroizing::new(String::new());
    input
        .take(1025)
        .read_to_string(&mut credential)
        .map_err(|_| "credential input unavailable")?;
    let bearer = credential.trim_end_matches(['\r', '\n']);
    if credential.len() > 1024
        || bearer.is_empty()
        || bearer.len() > 1024
        || !bearer
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err("invalid credential input");
    }
    let client =
        TenantQuotaServiceClient::new(transport).map_err(|_| "API endpoint unavailable")?;
    let response = client.update(bearer, &request).map_err(client_failure)?;
    println!("resource_generation={}", response.resource_generation);
    Ok(())
}

fn client_failure(failure: TenantQuotaServiceClientFailure) -> &'static str {
    match failure {
        TenantQuotaServiceClientFailure::InvalidRequest => {
            "invalid tenant quota request; correct the request before retrying"
        },
        TenantQuotaServiceClientFailure::AuthenticationRejected => "authentication rejected",
        TenantQuotaServiceClientFailure::StaleGeneration { .. } => {
            "stale generation; inspect current state before retrying"
        },
        TenantQuotaServiceClientFailure::IdempotencyConflict => {
            "idempotency conflict; inspect current state before retrying"
        },
        TenantQuotaServiceClientFailure::AdministrationUnavailable => {
            "administration unavailable; retry with the same idempotency key"
        },
        TenantQuotaServiceClientFailure::Transport => {
            "API transport unavailable; inspect state before retrying"
        },
    }
}

fn parse(
    mut arguments: impl Iterator<Item = String>,
) -> Result<(TenantQuotaTransport, TenantQuotaUpdateRequest), &'static str> {
    if arguments.next().as_deref() != Some("quota") || arguments.next().as_deref() != Some("update")
    {
        return Err(
            "usage: positron tenant quota update --endpoint IP:PORT --credential-stdin --tenant ID --expected-generation N --idempotency-key UUID --weight N --memory-bytes N --queue-slots N --task-slots N --buffer-cache-bytes N --batch-items N --lease-slots N --retry-slots N --io-permits N --cpu-work-units N --file-descriptors N --disk-headroom-bytes N [--server-name NAME --trust-file PATH | --allow-plaintext]",
        );
    }
    let mut options = std::collections::BTreeMap::new();
    let mut credential_stdin = false;
    let mut allow_plaintext = false;
    while let Some(argument) = arguments.next() {
        if argument == "--credential-stdin" {
            if credential_stdin {
                return Err("duplicate quota option");
            }
            credential_stdin = true;
            continue;
        }
        if argument == "--allow-plaintext" {
            if allow_plaintext {
                return Err("duplicate quota option");
            }
            allow_plaintext = true;
            continue;
        }
        if !matches!(
            argument.as_str(),
            "--endpoint"
                | "--tenant"
                | "--expected-generation"
                | "--idempotency-key"
                | "--weight"
                | "--memory-bytes"
                | "--queue-slots"
                | "--task-slots"
                | "--buffer-cache-bytes"
                | "--batch-items"
                | "--lease-slots"
                | "--retry-slots"
                | "--io-permits"
                | "--cpu-work-units"
                | "--file-descriptors"
                | "--disk-headroom-bytes"
                | "--server-name"
                | "--trust-file"
        ) {
            return Err("unknown quota option");
        }
        let value = arguments.next().ok_or("missing quota option value")?;
        if options.insert(argument, value).is_some() {
            return Err("duplicate quota option");
        }
    }
    if !credential_stdin {
        return Err(
            "--credential-stdin is required; secrets are never accepted as arguments or environment variables",
        );
    }
    let endpoint: SocketAddr = options
        .remove("--endpoint")
        .ok_or("--endpoint is required")?
        .parse()
        .map_err(|_| "invalid API endpoint")?;
    if endpoint.port() == 0 {
        return Err("invalid API endpoint");
    }
    let transport = if allow_plaintext {
        if options.contains_key("--trust-file") || options.contains_key("--server-name") {
            return Err("TLS options do not apply to plaintext opt-out");
        }
        TenantQuotaTransport::PlaintextOptOut { endpoint }
    } else {
        TenantQuotaTransport::Tls {
            endpoint,
            server_name: options
                .remove("--server-name")
                .ok_or("--server-name is required for TLS")?,
            trust_file: options
                .remove("--trust-file")
                .ok_or("--trust-file is required unless --allow-plaintext is explicit")?
                .into(),
        }
    };
    let request = TenantQuotaUpdateRequest::new(
        options.remove("--tenant").ok_or("--tenant is required")?,
        take_u64(&mut options, "--expected-generation")?,
        options
            .remove("--idempotency-key")
            .ok_or("--idempotency-key is required")?,
        take_u32(&mut options, "--weight")?,
        TenantQuotaResources {
            memory_bytes: take_u64(&mut options, "--memory-bytes")?,
            queue_slots: take_u64(&mut options, "--queue-slots")?,
            task_slots: take_u64(&mut options, "--task-slots")?,
            buffer_cache_bytes: take_u64(&mut options, "--buffer-cache-bytes")?,
            batch_items: take_u64(&mut options, "--batch-items")?,
            lease_slots: take_u64(&mut options, "--lease-slots")?,
            retry_slots: take_u64(&mut options, "--retry-slots")?,
            io_permits: take_u64(&mut options, "--io-permits")?,
            cpu_work_units: take_u64(&mut options, "--cpu-work-units")?,
            file_descriptors: take_u64(&mut options, "--file-descriptors")?,
            disk_headroom_bytes: take_u64(&mut options, "--disk-headroom-bytes")?,
        },
    );
    if !options.is_empty() {
        return Err("option does not apply to tenant quota update");
    }
    request
        .validate()
        .map_err(|_| "invalid tenant quota request")?;
    Ok((transport, request))
}

fn take_u64(
    options: &mut std::collections::BTreeMap<String, String>,
    flag: &str,
) -> Result<u64, &'static str> {
    options
        .remove(flag)
        .ok_or("required quota option absent")?
        .parse()
        .map_err(|_| "invalid quota value")
}

fn take_u32(
    options: &mut std::collections::BTreeMap<String, String>,
    flag: &str,
) -> Result<u32, &'static str> {
    options
        .remove(flag)
        .ok_or("required quota option absent")?
        .parse()
        .map_err(|_| "invalid quota value")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quota_update_defaults_to_tls_and_accepts_plaintext_only_by_opt_out() {
        let tls = parse(
            valid_command("--server-name quota.example --trust-file quota-ca.pem")
                .split_whitespace()
                .map(ToOwned::to_owned),
        )
        .expect("TLS request parses");
        assert!(matches!(tls.0, TenantQuotaTransport::Tls { .. }));

        let plaintext = parse(
            valid_command("--allow-plaintext")
                .split_whitespace()
                .map(ToOwned::to_owned),
        )
        .expect("explicit plaintext request parses");
        assert!(matches!(
            plaintext.0,
            TenantQuotaTransport::PlaintextOptOut { .. }
        ));
    }

    #[test]
    fn quota_update_rejects_missing_or_invalid_named_administration_inputs() {
        for command in [
            valid_command(""),
            valid_command("--allow-plaintext --weight 0"),
            valid_command("--allow-plaintext --tenant malformed"),
            valid_command("--allow-plaintext --memory-bytes 0"),
            valid_command("--allow-plaintext --unknown value"),
        ] {
            assert!(
                parse(command.split_whitespace().map(ToOwned::to_owned)).is_err(),
                "{command}"
            );
        }
    }

    #[test]
    fn quota_update_parse_builds_the_generated_client_request()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let endpoint = listener.local_addr()?;
        let command = valid_command("--allow-plaintext").replacen(
            "--endpoint 127.0.0.1:8080",
            &format!("--endpoint {endpoint}"),
            1,
        );
        let (transport, request) = parse(command.split_whitespace().map(ToOwned::to_owned))?;
        let server = thread::spawn(move || -> Result<(), std::io::Error> {
            let (mut stream, _) = listener.accept()?;
            let mut bytes = [0_u8; 4096];
            let read = stream.read(&mut bytes)?;
            let request = String::from_utf8_lossy(&bytes[..read]);
            assert!(request.starts_with("POST /v1/tenant-quotas:update HTTP/1.1\r\n"));
            assert!(request.contains("\"tenant\":\"22222222-2222-2222-2222-222222222222\""));
            assert!(request.contains("\"memory_bytes\":11"));
            assert!(request.contains("\"disk_headroom_bytes\":21"));
            let body = r#"{"resource_generation":2}"#;
            stream.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )?;
            Ok(())
        });
        let client = TenantQuotaServiceClient::new(transport)?;
        assert_eq!(
            client.update("key-material", &request)?.resource_generation,
            2
        );
        server.join().map_err(|_| "server panicked")??;
        Ok(())
    }

    fn valid_command(transport: &str) -> String {
        format!(
            "quota update --endpoint 127.0.0.1:8080 --credential-stdin --tenant 22222222-2222-2222-2222-222222222222 --expected-generation 1 --idempotency-key 01010101-0101-0101-0101-010101010101 --weight 7 --memory-bytes 11 --queue-slots 12 --task-slots 13 --buffer-cache-bytes 14 --batch-items 15 --lease-slots 16 --retry-slots 17 --io-permits 18 --cpu-work-units 19 --file-descriptors 20 --disk-headroom-bytes 21 {transport}"
        )
    }
}
